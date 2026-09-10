#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive

readonly SUPPORTED_UBUNTU_VERSIONS="20.04 22.04 24.04"
readonly AUTH_URL="${AUTH_URL:-https://ddxvpn.org/database/api/auth.php}"
readonly CONNECT_URL="${CONNECT_URL:-https://ddxvpn.org/database/api/connect.php}"
readonly DISCONNECT_URL="${DISCONNECT_URL:-https://ddxvpn.org/database/api/disconnect.php}"
readonly DATA_CIPHER_MODE="${DATA_CIPHER_MODE:-secure}"
BACKUP_TAG=$(date +%Y%m%d-%H%M%S)
readonly BACKUP_TAG

log() {
  printf '[firenet] %s\n' "$*"
}

die() {
  printf '[firenet] ERROR: %s\n' "$*" >&2
  exit 1
}

on_error() {
  printf '[firenet] ERROR: command failed at line %s: %s\n' "$1" "$2" >&2
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

backup_file() {
  local path=$1
  if [[ -e $path && ! -e ${path}.firenet-backup-${BACKUP_TAG} ]]; then
    cp -a -- "$path" "${path}.firenet-backup-${BACKUP_TAG}"
  fi
}

require_supported_system() {
  [[ $EUID -eq 0 ]] || die "Run this installer as root."
  [[ -r /etc/os-release ]] || die "Cannot identify the operating system."

  # shellcheck disable=SC1091
  . /etc/os-release
  [[ ${ID:-} == ubuntu ]] || die "Only Ubuntu is supported."
  case " $SUPPORTED_UBUNTU_VERSIONS " in
    *" ${VERSION_ID:-} "*) ;;
    *) die "Ubuntu ${VERSION_ID:-unknown} is unsupported; use 20.04, 22.04, or 24.04." ;;
  esac
  [[ $DATA_CIPHER_MODE == secure || $DATA_CIPHER_MODE == none ]] \
    || die "DATA_CIPHER_MODE must be 'secure' or 'none'."

  timedatectl set-timezone Asia/Riyadh
  log "Detected Ubuntu $VERSION_ID."
}

install_packages() {
  log "Updating package metadata."
  # Never mix the legacy Ubuntu 14.04 repository with supported releases.
  if [[ -f /etc/apt/sources.list.d/trusty_sources.list ]]; then
    backup_file /etc/apt/sources.list.d/trusty_sources.list
    rm -f /etc/apt/sources.list.d/trusty_sources.list
  fi

  apt-get -o Acquire::ForceIPv4=true update
  apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
  add-apt-repository -y universe
  apt-get -o Acquire::ForceIPv4=true update
  log "Installing supported distribution packages."
  apt-get -o Acquire::ForceIPv4=true install -y \
    ca-certificates curl iproute2 iptables jq nano net-tools openssl \
    openvpn squid stunnel4 unzip virt-what
}

discover_network() {
  SERVER_INTERFACE=$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  SERVER_IP=$(curl -4 --fail --silent --show-error --max-time 10 https://api.ipify.org || true)
  [[ -n ${SERVER_INTERFACE:-} ]] || die "Could not determine the public network interface."
  [[ -n ${SERVER_IP:-} ]] \
    || SERVER_IP=$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
  [[ -n ${SERVER_IP:-} ]] || die "Could not determine the server IPv4 address."
  VPN_HOST=${VPN_HOST:-$SERVER_IP}
  log "Using interface $SERVER_INTERFACE and VPN endpoint $VPN_HOST."
}

configure_pki() {
  local key_dir=/etc/openvpn/easy-rsa/keys
  local cert_pub key_pub
  install -d -m 700 "$key_dir"

  cert_pub=$(openssl x509 -in "$key_dir/server.crt" -pubkey -noout 2>/dev/null || true)
  key_pub=$(openssl pkey -in "$key_dir/server.key" -pubout 2>/dev/null || true)

  if openssl x509 -in "$key_dir/ca.crt" -noout >/dev/null 2>&1 \
    && openssl x509 -in "$key_dir/server.crt" -noout >/dev/null 2>&1 \
    && openssl pkey -in "$key_dir/server.key" -noout >/dev/null 2>&1 \
    && openssl verify -CAfile "$key_dir/ca.crt" "$key_dir/server.crt" >/dev/null 2>&1 \
    && [[ -n $cert_pub && $cert_pub == "$key_pub" ]]; then
    log "Preserving the existing OpenVPN CA and server certificate."
    return
  fi

  log "Generating a unique OpenVPN CA and server certificate."
  for name in ca.crt ca.key ca.srl server.crt server.csr server.key server-ext.cnf; do
    backup_file "$key_dir/$name"
  done

  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj "/CN=Firenet-OpenVPN-CA" \
    -keyout "$key_dir/ca.key" -out "$key_dir/ca.crt"
  openssl req -new -newkey rsa:3072 -sha256 -nodes \
    -subj "/CN=server" \
    -keyout "$key_dir/server.key" -out "$key_dir/server.csr"
  cat >"$key_dir/server-ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,IP:${SERVER_IP}
EOF
  openssl x509 -req -in "$key_dir/server.csr" \
    -CA "$key_dir/ca.crt" -CAkey "$key_dir/ca.key" -CAcreateserial \
    -days 3650 -sha256 -extfile "$key_dir/server-ext.cnf" \
    -out "$key_dir/server.crt"
  chmod 600 "$key_dir/ca.key" "$key_dir/server.key"
  chmod 644 "$key_dir/ca.crt" "$key_dir/server.crt"
}

openvpn_security_settings() {
  local version_output version
  version_output=$(openvpn --version 2>&1 || true)
  version=$(awk 'NR==1 {print $2}' <<<"$version_output")
  [[ -n $version ]] || die "Could not determine the OpenVPN version."
  if [[ $DATA_CIPHER_MODE == secure ]]; then
    if dpkg --compare-versions "$version" lt 2.5; then
      printf '%s\n' \
        'cipher AES-256-GCM' \
        'ncp-ciphers AES-256-GCM:AES-128-GCM' \
        'auth SHA256'
    else
      printf '%s\n' \
        'cipher AES-256-GCM' \
        'data-ciphers AES-256-GCM:AES-128-GCM' \
        'data-ciphers-fallback AES-256-GCM' \
        'auth SHA256'
    fi
  elif dpkg --compare-versions "$version" lt 2.5; then
    printf '%s\n' 'cipher none' 'ncp-disable' 'auth none'
  else
    printf '%s\n' 'cipher none' 'data-ciphers none' 'data-ciphers-fallback none' 'auth none'
  fi
}

write_auth_scripts() {
  install -d -m 750 /etc/openvpn/login /etc/openvpn/server /var/www/html/stat

  cat >/etc/openvpn/login/config.sh <<EOF
#!/usr/bin/env bash
AUTH_URL='${AUTH_URL}'
CONNECT_URL='${CONNECT_URL}'
DISCONNECT_URL='${DISCONNECT_URL}'
SERVER_IP='${SERVER_IP}'
EOF

  cat >/etc/openvpn/login/auth_vpn <<'EOF'
#!/usr/bin/env bash
set -u
. /etc/openvpn/login/config.sh
response=$(curl --fail --silent --show-error --max-time 10 \
  --data-urlencode "username=${username:-}" "$AUTH_URL") || exit 1
[[ $response == ok ]]
EOF

  cat >/etc/openvpn/login/connect.sh <<'EOF'
#!/usr/bin/env bash
set -u
. /etc/openvpn/login/config.sh
curl --fail --silent --show-error --max-time 10 \
  --data-urlencode "username=${common_name:-}" \
  --data-urlencode "server_ip=$SERVER_IP" \
  --data-urlencode "active_date=$(date '+%Y-%m-%d %T')" \
  "$CONNECT_URL" >/dev/null || true
exit 0
EOF

  cat >/etc/openvpn/login/disconnect.sh <<'EOF'
#!/usr/bin/env bash
set -u
. /etc/openvpn/login/config.sh
curl --fail --silent --show-error --max-time 10 \
  --data-urlencode "username=${common_name:-}" \
  "$DISCONNECT_URL" >/dev/null || true
exit 0
EOF

  # OpenVPN executes these after dropping to the nobody account.
  chmod 644 /etc/openvpn/login/config.sh
  chmod 755 /etc/openvpn/login/auth_vpn /etc/openvpn/login/connect.sh /etc/openvpn/login/disconnect.sh
}

write_openvpn_config() {
  local path=$1 protocol=$2 port=$3 network=$4 status_path=$5 log_path=$6
  local security_settings
  security_settings=$(openvpn_security_settings)

  backup_file "$path"
  cat >"$path" <<EOF
# Firenet OpenVPN configuration for Ubuntu 20.04, 22.04, and 24.04
duplicate-cn
dev tun
port $port
proto $protocol
topology subnet
server $network 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh none
tls-server
tls-version-min 1.2
$security_settings
sndbuf 0
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
script-security 2
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_${port}.txt
auth-user-pass-verify /etc/openvpn/login/auth_vpn via-env
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log-append $log_path
status $status_path
verb 3
EOF
  chmod 600 "$path"
}

generate_client_profile() {
  local path=$1 protocol=$2 port=$3
  local client_security
  if [[ $DATA_CIPHER_MODE == secure ]]; then
    client_security=$'cipher AES-256-GCM\nauth SHA256'
  else
    client_security=$'cipher none\nauth none\ndata-ciphers none'
  fi
  cat >"$path" <<EOF
client
dev tun
proto $protocol
remote $VPN_HOST $port
$client_security
auth-user-pass
auth-nocache
remote-cert-tls server
redirect-gateway def1
setenv CLIENT_CERT 0
verb 3
<ca>
$(cat /etc/openvpn/easy-rsa/keys/ca.crt)
</ca>
EOF
  chmod 600 "$path"
}

configure_openvpn() {
  log "Configuring OpenVPN."
  write_auth_scripts
  write_openvpn_config /etc/openvpn/server.conf udp 443 10.30.0.0 \
    /etc/openvpn/server/udpclient.log /etc/openvpn/server/udpserver.log
  write_openvpn_config /etc/openvpn/server2.conf tcp-server 1194 10.20.0.0 \
    /var/www/html/tcpclient.log /etc/openvpn/server/tcpserver.log
  generate_client_profile /root/openvpn-udp-443.ovpn udp 443
  generate_client_profile /root/openvpn-tcp-1194.ovpn tcp-client 1194
}

configure_squid() {
  log "Configuring Squid from the Ubuntu repository."
  backup_file /etc/squid/squid.conf
  cat >/etc/squid/squid.conf <<EOF
acl server_ip dst $SERVER_IP
acl SSL_ports port 443
acl Safe_ports port 21
acl Safe_ports port 70
acl Safe_ports port 80
acl Safe_ports port 210
acl Safe_ports port 280
acl Safe_ports port 443
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl Safe_ports port 1025-65535
acl CONNECT method CONNECT
http_access allow server_ip
http_access deny manager
http_access deny all
http_port 3128
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Firenet-Proxy
EOF
  squid -k parse
  systemctl disable --now squid3.service >/dev/null 2>&1 || true
  systemctl enable --now squid.service
}

configure_stunnel() {
  log "Configuring stunnel on TCP port 443."
  install -d -m 755 /etc/stunnel
  if ! openssl x509 -in /etc/stunnel/stunnel.crt -noout >/dev/null 2>&1 \
    || ! openssl pkey -in /etc/stunnel/stunnel.key -noout >/dev/null 2>&1; then
    backup_file /etc/stunnel/stunnel.crt
    backup_file /etc/stunnel/stunnel.key
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
      -subj "/CN=$VPN_HOST" \
      -keyout /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.crt
  fi
  cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt >/etc/stunnel/stunnel.pem
  chmod 600 /etc/stunnel/stunnel.key /etc/stunnel/stunnel.pem
  chmod 644 /etc/stunnel/stunnel.crt

  backup_file /etc/stunnel/stunnel.conf
  cat >/etc/stunnel/stunnel.conf <<'EOF'
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
connect = 127.0.0.1:1194
accept = 443
EOF
  cat >/etc/default/stunnel4 <<'EOF'
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""
EOF
  chmod 644 /etc/default/stunnel4 /etc/stunnel/stunnel.conf
  systemctl enable stunnel4.service
}

install_firewall_service() {
  log "Installing idempotent firewall and NAT rules."
  cat >/usr/local/sbin/firenet-firewall <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
interface=$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
[[ -n $interface ]]

ensure_rule() {
  local table=$1
  shift
  if ! iptables -t "$table" -C "$@" 2>/dev/null; then
    iptables -t "$table" -A "$@"
  fi
}

ensure_input_rule() {
  if ! iptables -C INPUT "$@" 2>/dev/null; then
    iptables -I INPUT 1 "$@"
  fi
}

ensure_forward_rule() {
  if ! iptables -C FORWARD "$@" 2>/dev/null; then
    iptables -I FORWARD 1 "$@"
  fi
}

ensure_rule nat POSTROUTING -s 10.20.0.0/22 -o "$interface" -j MASQUERADE
ensure_rule nat POSTROUTING -s 10.30.0.0/22 -o "$interface" -j MASQUERADE
ensure_forward_rule -s 10.20.0.0/22 -o "$interface" -j ACCEPT
ensure_forward_rule -s 10.30.0.0/22 -o "$interface" -j ACCEPT
ensure_forward_rule -d 10.20.0.0/22 -i "$interface" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ensure_forward_rule -d 10.30.0.0/22 -i "$interface" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ensure_input_rule -p tcp --dport 1194 -j ACCEPT
ensure_input_rule -p udp --dport 443 -j ACCEPT
ensure_input_rule -p tcp --dport 443 -j ACCEPT
ensure_input_rule -p tcp --dport 3128 -j ACCEPT
ensure_input_rule -p tcp --dport 8080 -j ACCEPT
EOF
  chmod 750 /usr/local/sbin/firenet-firewall

  cat >/etc/systemd/system/firenet-firewall.service <<'EOF'
[Unit]
Description=Firenet VPN firewall and NAT rules
Wants=network-online.target
After=network-online.target ufw.service
Before=openvpn@server.service openvpn@server2.service stunnel4.service squid.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/firenet-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now firenet-firewall.service
}

configure_sysctl() {
  log "Enabling IPv4 forwarding."
  cat >/etc/sysctl.d/99-firenet-vpn.conf <<'EOF'
net.ipv4.ip_forward=1
net.core.somaxconn=4096
net.ipv4.tcp_mtu_probing=1
EOF
  sysctl --system >/dev/null
}

start_services() {
  log "Starting and enabling VPN services."
  systemctl daemon-reload
  systemctl enable openvpn@server.service openvpn@server2.service stunnel4.service squid.service
  systemctl restart openvpn@server.service openvpn@server2.service
  systemctl restart stunnel4.service squid.service
}

verify_installation() {
  local failed=0
  for unit in firenet-firewall openvpn@server openvpn@server2 stunnel4 squid; do
    if ! systemctl is-active --quiet "$unit.service"; then
      systemctl --no-pager --full status "$unit.service" || true
      failed=1
    fi
  done
  (( failed == 0 )) || die "One or more required services failed."

  ss -H -lun sport = :443 | grep -q . || die "OpenVPN UDP port 443 is not listening."
  ss -H -ltn sport = :1194 | grep -q . || die "OpenVPN TCP port 1194 is not listening."
  ss -H -ltn sport = :443 | grep -q . || die "stunnel TCP port 443 is not listening."
  log "Installation verified successfully."
}

main() {
  require_supported_system
  install_packages
  discover_network
  configure_pki
  configure_openvpn
  configure_squid
  configure_stunnel
  configure_sysctl
  install_firewall_service
  start_services
  verify_installation

  printf '\nFirenet installation complete.\n'
  printf 'VPN endpoint: %s\n' "$VPN_HOST"
  printf 'OpenVPN TCP: 1194\nOpenVPN UDP: 443\nstunnel TLS: 443\n'
  printf 'Client profiles:\n  /root/openvpn-tcp-1194.ovpn\n  /root/openvpn-udp-443.ovpn\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
