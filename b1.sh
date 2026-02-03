#!/bin/bash
set -e

# =============================
# Variables
# =============================
SERVER_IP=$(curl -s https://api.ipify.org)
SERVER_IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')

# =============================
# Install Requirements
# =============================
install_require() {
  clear
  echo "Installing base packages..."

  apt update -y
  apt upgrade -y

  apt install -y \
    mariadb-server mariadb-client \
    openvpn easy-rsa \
    squid \
    stunnel4 \
    iptables iptables-persistent \
    curl unzip jq dos2unix nano \
    net-tools cron virt-what \
    php-cli php-fpm php-mysql php-zip php-gd php-mbstring php-curl php-xml php-bcmath \
    gnutls-bin pwgen \
    python3 python3-pip \
    screen
}

# =============================
# Squid (Modern)
# =============================
install_squid() {
  echo "Configuring Squid..."

  cat > /etc/squid/squid.conf <<EOF
acl SSH dst $SERVER_IP
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

http_access allow SSH
http_access deny all

http_port 3128
http_port 8080

visible_hostname Firenet-Proxy
coredump_dir /var/spool/squid
EOF

  systemctl enable squid
  systemctl restart squid
}

# =============================
# OpenVPN
# =============================
install_openvpn() {
  echo "Installing OpenVPN..."

  mkdir -p /etc/openvpn/{server,login,easy-rsa/keys}
  mkdir -p /var/www/html

  sed -i 's/#DNS=/DNS=1.1.1.1/' /etc/systemd/resolved.conf
  sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
  systemctl restart systemd-resolved
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

  cat > /etc/openvpn/server/server.conf <<EOF
port 443
proto udp
dev tun
server 10.30.0.0 255.255.252.0
duplicate-cn
topology subnet
cipher none
auth none
keepalive 10 120
persist-key
persist-tun
client-cert-not-required
verify-client-cert none
username-as-common-name
script-security 3
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
log /etc/openvpn/server/udp.log
verb 3
EOF

  cat > /etc/openvpn/server/server2.conf <<EOF
port 1194
proto tcp
dev tun
server 10.20.0.0 255.255.252.0
duplicate-cn
topology subnet
cipher none
auth none
keepalive 10 120
persist-key
persist-tun
client-cert-not-required
verify-client-cert none
username-as-common-name
script-security 3
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
log /etc/openvpn/server/tcp.log
verb 3
EOF

  cat > /etc/openvpn/login/connect.sh <<EOF
#!/bin/bash
curl -s -d "user=\$common_name&ip=$SERVER_IP" https://panel.onebesthost.com/database/api/connect.php >/dev/null
EOF

  cat > /etc/openvpn/login/disconnect.sh <<EOF
#!/bin/bash
curl -s -d "user=\$common_name" https://panel.onebesthost.com/database/api/disconnect.php >/dev/null
EOF

  chmod +x /etc/openvpn/login/*.sh

  systemctl enable openvpn@server
  systemctl enable openvpn@server2
  systemctl restart openvpn@server
  systemctl restart openvpn@server2
}

# =============================
# Stunnel
# =============================
install_stunnel() {
  echo "Installing Stunnel..."

  cat > /etc/stunnel/stunnel.conf <<EOF
cert = /etc/stunnel/stunnel.pem
client = no

[openvpn]
accept = 443
connect = 127.0.0.1:1194
EOF

  systemctl enable stunnel4
  systemctl restart stunnel4
}

# =============================
# IPTables + Sysctl
# =============================
install_iptables() {
  echo "Configuring firewall..."

  cat >> /etc/sysctl.conf <<EOF
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

  sysctl -p

  iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o $SERVER_IFACE -j MASQUERADE
  iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o $SERVER_IFACE -j MASQUERADE

  netfilter-persistent save
}

# =============================
# Systemd Startup Service
# =============================
install_startup() {
  cat > /usr/local/bin/firenet-start.sh <<EOF
#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
sysctl -p
systemctl restart squid
systemctl restart stunnel4
systemctl restart openvpn@server
systemctl restart openvpn@server2
EOF

  chmod +x /usr/local/bin/firenet-start.sh

  cat > /etc/systemd/system/firenet.service <<EOF
[Unit]
Description=Firenet Startup
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firenet-start.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reexec
  systemctl enable firenet
}

# =============================
# Finish
# =============================
install_done() {
  clear
  echo "=============================="
  echo " FIRENET VPN INSTALLED"
  echo "=============================="
  echo "IP            : $SERVER_IP"
  echo "OpenVPN TCP   : 1194"
  echo "OpenVPN UDP   : 443"
  echo "Squid Proxy   : 3128 / 8080"
  echo "=============================="
}

# =============================
# Run
# =============================
install_require
install_squid
install_openvpn
install_stunnel
install_iptables
install_startup
install_done
