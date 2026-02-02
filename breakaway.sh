#!/bin/bash

# Set timezone
cp /usr/share/zoneinfo/Asia/Riyadh /etc/localtime

# Database Details
HOST='92.113.22.127';
USER='u672427164_vlpvvs';
PASS='wcsMc30rcg';
DBNAME='u672427164_vlpvvs';

install_require()
{
  clear
  echo "Updating your system."
  {
    apt-get -o Acquire::ForceIPv4=true update
  } &>/dev/null
  clear
  echo "Installing dependencies."
  {
    apt-get -o Acquire::ForceIPv4=true install mysql-client iptables -y
    apt-get -o Acquire::ForceIPv4=true install mariadb-server stunnel4 openvpn -y
    apt-get -o Acquire::ForceIPv4=true install dos2unix easy-rsa nano curl unzip jq virt-what net-tools -y
    apt-get -o Acquire::ForceIPv4=true install php-cli net-tools cron php-fpm php-json php-pdo php-zip php-gd php-mbstring php-curl php-xml php-bcmath php-json -y
    apt-get -o Acquire::ForceIPv4=true install gnutls-bin pwgen python3 python-is-python3 -y
    
    # Install Easy-RSA for Ubuntu 22/24
    if [ -f /etc/os-release ]; then
      . /etc/os-release
      if [ "$VERSION_ID" = "22.04" ] || [ "$VERSION_ID" = "24.04" ]; then
        apt-get -o Acquire::ForceIPv4=true install easy-rsa -y
        # Fix easy-rsa path for newer Ubuntu
        if [ ! -d "/etc/openvpn/easy-rsa" ]; then
          mkdir -p /etc/openvpn/easy-rsa
          cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
        fi
      fi
    fi
  } &>/dev/null
}

install_squid()
{
clear
echo "Installing proxy."
{
# Remove old trusty sources and install squid from default repos
rm -f /etc/apt/sources.list.d/trusty_sources.list
apt update -y

# Install squid for Ubuntu 20/22/24
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [ "$VERSION_ID" = "20.04" ]; then
    apt install -y squid squid-common
  elif [ "$VERSION_ID" = "22.04" ] || [ "$VERSION_ID" = "24.04" ]; then
    apt install -y squid squid-common
    # For Ubuntu 22/24, use systemd service directly
    systemctl enable squid
  fi
else
  apt install -y squid squid-common
fi

# Create squid config
echo "acl SSH dst $(curl -s https://api.ipify.org)
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
http_access allow SSH
http_access deny manager
http_access deny all
http_port 8080
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Firenet-Proxy
error_directory /usr/share/squid/errors/English" > /etc/squid/squid.conf

# Create errors directory if it doesn't exist
mkdir -p /usr/share/squid/errors/English

# Restart squid based on Ubuntu version
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [ "$VERSION_ID" = "20.04" ]; then
    systemctl restart squid
  elif [ "$VERSION_ID" = "22.04" ] || [ "$VERSION_ID" = "24.04" ]; then
    systemctl restart squid
  fi
else
  systemctl restart squid
fi
} &>/dev/null
}

install_openvpn()
{
clear
echo "Installing openvpn."
{
mkdir -p /etc/openvpn/easy-rsa/keys
mkdir -p /etc/openvpn/login
mkdir -p /etc/openvpn/server
mkdir -p /var/www/html/stat
touch /etc/openvpn/server.conf
touch /etc/openvpn/server2.conf

# Fix for systemd-resolved on Ubuntu 22/24
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [ "$VERSION_ID" = "22.04" ] || [ "$VERSION_ID" = "24.04" ]; then
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true
  else
    echo 'DNS=1.1.1.1
DNSStubListener=no' >> /etc/systemd/resolved.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
  fi
fi

echo '# Openvpn Configuration by techydev :)
duplicate-cn
dev tun
port 443
proto udp
topology subnet
server 10.30.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher none
ncp-disable
auth none
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
client-cert-not-required
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_udp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log /etc/openvpn/server/udpserver.log
status /etc/openvpn/server/udpclient.log
verb 3' > /etc/openvpn/server.conf

echo '# Fixed Cert By techydev
# Openvpn Configuration by Firenet Philippines :)
duplicate-cn
dev tun
port 1194
proto tcp
topology subnet
server 10.20.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher none
ncp-disable
auth none
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
client-cert-not-required
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_tcp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log /etc/openvpn/server/tcpserver.log
status /var/www/html/tcpclient.log
verb 3' > /etc/openvpn/server2.conf

cat <<\EOM >/etc/openvpn/login/config.sh
#!/bin/bash
# config.sh - VPN server config

AUTH_URL="https://panel.onebesthost.com/database/api/auth.php"
CONNECT_URL="https://panel.onebesthost.com/database/api/connect.php"
DISCONNECT_URL="https://panel.onebesthost.com/database/api/disconnect.php"
EOM

sed -i "s|https://breakawayvpn.co.uk/database/api/auth.php|$HOST|g" /etc/openvpn/login/config.sh
sed -i "s|https://breakawayvpn.co.uk/database/api/connect.php|$USER|g" /etc/openvpn/login/config.sh
sed -i "s|https://breakawayvpn.co.uk/database/api/disconnect.php|$DBNAME|g" /etc/openvpn/login/config.sh

/bin/cat <<"EOM" >/etc/openvpn/login/auth_vpn
#!/bin/bash
. /etc/openvpn/login/config.sh

# Send username and optional password to PHP auth
RESPONSE=$(curl -s -d "username=$username" "$AUTH_URL")

if [ "$RESPONSE" = "ok" ]; then
    exit 0
else
    exit 1
fi
EOM

cat <<'LENZ05' >/etc/openvpn/login/connect.sh
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"
SERVER_IP=$(curl -s https://api.ipify.org)
DATENOW=$(date +"%Y-%m-%d %T")

curl -s -d "username=$USERNAME&server_ip=$SERVER_IP&active_date=$DATENOW" "$CONNECT_URL"
LENZ05

cat <<'LENZ06' >/etc/openvpn/login/disconnect.sh
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"
curl -s -d "username=$USERNAME" "$DISCONNECT_URL"
LENZ06

cat << EOF > /etc/openvpn/easy-rsa/keys/ca.crt
-----BEGIN CERTIFICATE-----
MIICMTCCAZqgAwIBAgIUAaQBApMS2dYBqYPcA3Pa7cjjw7cwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwES29iWjAeFw0yMDA3MjIyMjIzMzNaFw0zMDA3MjAyMjIz
MzNaMA8xDTALBgNVBAMMBEtvYlowgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
AMF46UVi2O5pZpddOPyzU2EyIrr8NrpXqs8BlYhUjxOcCrkMjFu2G9hk7QIZ4qO0
GWVZpPhYk5qWk+LxCsryrSoe0a5HaqIye8BFJmXV0k+O/3e6k06UGNii3gxBWQpF
7r/2CyQLus9OSpQPYszByBvtkwiBAo/V98jdpm+EVu6tAgMBAAGjgYkwgYYwHQYD
VR0OBBYEFGRJMm/+ZmLxV027kahdvSY+UaTSMEoGA1UdIwRDMEGAFGRJMm/+ZmLx
V027kahdvSY+UaTSoROkETAPMQ0wCwYDVQQDDARLb2JaghQBpAECkxLZ1gGpg9wD
c9rtyOPDtzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsF
AAOBgQC0f8wb5hyEOEEX64l8QCNpyd/WLjoeE5bE+xnIcKE+XpEoDRZwugLoyQdc
HKa3aRHNqKpR7H696XJReo4+pocDeyj7rATbO5dZmSMNmMzbsjQeXux0XjwmZIHu
eDKMefDi0ZfiZmnU2njmTncyZKxv18Ikjws0Myc8PtAxy2qdcA==
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.crt
-----BEGIN CERTIFICATE-----
MIICVDCCAb2gAwIBAgIQQCbakRgrd5yFagy7ypBT/jANBgkqhkiG9w0BAQsFADAP
MQ0wCwYDVQQDDARLb2JaMB4XDTIwMDcyMjIyMjM1NVoXDTMwMDcyMDIyMjM1NVow
ETEPMA0GA1UEAwwGc2VydmVyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDO
NSPYXZ+2m8tqieGQr0LfX/i9rad4msog8D1b1snvTEqZlsM4/Vm012Xt1Kf6qwPi
vogvyvyQ3bC3vCPLg6w24gFXaWS44Z5R8KadE9mSa00EphBkoz9r//4yrJFjwnEk
vp52T4fMOgOhnkg/EZIzOxkWnNBdFu7BQmeZR2ZnZwIDAQABo4GuMIGrMAkGA1Ud
EwQCMAAwHQYDVR0OBBYEFGsIwGQQcagyfwv+HpgfvXJ0D8hmMEoGA1UdIwRDMEGA
FGRJMm/+ZmLxV027kahdvSY+UaTSoROkETAPMQ0wCwYDVQQDDARLb2JaghQBpAEC
kxLZ1gGpg9wDc9rtyOPDtzATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
BaAwEQYDVR0RBAowCIIGc2VydmVyMA0GCSqGSIb3DQEBCwUAA4GBAKE+rIML5V3K
NrfQq9DZc2bRYojOPUeeCAugW1ET/H7XbhcOvfXZqdkGeFKIWuXf0zIiSksIb7Ei
gE8Z0V+dtloX961wqQQA//6EquHLDnTAGnULPpiQHSK6pHomZX3RO1xFoXci7bZr
GKPE7j4GuwvsEqwWpVCz7UZDh3L9dYw4
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.key
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM41I9hdn7aby2qJ
4ZCvQt9f+L2tp3iayiDwPVvWye9MSpmWwzj9WbTXZe3Up/qrA+K+iC/K/JDdsLe8
I8uDrDbiAVdpZLjhnlHwpp0T2ZJrTQSmEGSjP2v//jKskWPCcSS+nnZPh8w6A6Ge
SD8RkjM7GRac0F0W7sFCZ5lHZmdnAgMBAAECgYAFNrC+UresDUpaWjwaxWOidDG8
0fwu/3Lm3Ewg21BlvX8RXQ94jGdNPDj2h27r1pEVlY2p767tFr3WF2qsRZsACJpI
qO1BaSbmhek6H++Fw3M4Y/YY+JD+t1eEBjJMa+DR5i8Vx3AE8XOdTXmkl/xK4jaB
EmLYA7POyK+xaDCeEQJBAPJadiYd3k9OeOaOMIX+StCs9OIMniRz+090AJZK4CMd
jiOJv0mbRy945D/TkcqoFhhScrke9qhgZbgFj11VbDkCQQDZ0aKBPiZdvDMjx8WE
y7jaltEDINTCxzmjEBZSeqNr14/2PG0X4GkBL6AAOLjEYgXiIvwfpoYE6IIWl3re
ebCfAkAHxPimrixzVGux0HsjwIw7dl//YzIqrwEugeSG7O2Ukpz87KySOoUks3Z1
yV2SJqNWskX1Q1Xa/gQkyyDWeCeZAkAbyDBI+ctc8082hhl8WZunTcs08fARM+X3
FWszc+76J1F2X7iubfIWs6Ndw95VNgd4E2xDATNg1uMYzJNgYvcTAkBoE8o3rKkp
em2n0WtGh6uXI9IC29tTQGr3jtxLckN/l9KsJ4gabbeKNoes74zdena1tRdfGqUG
JQbf7qSE3mg2
-----END PRIVATE KEY-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIGHAoGBAKqeBUWMYdj6+Z6kPVyQjm5Pc/nhSeczplV0AX/zJ5lL9TXRGNg+q/nK
tQyaBpmBWAHxHP8j7NmRQaN6rpBkqHOtXJB9FT35xDvnAAaMxYW5RetBRUW7UnJ3
s1qQZ6kAUwIgDHzS9ykP9IzKPTbCrMIA/8kHfJ1qMfSDY8slKSVjAgEC
-----END DH PARAMETERS-----
EOF

chmod 755 /etc/openvpn/server.conf
chmod 755 /etc/openvpn/server2.conf
chmod 755 /etc/openvpn/login/connect.sh
chmod 755 /etc/openvpn/login/disconnect.sh
chmod 755 /etc/openvpn/login/config.sh
chmod 755 /etc/openvpn/login/auth_vpn
}&>/dev/null
}

install_stunnel() {
  {
cd /etc/stunnel/

echo "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClmgCdm7RB2VWK
wfH8HO/T9bxEddWDsB3fJKpM/tiVMt4s/WMdGJtFdRlxzUb03u+HT6t00sLlZ78g
ngjxLpJGFpHAGdVf9vACBtrxv5qcrG5gd8k7MJ+FtMTcjeQm8kVRyIW7cOWxlpGY
6jringYZ6NcRTrh/OlxIHKdsLI9ddcekbYGyZVTm1wd22HVG+07PH/AeyY78O2+Z
tbjxGTFRSYt3jUaFeUmWNtxqWnR4MPmC+6iKvUKisV27P89g8v8CiZynAAWRJ0+A
qp+PWxwHi/iJ501WdLspeo8VkXIb3PivyIKC356m+yuuibD2uqwLZ2//afup84Qu
pRtgW/PbAgMBAAECggEAVo/efIQUQEtrlIF2jRNPJZuQ0rRJbHGV27tdrauU6MBT
NG8q7N2c5DymlT75NSyHRlKVzBYTPDjzxgf1oqR2X16Sxzh5uZTpthWBQtal6fmU
JKbYsDDlYc2xDZy5wsXnCC3qAaWs2xxadPUS3Lw/cjGsoeZlOFP4QtV/imLseaws
7r4KZE7SVO8dF8Xtcy304Bd7UsKClnbCrGsABUF/rqA8g34o7yrpo9XqcwbF5ihQ
TbnB0Ns8Bz30pjgGjJZTdTL3eskP9qMJWo/JM76kSaJWReoXTws4DlQHxO29z3eK
zKdxieXaBGMwFnv23JvXKJ5eAnxzqsL6a+SuNPPN4QKBgQDQhisSDdjUJWy0DLnJ
/HjtsnQyfl0efOqAlUEir8r5IdzDTtAEcW6GwPj1rIOm79ZeyysT1pGN6eulzS1i
6lz6/c5uHA9Z+7LT48ZaQjmKF06ItdfHI9ytoXaaQPMqW7NnyOFxCcTHBabmwQ+E
QZDFkM6vVXL37Sz4JyxuIwCNMQKBgQDLThgKi+L3ps7y1dWayj+Z0tutK2JGDww7
6Ze6lD5gmRAURd0crIF8IEQMpvKlxQwkhqR4vEsdkiFFJQAaD+qZ9XQOkWSGXvKP
A/yzk0Xu3qL29ZqX+3CYVjkDbtVOLQC9TBG60IFZW79K/Zp6PhHkO8w6l+CBR+yR
X4+8x1ReywKBgQCfSg52wSski94pABugh4OdGBgZRlw94PCF/v390En92/c3Hupa
qofi2mCT0w/Sox2f1hV3Fw6jWNDRHBYSnLMgbGeXx0mW1GX75OBtrG8l5L3yQu6t
SeDWpiPim8DlV52Jp3NHlU3DNrcTSOFgh3Fe6kpot56Wc5BJlCsliwlt0QKBgEol
u0LtbePgpI2QS41ewf96FcB8mCTxDAc11K6prm5QpLqgGFqC197LbcYnhUvMJ/eS
W53lHog0aYnsSrM2pttr194QTNds/Y4HaDyeM91AubLUNIPFonUMzVJhM86FP0XK
3pSBwwsyGPxirdpzlNbmsD+WcLz13GPQtH2nPTAtAoGAVloDEEjfj5gnZzEWTK5k
4oYWGlwySfcfbt8EnkY+B77UVeZxWnxpVC9PhsPNI1MTNET+CRqxNZzxWo3jVuz1
HtKSizJpaYQ6iarP4EvUdFxHBzjHX6WLahTgUq90YNaxQbXz51ARpid8sFbz1f37
jgjgxgxbitApzno0E2Pq/Kg=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIUOvs3vdjcBtCLww52CggSlAKafDkwDQYJKoZIhvcNAQEL
BQAwMjEQMA4GA1UEAwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNV
BAYTAlBIMB4XDTIxMDcwNzA1MzQwN1oXDTMxMDcwNTA1MzQwN1owMjEQMA4GA1UE
AwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNVBAYTAlBIMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApZoAnZu0QdlVisHx/Bzv0/W8RHXV
g7Ad3ySqTP7YlTLeLP1jHRibRXUZcc1G9N7vh0+rdNLC5We/IJ4I8S6SRhaRwBnV
X/bwAgba8b+anKxuYHfJOzCfhbTE3I3kJvJFUciFu3DlsZaRmOo64p4GGejXEU64
fzpcSBynbCyPXXXHpG2BsmVU5tcHdth1RvtOzx/wHsmO/DtvmbW48RkxUUmLd41G
hXlJljbcalp0eDD5gvuoir1CorFduz/PYPL/AomcpwAFkSdPgKqfj1scB4v4iedN
VnS7KXqPFZFyG9z4r8iCgt+epvsrromw9rqsC2dv/2n7qfOELqUbYFvz2wIDAQAB
o1MwUTAdBgNVHQ4EFgQUcKFL6tckon2uS3xGrpe1Zpa68VEwHwYDVR0jBBgwFoAU
cKFL6tckon2uS3xGrpe1Zpa68VEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAYQP0S67eoJWpAMavayS7NjK+6KMJtlmL8eot/3RKPLleOjEuCdLY
QvrP0Tl3M5gGt+I6WO7r+HKT2PuCN8BshIob8OGAEkuQ/YKEg9QyvmSm2XbPVBaG
RRFjvxFyeL4gtDlqb9hea62tep7+gCkeiccyp8+lmnS32rRtFa7PovmK5pUjkDOr
dpvCQlKoCRjZ/+OfUaanzYQSDrxdTSN8RtJhCZtd45QbxEXzHTEaICXLuXL6cmv7
tMuhgUoefS17gv1jqj/C9+6ogMVa+U7QqOvL5A7hbevHdF/k/TMn+qx4UdhrbL5Q
enL3UGT+BhRAPiA1I5CcG29RqjCzQoaCNg==
-----END CERTIFICATE-----" > stunnel.pem

echo "cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
connect = 127.0.0.1:1194
accept = 443" > stunnel.conf

echo 'ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""' > /etc/default/stunnel4

chmod 755 /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4
  } &>/dev/null
}

install_iptables(){
  {
echo -e "\033[01;31m Configure Sysctl \033[0m"
echo 'fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_all = 1' > /etc/sysctl.conf

echo '* soft nofile 512000
* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000

# Get server interface and IP
server_interface=$(ip route get 8.8.8.8 | awk '/dev/ {print $5}')
server_ip=$(curl -s https://api.ipify.org)

iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o "$server_interface" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o "$server_interface" -j SNAT --to-source "$server_ip"
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o "$server_interface" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o "$server_interface" -j SNAT --to-source "$server_ip"
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --update --seconds 30 --hitcount 10 --name DEFAULT --mask 255.255.255.255 --rsource -j DROP
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource

# Save iptables rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# Install iptables-persistent for Ubuntu 22/24
apt-get install -y iptables-persistent netfilter-persistent

sysctl -p
  }&>/dev/null
}

install_rclocal(){
  {
    # Download socks proxy script
    wget https://pastebin.com/raw/z9j2nA8p -O /etc/ubuntu
    dos2unix /etc/ubuntu
    chmod +x /etc/ubuntu
    
    # Create systemd service for socks proxy
    cat << EOF > /etc/systemd/system/socks-proxy.service
[Unit]
Description=SOCKS5 Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/ubuntu
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Create rc-local service for Ubuntu 22/24 compatibility
    cat << EOF > /etc/systemd/system/rc-local.service
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF

    # Create rc.local script
    cat << 'EOF' > /etc/rc.local
#!/bin/bash
# rc.local - Script to run at boot

# Sleep for network to be ready
sleep 10

# Stop UFW if installed
systemctl stop ufw 2>/dev/null || true
systemctl disable ufw 2>/dev/null || true

# Restore iptables rules
iptables-restore < /etc/iptables/rules.v4 2>/dev/null || true
ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null || true

# Apply sysctl settings
sysctl -p >/dev/null 2>&1

# Start services
systemctl restart squid 2>/dev/null || true
systemctl restart stunnel4 2>/dev/null || true
systemctl restart openvpn@server 2>/dev/null || true
systemctl restart openvpn@server2 2>/dev/null || true
systemctl restart socks-proxy 2>/dev/null || true

# Start socks proxy in screen as fallback
screen -dmS socks python3 /etc/ubuntu 2>/dev/null || true

exit 0
EOF

    chmod +x /etc/rc.local
    
    # Enable services
    systemctl enable rc-local
    systemctl enable socks-proxy
    systemctl enable openvpn@server
    systemctl enable openvpn@server2
    
    # Start services
    systemctl start rc-local
    systemctl start socks-proxy
  }&>/dev/null
}

install_done()
{
  # Start OpenVPN services
  systemctl start openvpn@server
  systemctl start openvpn@server2
  
  clear
  echo "================================================"
  echo "OPENVPN SERVER FIRENET INSTALLATION COMPLETE"
  echo "================================================"
  echo "Server IP: $(curl -s https://api.ipify.org)"
  echo "------------------------------------------------"
  echo "OPENVPN TCP port: 1194"
  echo "OPENVPN UDP port: 443"
  echo "OPENVPN SSL port: 443"
  echo "SOCKS port: 80"
  echo "PROXY port: 3128"
  echo "PROXY port: 8080"
  echo "================================================"
  echo "Installation completed successfully!"
  echo "================================================"
  
  # Clean up
  history -c
  rm -f maindbv2.sh
}

# Main installation flow
install_require
install_squid
install_openvpn
install_stunnel
install_iptables
install_rclocal
install_done
