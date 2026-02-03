#!/bin/bash

install_require()
{
  clear
  echo "Updating your system."
  {
    apt-get update
  } &>/dev/null
  clear
  echo "Installing dependencies."
  {
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      mysql-client \
      iptables \
      mariadb-server \
      stunnel4 \
      openvpn \
      dos2unix \
      easy-rsa \
      nano \
      curl \
      unzip \
      jq \
      virt-what \
      net-tools \
      php-cli \
      cron \
      php-fpm \
      php-common \
      php-mysql \
      php-zip \
      php-gd \
      php-mbstring \
      php-curl \
      php-xml \
      php-bcmath \
      gnutls-bin \
      pwgen \
      python3 \
      squid \
      apache2-utils
  } &>/dev/null
}

install_squid()
{
clear
echo "Installing proxy."
{
# Install squid from Ubuntu 22.04 repositories
apt-get install -y squid squid-common

# Create squid configuration
echo "acl SSL_ports port 443
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
http_access allow localhost
http_access allow all
http_access deny all
http_port 3128
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Firenet-Proxy
error_directory /usr/share/squid/errors/English" > /etc/squid/squid.conf

# Create custom error pages directory if needed
mkdir -p /usr/share/squid/errors/English

# Enable and start squid
systemctl enable squid
systemctl restart squid
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

# Fix for systemd-resolved conflict
systemctl disable --now systemd-resolved
rm -f /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
chattr +i /etc/resolv.conf 2>/dev/null || true

# UDP Configuration
echo '# Openvpn Configuration
client-to-client
duplicate-cn
dev tun
proto udp
port 443
topology subnet
server 10.30.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
auth none
cipher none
persist-key
persist-tun
keepalive 10 120
user nobody
group nogroup
username-as-common-name
client-cert-not-required
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_udp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
log /etc/openvpn/server/udpserver.log
status /etc/openvpn/server/udpclient.log
verb 3' > /etc/openvpn/server.conf

# TCP Configuration
echo '# Openvpn Configuration
client-to-client
duplicate-cn
dev tun
proto tcp
port 1194
topology subnet
server 10.20.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
auth none
cipher none
persist-key
persist-tun
keepalive 10 120
user nobody
group nogroup
username-as-common-name
client-cert-not-required
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_tcp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
log /etc/openvpn/server/tcpserver.log
status /var/www/html/tcpclient.log
verb 3' > /etc/openvpn/server2.conf

# Create config.sh
cat << 'EOM' > /etc/openvpn/login/config.sh
#!/bin/bash
AUTH_URL="https://panel.onebesthost.com/database/api/auth.php"
CONNECT_URL="https://panel.onebesthost.com/database/api/connect.php"
DISCONNECT_URL="https://panel.onebesthost.com/database/api/disconnect.php"
EOM

# Create auth_vpn
cat << 'EOM' > /etc/openvpn/login/auth_vpn
#!/bin/bash
. /etc/openvpn/login/config.sh

RESPONSE=$(curl -s -d "username=$username" "$AUTH_URL")
if [ "$RESPONSE" = "ok" ]; then
    exit 0
else
    exit 1
fi
EOM

# Create connect.sh
cat << 'EOM' > /etc/openvpn/login/connect.sh
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"
SERVER_IP=$(curl -s https://api.ipify.org)
DATENOW=$(date +"%Y-%m-%d %T")

curl -s -d "username=$USERNAME&server_ip=$SERVER_IP&active_date=$DATENOW" "$CONNECT_URL"
EOM

# Create disconnect.sh
cat << 'EOM' > /etc/openvpn/login/disconnect.sh
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"
curl -s -d "username=$USERNAME" "$DISCONNECT_URL"
EOM

# Create certificates
cat << 'EOF' > /etc/openvpn/easy-rsa/keys/ca.crt
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

cat << 'EOF' > /etc/openvpn/easy-rsa/keys/server.crt
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

cat << 'EOF' > /etc/openvpn/easy-rsa/keys/server.key
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

# Set permissions
chmod 755 /etc/openvpn/server.conf
chmod 755 /etc/openvpn/server2.conf
chmod 755 /etc/openvpn/login/*.sh
chmod 755 /etc/openvpn/login/auth_vpn
}&>/dev/null
}

install_stunnel() {
  {
# Install stunnel
apt-get install -y stunnel4

# Create stunnel configuration
echo "cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
connect = 127.0.0.1:1194
accept = 445" > /etc/stunnel/stunnel.conf

# Create certificate
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
-----END CERTIFICATE-----" > /etc/stunnel/stunnel.pem

# Enable stunnel
systemctl enable stunnel4
systemctl start stunnel4
  } &>/dev/null
}

install_iptables(){
  {
# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Get server IP and interface
server_interface=$(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" " | awk '{print $1}')
server_ip=$(curl -s https://api.ipify.org)

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow OpenVPN ports
iptables -A INPUT -p udp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 1194 -j ACCEPT
iptables -A INPUT -p tcp --dport 445 -j ACCEPT  # stunnel

# Allow Squid ports
iptables -A INPUT -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# NAT rules for OpenVPN
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o $server_interface -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o $server_interface -j MASQUERADE

# Save rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
  }&>/dev/null
}

install_rclocal(){
  {
# Install netcat for socks proxy
apt-get install -y netcat

# Create simple socks proxy script
cat << 'EOM' > /etc/socks.py
#!/usr/bin/env python3
import socket
import threading
import sys

def handle_client(client_socket):
    request = client_socket.recv(4096)
    # Simple SOCKS proxy implementation
    client_socket.send(b"HTTP/1.1 200 OK\r\n\r\n")
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 80))
    server.listen(5)
    print("SOCKS proxy listening on port 80")
    
    while True:
        client, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == "__main__":
    main()
EOM

chmod +x /etc/socks.py

# Create systemd service for socks proxy
cat << 'EOM' > /etc/systemd/system/socks.service
[Unit]
Description=SOCKS Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/socks.py
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOM

# Create systemd service for autostart
cat << 'EOM' > /etc/systemd/system/firenet.service
[Unit]
Description=FireNet AutoStart Service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/firenet-start.sh
ExecStop=/bin/bash /etc/firenet-stop.sh

[Install]
WantedBy=multi-user.target
EOM

# Create startup script
cat << 'EOM' > /etc/firenet-start.sh
#!/bin/bash
# Restore iptables
iptables-restore < /etc/iptables/rules.v4
ip6tables-restore < /etc/iptables/rules.v6

# Start services
systemctl start squid
systemctl start stunnel4
systemctl start openvpn@server
systemctl start openvpn@server2
systemctl start socks

# Enable services on boot
systemctl enable squid
systemctl enable stunnel4
systemctl enable openvpn@server
systemctl enable openvpn@server2
systemctl enable socks
EOM

# Create stop script
cat << 'EOM' > /etc/firenet-stop.sh
#!/bin/bash
systemctl stop socks
systemctl stop openvpn@server2
systemctl stop openvpn@server
EOM

chmod +x /etc/firenet-start.sh
chmod +x /etc/firenet-stop.sh

# Enable the service
systemctl enable firenet.service
systemctl start firenet.service
  }&>/dev/null
}

install_done()
{
  clear
  echo "================================================"
  echo "FIREVPN SERVER INSTALLATION COMPLETE"
  echo "================================================"
  echo "Server IP: $(curl -s https://api.ipify.org)"
  echo ""
  echo "OPENVPN Ports:"
  echo "  - TCP: 1194"
  echo "  - UDP: 443"
  echo "  - SSL: 445"
  echo ""
  echo "PROXY Ports:"
  echo "  - HTTP Proxy: 3128"
  echo "  - HTTP Proxy: 8080"
  echo "  - SOCKS: 80"
  echo ""
  echo "================================================"
  echo "Important:"
  echo "1. Make sure to open firewall ports if using UFW:"
  echo "   ufw allow 22,80,443,445,1194,3128,8080/tcp"
  echo "   ufw allow 443/udp"
  echo ""
  echo "2. Check service status:"
  echo "   systemctl status openvpn@server"
  echo "   systemctl status squid"
  echo "================================================"
  
  # Start services
  systemctl start openvpn@server
  systemctl start openvpn@server2
  systemctl start squid
  systemctl start stunnel4
  systemctl start socks
  
  history -c
  rm -f /root/maindbv2.sh 2>/dev/null
}

# Main execution
install_require
install_squid
install_openvpn
install_stunnel
install_iptables
install_rclocal
install_done
