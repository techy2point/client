#!/bin/bash

# Get server information
SERVER_IP=$(curl -s https://api.ipify.org)
SERVER_INTERFACE=$(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ")

install_require()
{
  clear
  echo "Updating your system."
  {
    apt-get update
    apt-get upgrade -y
  } &>/dev/null
  clear
  echo "Installing dependencies."
  {
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      mysql-client \
      iptables \
      iptables-persistent \
      mariadb-server \
      stunnel4 \
      openvpn \
      dos2unix \
      easy-rsa \
      nano \
      curl \
      wget \
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
      apache2-utils \
      socat \
      netcat-openbsd
  } &>/dev/null
}

install_squid()
{
clear
echo "Installing Squid proxy."
{
# Remove any existing squid config
apt-get remove --purge -y squid squid3 2>/dev/null
apt-get autoremove -y

# Install squid
apt-get install -y squid squid-common

# Backup original config
mv /etc/squid/squid.conf /etc/squid/squid.conf.backup

# Create new squid configuration
cat > /etc/squid/squid.conf << EOF
acl localnet src 0.0.0.0/0
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
http_access allow localnet
http_access allow localhost
http_access deny all
http_port 3128
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Firenet-Proxy
error_directory /usr/share/squid/errors/English
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
EOF

# Create error directory
mkdir -p /usr/share/squid/errors/English

# Set proper permissions
chown -R proxy:proxy /var/log/squid/
chown -R proxy:proxy /var/spool/squid/

# Enable and start squid
systemctl enable squid
systemctl restart squid

# Check squid status
if ! systemctl is-active --quiet squid; then
    echo "Squid failed to start. Checking logs..."
    journalctl -u squid --no-pager -n 20
fi
} &>/dev/null
}

install_openvpn()
{
clear
echo "Installing OpenVPN."
{
# Install OpenVPN
apt-get install -y openvpn easy-rsa

# Create directories
mkdir -p /etc/openvpn/{server,login,easy-rsa/keys}
mkdir -p /var/www/html/stat

# Fix DNS issues
systemctl stop systemd-resolved 2>/dev/null
systemctl disable systemd-resolved 2>/dev/null
rm -f /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

# Create OpenVPN UDP configuration
cat > /etc/openvpn/server.conf << 'EOF'
port 443
proto udp
dev tun
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/server/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth /etc/openvpn/easy-rsa/keys/ta.key 0
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
explicit-exit-notify 1
EOF

# Create OpenVPN TCP configuration
cat > /etc/openvpn/server2.conf << 'EOF'
port 1194
proto tcp
dev tun
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/server/ipp-tcp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth /etc/openvpn/easy-rsa/keys/ta.key 0
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-tcp-status.log
log /var/log/openvpn-tcp.log
verb 3
EOF

# Create login scripts
cat > /etc/openvpn/login/config.sh << 'EOF'
#!/bin/bash
AUTH_URL="https://panel.onebesthost.com/database/api/auth.php"
CONNECT_URL="https://panel.onebesthost.com/database/api/connect.php"
DISCONNECT_URL="https://panel.onebesthost.com/database/api/disconnect.php"
EOF

cat > /etc/openvpn/login/auth_vpn << 'EOF'
#!/bin/bash
. /etc/openvpn/login/config.sh
RESPONSE=$(curl -s -d "username=$username" "$AUTH_URL")
[ "$RESPONSE" = "ok" ] && exit 0 || exit 1
EOF

cat > /etc/openvpn/login/connect.sh << 'EOF'
#!/bin/bash
. /etc/openvpn/login/config.sh
USERNAME="$common_name"
SERVER_IP=$(curl -s https://api.ipify.org)
DATENOW=$(date +"%Y-%m-%d %T")
curl -s -d "username=$USERNAME&server_ip=$SERVER_IP&active_date=$DATENOW" "$CONNECT_URL"
EOF

cat > /etc/openvpn/login/disconnect.sh << 'EOF'
#!/bin/bash
. /etc/openvpn/login/config.sh
USERNAME="$common_name"
curl -s -d "username=$USERNAME" "$DISCONNECT_URL"
EOF

# Set permissions
chmod 755 /etc/openvpn/login/*.sh
chmod 755 /etc/openvpn/login/auth_vpn

# Generate certificates
cd /etc/openvpn/easy-rsa
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# Initialize PKI
./easyrsa init-pki

# Build CA
./easyrsa --batch build-ca nopass

# Generate server certificate
./easyrsa build-server-full server nopass

# Generate DH parameters
./easyrsa gen-dh

# Generate TLS-auth key
openvpn --genkey --secret /etc/openvpn/easy-rsa/keys/ta.key

# Copy certificates
cp pki/ca.crt /etc/openvpn/easy-rsa/keys/
cp pki/issued/server.crt /etc/openvpn/easy-rsa/keys/
cp pki/private/server.key /etc/openvpn/easy-rsa/keys/
cp pki/dh.pem /etc/openvpn/easy-rsa/keys/dh2048.pem

# Create systemd service files
cat > /etc/systemd/system/openvpn-server.service << 'EOF'
[Unit]
Description=OpenVPN server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/server.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/openvpn-server2.service << 'EOF'
[Unit]
Description=OpenVPN server (TCP)
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/server2.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Enable services
systemctl daemon-reload
systemctl enable openvpn-server
systemctl enable openvpn-server2

} &>/dev/null
}

install_stunnel() {
clear
echo "Installing Stunnel."
{
# Install stunnel
apt-get install -y stunnel4

# Create stunnel configuration
cat > /etc/stunnel/stunnel.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
accept = 445
connect = 127.0.0.1:1194
EOF

# Generate self-signed certificate for stunnel
openssl genrsa -out /etc/stunnel/stunnel.key 2048
openssl req -new -x509 -key /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.crt -days 3650 -subj "/C=PH/ST=QC/L=Manila/O=Firenet/CN=firenet-vpn"
cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem

# Set permissions
chmod 600 /etc/stunnel/stunnel.pem

# Enable stunnel
systemctl enable stunnel4
} &>/dev/null
}

install_iptables(){
clear
echo "Configuring firewall."
{
# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Get server interface if not already set
if [ -z "$SERVER_INTERFACE" ]; then
    SERVER_INTERFACE=$(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ")
fi

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

# Allow SOCKS port
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# NAT for OpenVPN clients
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $SERVER_INTERFACE -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o $SERVER_INTERFACE -j MASQUERADE

# Save rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# Install iptables-persistent
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y iptables-persistent

# Save current rules
netfilter-persistent save

} &>/dev/null
}

install_socks(){
clear
echo "Installing SOCKS proxy."
{
# Install dante-server for SOCKS proxy
apt-get install -y dante-server

# Create dante configuration
cat > /etc/danted.conf << EOF
logoutput: /var/log/danted.log
internal: 0.0.0.0 port = 80
external: $SERVER_INTERFACE
method: username none
user.privileged: root
user.notprivileged: nobody
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect
}
pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: connect disconnect
}
pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: bindreply udpreply
    log: connect disconnect
}
EOF

# Create log file
touch /var/log/danted.log
chown nobody:nogroup /var/log/danted.log

# Create systemd service file
cat > /etc/systemd/system/danted.service << 'EOF'
[Unit]
Description=Dante SOCKS v4/v5 proxy daemon
After=network.target

[Service]
Type=forking
PIDFile=/var/run/danted.pid
ExecStart=/usr/sbin/danted
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable and start danted
systemctl daemon-reload
systemctl enable danted
} &>/dev/null
}

install_rclocal(){
clear
echo "Configuring auto-start services."
{
# Create startup script
cat > /etc/firenet-start.sh << 'EOF'
#!/bin/bash
# Start all Firenet services

# Restore iptables
iptables-restore < /etc/iptables/rules.v4 2>/dev/null
ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null

# Start services
systemctl start squid
systemctl start stunnel4
systemctl start openvpn-server
systemctl start openvpn-server2
systemctl start danted

# Enable services on boot
systemctl enable squid
systemctl enable stunnel4
systemctl enable openvpn-server
systemctl enable openvpn-server2
systemctl enable danted

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
EOF

chmod +x /etc/firenet-start.sh

# Create systemd service for startup
cat > /etc/systemd/system/firenet.service << 'EOF'
[Unit]
Description=Firenet VPN Service
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/firenet-start.sh
ExecStop=/bin/true

[Install]
WantedBy=multi-user.target
EOF

# Enable firenet service
systemctl daemon-reload
systemctl enable firenet.service
} &>/dev/null
}

start_services(){
clear
echo "Starting all services..."
{
# Start all services
systemctl start squid
systemctl start stunnel4
systemctl start openvpn-server
systemctl start openvpn-server2
systemctl start danted
systemctl start firenet

# Check service status
echo "Checking service status..."
echo "========================================"

services=("squid" "stunnel4" "openvpn-server" "openvpn-server2" "danted")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "✓ $service is running"
    else
        echo "✗ $service failed to start"
        echo "  Checking logs: journalctl -u $service --no-pager -n 10"
        journalctl -u $service --no-pager -n 10 | tail -5
    fi
done

echo "========================================"
} &>/dev/null
}

install_done()
{
clear
echo "================================================"
echo "FIREVPN SERVER INSTALLATION COMPLETE"
echo "================================================"
echo "Server IP: $SERVER_IP"
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
echo "VPN Networks:"
echo "  - UDP VPN: 10.8.0.0/24"
echo "  - TCP VPN: 10.9.0.0/24"
echo ""
echo "Important:"
echo "1. Make sure to open firewall ports if using UFW:"
echo "   ufw allow 22,80,443,445,1194,3128,8080/tcp"
echo "   ufw allow 443/udp"
echo ""
echo "2. Check service status:"
echo "   systemctl status openvpn-server"
echo "   systemctl status squid"
echo ""
echo "3. To create client configs, use:"
echo "   cat /etc/openvpn/client.ovpn"
echo "================================================"
echo ""
echo "Creating client configuration template..."

# Create client configuration template
cat > /etc/openvpn/client.ovpn << EOF
client
dev tun
proto udp
remote $SERVER_IP 443
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3
<ca>
$(cat /etc/openvpn/easy-rsa/keys/ca.crt)
</ca>
EOF

echo "Client configuration template created at: /etc/openvpn/client.ovpn"
echo "Add client certificate and key sections as needed."
echo ""
echo "Installation complete! Reboot recommended."
}

# Main installation process
echo "Starting FireVPN installation..."
echo "Server IP: $SERVER_IP"
echo "Interface: $SERVER_INTERFACE"
echo ""

install_require
install_squid
install_openvpn
install_stunnel
install_socks
install_iptables
install_rclocal
start_services
install_done

# Final reboot recommendation
echo ""
read -p "Do you want to reboot now? (recommended) [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    reboot
fi
