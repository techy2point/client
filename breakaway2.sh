#!/bin/bash

# Debug function
debug_info() {
    echo "=== DEBUG INFO ==="
    echo "Server IP: $(curl -s https://api.ipify.org)"
    echo "Server Interface: $(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ")"
    echo "OpenVPN TCP Config: /etc/openvpn/server2.conf"
    echo "=== Checking Services ==="
    systemctl status openvpn-server@server2.service --no-pager -l
    echo "=== Checking Listening Ports ==="
    netstat -tlnp | grep -E '(1194|443)' || echo "No ports found"
    netstat -ulnp | grep 443 || echo "No UDP 443 found"
    echo "=== Checking OpenVPN Processes ==="
    ps aux | grep openvpn | grep -v grep
    echo "=== Checking iptables ==="
    iptables -L -n | grep 1194 || echo "No iptables rule for 1194"
    echo "=== END DEBUG ==="
}

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
    apt-get -o Acquire::ForceIPv4=true install php-cli net-tools cron php-fpm php-json php-pdo php-zip php-gd  php-mbstring php-curl php-xml php-bcmath php-json -y
    apt-get -o Acquire::ForceIPv4=true install gnutls-bin pwgen python -y
  } &>/dev/null
}

install_squid()
{
clear
echo "Installing proxy."
{
sudo touch /etc/apt/sources.list.d/trusty_sources.list
echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | sudo tee --append /etc/apt/sources.list.d/trusty_sources.list > /dev/null
sudo apt update -y

sudo apt install -y squid3=3.3.8-1ubuntu6 squid=3.3.8-1ubuntu6 squid3-common=3.3.8-1ubuntu6
/bin/cat <<"EOM" >/etc/init.d/squid3
#! /bin/sh
#
# squid		Startup script for the SQUID HTTP proxy-cache.
#
# Version:	@(#)squid.rc  1.0  07-Jul-2006  luigi@debian.org
#
### BEGIN INIT INFO
# Provides:          squid
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Squid HTTP Proxy version 3.x
### END INIT INFO

NAME=squid3
DESC="Squid HTTP Proxy"
DAEMON=/usr/sbin/squid3
PIDFILE=/var/run/$NAME.pid
CONFIG=/etc/squid3/squid.conf
SQUID_ARGS="-YC -f $CONFIG"

[ ! -f /etc/default/squid ] || . /etc/default/squid

. /lib/lsb/init-functions

PATH=/bin:/usr/bin:/sbin:/usr/sbin

[ -x $DAEMON ] || exit 0

ulimit -n 65535

find_cache_dir () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+[^'"$w"']\+['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
        [ -n "$res" ] || res=$2
        echo "$res"
}

grepconf () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
	[ -n "$res" ] || res=$2
	echo "$res"
}

create_run_dir () {
	run_dir=/var/run/squid3
	usr=`grepconf cache_effective_user proxy`
	grp=`grepconf cache_effective_group proxy`

	if [ "$(dpkg-statoverride --list $run_dir)" = "" ] &&
	   [ ! -e $run_dir ] ; then
		mkdir -p $run_dir
	  	chown $usr:$grp $run_dir
		[ -x /sbin/restorecon ] && restorecon $run_dir
	fi
}

start () {
	cache_dir=`find_cache_dir cache_dir`
	cache_type=`grepconf cache_dir`
	run_dir=/var/run/squid3

	#
	# Create run dir (needed for several workers on SMP)
	#
	create_run_dir

	#
	# Create spool dirs if they don't exist.
	#
	if test -d "$cache_dir" -a ! -d "$cache_dir/00"
	then
		log_warning_msg "Creating $DESC cache structure"
		$DAEMON -z -f $CONFIG
		[ -x /sbin/restorecon ] && restorecon -R $cache_dir
	fi

	umask 027
	ulimit -n 65535
	cd $run_dir
	start-stop-daemon --quiet --start \
		--pidfile $PIDFILE \
		--exec $DAEMON -- $SQUID_ARGS < /dev/null
	return $?
}

stop () {
	PID=`cat $PIDFILE 2>/dev/null`
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --exec $DAEMON
	#
	#	Now we have to wait until squid has _really_ stopped.
	#
	sleep 2
	if test -n "$PID" && kill -0 $PID 2>/dev/null
	then
		log_action_begin_msg " Waiting"
		cnt=0
		while kill -0 $PID 2>/dev/null
		do
			cnt=`expr $cnt + 1`
			if [ $cnt -gt 24 ]
			then
				log_action_end_msg 1
				return 1
			fi
			sleep 5
			log_action_cont_msg ""
		done
		log_action_end_msg 0
		return 0
	else
		return 0
	fi
}

cfg_pidfile=`grepconf pid_filename`
if test "${cfg_pidfile:-none}" != "none" -a "$cfg_pidfile" != "$PIDFILE"
then
	log_warning_msg "squid.conf pid_filename overrides init script"
	PIDFILE="$cfg_pidfile"
fi

case "$1" in
    start)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Starting $DESC" "$NAME"
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	if stop ; then
		log_end_msg $?
	else
		log_end_msg $?
	fi
	;;
    reload|force-reload)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_action_msg "Reloading $DESC configuration files"
	  	start-stop-daemon --stop --signal 1 \
			--pidfile $PIDFILE --quiet --exec $DAEMON
		log_action_end_msg 0
	fi
	;;
    restart)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Restarting $DESC" "$NAME"
		stop
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    status)
	status_of_proc -p $PIDFILE $DAEMON $NAME && exit 0 || exit 3
	;;
    *)
	echo "Usage: /etc/init.d/$NAME {start|stop|reload|force-reload|restart|status}"
	exit 3
	;;
esac

exit 0
EOM

sudo chmod +x /etc/init.d/squid3
sudo update-rc.d squid3 defaults

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
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Firenet-Proxy
error_directory /usr/share/squid3/errors/English"| sudo tee /etc/squid3/squid.conf
sudo service squid3 restart
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

echo 'DNS=1.1.1.1
DNSStubListener=no' >> /etc/systemd/resolved.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

# UDP Server Config (port 443)
cat > /etc/openvpn/server.conf << 'EOF'
# Openvpn Configuration by techydev :)
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
verb 3
EOF

# TCP Server Config (port 1194) - FIXED VERSION
cat > /etc/openvpn/server2.conf << 'EOF'
# Fixed OpenVPN TCP Configuration
# Listening on all interfaces for port 1194
port 1194
proto tcp
dev tun
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
verb 3
explicit-exit-notify 0
EOF

# Create Systemd Service Files
cat > /lib/systemd/system/openvpn-server@.service << 'EOF'
[Unit]
Description=OpenVPN service for %i
After=network.target
Wants=network-online.target
Documentation=man:openvpn(8)
Documentation=https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
Documentation=https://community.openvpn.net/openvpn/wiki/HOWTO

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn
ExecStart=/usr/sbin/openvpn --daemon ovpn-%i --status /run/openvpn/%i.status 10 --cd /etc/openvpn --script-security 2 --config /etc/openvpn/%i.conf --writepid /run/openvpn/%i.pid
ExecReload=/bin/kill -HUP $MAINPID
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
LimitNPROC=10
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=true
ProtectHome=true
KillMode=process
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Create symbolic links for our configs
ln -sf /etc/openvpn/server.conf /etc/openvpn/server
ln -sf /etc/openvpn/server2.conf /etc/openvpn/server2

# Create auth scripts
cat <<\EOM >/etc/openvpn/login/config.sh
#!/bin/bash
# config.sh - VPN server config

AUTH_URL="https://breakawayvpn.co.uk/database/api/auth.php"       # authentication
CONNECT_URL="https://breakawayvpn.co.uk/database/api/connect.php" # user connect tracking
DISCONNECT_URL="https://breakawayvpn.co.uk/database/api/disconnect.php" # user disconnect tracking
EOM

cat <<'EOM' >/etc/openvpn/login/auth_vpn
#!/bin/bash
. /etc/openvpn/login/config.sh

# Send username and optional password to PHP auth
RESPONSE=$(curl -s -d "username=$username" "$AUTH_URL")

if [ "$RESPONSE" = "ok" ]; then
    exit 0   # success
else
    exit 1   # fail
fi
EOM

cat <<'EOM' >/etc/openvpn/login/connect.sh
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"
SERVER_IP=$(curl -s https://api.ipify.org)
DATENOW=$(date +"%Y-%m-%d %T")

# Send user online status to PHP
curl -s -d "username=$USERNAME&server_ip=$SERVER_IP&active_date=$DATENOW" "$CONNECT_URL"
EOM

cat <<'EOM' >/etc/openvpn/login/disconnect.sh
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"

# Send user offline status to PHP
curl -s -d "username=$USERNAME" "$DISCONNECT_URL"
EOM

# Create certificates
#!/bin/bash

# Clear terminal
clear

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Function to check if command was successful
check_success() {
    if [ $? -eq 0 ]; then
        print_status "$1"
    else
        print_error "$2"
        exit 1
    fi
}

# Get server information
get_server_info() {
    SERVER_IP=$(curl -s https://api.ipify.org)
    SERVER_INTERFACE=$(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ")
    print_status "Server IP: $SERVER_IP"
    print_status "Server Interface: $SERVER_INTERFACE"
}

# Update and install dependencies
install_dependencies() {
    print_status "Updating system packages..."
    apt-get update -y
    check_success "System updated successfully" "Failed to update system"
    
    print_status "Installing dependencies..."
    apt-get install -y \
        openvpn \
        stunnel4 \
        squid \
        mysql-client \
        mariadb-server \
        dos2unix \
        nano \
        curl \
        unzip \
        jq \
        net-tools \
        php-cli \
        php-fpm \
        php-json \
        php-pdo \
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
        screen \
        iptables-persistent
    check_success "Dependencies installed" "Failed to install dependencies"
}

# Configure system settings
configure_system() {
    print_status "Configuring system settings..."
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Configure DNS
    echo "DNS=1.1.1.1" >> /etc/systemd/resolved.conf
    echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
    systemctl restart systemd-resolved
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    
    # Increase file limits
    echo "* soft nofile 512000" >> /etc/security/limits.conf
    echo "* hard nofile 512000" >> /etc/security/limits.conf
    ulimit -n 512000
}

# Create OpenVPN configurations
create_openvpn_configs() {
    print_status "Creating OpenVPN configurations..."
    
    # Create directories
    mkdir -p /etc/openvpn/easy-rsa/keys
    mkdir -p /etc/openvpn/login
    mkdir -p /etc/openvpn/server
    mkdir -p /var/www/html/stat
    
    # Create UDP server config (port 443)
    cat > /etc/openvpn/server.conf << 'EOF'
# OpenVPN UDP Configuration
port 443
proto udp
dev tun
topology subnet
server 10.30.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem
tls-server
tls-version-min 1.2
cipher AES-256-CBC
auth SHA256
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
client-cert-not-required
script-security 2
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_udp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env
push "redirect-gateway def1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
log /var/log/openvpn-udp.log
status /var/log/openvpn-udp-status.log
verb 3
mute 20
EOF

    # Create TCP server config (port 1194)
    cat > /etc/openvpn/server2.conf << 'EOF'
# OpenVPN TCP Configuration
port 1194
proto tcp
dev tun
topology subnet
server 10.20.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem
tls-server
tls-version-min 1.2
cipher AES-256-CBC
auth SHA256
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
client-cert-not-required
script-security 2
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_tcp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env
push "redirect-gateway def1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
log /var/log/openvpn-tcp.log
status /var/log/openvpn-tcp-status.log
verb 3
mute 20
explicit-exit-notify 0
EOF

    # Create your provided certificates
    cat > /etc/openvpn/easy-rsa/keys/ca.crt << 'EOF'
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

    cat > /etc/openvpn/easy-rsa/keys/server.crt << 'EOF'
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

    cat > /etc/openvpn/easy-rsa/keys/server.key << 'EOF'
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

    cat > /etc/openvpn/easy-rsa/keys/dh2048.pem << 'EOF'
-----BEGIN DH PARAMETERS-----
MIGHAoGBAKqeBUWMYdj6+Z6kPVyQjm5Pc/nhSeczplV0AX/zJ5lL9TXRGNg+q/nK
tQyaBpmBWAHxHP8j7NmRQaN6rpBkqHOtXJB9FT35xDvnAAaMxYW5RetBRUW7UnJ3
s1qQZ6kAUwIgDHzS9ykP9IzKPTbCrMIA/8kHfJ1qMfSDY8slKSVjAgEC
-----END DH PARAMETERS-----
EOF

    # Create login scripts
    cat > /etc/openvpn/login/config.sh << 'EOF'
#!/bin/bash
# config.sh - VPN server config

AUTH_URL="https://breakawayvpn.co.uk/database/api/auth.php"       # authentication
CONNECT_URL="https://breakawayvpn.co.uk/database/api/connect.php" # user connect tracking
DISCONNECT_URL="https://breakawayvpn.co.uk/database/api/disconnect.php" # user disconnect tracking
EOF

    cat > /etc/openvpn/login/auth_vpn << 'EOF'
#!/bin/bash
. /etc/openvpn/login/config.sh

# Send username and optional password to PHP auth
RESPONSE=$(curl -s -d "username=$username" "$AUTH_URL")

if [ "$RESPONSE" = "ok" ]; then
    exit 0   # success
else
    exit 1   # fail
fi
EOF

    cat > /etc/openvpn/login/connect.sh << 'EOF'
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"
SERVER_IP=$(curl -s https://api.ipify.org)
DATENOW=$(date +"%Y-%m-%d %T")

# Send user online status to PHP
curl -s -d "username=$USERNAME&server_ip=$SERVER_IP&active_date=$DATENOW" "$CONNECT_URL"
EOF

    cat > /etc/openvpn/login/disconnect.sh << 'EOF'
#!/bin/bash
. /etc/openvpn/login/config.sh

USERNAME="$common_name"

# Send user offline status to PHP
curl -s -d "username=$USERNAME" "$DISCONNECT_URL"
EOF

    # Set permissions
    chmod 755 /etc/openvpn/server.conf
    chmod 755 /etc/openvpn/server2.conf
    chmod 755 /etc/openvpn/login/connect.sh
    chmod 755 /etc/openvpn/login/disconnect.sh
    chmod 755 /etc/openvpn/login/config.sh
    chmod 755 /etc/openvpn/login/auth_vpn
    chmod 600 /etc/openvpn/easy-rsa/keys/server.key
    chmod 644 /etc/openvpn/easy-rsa/keys/server.crt
    chmod 644 /etc/openvpn/easy-rsa/keys/ca.crt
    chmod 644 /etc/openvpn/easy-rsa/keys/dh2048.pem
    
    print_status "OpenVPN configurations created successfully"
}

# Install and configure Squid proxy
install_squid() {
    print_status "Installing and configuring Squid proxy..."
    
    # Install squid
    apt-get install -y squid
    
    # Configure squid
    cat > /etc/squid/squid.conf << EOF
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
error_directory /usr/share/squid/errors/English
EOF
    
    # Restart squid
    systemctl restart squid
    systemctl enable squid
    
    print_status "Squid proxy installed and configured"
}

# Install and configure stunnel
install_stunnel() {
    print_status "Installing and configuring stunnel..."
    
    # Create stunnel configuration
    cat > /etc/stunnel/stunnel.pem << 'EOF'
-----BEGIN PRIVATE KEY-----
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
X/bwAgba8b+anKxuYHfJMzCfhbTE3I3kJvJFUciFu3DlsZaRmOo64p4GGejXEU64
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
-----END CERTIFICATE-----
EOF

    cat > /etc/stunnel/stunnel.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
accept = 443
connect = 127.0.0.1:1194
EOF

    cat > /etc/default/stunnel << 'EOF'
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""
EOF

    # Set permissions
    chmod 600 /etc/stunnel/stunnel.pem
    chmod 644 /etc/stunnel/stunnel.conf
    
    # Enable and start stunnel
    systemctl enable stunnel
    systemctl restart stunnel
    
    print_status "Stunnel installed and configured"
}

# Configure firewall rules
configure_iptables() {
    print_status "Configuring firewall rules..."
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
    # Set default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow OpenVPN ports
    iptables -A INPUT -p tcp --dport 1194 -j ACCEPT
    iptables -A INPUT -p udp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # stunnel
    
    # Allow proxy ports
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 3128 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
    
    # NAT for OpenVPN clients
    iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o $SERVER_INTERFACE -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o $SERVER_INTERFACE -j MASQUERADE
    
    # Allow forwarding for VPN traffic
    iptables -A FORWARD -s 10.20.0.0/22 -j ACCEPT
    iptables -A FORWARD -d 10.20.0.0/22 -j ACCEPT
    iptables -A FORWARD -s 10.30.0.0/22 -j ACCEPT
    iptables -A FORWARD -d 10.30.0.0/22 -j ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    
    print_status "Firewall rules configured"
}

# Create systemd services for OpenVPN
create_openvpn_services() {
    print_status "Creating OpenVPN systemd services..."
    
    # Create service for UDP server
    cat > /etc/systemd/system/openvpn-udp.service << 'EOF'
[Unit]
Description=OpenVPN UDP Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/server.conf
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Create service for TCP server
    cat > /etc/systemd/system/openvpn-tcp.service << 'EOF'
[Unit]
Description=OpenVPN TCP Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/server2.conf
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start services
    systemctl daemon-reload
    systemctl enable openvpn-udp.service
    systemctl enable openvpn-tcp.service
    systemctl start openvpn-udp.service
    systemctl start openvpn-tcp.service
    
    print_status "OpenVPN systemd services created and started"
}

# Download and configure SOCKS proxy
install_socks_proxy() {
    print_status "Installing SOCKS proxy..."
    
    # Download socks proxy script
    wget -q https://pastebin.com/raw/z9j2nA8p -O /etc/socks.py
    dos2unix /etc/socks.py > /dev/null 2>&1
    chmod +x /etc/socks.py
    
    # Create service for socks proxy
    cat > /etc/systemd/system/socks-proxy.service << 'EOF'
[Unit]
Description=SOCKS5 Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/socks.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable socks-proxy.service
    systemctl start socks-proxy.service
    
    print_status "SOCKS proxy installed"
}

# Create startup script
create_startup_script() {
    print_status "Creating startup script..."
    
    cat > /etc/rc.local << 'EOF'
#!/bin/bash
# rc.local

# Restore iptables rules
iptables-restore < /etc/iptables/rules.v4

# Start OpenVPN services
systemctl start openvpn-udp.service
systemctl start openvpn-tcp.service

# Start other services
systemctl start squid
systemctl start stunnel
systemctl start socks-proxy.service

exit 0
EOF

    chmod +x /etc/rc.local
    
    print_status "Startup script created"
}

# Test OpenVPN installation
test_installation() {
    print_status "Testing installation..."
    
    # Wait for services to start
    sleep 5
    
    # Check if OpenVPN is running
    echo ""
    print_status "Checking OpenVPN services:"
    
    if systemctl is-active --quiet openvpn-udp.service; then
        print_status "✓ OpenVPN UDP service is running"
    else
        print_error "✗ OpenVPN UDP service is NOT running"
    fi
    
    if systemctl is-active --quiet openvpn-tcp.service; then
        print_status "✓ OpenVPN TCP service is running"
    else
        print_error "✗ OpenVPN TCP service is NOT running"
    fi
    
    # Check listening ports
    echo ""
    print_status "Checking listening ports:"
    
    if netstat -tuln | grep -q ":1194 "; then
        print_status "✓ TCP port 1194 is listening"
    else
        print_error "✗ TCP port 1194 is NOT listening"
    fi
    
    if netstat -tuln | grep -q ":443 "; then
        print_status "✓ TCP port 443 (stunnel) is listening"
    else
        print_error "✗ TCP port 443 (stunnel) is NOT listening"
    fi
    
    if netstat -tuln | grep -q ":443 " | grep -q udp; then
        print_status "✓ UDP port 443 is listening"
    else
        print_warning "Note: UDP port check may need separate verification"
    fi
    
    # Display server info
    echo ""
    print_status "============================================="
    print_status "INSTALLATION COMPLETE!"
    print_status "============================================="
    print_status "Server IP: $SERVER_IP"
    print_status "OpenVPN TCP Port: 1194"
    print_status "OpenVPN UDP Port: 443"
    print_status "OpenVPN SSL Port: 443 (via stunnel)"
    print_status "SOCKS Proxy Port: 80"
    print_status "HTTP Proxy Ports: 3128, 8080"
    print_status "============================================="
    echo ""
    print_status "To check service status:"
    print_status "  systemctl status openvpn-tcp.service"
    print_status "  systemctl status openvpn-udp.service"
    echo ""
    print_status "To view logs:"
    print_status "  tail -f /var/log/openvpn-tcp.log"
    print_status "  tail -f /var/log/openvpn-udp.log"
}

# Main installation function
main_installation() {
    clear
    echo "============================================="
    echo "    OPENVPN SERVER INSTALLATION SCRIPT"
    echo "============================================="
    echo ""
    
    # Get server info
    get_server_info
    
    # Run installation steps
    install_dependencies
    configure_system
    create_openvpn_configs
    install_squid
    install_stunnel
    configure_iptables
    create_openvpn_services
    install_socks_proxy
    create_startup_script
    
    # Test installation
    test_installation
}

# Run the installation
main_installation

# Final instructions
echo ""
print_warning "If you still have connection issues, run these commands:"
print_warning "1. Check OpenVPN logs: tail -f /var/log/openvpn-tcp.log"
print_warning "2. Check if port 1194 is listening: netstat -tlnp | grep 1194"
print_warning "3. Restart OpenVPN TCP: systemctl restart openvpn-tcp.service"
print_warning "4. Test connection from client: nc -zv $SERVER_IP 1194"

cat > stunnel.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
accept = 443
connect = 127.0.0.1:1194
EOF

cat > /etc/default/stunnel4 << 'EOF'
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""
EOF

chmod 600 stunnel.pem
chmod 644 stunnel.conf
systemctl enable stunnel4
systemctl restart stunnel4
  } &>/dev/null
}

install_iptables(){
  {
echo "Configuring iptables and sysctl..."
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
ip6tables -F
ip6tables -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow OpenVPN ports
iptables -A INPUT -p tcp --dport 1194 -j ACCEPT
iptables -A INPUT -p udp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # stunnel

# Allow proxy ports
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow UDP ports for proxy
iptables -A INPUT -p udp --dport 20100:20900 -j ACCEPT

# Rate limiting for UDP ports
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --update --seconds 30 --hitcount 10 --name DEFAULT --mask 255.255.255.255 --rsource -j DROP
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource

# NAT for OpenVPN clients
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o "$server_interface" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o "$server_interface" -j MASQUERADE

# Allow forwarding for VPN traffic
iptables -A FORWARD -s 10.20.0.0/22 -j ACCEPT
iptables -A FORWARD -d 10.20.0.0/22 -j ACCEPT
iptables -A FORWARD -s 10.30.0.0/22 -j ACCEPT
iptables -A FORWARD -d 10.30.0.0/22 -j ACCEPT

# Save rules
iptables-save > /etc/iptables_rules.v4
ip6tables-save > /etc/iptables_rules.v6

# Configure sysctl
cat > /etc/sysctl.conf << 'EOF'
# Kernel sysctl configuration
fs.file-max = 51200
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
net.ipv4.icmp_echo_ignore_all = 1
EOF

# Apply limits
echo '* soft nofile 512000' >> /etc/security/limits.conf
echo '* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000

# Apply sysctl
sysctl -p
  }&>/dev/null
}

install_rclocal(){
  {
echo "Configuring rc.local and startup scripts..."
# Download socks proxy
wget https://pastebin.com/raw/z9j2nA8p -O /etc/ubuntu
dos2unix /etc/ubuntu
chmod +x /etc/ubuntu

# Create systemd service for socks
cat > /etc/systemd/system/socks-proxy.service << 'EOF'
[Unit]
Description=SOCKS5 Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python /etc/ubuntu
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Create rc.local
cat > /etc/rc.local << 'EOF'
#!/bin/bash
# rc.local - startup script

# Restore iptables
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6

# Apply sysctl
sysctl -p

# Start services
service squid3 restart
service stunnel4 restart

# Start OpenVPN manually to ensure it runs
if ! pgrep -f "openvpn.*server2.conf" > /dev/null; then
    echo "Starting OpenVPN TCP server..."
    /usr/sbin/openvpn --daemon --config /etc/openvpn/server2.conf --log /var/log/openvpn-tcp.log
fi

if ! pgrep -f "openvpn.*server.conf" > /dev/null; then
    echo "Starting OpenVPN UDP server..."
    /usr/sbin/openvpn --daemon --config /etc/openvpn/server.conf --log /var/log/openvpn-udp.log
fi

# Start SOCKS proxy via systemd
systemctl start socks-proxy.service

# Wait a bit
sleep 3

# Check if services are running
echo "Checking services..."
netstat -tlnp | grep -E '(1194|443)' || echo "Warning: OpenVPN may not be listening"

exit 0
EOF

chmod +x /etc/rc.local

# Create systemd rc-local service
cat > /etc/systemd/system/rc-local.service << 'EOF'
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

systemctl enable rc-local
systemctl enable socks-proxy.service
systemctl start rc-local
  }&>/dev/null
}

start_openvpn_manually() {
    echo "Starting OpenVPN servers manually..."
    
    # Kill any existing OpenVPN processes
    pkill -f openvpn
    
    # Start UDP server (port 443)
    echo "Starting UDP server on port 443..."
    /usr/sbin/openvpn --daemon --config /etc/openvpn/server.conf --log /var/log/openvpn-udp.log
    
    # Start TCP server (port 1194)
    echo "Starting TCP server on port 1194..."
    /usr/sbin/openvpn --daemon --config /etc/openvpn/server2.conf --log /var/log/openvpn-tcp.log
    
    sleep 3
    
    echo "Checking OpenVPN processes..."
    ps aux | grep openvpn | grep -v grep
    
    echo "Checking listening ports..."
    netstat -tlnp | grep -E '(1194|443)'
    netstat -ulnp | grep 443
}

install_done()
{
  echo "Finalizing installation..."
  
  # Start OpenVPN manually first
  start_openvpn_manually
  
  # Run rc.local
  /etc/rc.local
  
  # Wait for services to start
  sleep 5
  
  clear
  echo "=========================================="
  echo "OPENVPN SERVER FIRENET - INSTALLATION COMPLETE"
  echo "=========================================="
  echo "Server IP : $server_ip"
  echo "Server Interface : $server_interface"
  echo "------------------------------------------"
  echo "SERVICES:"
  echo "  OpenVPN TCP : port 1194"
  echo "  OpenVPN UDP : port 443"
  echo "  OpenVPN SSL : port 443 (via stunnel)"
  echo "  SOCKS proxy : port 80"
  echo "  HTTP Proxy  : ports 3128, 8080"
  echo "=========================================="
  echo ""
  echo "CHECKING SERVICES:"
  echo ""
  
  # Check OpenVPN processes
  echo "OpenVPN Processes:"
  ps aux | grep openvpn | grep -v grep || echo "  No OpenVPN processes found"
  
  echo ""
  echo "Listening Ports:"
  echo "TCP 1194: $(netstat -tlnp | grep ':1194' | awk '{print $4 " - " $7}' || echo 'Not listening')"
  echo "UDP 443: $(netstat -ulnp | grep ':443' | awk '{print $4 " - " $6}' || echo 'Not listening')"
  echo "TCP 443: $(netstat -tlnp | grep ':443' | grep -v ':1194' | awk '{print $4 " - " $7}' || echo 'Not listening')"
  
  echo ""
  echo "Iptables Rules for 1194:"
  iptables -L INPUT -n | grep 1194 || echo "  No rule found"
  
  echo ""
  echo "DEBUG INFO:"
  echo "To test connection from client:"
  echo "  nc -zv $server_ip 1194"
  echo "  nc -zvu $server_ip 443"
  echo ""
  echo "View OpenVPN logs:"
  echo "  tail -f /var/log/openvpn-tcp.log"
  echo "  tail -f /var/log/openvpn-udp.log"
  echo ""
  echo "If TCP 1194 is not listening, run:"
  echo "  /usr/sbin/openvpn --daemon --config /etc/openvpn/server2.conf"
  echo ""
  history -c;
}

# Get server info
server_interface=$(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ")
server_ip=$(curl -s https://api.ipify.org)

# Main installation
echo "Starting installation on $server_ip ($server_interface)"
install_require
install_squid
install_openvpn
install_stunnel
install_iptables
install_rclocal
install_done

# Run debug info
debug_info

# Final check
echo ""
echo "=== FINAL CONNECTION TEST ==="
echo "Testing TCP port 1194..."
timeout 3 bash -c "</dev/tcp/$server_ip/1194" && echo "✓ TCP 1194 is open" || echo "✗ TCP 1194 is closed"
echo "Testing UDP port 443..."
timeout 3 bash -c "</dev/udp/$server_ip/443" && echo "✓ UDP 443 is reachable" || echo "✗ UDP 443 may be blocked"
