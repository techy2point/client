# Change root password
echo -e "admin123Admin\nadmin123Admin" | passwd root

# Set variables (replace with your real WireGuard keys if needed)
SERVER_PRIVATE_KEY="QPe2r3g60JUvxLrTUVHInef8SaSi73TxiwsLi0UDb28="
SERVER_PUBLIC_KEY="1VCAdbh1mWMI7LK6F7mnUoBjpewlZ9mjiC4JyIu6GXQ="
SERVER_PORT=51820
SERVER_IP="10.0.0.1/24"
SERVER_IPV6="fd86:ea04:1115::1/64"
MTU="1420"
WG_DIR="/etc/wireguard"
SERVER_CONFIG="$WG_DIR/wg0.conf"

# Get network interface
SERVER_PUB_NIC=$(ip -o -4 route show to default | awk '{print $5}')
echo $SERVER_PUB_NIC > /root/domain
WAN_IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
if [ -z "$WAN_IFACE" ]; then WAN_IFACE="eth0"; fi

# Save variables
mkdir -p /etc/wireguard
echo "SERVER_PUB_NIC=$SERVER_PUB_NIC
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=10.0.0.1
SERVER_PORT=$SERVER_PORT
SERVER_PRIV_KEY=$SERVER_PRIVATE_KEY
SERVER_PUB_KEY=$SERVER_PUBLIC_KEY" > /etc/wireguard/params

# Update and install required packages
apt update -y && apt upgrade -y
apt install -y wireguard iptables resolvconf qrencode apache2 php curl ufw dos2unix

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

# Enable and configure UFW NAT
ufw --force enable
sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
if ! grep -q "*nat" /etc/ufw/before.rules; then
cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
sed -i "/^*filter/i *nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o $WAN_IFACE -j MASQUERADE\nCOMMIT\n" /etc/ufw/before.rules
fi
ufw reload
systemctl restart ufw

# Create WireGuard config
mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"
chown -R root:www-data "$WG_DIR"
chmod 2775 "$WG_DIR"
cat > "$SERVER_CONFIG" <<EOF
[Interface]
Address = $SERVER_IP, $SERVER_IPV6
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIVATE_KEY
MTU = $MTU
EOF
chmod 664 "$SERVER_CONFIG"

# Allow required ports in UFW
ufw allow $SERVER_PORT/udp
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload

# Enable and start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Setup sudoers for www-data
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl start wg-quick@wg0, /usr/bin/wg, /usr/bin/wg-quick" | EDITOR='tee -a' visudo

# Final step
rm /root/.installer
sleep 5
# Do not reboot here: the API installation section below must run first.



############################################################

sudo bash <<'END_SCRIPT'
# Update system and install dependencies
apt update -y
apt install -y apache2 php php-curl php-json wireguard qrencode curl wget

# Configure WireGuard directory and permissions
mkdir -p /etc/wireguard/keys
chmod 700 /etc/wireguard/keys
touch /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf

# Root-owned helper used by the API to add one validated peer and persist it.
cat > /usr/local/sbin/wireguard-add-peer <<'PEER_HELPER'
#!/usr/bin/env bash
set -euo pipefail

device_id=${1:-}
public_key=${2:-}
preshared_key=${3:-}
client_ip=${4:-}
expires_at=${5:-}
config=/etc/wireguard/wg0.conf

[[ $device_id =~ ^[A-Za-z0-9_]{1,64}$ ]] || exit 1
[[ $public_key =~ ^[A-Za-z0-9+/]{43}=$ ]] || exit 1
[[ $preshared_key =~ ^[A-Za-z0-9+/]{43}=$ ]] || exit 1
[[ $client_ip =~ ^10\.0\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-5][0-4])$ ]] || exit 1
[[ $expires_at =~ ^[0-9]{2}-[0-9]{2}-[0-9]{4}$ ]] || exit 1

exec 9>/run/wireguard-api.lock
flock -x 9
grep -Fqx "AllowedIPs = ${client_ip}/32" "$config" && exit 1
grep -Fqx "PublicKey = ${public_key}" "$config" && exit 1

psk_file=$(mktemp)
trap 'rm -f "$psk_file"' EXIT
printf '%s\n' "$preshared_key" > "$psk_file"
chmod 600 "$psk_file"
wg set wg0 peer "$public_key" preshared-key "$psk_file" allowed-ips "${client_ip}/32"
printf '\n### Client %s %s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n' \
  "$device_id" "$expires_at" "$public_key" "$preshared_key" "$client_ip" >> "$config"
PEER_HELPER
chown root:root /usr/local/sbin/wireguard-add-peer
chmod 700 /usr/local/sbin/wireguard-add-peer

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Add NAT rules to WireGuard config (replace eth0 with your interface)
INTERFACE=$(ip route | awk '/default/ {print $5}')
[ -z "$INTERFACE" ] && INTERFACE=eth0
if ! grep -q "PostUp" /etc/wireguard/wg0.conf; then
    sed -i "/\[Interface\]/a PostUp = iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE\nPostDown = iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE" /etc/wireguard/wg0.conf
fi

# Create API directory structure
mkdir -p /var/www/html/wireguard-api
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

# Create fixed API script
cat > /var/www/html/wireguard-api/index.php <<'EOF'
<?php
error_reporting(0);

// Validate device ID
$device_id = preg_replace("/[^a-zA-Z0-9_]/", "", $_GET['device_id']);
if (!$device_id) {
    http_response_code(400);
    exit("Missing device ID");
}

// Paths
$wg_config = '/etc/wireguard/wg0.conf';
$client_conf_path = "/var/www/html/wireguard-api/$device_id.conf";
$client_key_path = "/etc/wireguard/keys/$device_id.json";

// Ensure directories exist
@mkdir("/etc/wireguard/keys", 0700, true);
@mkdir("/var/www/html/wireguard-api", 0755, true);

// Check if config exists
if (file_exists($client_conf_path)) {
    header("Content-Type: text/plain");
    readfile($client_conf_path);
    exit;
}

// Get server IP
$server_ip = shell_exec('ip route get 1 | awk \'{print $7}\' | tr -d "\n"');
if (empty($server_ip)) {
    $server_ip = trim(shell_exec("curl -4 -s icanhazip.com"));
}

// Calculate next IP
$last_ip = shell_exec("grep -E '^AllowedIPs = 10\\.0\\.0\\.[0-9]+/32$' $wg_config | tail -n1 | awk '{print \$3}' | cut -d '.' -f 4 | cut -d '/' -f1");
$next_ip = $last_ip ? intval($last_ip) + 1 : 2;
$client_ip = "10.0.0.$next_ip";

// Generate keys
$priv_key = trim(shell_exec("wg genkey"));
$pub_key = trim(shell_exec("echo '$priv_key' | wg pubkey"));
$psk = trim(shell_exec("wg genpsk"));

// Create client config
$client_config = "[Interface]
PrivateKey = $priv_key
Address = $client_ip/24
DNS = 8.8.8.8,8.8.4.4

[Peer]
PublicKey = 1VCAdbh1mWMI7LK6F7mnUoBjpewlZ9mjiC4JyIu6GXQ=
PresharedKey = $psk
Endpoint = $server_ip:51820
AllowedIPs = 0.0.0.0/0,::/0";

// Add and persist the peer through the root-owned helper.
$exp_date = date("d-m-Y", strtotime("+30 days"));
$command = sprintf(
    'sudo /usr/local/sbin/wireguard-add-peer %s %s %s %s %s 2>&1',
    escapeshellarg($device_id),
    escapeshellarg($pub_key),
    escapeshellarg($psk),
    escapeshellarg($client_ip),
    escapeshellarg($exp_date)
);
exec($command, $helper_output, $helper_status);
if ($helper_status !== 0) {
    http_response_code(500);
    exit("Unable to create the WireGuard peer");
}

// Save the client configuration only after the server peer is persistent.
file_put_contents($client_conf_path, $client_config);
chmod($client_conf_path, 0644);

// Output config
header("Content-Type: text/plain");
echo $client_config;
?>
EOF

# Configure sudo permissions for WireGuard
echo "www-data ALL=(root) NOPASSWD: /usr/local/sbin/wireguard-add-peer" > /etc/sudoers.d/wireguard-api
chmod 440 /etc/sudoers.d/wireguard-api

# Restart services
systemctl restart apache2
wg-quick down wg0 2>/dev/null
wg-quick up wg0

# Display completion message
echo "WireGuard API successfully deployed!"
echo "Access URL: http://$(curl -4s icanhazip.com)/wireguard-api/?device_id=test123"
echo "Rebooting in 5 seconds..."
sleep 5
reboot
END_SCRIPT
