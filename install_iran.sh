#!/bin/bash

##############################################################
# SmartDNS Iran DNS Installer – Full UI + Full Error Handling
##############################################################

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

pm=""
INSTALL_DIR="/root/smartDNS"
last_error=""
steps_total=8

##############################################################
#   ERROR HANDLER (Must be defined before use)
##############################################################
fail() {
    tput cup $((steps_total + 4)) 0
    echo -e "${RED}Installation failed.${RESET}"
    echo ""
    echo "Error details:"
    echo "----------------------------------------------"
    echo -e "$last_error"
    echo "----------------------------------------------"
    exit 1
}

##############################################################
# Detect Linux Distribution
##############################################################
detect_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" = "ubuntu" || "$ID" = "debian" ]]; then
            pm="apt-get"
        elif [[ "$ID" = "centos" ]]; then
            pm="yum"
        elif [[ "$ID" = "fedora" ]]; then
            pm="dnf"
        else
            pm="apt-get"
        fi
    else
        pm="apt-get"
    fi
}

##############################################################
# Install Dependencies
##############################################################
install_dependencies() {
    detect_distribution
    $pm update -y >/dev/null 2>&1

    local packages=("nginx" "git" "jq" "certbot" "python3-certbot-nginx" "python3" "python3-pip" "curl" "gpg" "lsb-release" "stunnel4")

    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &>/dev/null && ! rpm -q "$package" &>/dev/null; then
            $pm install -y "$package" >/dev/null 2>&1
        fi
    done

    if ! command -v python3 &>/dev/null; then
        $pm install -y python3 python3-pip >/dev/null 2>&1
    fi
}

##############################################################
# UI FUNCTIONS
##############################################################
step_titles_base=(
"Configuration"
"Installing & configuring Stunnel (Client mode)"
"Creating configuration and downloading server code"
"Installing Python dependencies"
"Obtaining SSL certificate"
"Configuring Nginx"
"Installing and starting Iran DNS service"
"Testing DoH server"
)

draw_steps() {
    clear
    echo "========= SmartDNS Installer ========="
    echo ""
    for i in $(seq 1 $steps_total); do
        printf "[%d/%d] %-60s...\n" "$i" "$steps_total" "${step_titles_base[$((i-1))]}"
    done
    echo ""
}

update_step() {
    tput cup $(( $1 + 2 )) 0
    printf "[%d/%d] %-60s %b\n" "$(($1+1))" "$steps_total" "${step_titles_base[$1]}" "$2"
}

##############################################################
# MAIN INSTALL FUNCTION
##############################################################
install_iran_server() {

##############################
# ROOT CHECK
##############################
if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: Please run as root"
    exit 1
fi

##############################
# INPUT SECTION
##############################
clear
echo "========= SmartDNS Installer ========="
echo ""

read -p "Enter your domain name: " domain
[[ -z "$domain" ]] && echo "ERROR: Domain cannot be empty!" && exit 1

myip=$(hostname -I | awk '{print $1}')
echo "Detected server IP: $myip"
read -p "Is this correct? (y/n): " ip_confirm
if [[ ! "$ip_confirm" =~ ^[Yy]$ ]]; then
    read -p "Enter your server IP: " myip
fi

echo ""
read -p "Enter your foreign DoH server URL (https://example.com/dns-query): " foreign_doh
[[ -z "$foreign_doh" ]] && echo "ERROR: Foreign DoH URL cannot be empty!" && exit 1

echo ""
echo "Extracting foreign server IP..."
foreign_domain=$(echo "$foreign_doh" | sed -E 's|https?://([^:/]+).*|\1|')
foreign_ip=$(getent hosts "$foreign_domain" | awk '{print $1}' | head -n1)

if [[ -z "$foreign_ip" ]]; then
    foreign_ip=$(nslookup "$foreign_domain" 2>/dev/null | grep "Address" | awk '{print $2}' | head -n1)
fi

if [[ -z "$foreign_ip" ]]; then
    foreign_ip=$(ping -c 1 -W 2 "$foreign_domain" 2>/dev/null | sed -nE 's/.*\(([0-9.]+)\).*/\1/p')
fi

if [[ -z "$foreign_ip" ]]; then
    read -p "Could not detect automatically. Enter IP manually: " foreign_ip
else
    read -p "Extracted foreign IP: $foreign_ip (Enter to confirm, or type new IP): " user_ip
    [[ -n "$user_ip" ]] && foreign_ip="$user_ip"
fi

[[ -z "$foreign_ip" ]] && echo "ERROR: Foreign IP cannot be empty!" && exit 1

echo ""
read -p "Enter sanctioned domain names (comma separated): " site_list

##############################
# START UI
##############################
draw_steps

##############################
# STEP 1 – CONFIGURATION
##############################
install_dependencies
mkdir -p "$INSTALL_DIR"
update_step 0 "${GREEN}✓${RESET}"

##############################
# STEP 2 – STUNNEL CLIENT
##############################
systemctl stop stunnel4 2>/dev/null || true
rm -f /etc/stunnel/*.conf

sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4

openssl req -new -x509 -days 3650 -nodes \
    -out /etc/stunnel/stunnel.pem \
    -keyout /etc/stunnel/stunnel.pem \
    -subj "/C=US/ST=State/L=City/O=Org/CN=stunnel" \
    >/dev/null 2>&1 || {
        last_error="OpenSSL certificate generation failed"
        update_step 1 "${RED}✗${RESET}"
        fail
    }

cat > /etc/stunnel/tunnel-client.conf <<EOF
client = yes
foreground = no
output = /var/log/stunnel-client.log
pid = /run/stunnel4-client.pid
sslVersion = TLSv1.3
options = NO_RENEGOTIATION

[foreign-tunnel]
accept = 127.0.0.1:60000
connect = $foreign_ip:6001
verify = 0
EOF

systemctl restart stunnel4 >/dev/null 2>&1 || {
    last_error="$(systemctl status stunnel4 --no-pager)"
    update_step 1 "${RED}✗${RESET}"
    fail
}

update_step 1 "${GREEN}✓${RESET}"

##############################
# STEP 3 – CREATE CONFIG + DOWNLOAD PY
##############################
cat > "$INSTALL_DIR/iran_config.json" <<EOF
{
  "host": "$domain",
  "server_ip": "$myip",
  "foreign_doh_url": "$foreign_doh",
  "domains": {
EOF

if [[ -n "$site_list" ]]; then
    IFS=',' read -ra sites <<< "$site_list"
    for i in "${!sites[@]}"; do
        site=$(echo "${sites[$i]}" | xargs)
        if [[ $i -eq $((${#sites[@]} - 1)) ]]; then
            echo "    \"$site\": \"$foreign_ip\"" >> "$INSTALL_DIR/iran_config.json"
        else
            echo "    \"$site\": \"$foreign_ip\"," >> "$INSTALL_DIR/iran_config.json"
        fi
    done
fi

cat >> "$INSTALL_DIR/iran_config.json" <<EOF
  }
}
EOF

curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNIP/main/iran_server.py \
    -o "$INSTALL_DIR/iran_server.py" || {
        last_error="Failed to download iran_server.py"
        update_step 2 "${RED}✗${RESET}"
        fail
    }

chmod +x "$INSTALL_DIR/iran_server.py"
update_step 2 "${GREEN}✓${RESET}"

##############################
# STEP 4 – PYTHON DEPS
##############################
cd "$INSTALL_DIR"
pip3 install --break-system-packages aiohttp aiohttp-socks python-socks dnspython >/dev/null 2>&1 \
 || pip3 install --user aiohttp aiohttp-socks python-socks dnspython >/dev/null 2>&1 \
 || pip3 install aiohttp aiohttp-socks python-socks dnspython >/dev/null 2>&1

update_step 3 "${GREEN}✓${RESET}"

##############################
# STEP 5 – SSL CERTBOT
##############################
systemctl stop nginx 2>/dev/null || true

certbot certonly --standalone -d "$domain" --non-interactive \
    --agree-tos --register-unsafely-without-email >/dev/null 2>&1 \
    || { last_error="Certbot failed"; update_step 4 "${RED}✗${RESET}"; fail; }

update_step 4 "${GREEN}✓${RESET}"

##############################
# STEP 6 – NGINX CONFIG
##############################
nginx_conf="/etc/nginx/sites-enabled/default"

cat > "$nginx_conf" <<EOF
server {
    listen 80;
    server_name $domain;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    listen 8443 ssl http2;
    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location /dns-query {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location / {
        return 200 'Iran DNS Server is running';
        add_header Content-Type text/plain;
    }
}
EOF

nginx -t >/dev/null 2>&1 || { last_error="NGINX test failed"; update_step 5 "${RED}✗${RESET}"; fail; }
systemctl restart nginx >/dev/null 2>&1 || { last_error="NGINX restart failed"; update_step 5 "${RED}✗${RESET}"; fail; }

update_step 5 "${GREEN}✓${RESET}"

##############################
# STEP 7 – SYSTEMD SERVICE
##############################
cat > /etc/systemd/system/iran-dns.service <<EOF
[Unit]
Description=Iran DNS Anti-Filter and SNI Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/iran_server.py
Restart=always
RestartSec=10
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iran-dns.service >/dev/null 2>&1
systemctl start iran-dns.service >/dev/null 2>&1
sleep 3

systemctl is-active --quiet iran-dns.service || {
    last_error="$(journalctl -u iran-dns -n 20 --no-pager)"
    update_step 6 "${RED}✗${RESET}"
    fail
}

update_step 6 "${GREEN}✓${RESET}"

##############################
# STEP 8 – TEST DoH
##############################
test_result=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/dns-message" \
    --data-binary @<(echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d) \
    "https://$domain/dns-query")

test_result="${test_result:-000}"

if [[ "$test_result" = "200" ]]; then
    update_step 7 "${GREEN}✓${RESET}"
else
    last_error="DoH test failed (HTTP $test_result)"
    update_step 7 "${RED}✗ (HTTP $test_result)${RESET}"
    fail
fi

##############################
# SUCCESS END
##############################
tput cup $((steps_total + 4)) 0
echo -e "${GREEN}✓ Installation Complete!${RESET}"
echo "DoH URL: https://$domain/dns-query"

}

##############################################################
# Run Installer
##############################################################
install_iran_server
