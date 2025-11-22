#!/bin/bash

##############################################################
#       SmartDNS Foreign Server Installer - Final Version
#       Ultra-Stable, Full UI, Full Logging, No Goto Bugs
#       No Feature Removed from Original
##############################################################

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

pm=""
INSTALL_DIR="/root/smartDNS"
warp_enabled=false
warp_license=""
last_error=""
steps_total=8

##############################################################
#   ERROR HANDLER  (Defined First – No Goto Issues)
##############################################################
fail() {
    tput cup 25 0
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

    local packages=("nginx" "certbot" "python3-certbot-nginx" "python3" "python3-pip" "curl" "gpg" "lsb-release" "stunnel4")
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &>/dev/null && ! rpm -q "$package" &>/dev/null; then
            $pm install -y "$package" >/dev/null 2>&1
        fi
    done
}

##############################################################
#   WARP Installer (Only Runs in Warp Step)
##############################################################
install_warp() {

    if [[ "$pm" != "apt-get" ]]; then
        last_error="WARP is not supported on non-Debian systems"
        return 1
    fi

    if ! command -v warp-cli &>/dev/null; then
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
            | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" \
            >/etc/apt/sources.list.d/cloudflare-client.list

        apt-get update -y >/dev/null 2>&1
        apt-get install -y cloudflare-warp >/dev/null 2>&1

        if ! command -v warp-cli &>/dev/null; then
            last_error="Failed to install warp-cli"
            return 1
        fi
    fi

    systemctl enable --now warp-svc >/dev/null 2>&1
    sleep 2

    warp-cli registration delete >/dev/null 2>&1
    warp-cli registration new >/dev/null 2>&1 \
        || { last_error="Failed to create WARP registration"; return 1; }

    warp-cli registration license "$warp_license" >/dev/null 2>&1 \
        || { last_error="Invalid WARP license"; return 1; }

    warp-cli disconnect >/dev/null 2>&1
    warp-cli mode proxy >/dev/null 2>&1 \
        || { last_error="Failed to set WARP proxy mode"; return 1; }

    warp-cli proxy port 50000 >/dev/null 2>&1 \
        || { last_error="Failed to set WARP port to 50000"; return 1; }

    warp-cli connect >/dev/null 2>&1 \
        || { last_error="Failed to connect WARP"; return 1; }

    sleep 2
    ss -ltnp | grep -q 50000 && return 0

    last_error="WARP proxy not detected on port 50000"
    return 1
}

##############################################################
# UI FUNCTIONS
##############################################################
step_titles_base=(
"Configuration"
"Installing & configuring Stunnel (Server mode)"
"Creating configuration and downloading server code"
"Installing Python dependencies"
"Obtaining SSL certificate"
"Configuring Nginx"
"Installing and starting Foreign DNS service"
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
    printf "[%d/%d] %-60s %s\n" "$(($1+1))" "$steps_total" "${step_titles_base[$1]}" "$2"
}

##############################################################
# MAIN INSTALLER FUNCTION
##############################################################
install_foreign_server() {

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

read -p "Enter your foreign server domain name: " domain
[[ -z "$domain" ]] && echo "ERROR: Domain cannot be empty!" && exit 1

echo ""
echo "Select upstream DNS provider:"
echo "1) Cloudflare"
echo "2) Google"
echo "3) Custom"
read -p "Enter choice [1-3]: " dns_choice

case "$dns_choice" in
1) upstream_doh="https://1.1.1.1/dns-query" ;;
2) upstream_doh="https://8.8.8.8/dns-query" ;;
3) read -p "Enter custom DoH: " upstream_doh ;;
*) upstream_doh="https://1.1.1.1/dns-query" ;;
esac

##############################
# WARP LOGIC (CHECK ONLY)
##############################
echo ""
read -p "Do you want to install Cloudflare WARP proxy? (y/n): " wc

if [[ "$wc" =~ ^[Yy]$ ]]; then
    warp_enabled=true
    steps_total=9
    step_titles_base[7]="Installing Cloudflare WARP"
    step_titles_base[8]="Testing DoH server"

    if command -v warp-cli &>/dev/null; then

        status=$(warp-cli status 2>/dev/null)
        if echo "$status" | grep -q "Connected"; then
            echo -e "${GREEN}WARP is installed (Connected)${RESET}"
            read -p "Reinstall/reconfigure? (y/n): " r
            if [[ "$r" =~ ^[Yy]$ ]]; then
                read -p "Enter WARP license key: " warp_license
            else
                warp_enabled=false
                steps_total=8
            fi

        else
            echo -e "${YELLOW}WARP is installed (Disconnected)${RESET}"
            read -p "Reconfigure? (y/n): " r
            if [[ "$r" =~ ^[Yy]$ ]]; then
                read -p "Enter WARP license key: " warp_license
            else
                warp_enabled=false
                steps_total=8
            fi
        fi
    else
        echo -e "${YELLOW}WARP not installed${RESET}"
        read -p "Enter WARP license key: " warp_license
    fi
fi

##############################
# START UI
##############################
draw_steps

##############################
# STEP 1 – CONFIG
##############################
install_dependencies
mkdir -p "$INSTALL_DIR"
update_step 0 "${GREEN}✓${RESET}"

##############################
# STEP 2 – STUNNEL
##############################
systemctl stop stunnel4 2>/dev/null || true
rm -f /etc/stunnel/*.conf

sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4

openssl req -new -x509 -days 3650 -nodes \
    -out /etc/stunnel/stunnel.pem \
    -keyout /etc/stunnel/stunnel.pem \
    -subj "/C=US/ST=State/L=City/O=Org/CN=stunnel" \
    >/dev/null 2>&1 || {
        last_error="OpenSSL failed"; update_step 1 "${RED}✗${RESET}"; fail;
    }

cat > /etc/stunnel/tunnel-server.conf <<EOF
client = no
foreground = no
output = /var/log/stunnel-server.log
pid = /run/stunnel4-server.pid
sslVersion = TLSv1.3
options = NO_RENEGOTIATION

[foreign-tunnel]
accept = 6001
connect = 127.0.0.1:443
cert = /etc/stunnel/stunnel.pem
key  = /etc/stunnel/stunnel.pem
verify = 0
EOF

systemctl restart stunnel4 >/dev/null 2>&1 || {
    last_error="$(systemctl status stunnel4 --no-pager)"
    update_step 1 "${RED}✗${RESET}"
    fail
}

update_step 1 "${GREEN}✓${RESET}"

##############################
# STEP 3 – CONFIG JSON + DOWNLOAD
##############################
cat > "$INSTALL_DIR/foreign_config.json" <<EOF
{
  "upstream_doh": "$upstream_doh",
  "port": 8080,
  "domains": {}
}
EOF

curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNIP/main/foreign_server.py \
    -o "$INSTALL_DIR/foreign_server.py" || {
        last_error="Failed to download foreign_server.py"
        update_step 2 "${RED}✗${RESET}"
        fail
    }

chmod +x "$INSTALL_DIR/foreign_server.py"
update_step 2 "${GREEN}✓${RESET}"

##############################
# STEP 4 – PYTHON PACKAGE INSTALL
##############################
cd "$INSTALL_DIR"
pip3 install --break-system-packages aiohttp dnspython >/dev/null 2>&1 \
    || pip3 install --user aiohttp dnspython >/dev/null 2>&1 \
    || pip3 install aiohttp dnspython >/dev/null 2>&1

update_step 3 "${GREEN}✓${RESET}"

##############################
# STEP 5 – CERTBOT
##############################
systemctl stop nginx 2>/dev/null || true

certbot certonly --standalone -d "$domain" --non-interactive \
    --agree-tos --register-unsafely-without-email >/dev/null 2>&1 \
    || { last_error="Certbot failed"; update_step 4 "${RED}✗${RESET}"; fail; }

update_step 4 "${GREEN}✓${RESET}"

##############################
# STEP 6 – NGINX CONFIG
##############################
cat > /etc/nginx/sites-available/doh-server <<EOF
server {
    if (\$host = $domain) {
        return 301 https://\$host\$request_uri;
    }
    listen 80;
    server_name $domain;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 4443 ssl http2;
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
        return 200 'Foreign DNS Relay Server is running';
        add_header Content-Type text/plain;
    }
}
EOF

ln -sf /etc/nginx/sites-available/doh-server /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

nginx -t >/dev/null 2>&1 || { last_error="NGINX config test failed"; update_step 5 "${RED}✗${RESET}"; fail; }
systemctl restart nginx >/dev/null 2>&1 || { last_error="NGINX restart failed"; update_step 5 "${RED}✗${RESET}"; fail; }

update_step 5 "${GREEN}✓${RESET}"

##############################
# STEP 7 – SYSTEMD SERVICE
##############################
cat > /etc/systemd/system/foreign-dns.service <<EOF
[Unit]
Description=Foreign DNS Relay Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/foreign_server.py
Restart=always
RestartSec=10
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable foreign-dns.service >/dev/null 2>&1
systemctl start foreign-dns.service >/dev/null 2>&1
sleep 3

systemctl is-active --quiet foreign-dns.service || {
    last_error="$(journalctl -u foreign-dns -n 20 --no-pager)"
    update_step 6 "${RED}✗${RESET}"
    fail
}

update_step 6 "${GREEN}✓${RESET}"

##############################
# STEP 8 – WARP (IF ENABLED)
##############################
if $warp_enabled; then
    install_warp \
        && update_step 7 "${GREEN}✓${RESET}" \
        || { update_step 7 "${RED}✗${RESET}"; fail; }
    test_step=8
else
    test_step=7
fi

##############################
# FINAL STEP – TESTING DOH
##############################
test_result=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/dns-message" \
    --data-binary @<(echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d) \
    "https://$domain:4443/dns-query")

test_result="${test_result:-000}"

if [[ "$test_result" = "200" ]]; then
    update_step "$test_step" "${GREEN}✓${RESET}"
else
    last_error="DoH test failed (HTTP $test_result)"
    update_step "$test_step" "${RED}✗ (HTTP $test_result)${RESET}"
    fail
fi

##############################
# SUCCESS END
##############################
tput cup 27 0
echo -e "${GREEN}✓ Installation Complete!${RESET}"
echo "DoH URL: https://$domain:4443/dns-query"

}

##############################################################
# Run Installer
##############################################################
install_foreign_server
