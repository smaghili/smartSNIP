#!/bin/bash

detect_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "${ID}" = "ubuntu" || "${ID}" = "debian" ]]; then
            pm="apt-get"
        elif [[ "${ID}" = "centos" ]]; then
            pm="yum"
        elif [[ "${ID}" = "fedora" ]]; then
            pm="dnf"
        else
            pm="apt-get"
        fi
    else
        pm="apt-get"
    fi
}

install_dependencies() {
    detect_distribution
    $pm update -y >/dev/null 2>&1
    
    local packages=("nginx" "git" "jq" "certbot" "python3-certbot-nginx" "python3" "python3-pip" "curl" "gpg" "lsb-release" "stunnel4")
    
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &> /dev/null 2>&1 && ! rpm -q "$package" &> /dev/null 2>&1; then
            $pm install -y "$package" >/dev/null 2>&1
        fi
    done
    
    if ! command -v python3 &> /dev/null; then
        $pm install -y python3 python3-pip >/dev/null 2>&1
    fi
}

install_iran_server() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root (use sudo)"
        exit 1
    fi

    install_dependencies
    
    INSTALL_DIR="/root/smartDNS"
    mkdir -p "$INSTALL_DIR"
    
    echo "[1/8] Configuration"
    read -p "Enter your domain name: " domain
    if [ -z "$domain" ]; then
        echo "ERROR: Domain cannot be empty!"
        exit 1
    fi
    
    myip=$(hostname -I | awk '{print $1}')
    echo "Detected server IP: $myip"
    read -p "Is this correct? (y/n): " ip_confirm
    if [[ ! "$ip_confirm" =~ ^[Yy]$ ]]; then
        read -p "Enter your server IP: " myip
    fi
    
    echo ""
    read -p "Enter your foreign DoH server URL (e.g., https://foreign.example.com/dns-query): " foreign_doh
    if [ -z "$foreign_doh" ]; then
        echo "ERROR: Foreign DoH URL cannot be empty!"
        exit 1
    fi
    
    echo ""
    echo "Extracting foreign server IP..."
    foreign_domain=$(echo "$foreign_doh" | sed -E 's|https?://([^:/]+).*|\1|')
    foreign_ip=$(getent hosts "$foreign_domain" 2>/dev/null | awk '{print $1}' | head -n1)
    if [ -z "$foreign_ip" ]; then
        foreign_ip=$(nslookup "$foreign_domain" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -n1)
    fi
    if [ -z "$foreign_ip" ]; then
        foreign_ip=$(ping -c 1 -W 2 "$foreign_domain" 2>/dev/null | grep "PING" | sed -E 's/.*\(([0-9.]+)\).*/\1/')
    fi
    if [ -z "$foreign_ip" ]; then
        echo "Could not extract IP automatically."
        read -p "Enter foreign server IP manually: " foreign_ip
    else
        read -p "Extracted foreign IP: $foreign_ip (Press Enter to confirm or type a different IP): " user_ip
        if [ ! -z "$user_ip" ]; then
            foreign_ip="$user_ip"
        fi
    fi
    
    if [ -z "$foreign_ip" ]; then
        echo "ERROR: Foreign IP cannot be empty!"
        exit 1
    fi
    
    echo ""
    read -p "Enter sanctioned domain names separated by commas (e.g., youtube.com,googlevideo.com): " site_list
    echo "✓ [1/8] Configuration completed"
    
    echo "[2/8] Installing and configuring Stunnel (Client mode)"
    
    systemctl stop stunnel4 2>/dev/null || true
    systemctl disable stunnel4 2>/dev/null || true
    rm -f /etc/stunnel/*.conf 2>/dev/null || true
    
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null || true
    
    if ! openssl req -new -x509 -days 3650 -nodes \
        -out /etc/stunnel/stunnel.pem \
        -keyout /etc/stunnel/stunnel.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=stunnel" 2>/dev/null; then
        echo "✗ [2/8] Failed to create Stunnel certificate"
        exit 1
    fi
    
    if ! cat > /etc/stunnel/tunnel-client.conf 2>/dev/null <<EOF
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
    then
        echo "✗ [2/8] Failed to create Stunnel config (disk full?)"
        df -h /etc
        exit 1
    fi
    
    if systemctl restart stunnel4 2>&1 && sleep 2 && systemctl is-active --quiet stunnel4; then
        echo "✓ [2/8] Stunnel configured (127.0.0.1:60000 → $foreign_ip:6001)"
    else
        echo "✗ [2/8] Stunnel failed to start"
        systemctl status stunnel4 --no-pager
        exit 1
    fi
    
    echo "[3/8] Creating configuration and downloading server code"
    cat > "$INSTALL_DIR/iran_config.json" <<EOF
{
  "host": "$domain",
  "server_ip": "$myip",
  "foreign_doh_url": "$foreign_doh",
  "domains": {
    "filter.txt": "$foreign_ip",
    "ban.txt": "$foreign_ip",
    "warp.txt": "$foreign_ip"
EOF
    
    if [ ! -z "$site_list" ]; then
        IFS=',' read -ra sites <<< "$site_list"
        for site in "${sites[@]}"; do
            site=$(echo "$site" | xargs)
            echo "    ,\"$site\": \"$foreign_ip\"" >> "$INSTALL_DIR/iran_config.json"
        done
    fi
    
    cat >> "$INSTALL_DIR/iran_config.json" <<EOF
  }
}
EOF
    
    local files=("iran_server.py" "filter.txt" "ban.txt" "warp.txt")
    local base_url="https://raw.githubusercontent.com/smaghili/smartSNIP/main"
    
    for file in "${files[@]}"; do
        if curl -fsSL "$base_url/$file" -o "$INSTALL_DIR/$file" 2>/dev/null && [ -f "$INSTALL_DIR/$file" ]; then
            [ "$file" = "iran_server.py" ] && chmod +x "$INSTALL_DIR/$file"
        else
            if [ "$file" = "iran_server.py" ]; then
                echo "✗ [3/8] Failed to download $file"
                exit 1
            else
                echo "WARNING: Failed to download $file (continuing without it)"
            fi
        fi
    done
    
    echo "✓ [3/8] Configuration created and server code downloaded"
    
    echo "[4/8] Installing Python dependencies"
    cd "$INSTALL_DIR"
    if pip3 install --break-system-packages aiohttp aiohttp-socks python-socks dnspython 2>/dev/null || \
       pip3 install --user aiohttp aiohttp-socks python-socks dnspython 2>/dev/null || \
       pip3 install aiohttp aiohttp-socks python-socks dnspython 2>&1; then
        echo "✓ [4/8] Python dependencies installed"
    else
        echo "✗ [4/8] Failed to install Python dependencies"
        exit 1
    fi
    
    echo "[5/8] Obtaining SSL certificate"
    systemctl stop nginx 2>/dev/null || true
    if certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email 2>&1; then
        echo "✓ [5/8] SSL certificate obtained"
    else
        echo "✗ [5/8] Failed to obtain SSL certificate"
        echo "Make sure DNS points to this server and port 80 is open."
        exit 1
    fi
    
    echo "[6/8] Configuring Nginx"
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
    
    if nginx -t 2>&1 && systemctl restart nginx 2>&1; then
        echo "✓ [6/8] Nginx configured and started"
    else
        echo "✗ [6/8] Nginx configuration failed"
        exit 1
    fi
    
    echo "[7/8] Installing and starting Iran DNS service"
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
    
    systemctl daemon-reload 2>&1
    systemctl enable iran-dns.service 2>&1
    systemctl start iran-dns.service 2>&1
    
    sleep 3
    
    if systemctl is-active --quiet iran-dns.service; then
        echo "✓ [7/8] Iran DNS service installed and started"
    else
        echo "✗ [7/8] Iran DNS service failed to start"
        journalctl -u iran-dns -n 20 --no-pager
        exit 1
    fi
    
    echo "[8/8] Testing DoH server"
    sleep 2
    test_result=$(curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/dns-message" \
        --data-binary @<(echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d 2>/dev/null) \
        "https://$domain/dns-query" 2>/dev/null || echo "000")
    
    if [ "$test_result" = "200" ]; then
        echo "✓ [8/8] DoH server test passed"
    else
        echo "✗ [8/8] DoH server test returned HTTP $test_result"
    fi
    
    echo ""
    echo "✓ Installation Complete!"
    echo "DoH URL: https://$domain/dns-query"
}

install_iran_server
