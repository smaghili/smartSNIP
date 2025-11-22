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
    
    local packages=("nginx" "certbot" "python3-certbot-nginx" "python3" "python3-pip" "curl" "gpg" "lsb-release" "stunnel4")
    
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &> /dev/null 2>&1 && ! rpm -q "$package" &> /dev/null 2>&1; then
            $pm install -y "$package" >/dev/null 2>&1
        fi
    done
}

install_warp() {
    if [[ "$pm" != "apt-get" ]]; then
        return 1
    fi
    
    if command -v warp-cli &> /dev/null; then
        read -p "WARP is already installed. Reconfigure it now? (y/n): " reconfigure
        if [[ ! "$reconfigure" =~ ^[Yy]$ ]]; then
            return 0
        fi
    else
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg 2>/dev/null | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list 2>/dev/null
        apt-get update -y >/dev/null 2>&1
        apt-get install -y cloudflare-warp >/dev/null 2>&1
        if ! command -v warp-cli &> /dev/null; then
            return 1
        fi
    fi
    
    systemctl enable --now warp-svc >/dev/null 2>&1
    sleep 2
    
    warp-cli registration delete &> /dev/null
    if ! warp-cli registration new >/dev/null 2>&1; then
        return 1
    fi
    
    while true; do
        read -p "Enter your WARP license key: " warp_license
        if [ -z "$warp_license" ]; then
            continue
        fi
        if warp-cli registration license "$warp_license" >/dev/null 2>&1; then
            break
        fi
        read -p "Invalid license key. Try again? (y/n): " retry
        if [[ ! "$retry" =~ ^[Yy]$ ]]; then
            return 1
        fi
    done
    
    warp-cli disconnect &> /dev/null
    if ! warp-cli mode proxy >/dev/null 2>&1; then
        return 1
    fi
    
    if ! warp-cli proxy port 50000 >/dev/null 2>&1; then
        return 1
    fi
    
    if ! warp-cli connect >/dev/null 2>&1; then
        return 1
    fi
    
    sleep 2
    
    if ss -ltnp 2>/dev/null | grep -q 50000 || netstat -plant 2>/dev/null | grep -q 50000; then
        return 0
    fi
    
    return 1
}

install_foreign_server() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root (use sudo)"
        exit 1
    fi

    install_dependencies
    
    INSTALL_DIR="/root/smartDNS"
    mkdir -p "$INSTALL_DIR"
    
    echo "[1/8] Configuration"
    read -p "Enter your foreign server domain name (e.g., foreign.example.com): " domain
    if [ -z "$domain" ]; then
        echo "ERROR: Domain cannot be empty!"
        exit 1
    fi
    
    echo ""
    echo "Select upstream DNS provider:"
    echo "1) Cloudflare (1.1.1.1)"
    echo "2) Google (8.8.8.8)"
    echo "3) Custom"
    read -p "Enter choice [1-3]: " dns_choice
    
    case "$dns_choice" in
        1)
            upstream_doh="https://1.1.1.1/dns-query"
            ;;
        2)
            upstream_doh="https://8.8.8.8/dns-query"
            ;;
        3)
            read -p "Enter custom DoH URL: " upstream_doh
            ;;
        *)
            upstream_doh="https://1.1.1.1/dns-query"
            ;;
    esac
    echo "✓ [1/8] Configuration completed"
    
    echo -n "[2/8] Installing and configuring Stunnel (Server mode)... "
    systemctl stop stunnel4 2>/dev/null || true
    rm -f /etc/stunnel/*.conf 2>/dev/null
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null || true
    openssl req -new -x509 -days 3650 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=stunnel" 2>/dev/null || { echo "✗"; exit 1; }
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
    systemctl restart stunnel4 2>&1 && sleep 2 && systemctl is-active --quiet stunnel4 && echo "✓" || { echo "✗"; systemctl status stunnel4 --no-pager; exit 1; }
    
    echo "[3/8] Creating configuration and downloading server code"
    cat > "$INSTALL_DIR/foreign_config.json" <<EOF
{
  "upstream_doh": "$upstream_doh",
  "port": 8080,
  "domains": {}
}
EOF
    
    curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNIP/main/foreign_server.py -o "$INSTALL_DIR/foreign_server.py" 2>/dev/null
    
    if [ ! -f "$INSTALL_DIR/foreign_server.py" ]; then
        echo "ERROR: Failed to download foreign_server.py"
        exit 1
    fi
    
    chmod +x "$INSTALL_DIR/foreign_server.py"
    echo "✓ [3/8] Configuration created and server code downloaded"
    
    echo -n "[4/8] Installing Python dependencies... "
    cd "$INSTALL_DIR"
    pip3 install --break-system-packages aiohttp dnspython 2>/dev/null || pip3 install --user aiohttp dnspython 2>/dev/null || pip3 install aiohttp dnspython 2>&1 && echo "✓" || { echo "✗"; exit 1; }
    
    echo -n "[5/8] Obtaining SSL certificate... "
    systemctl stop nginx 2>/dev/null || true
    certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email 2>&1 && echo "✓" || { echo "✗"; exit 1; }
    
    echo -n "[6/8] Configuring Nginx... "
    cat > /etc/nginx/sites-available/doh-server <<EOF
server {
    if (\$host = $domain) {
        return 301 https://\$host\$request_uri;
    }

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
    nginx -t 2>&1 && systemctl restart nginx 2>&1 && echo "✓" || { echo "✗"; exit 1; }
    
    echo -n "[7/8] Installing and starting Foreign DNS service... "
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
    
    systemctl daemon-reload 2>&1
    systemctl enable foreign-dns.service 2>&1
    systemctl start foreign-dns.service 2>&1
    sleep 3
    systemctl is-active --quiet foreign-dns.service && echo "✓" || { echo "✗"; journalctl -u foreign-dns -n 20 --no-pager; exit 1; }
    
    echo -n "[8/8] Testing DoH server... "
    sleep 2
    test_result=$(curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/dns-message" --data-binary @<(echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d 2>/dev/null) "https://$domain:4443/dns-query" 2>/dev/null || echo "000")
    [ "$test_result" = "200" ] && echo "✓" || echo "✗ (HTTP $test_result)"
    
    echo ""
    echo "✓ Installation Complete!"
    echo "DoH URL: https://$domain:4443/dns-query"
    
    echo ""
    read -p "Install Cloudflare WARP proxy support on port 50000? (y/n): " warp_choice
    if [[ "$warp_choice" =~ ^[Yy]$ ]]; then
        echo -n "[9/9] Installing Cloudflare WARP... "
        install_warp && echo "✓" || echo "✗"
    fi
}

install_foreign_server
