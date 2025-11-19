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
    echo "Updating package list..."
    $pm update -y
    
    local packages=("nginx" "certbot" "python3-certbot-nginx" "python3" "python3-pip" "curl" "gpg" "lsb-release")
    
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &> /dev/null 2>&1 && ! rpm -q "$package" &> /dev/null 2>&1; then
            echo "$package is not installed. Installing..."
            $pm install -y "$package"
        else
            echo "$package is already installed."
        fi
    done
}

install_warp() {
    if [[ "$pm" != "apt-get" ]]; then
        echo "Cloudflare WARP installation currently supports Debian and Ubuntu hosts."
        return 1
    fi
    
    echo ""
    echo "======================================"
    echo "Installing Cloudflare WARP..."
    echo "======================================"
    
    if command -v warp-cli &> /dev/null; then
        read -p "WARP is already installed. Reconfigure it now? (y/n): " reconfigure
        if [[ ! "$reconfigure" =~ ^[Yy]$ ]]; then
            echo "Skipping WARP configuration."
            return 0
        fi
    else
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
        apt-get update -y
        apt-get install -y cloudflare-warp
        if ! command -v warp-cli &> /dev/null; then
            echo "ERROR: Cloudflare WARP installation failed."
            return 1
        fi
    fi
    
    systemctl enable --now warp-svc
    sleep 2
    
    warp-cli registration delete &> /dev/null
    if ! warp-cli registration new; then
        echo "ERROR: WARP registration failed."
        return 1
    fi
    
    while true; do
        read -p "Enter your WARP license key: " warp_license
        if [ -z "$warp_license" ]; then
            echo "ERROR: License key cannot be empty."
            continue
        fi
        if warp-cli registration license "$warp_license"; then
            echo "License applied successfully."
            break
        fi
        read -p "Invalid license key. Try again? (y/n): " retry
        if [[ ! "$retry" =~ ^[Yy]$ ]]; then
            echo "WARP configuration cancelled."
            return 1
        fi
    done
    
    warp-cli disconnect &> /dev/null
    if ! warp-cli mode proxy; then
        echo "ERROR: Failed to set WARP proxy mode."
        return 1
    fi
    
    if ! warp-cli proxy port 50000; then
        echo "ERROR: Failed to bind WARP proxy to port 50000."
        return 1
    fi
    
    if ! warp-cli connect; then
        echo "ERROR: WARP connection failed."
        return 1
    fi
    
    sleep 2
    warp-cli status || true
    
    if ss -ltnp 2>/dev/null | grep -q 50000 || netstat -plant 2>/dev/null | grep -q 50000; then
        echo "WARP SOCKS5 proxy is listening on port 50000"
        return 0
    fi
    
    echo "WARNING: Port 50000 is not listening yet. Verify manually with ss -ltnp | grep 50000"
    return 1
}

install_foreign_server() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root (use sudo)"
        exit 1
    fi

    echo "=========================================="
    echo "  Foreign DNS Relay Server Installation"
    echo "=========================================="
    
    install_dependencies
    
    INSTALL_DIR="/root/smartDNS"
    mkdir -p "$INSTALL_DIR"
    
    echo ""
    echo "======================================"
    echo "Configuration"
    echo "======================================"
    
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
    
    echo ""
    echo "Creating configuration file..."
    cat > "$INSTALL_DIR/foreign_config.json" <<EOF
{
  "upstream_doh": "$upstream_doh",
  "port": 8080,
  "domains": {}
}
EOF
    
    echo "Configuration created:"
    cat "$INSTALL_DIR/foreign_config.json"
    echo ""
    
    echo "Downloading foreign_server.py from GitHub..."
    curl -fsSL https://raw.githubusercontent.com/smaghili/smartSNIP/main/foreign_server.py -o "$INSTALL_DIR/foreign_server.py"
    
    if [ ! -f "$INSTALL_DIR/foreign_server.py" ]; then
        echo "ERROR: Failed to download foreign_server.py"
        exit 1
    fi
    
    chmod +x "$INSTALL_DIR/foreign_server.py"
    echo "foreign_server.py downloaded successfully!"
    
    echo "Installing Python dependencies..."
    cd "$INSTALL_DIR"
    pip3 install --break-system-packages aiohttp dnspython 2>/dev/null || \
    pip3 install --user aiohttp dnspython 2>/dev/null || \
    pip3 install aiohttp dnspython
    
    echo ""
    echo "======================================"
    echo "Configuring Nginx with SSL..."
    echo "======================================"
    
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
    listen 443 ssl http2;
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
    
    echo "Testing Nginx configuration..."
    nginx -t
    
    echo ""
    echo "Obtaining SSL certificate..."
    certbot --nginx -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email
    
    if [ $? -eq 0 ]; then
        echo "SSL certificate obtained successfully!"
    else
        echo "ERROR: Failed to obtain SSL certificate!"
        exit 1
    fi
    
    systemctl restart nginx
    
    echo ""
    echo "======================================"
    echo "Installing systemd service..."
    echo "======================================"
    
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
    systemctl enable foreign-dns.service
    systemctl start foreign-dns.service
    
    sleep 3
    
    echo ""
    echo "=========================================="
    echo "  Installation Complete!"
    echo "=========================================="
    echo ""
    
    if systemctl is-active --quiet foreign-dns.service; then
        echo "✓ Foreign DNS Server is running!"
        echo ""
        echo "Service Status:"
        systemctl status foreign-dns.service --no-pager | head -n 10
    else
        echo "✗ Foreign DNS Server failed to start!"
        echo ""
        echo "Check logs with:"
        echo "  journalctl -u foreign-dns -f"
        exit 1
    fi
    
    echo ""
    echo "======================================"
    echo "Testing DoH Server..."
    echo "======================================"
    
    sleep 2
    
    echo "Testing HTTPS DoH endpoint..."
    test_response=$(curl -s -w "\n%{http_code}" -H "Content-Type: application/dns-message" \
        --data-binary @<(echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d) \
        "https://$domain/dns-query" 2>/dev/null || echo "000")
    
    http_code=$(echo "$test_response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        echo "✓ DoH server is working correctly!"
    else
        echo "⚠ DoH server returned HTTP $http_code"
        echo "Please check logs: journalctl -u foreign-dns -f"
    fi
    
    echo ""
    echo "======================================"
    echo "Configuration Summary:"
    echo "======================================"
    echo "Domain: $domain"
    echo "Upstream DNS: $upstream_doh"
    echo ""
    echo "Your DoH URL (use this in iran_config.json):"
    echo "  https://$domain/dns-query"
    echo ""
    echo "Test your DoH server:"
    echo "  curl -H 'Content-Type: application/dns-message' \\"
    echo "       --data-binary @<(echo -n 'AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' | base64 -d) \\"
    echo "       https://$domain/dns-query"
    echo ""
    echo "View logs:"
    echo "  journalctl -u foreign-dns -f"
    echo ""
    echo "Restart service:"
    echo "  systemctl restart foreign-dns"
    echo "=========================================="
    
    echo ""
    read -p "Install Cloudflare WARP proxy support on port 50000? (y/n): " warp_choice
    if [[ "$warp_choice" =~ ^[Yy]$ ]]; then
        install_warp
    else
        echo "Skipping Cloudflare WARP installation."
    fi
}

install_foreign_server
