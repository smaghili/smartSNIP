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
    
    local packages=("nginx" "git" "jq" "certbot" "python3-certbot-nginx" "python3" "python3-pip" "curl" "gpg" "lsb-release")
    
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &> /dev/null 2>&1 && ! rpm -q "$package" &> /dev/null 2>&1; then
            echo "$package is not installed. Installing..."
            $pm install -y "$package"
        else
            echo "$package is already installed."
        fi
    done
    
    if ! command -v python3 &> /dev/null; then
        echo "python3 is not installed. Installing..."
        $pm install -y python3 python3-pip
    else
        echo "python3 is already installed."
    fi
}

install_iran_server() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root (use sudo)"
        exit 1
    fi

    echo "=========================================="
    echo "  Iran DNS Anti-Filter Server Installation"
    echo "=========================================="
    
    install_dependencies
    
    INSTALL_DIR="/root/smartSNI"
    mkdir -p "$INSTALL_DIR"
    
    echo ""
    echo "======================================"
    echo "Configuration"
    echo "======================================"
    
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
    read -p "Enter sanctioned domain names separated by commas (e.g., youtube.com,googlevideo.com): " site_list
    
    echo ""
    echo "Creating configuration file..."
    cat > "$INSTALL_DIR/iran_config.json" <<EOF
{
  "host": "$domain",
  "server_ip": "$myip",
  "foreign_doh_url": "$foreign_doh",
  "domains": {
EOF
    
    if [ ! -z "$site_list" ]; then
        IFS=',' read -ra sites <<< "$site_list"
        site_count=${#sites[@]}
        counter=0
        for site in "${sites[@]}"; do
            counter=$((counter + 1))
            site=$(echo "$site" | xargs)
            if [ $counter -eq $site_count ]; then
                echo "    \"$site\": \"$myip\"" >> "$INSTALL_DIR/iran_config.json"
            else
                echo "    \"$site\": \"$myip\"," >> "$INSTALL_DIR/iran_config.json"
            fi
        done
    fi
    
    cat >> "$INSTALL_DIR/iran_config.json" <<EOF
  }
}
EOF
    
    echo "Configuration created:"
    cat "$INSTALL_DIR/iran_config.json"
    echo ""
    
    echo "Copying server files..."
    cp iran_server.py "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/iran_server.py"
    
    echo "Installing Python dependencies..."
    cd "$INSTALL_DIR"
    pip3 install --break-system-packages aiohttp aiohttp-socks python-socks dnspython 2>/dev/null || \
    pip3 install --user aiohttp aiohttp-socks python-socks dnspython 2>/dev/null || \
    pip3 install aiohttp aiohttp-socks python-socks dnspython
    
    echo ""
    echo "======================================"
    echo "Configuring Nginx..."
    echo "======================================"
    
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
    
    echo "Obtaining SSL certificate..."
    certbot --nginx -d "$domain" --register-unsafely-without-email --non-interactive --agree-tos
    
    if [ $? -eq 0 ]; then
        echo "SSL certificate obtained successfully!"
    else
        echo "WARNING: SSL certificate failed. DoT may not work properly."
    fi
    
    systemctl stop nginx
    systemctl restart nginx
    
    echo ""
    echo "======================================"
    echo "Installing systemd service..."
    echo "======================================"
    
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
    systemctl enable iran-dns.service
    systemctl start iran-dns.service
    
    sleep 3
    
    echo ""
    echo "=========================================="
    echo "  Installation Complete!"
    echo "=========================================="
    echo ""
    
    if systemctl is-active --quiet iran-dns.service; then
        echo "✓ Iran DNS Server is running!"
        echo ""
        echo "Service Status:"
        systemctl status iran-dns.service --no-pager | head -n 10
    else
        echo "✗ Iran DNS Server failed to start!"
        echo ""
        echo "Check logs with:"
        echo "  journalctl -u iran-dns -f"
        exit 1
    fi
    
    echo ""
    echo "======================================"
    echo "Configuration Summary:"
    echo "======================================"
    echo "Domain: $domain"
    echo "Server IP: $myip"
    echo "Foreign DoH: $foreign_doh"
    echo ""
    echo "Services:"
    echo "  - DoH Server: http://$myip:8080/dns-query"
    echo "  - DoT Server: $domain:853"
    echo "  - SNI Proxy: $myip:443"
    echo ""
    echo "Client Configuration:"
    echo "  DoH URL: https://$domain/dns-query (if Nginx configured)"
    echo "  DoT: $domain (port 853)"
    echo ""
    echo "View logs:"
    echo "  journalctl -u iran-dns -f"
    echo ""
    echo "Restart service:"
    echo "  systemctl restart iran-dns"
    echo "=========================================="
}

install_iran_server
