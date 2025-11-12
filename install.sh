#!/bin/bash

detect_distribution() {
    # Detect the Linux distribution
    local supported_distributions=("ubuntu" "debian" "centos" "fedora")
    
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        if [[ "${ID}" = "ubuntu" || "${ID}" = "debian" || "${ID}" = "centos" || "${ID}" = "fedora" ]]; then
            pm="apt"
            [ "${ID}" = "centos" ] && pm="yum"
            [ "${ID}" = "fedora" ] && pm="dnf"
        else
            echo "Unsupported distribution!"
            exit 1
        fi
    else
        echo "Unsupported distribution!"
        exit 1
    fi
}

# Install necessary packages
install_dependencies() {
    detect_distribution
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

install_warp() {
    echo "======================================"
    echo "Installing Cloudflare WARP..."
    echo "======================================"
    
    if command -v warp-cli &> /dev/null; then
        echo "WARP is already installed."
        read -p "Do you want to reconfigure WARP? (y/n): " reconfigure
        if [[ ! "$reconfigure" =~ ^[Yy]$ ]]; then
            return 0
        fi
    else
        echo "Adding Cloudflare WARP repository..."
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
        
        echo "Updating package list..."
        apt update
        
        echo "Installing cloudflare-warp..."
        apt install -y cloudflare-warp
        
        if ! command -v warp-cli &> /dev/null; then
            echo "ERROR: WARP installation failed!"
            return 1
        fi
    fi
    
    echo ""
    echo "======================================"
    echo "Configuring WARP..."
    echo "======================================"
    
    systemctl enable --now warp-svc
    sleep 2
    
    warp-cli registration delete &> /dev/null
    warp-cli registration new
    
    if [ $? -ne 0 ]; then
        echo "ERROR: WARP registration failed!"
        return 1
    fi
    
    echo ""
    while true; do
        read -p "Please enter your WARP license key: " warp_license
        
        if [ -z "$warp_license" ]; then
            echo "ERROR: License key cannot be empty!"
            continue
        fi
        
        echo "Applying license key..."
        warp-cli registration license "$warp_license"
        
        if [ $? -eq 0 ]; then
            echo "License applied successfully!"
            break
        else
            echo "ERROR: Invalid license key or registration failed!"
            read -p "Do you want to try again? (y/n): " retry
            if [[ ! "$retry" =~ ^[Yy]$ ]]; then
                echo "WARP configuration cancelled."
                return 1
            fi
        fi
    done
    
    echo ""
    echo "Configuring WARP proxy mode on port 40000..."
    
    warp-cli disconnect &> /dev/null
    sleep 1
    
    warp-cli mode proxy
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to set proxy mode!"
        return 1
    fi
    
    warp-cli proxy port 40000
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to set proxy port!"
        return 1
    fi
    
    echo "Connecting to WARP..."
    warp-cli connect
    sleep 3
    
    echo ""
    echo "======================================"
    echo "WARP Status:"
    echo "======================================"
    warp-cli status
    
    echo ""
    echo "Checking if port 40000 is listening..."
    if ss -ltnp | grep -q 40000 || netstat -plant 2>/dev/null | grep -q 40000; then
        echo "SUCCESS: WARP proxy is listening on port 40000"
        echo ""
        echo "You can use SOCKS5 proxy: socks5://127.0.0.1:40000"
        return 0
    else
        echo "WARNING: Port 40000 is not listening yet. Please wait a moment and check with:"
        echo "  ss -ltnp | grep 40000"
        return 0
    fi
}

#install
install() {
    if systemctl is-active --quiet sni.service; then
        echo "The SNI service is already installed and active."
    else
        install_dependencies
        myip=$(hostname -I | awk '{print $1}')
        git clone https://github.com/smaghili/smartSNIP.git /root/smartSNI

        clear
        read -p "Enter your domain: " domain
        read -p "Enter the domain names separated by commas (example: google,youtube): " site_list
        
        # Save to config.json
        myip=$(hostname -I | awk '{print $1}')
        echo "{" > /root/smartSNI/config.json
        echo "  \"host\": \"$domain\"," >> /root/smartSNI/config.json
        echo "  \"domains\": {" >> /root/smartSNI/config.json
        
        IFS=',' read -ra sites <<< "$site_list"
        site_count=${#sites[@]}
        counter=0
        for site in "${sites[@]}"; do
            counter=$((counter + 1))
            if [ $counter -eq $site_count ]; then
                echo "    \"$site\": \"$myip\"" >> /root/smartSNI/config.json
            else
                echo "    \"$site\": \"$myip\"," >> /root/smartSNI/config.json
            fi
        done
        
        echo "  }" >> /root/smartSNI/config.json
        echo "}" >> /root/smartSNI/config.json

        nginx_conf="/etc/nginx/sites-enabled/default"
        sed -i "s/server_name _;/server_name $domain;/g" "$nginx_conf"
        sed -i "s/<YOUR_HOST>/$domain/g" /root/smartSNI/nginx.conf

        # Obtain SSL certificates
        certbot --nginx -d $domain --register-unsafely-without-email --non-interactive --agree-tos --redirect

        # Copy config
        sudo cp /root/smartSNI/nginx.conf "$nginx_conf"

        # Stop and restart nginx
        systemctl stop nginx
        systemctl restart nginx

        # Install Python dependencies
        cd /root/smartSNI
        pip3 install --break-system-packages -r requirements.txt 2>/dev/null || \
        pip3 install --user -r requirements.txt 2>/dev/null || \
        pip3 install -r requirements.txt

        # Install and configure WARP
        echo ""
        read -p "Do you want to install Cloudflare WARP proxy? (y/n): " install_warp_choice
        if [[ "$install_warp_choice" =~ ^[Yy]$ ]]; then
            install_warp
            if [ $? -ne 0 ]; then
                echo "WARNING: WARP installation failed but continuing with SNI setup..."
            fi
        else
            echo "Skipping WARP installation."
        fi

        # Create systemd service file
        cat > /etc/systemd/system/sni.service <<EOL
[Unit]
Description=Smart SNI Service

[Service]
User=root
WorkingDirectory=/root/smartSNI
ExecStart=/usr/bin/python3 main.py
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=default.target
EOL

        # Reload systemd, enable and start the service
        systemctl daemon-reload
        systemctl enable sni.service
        systemctl start sni.service

        # Check if the service is active
        if systemctl is-active --quiet sni.service; then
            echo "The SNI service is now active."
        else
            echo "The SNI service is not active."
        fi
    fi
}

# Uninstall function
uninstall() {
    # Check if the service is installed
    if [ ! -f "/etc/systemd/system/sni.service" ]; then
        echo "The service is not installed."
        return
    fi
    # Stop and disable the service
    sudo systemctl stop sni.service
    sudo systemctl disable sni.service

    # Remove service file
    sudo rm /etc/systemd/system/sni.service
    echo "Uninstallation completed successfully."
}

manage_warp() {
    clear
    echo "======================================"
    echo "WARP Management"
    echo "======================================"
    
    if ! command -v warp-cli &> /dev/null; then
        echo "WARP is not installed."
        read -p "Do you want to install it now? (y/n): " install_choice
        if [[ "$install_choice" =~ ^[Yy]$ ]]; then
            install_warp
        fi
        return
    fi
    
    echo "1) Install/Reconfigure WARP"
    echo "2) Check WARP Status"
    echo "3) Connect WARP"
    echo "4) Disconnect WARP"
    echo "5) Restart WARP Service"
    echo "6) Uninstall WARP"
    echo "0) Back to Main Menu"
    echo ""
    read -p "Enter your choice: " warp_choice
    
    case "$warp_choice" in
        1)
            install_warp
            ;;
        2)
            echo ""
            echo "======================================"
            warp-cli status
            echo "======================================"
            echo ""
            echo "Checking port 40000..."
            ss -ltnp | grep 40000 || echo "Port 40000 is not listening"
            ;;
        3)
            warp-cli connect
            echo "WARP connected."
            sleep 2
            warp-cli status
            ;;
        4)
            warp-cli disconnect
            echo "WARP disconnected."
            ;;
        5)
            systemctl restart warp-svc
            sleep 2
            echo "WARP service restarted."
            warp-cli status
            ;;
        6)
            read -p "Are you sure you want to uninstall WARP? (y/n): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                warp-cli disconnect &> /dev/null
                systemctl stop warp-svc
                systemctl disable warp-svc
                apt remove -y cloudflare-warp
                rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
                rm -f /etc/apt/sources.list.d/cloudflare-client.list
                echo "WARP uninstalled successfully."
            fi
            ;;
        0)
            return
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
    manage_warp
}

display_sites() {
    config_file="/root/smartSNI/config.json"

    if [ -d "/root/smartSNI" ]; then
        if [ -f "$config_file" ]; then
            echo "Current configuration in $config_file:"
            echo "---------------------"
            cat "$config_file"
            echo "---------------------"
        else
            echo "No config file found."
        fi
    else
        echo "Error: smartSNI directory not found. Please Install first."
    fi
}

check() {
    if systemctl is-active --quiet sni.service; then
        echo "[Service Is Active]"
    else
        echo "[Service Is Not active]"
    fi
}


clear
echo "By --> Seyed * Github.com/smaghili * "
echo "--*-* SMART SNI PROXY *-*--"
echo ""
echo "Select an option:"
echo "1) Install"
echo "2) Uninstall"
echo "---------------------------"
echo "3) Show Sites"
echo "4) Manage WARP Proxy"
echo "0) Exit"
echo "----$(check)----"
read -p "Enter your choice: " choice
case "$choice" in
    1)
        install
        ;;
    2)
        uninstall
        ;;
    3) 
        display_sites
        ;;
    4)
        manage_warp
        ;;
    0)   
        exit
        ;;
    *)
        echo "Invalid choice. Please select a valid option."
        ;;
esac