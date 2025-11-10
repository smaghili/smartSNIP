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
    local packages=("nginx" "git" "jq" "certbot" "python3-certbot-nginx" "python3" "python3-pip")
    
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

#install
install() {
    if systemctl is-active --quiet sni.service; then
        echo "The SNI service is already installed and active."
    else
        install_dependencies
        myip=$(hostname -I | awk '{print $1}')
        git clone https://github.com/bepass-org/smartSNI.git /root/smartSNI

        clear
        read -p "Enter your domain: " domain
        read -p "Enter the domain names separated by commas (example: google,youtube): " site_list
        
        # Save to domains.txt (just domain list, hostname is auto-detected)
        > /root/smartSNI/domains.txt
        IFS=',' read -ra sites <<< "$site_list"
        for site in "${sites[@]}"; do
            echo "$site" >> /root/smartSNI/domains.txt
        done

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
        pip3 install -r requirements.txt

        # Create systemd service file
        cat > /etc/systemd/system/sni.service <<EOL
[Unit]
Description=Smart SNI Service

[Service]
User=root
WorkingDirectory=/root/smartSNI
ExecStart=/usr/bin/python3 main.py
Restart=always

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

display_sites() {
    domains_file="/root/smartSNI/domains.txt"

    if [ -d "/root/smartSNI" ]; then
        if [ -f "$domains_file" ]; then
            echo "Current list of sites in $domains_file:"
            echo "---------------------"
            cat "$domains_file"
            echo "---------------------"
        else
            echo "No domains file found."
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
echo "By --> Peyman * Github.com/Ptechgithub * "
echo "--*-* SMART SNI PROXY *-*--"
echo ""
echo "Select an option:"
echo "1) Install"
echo "2) Uninstall"
echo "---------------------------"
echo "3) Show Sites"
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
    0)   
        exit
        ;;
    *)
        echo "Invalid choice. Please select a valid option."
        ;;
esac
