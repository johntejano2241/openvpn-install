#!/bin/bash

# OpenVPN installation and configuration script for Ubuntu
# with user and password authentication and expiration management

# Function to add a user with an expiration date
add_user() {
    read -p "Enter username: " username
    read -s -p "Enter password: " password
    echo
    read -p "Enter expiration days: " exp_days

    # Add the user with an expiration date
    useradd -e $(date -d "$exp_days days" +"%Y-%m-%d") -M -s /bin/false "$username"
    echo "$username:$password" | chpasswd

    # Add user to OpenVPN client config
    echo "username \"$username\"" >> /etc/openvpn/server/client-common.txt
    echo "password \"$password\"" >> /etc/openvpn/server/client-common.txt

    echo "$username added with expiration in $exp_days days."
}

# Function to delete expired users
delete_expired_users() {
    today=$(date +"%Y-%m-%d")
    for user in $(awk -F: '{ if ($2 != "*" && $2 != "!" && $8 != "" && $8 <= "'$today'") print $1 }' /etc/shadow); do
        userdel -r $user
        echo "$user has been deleted (expired)."
    done
}

# Function to create a new client configuration file
new_client() {
    client=$1
    {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
    } > /"$client".ovpn
}

# Main installation function
install_openvpn() {
    # Update and install necessary packages
    apt-get update
    apt-get install -y openvpn easy-rsa

    # Setup Easy-RSA
    make-cadir ~/openvpn-ca
    cd ~/openvpn-ca

    # Generate server certificates and keys
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server
    ./easyrsa gen-dh
    openvpn --genkey --secret ta.key

    # Move generated files
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/dh.pem ta.key /etc/openvpn/server

    # Generate client configuration template
    cat > /etc/openvpn/server/client-common.txt <<EOF
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-client
tls-auth /etc/openvpn/server/ta.key 1
cipher AES-256-CBC
auth SHA256
comp-lzo
verb 3
EOF

    # Enable and start OpenVPN service
    systemctl enable openvpn-server@server.service
    systemctl start openvpn-server@server.service

    # Prompt to add a user
    add_user
    new_client "$username"
}

# Execute the installation
if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root"
    exit 1
fi

install_openvpn

# Schedule the deletion of expired users via cron job
(crontab -l ; echo "0 0 * * * $(realpath $0) delete_expired_users") | crontab -
