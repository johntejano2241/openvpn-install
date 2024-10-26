#!/bin/bash

# https://github.com/Nyr/openvpn-install
# Modified to add user and expiration management
# Copyright (c) 2013 Nyr. Released under the MIT License.

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'This installer needs to be run with "bash", not "sh".'
    exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
    echo "The system is running an old kernel, which is incompatible with this installer."
    exit
fi

# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    os="centos"
    os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    group_name="nobody"
else
    echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
    exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
    echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
    exit
fi

if [[ "$os" == "debian" ]]; then
    if grep -q '/sid' /etc/debian_version; then
        echo "Debian Testing and Debian Unstable are unsupported by this installer."
        exit
    fi
    if [[ "$os_version" -lt 9 ]]; then
        echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
        exit
    fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
    echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
    exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
    echo '$PATH does not include sbin. Try using "su -" instead of "su".'
    exit
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "This installer needs to be run with superuser privileges."
    exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
    exit
fi

new_client () {
    # Generates the custom client.ovpn
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
    } > ~/"$client".ovpn
}

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

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
    # Existing code for installation process
    # ...

    # Prompt to add a user
    add_user
fi

# Update the existing function for adding a new client
if [[ "$option" == "1" ]]; then
    add_user
fi

# Schedule the deletion of expired users via cron job
(crontab -l ; echo "0 0 * * * $(realpath $0) delete_expired_users") | crontab -
