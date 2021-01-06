#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

check_OS() {
  if [[ -f /etc/lsb-release ]]; then
    return 0
  elif grep -Eqi "debian|raspbian" /etc/issue; then
    return 0
  elif grep -Eqi "ubuntu" /etc/issue; then
    return 0
  elif grep -Eqi "debian|raspbian" /proc/version; then
    return 0
  elif grep -Eqi "ubuntu" /proc/version; then
    return 0
  else
    return 1
  fi
}

error_detect_depends() {
  local command=$1
  local depend=$(echo "${command}" | awk '{print $4}')
  echo -e "[${green}Info${plain}] Starting to install package ${depend}"
  ${command} >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
    exit 1
  fi
}

config_firewall() {
  # If system has a single ethernet interface, then it will be selected automatically
  if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
    eth=$(ip -4 addr | grep -w inet | grep -vE '127(\.[0-9]{1,3}){3}' | awk '{ print $7}')
    ip_prefix=$(ip -4 addr | grep -w inet | grep -vE '127(\.[0-9]{1,3}){3}' | awk '{ print $2}' | cut -f 1)
  else
    # Else, ask to user
    number_of_eth=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
    echo
    echo "Which ethernet interface should be used?"
    ip -4 addr | grep -w inet | grep -vE '127(\.[0-9]{1,3}){3}' | awk '{ print $7 " " $2}' | nl -s ') '
    read -p "Ethernet interface [1]: " eth_number
    until [[ -z "$eth_number" || "$eth_number" =~ ^[0-9]+$ && "$eth_number" -le "$number_of_eth" ]]; do
      echo "$eth_number: invalid selection."
      read -p "Ethernet interface [1]: " eth_number
    done
    [[ -z "$eth_number" ]] && eth_number="1"
    eth=$(ip -4 addr | grep -w inet | grep -vE '127(\.[0-9]{1,3}){3}' | awk '{ print $7}' | sed -n "$eth_number"p)
    ip_prefix=$(ip -4 addr | grep -w inet | grep -vE '127(\.[0-9]{1,3}){3}' | awk '{ print $2}' | cut -f 1 | sed -n "$eth_number"p)
  fi

  # Forward
  grep -qxF 'net.ipv4.ip_forward = 1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward = 1' >>/etc/sysctl.conf
  sysctl -p >/dev/null

  # Flush
  iptables -t nat -F
  iptables -t mangle -F
  iptables -F
  iptables -X

  # Block All
  iptables -P OUTPUT DROP
  iptables -P INPUT DROP
  iptables -P FORWARD DROP

  # Allow Localhost
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  # Make sure you can communicate with any DHCP server
  iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT
  iptables -A INPUT -s 255.255.255.255 -j ACCEPT

  # Make sure that you can communicate within your own network
  iptables -A INPUT -s $ip_prefix -d $ip_prefix -j ACCEPT
  iptables -A OUTPUT -s $ip_prefix -d $ip_prefix -j ACCEPT

  # Allow established sessions to receive traffic:
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Allow TUN
  iptables -A INPUT -i tun+ -j ACCEPT
  iptables -A FORWARD -i tun+ -j ACCEPT
  iptables -A FORWARD -o tun+ -j ACCEPT
  iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
  iptables -A OUTPUT -o tun+ -j ACCEPT

  # Allow DNS connection
  iptables -I OUTPUT 1 -p udp --dport 53 -m comment --comment "Allow DNS UDP" -j ACCEPT
  iptables -I OUTPUT 2 -p tcp --dport 53 -m comment --comment "Allow DNS TCP" -j ACCEPT

  # Allow NTP connection
  iptables -I OUTPUT 3 -p udp --dport 123 -m comment --comment "Allow NTP" -j ACCEPT

  # Allow VPN connection
  iptables -I OUTPUT 4 -p udp --dport 1194 -m comment --comment "Allow VPN UDP" -j ACCEPT
  iptables -I OUTPUT 5 -p tcp --dport 1194 -m comment --comment "Allow VPN TCP" -j ACCEPT

  # Block All
  iptables -A OUTPUT -j DROP
  iptables -A INPUT -j DROP
  iptables -A FORWARD -j DROP

  # Log all dropped packages, debug only.
  iptables -N logging
  iptables -A INPUT -j logging
  iptables -A OUTPUT -j logging
  iptables -A logging -m limit --limit 2/min -j LOG --log-prefix "IPTables general: " --log-level 7
  iptables -A logging -j DROP

  # Iptable persistent
  netfilter-persistent save
  systemctl enable netfilter-persistent
}

config_openvpn() {
  echo
  echo -e "${yellow}Please enter your .ovpn|.conf file path${plain}"
  read -p "Path [/home/ubuntu/usa.ovpn]: " path
  until [[ -f $path ]]; do
    echo -e "[${red}Error${plain}] $path does not exist"
    read -p "Path [/home/ubuntu/usa.ovpn]: " path
  done
  # local profile=$(basename -- "$path")
  # local profile="${profile%.*}"
  # cp $path /etc/openvpn/$profile.conf

  # Remove default.conf file if exist
  if [[ -f /etc/openvpn/default.conf ]]; then
    rm -f /etc/openvpn/default.conf
  fi
  cp $path /etc/openvpn/default.conf
  echo
  echo -e "${yellow}Is OpenVPN profile requires authentication?${plain}"
  read -p "[y/N]: " isAuthReq
  until [[ "$isAuthReq" =~ ^[yYnN]*$ ]]; do
    echo "$isAuthReq: invalid selection."
    read -p "[y/N]: " isAuthReq
  done
  if [[ "$isAuthReq" =~ ^[yY]$ ]]; then
    echo
    echo -e "${yellow}Please enter openvpn username${plain}"
    read -p "User [admin]: " user
    until [[ ! "$user" = "" ]]; do
      echo "Cannot be blank please try again!"
      read -p "User [admin]: " user
    done
    echo
    echo -e "${yellow}Please enter openvpn password${plain}"
    read -p "Password [mypass]: " password
    until [[ ! "$password" = "" ]]; do
      echo "Cannot be blank please try again!"
      read -p "Password [mypass]: " password
    done
    # Remove auth file if exist
    if [[ -f /etc/openvpn/auth ]]; then
      rm -f /etc/openvpn/auth
    fi
    # Create auth file
    echo "$user
$password" >/etc/openvpn/auth
    # File permission
    chmod 600 /etc/openvpn/auth
    # Append auth file to openvpn profile
    sed -i 's|auth-user-pass|auth-user-pass /etc/openvpn/auth|g' /etc/openvpn/default.conf
  fi
  # Append log file to openvpn profile
  sed -i -e '$alog /var/log/openvpn.log' /etc/openvpn/default.conf
  # Connect openvpn
  openvpn --client --config /etc/openvpn/default.conf --daemon
}

install_openvpn() {
  error_detect_depends "apt-get update -y"
  error_detect_depends "apt-get -y install ntp"
  error_detect_depends "apt-get -y install openvpn"
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
  error_detect_depends "apt-get -y install iptables-persistent"
  config_firewall
  config_openvpn
  echo
  echo -e "[${green}Info${plain}] OpenVPN Gateway setup has been completed. Now change other devices default Gateway and DNS."
}

install_dnsmasq() {
  echo
  echo -e "[${green}Info${plain}] Select a DNS server"
  echo "   1) 1.1.1.1"
  echo "   2) Google"
  echo "   3) OpenDNS"
  echo "   4) Quad9"
  echo "   5) AdGuard"
  read -p "DNS server [1]: " dns
  until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
    echo "$dns: invalid selection."
    read -p "DNS server [1]: " dns
  done

  echo -e "[${green}Info${plain}] Disabling systemd-resolved"
  systemctl disable systemd-resolved
  systemctl stop systemd-resolved

  echo -e "[${green}Info${plain}] Reset resolv"
  echo "nameserver 8.8.8.8" >/etc/resolv.conf

  error_detect_depends "apt install -y dnsmasq"

  echo -e "[${green}Info${plain}] Config dnsmasq"
  cp /etc/dnsmasq.conf /etc/dnsmasq.conf.original
  rm -f /etc/dnsmasq.conf
  echo "port=53
domain-needed
bogus-priv
strict-order" >/etc/dnsmasq.conf
  echo -e "[${green}Info${plain}] Config resolv"
  rm -f /etc/resolv.conf
  # DNS
  case "$dns" in
  1 | "")
    echo "nameserver 127.0.0.1
nameserver 1.1.1.1
nameserver 1.0.0.1" >/etc/resolv.conf
    ;;
  2)
    echo "nameserver 127.0.0.1
nameserver 8.8.8.8
nameserver 8.8.4.4" >/etc/resolv.conf
    ;;
  3)
    echo "nameserver 127.0.0.1
nameserver 208.67.222.222
nameserver 208.67.220.220" >/etc/resolv.conf
    ;;
  4)
    echo "nameserver 127.0.0.1
nameserver 9.9.9.9
nameserver 149.112.112.112" >/etc/resolv.conf
    ;;
  5)
    echo "nameserver 127.0.0.1
nameserver 94.140.14.14
nameserver 94.140.15.15" >/etc/resolv.conf
    ;;
  esac

  echo -e "[${green}Info${plain}] Restart dnsmasq service"
  systemctl restart dnsmasq
}

uninstall_openvpn_gateway() {
  killall openvpn && killall openvpn && killall openvpn
  apt remove --purge -y iptables-persistent
  apt remove --purge -y openvpn
  apt remove --purge -y dnsmasq
  apt autoremove -y
  rm -rf /etc/openvpn
  rm -rf /etc/dnsmasq
  echo -e "[${green}Info${plain}] OpenVPN Gateway has been uninstalled. Please reboot your server."
}

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] Please run as root user to execute the script!" && exit 1

check_OS ||
  {
    echo -e "[${red}Error${plain}] This script can be run only on Ubuntu|Debian OS"
    exit 1
  }

if [[ ! -d /etc/openvpn ]]; then
  clear
  echo
  echo 'Welcome to OpenVPN Gateway installer!!!'
  echo
  install_dnsmasq
  install_openvpn
else
  clear
  echo
  echo "OpenVPN is already installed."
  echo
  echo "Select an option:"
  echo "   1) Connect OpenVPN"
  echo "   2) Change OpenVPN Profile"
  echo "   3) Disconnect OpenVPN"
  echo "   4) OpenVPN Log"
  echo "   5) Uninstall OpenVPN Gatway"
  echo "   6) Exit"
  read -p "Option: " option
  until [[ "$option" =~ ^[1-5]$ ]]; do
    echo "$option: invalid selection."
    read -p "Option: " option
  done
  case "$option" in
  1)
    openvpn --client --config /etc/openvpn/default.conf --daemon
    ;;
  2)
    killall openvpn && killall openvpn && killall openvpn
    config_openvpn
    ;;
  3)
    killall openvpn && killall openvpn && killall openvpn
    ;;
  4)
    clear
    tail -f /var/log/openvpn.log
    ;;
  5)
    uninstall_openvpn_gateway
    ;;
  5)
    exit
    ;;
  esac
fi
