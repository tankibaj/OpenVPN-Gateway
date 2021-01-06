A VPN (Virtual Private Network) secures your privacy by routing all your internet traffic through an encrypted tunnel to a VPN server that your ISP (or other prying eyes) can't see.

Setting up and using VPN service on PC is straightforward enough, but if you want to use VPN service on other devices in your homes such as Smartphones, Smart TV, and Game Console, you have to set up and manage them individually. Sometimes devices can drop VPN connections and route traffic through unencrypted tracks. It's challenging to monitor all devices 24/7.

So what is the solution?
1) You could buy a powerful VPN router that can handle all of your home network traffic and protect privacy in a single stroke.
2) Or you could install Ubuntu 18.04 LTS on your old Laptop/Desktop to use it as a home network VPN Gateway and remains connected to the VPN at all times.

To me, solution two is more simplistic and affordable. So I wrote this simple script to turn your old Laptop/Desktop into VPN Gateway and Kill Switch. It will only allow VPN traffic. If your VPN connection becomes unstable or drops, your entire network connection will be blocked to guard privacy.



### Prerequisite

1. Ubuntu 18.04 LTS (Server|Desktop).
2. Static IP (Please configure it before running the installer).
3. VPN Subscription (OpenVPN supported).
4. OpenVPN Profile (.ovpn | .conf extension file).
5. OpenVPN Authentication (That provided by VPN provider).



### Installation

```bash
wget -O OpenVPN_Gateway_Installer.sh https://git.io/JLAUi && sudo bash OpenVPN_Gateway_Installer.sh
```



### How To Use

Now your VPN Gateway is ready to use. Change other device default gateway to whatever IP Address your VPN Gateway has. To prevent DNS leaks and ensure all your DNS goes through the VPN tunnel, you could use it as a DNS server.

Just keep in mind your internet connection's speed might get slow. It depends on the VPN provider and your selected VPN server latency.
