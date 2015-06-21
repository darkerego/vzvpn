# vzvpn
Firewall (iptables) script for openvpn servers inside openvz containers, customized especially for servers running 
dnscrypt-proxy to serve DNS for the clients. You must edit the variables section to reflect your own server's 
configuration. By default the script will configure rules for OpenVPN to function, incoming SSH (I recommend that you limit SSH connections to from within the VPN, save for one static IP in case the VPN goes down. You can change this if it's not desirable), apache2; accesable only from the internal VPN, dnscrypt-proxy, and a DNS cache program like Unbound or DNSMasq, because dnscrypt-proxy does not allow connections other than from the localhost. There are some other preconfigured services that i left commented out as examples for writing your own rules.

# License

Feel free to use, modify, redistribute, or otherwise do whatever you want with this script. I only ask that you give the authors credit, as per the GPL licenes. 
