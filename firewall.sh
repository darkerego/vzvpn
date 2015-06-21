#!/bin/bash
# A linux iptables script for openvpn servers running inside openvz containers with restricted kernels, 
# with multiple IP addresses, OpenVPN, dnscrypt-proxy to server the clients, and maybe some other VPN reachable
# services. Inside openvz CT's we cannot referance interfaces like a physical server (ie: '-i eth1')
# so intead we use -i venet0 -d your.ip.addrs.here, we also use source routing instead of masquerading.
# Thanks to Cyberbiz/nixCraft for the original fw template!
# -------------------------------------------------------------------------
# Copyright (c) 2004 nixCraft project <http://cyberciti.biz/fb/>
# This script is licensed under GNU GPL version 2.0 or above
# -------------------------------------------------------------------------
# Author : Darkerego, 2015 <https://the-resistance.net> - GPL Liscense :
# Modify, redistribute, do whatever but please give credit to the authors!
#--------------------------------------------------------------------------
IPT="/sbin/iptables"
SPAMLIST="blockedip"
SPAMDROPMSG="BLOCKED IP DROP"

echo "Starting IPv4 Wall..."
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

[ -f /root/scripts/blocked.ips.txt ] && BADIPS=$(egrep -v -E "^#|^$" /root/scripts/blocked.ips.txt)
#### Define Constants ####
VPN_IF="tun+"
VPN_PRT="1194"
SSH_PRT="22555"
EXTIF="venet0"
EXTIP="1.2.3.4"
OUTIP="5.4.3.2"
VPN_SN="10.9.0.0/24"
VPNSRVR="10.9.0.1"
DNS_1="208.67.222.222"
DNS_2="208.67.220.220"
staticIP="x.x.x.x" # Limit SSH to one static IP
#### Log Messages ####
logSSI="Dropped Incoming source spoof!"
logSSO="Dropped Outgoing soure spoof!"
logDNSC="Dropped invalid from dnscrypt!"
logFW="Invalid FWD packet"
logIO="Dropped incoming on $OUTIP"
logTMS="Transmission-Daemon"
loghttp="Dropped invalid apache"
logHNY="Honey Pot Break?"
logUNPN="UPNP Traffic"
########################
# Allow local connections
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
# Log&Drop Source Spoofing
$IPT -A INPUT -s $EXTIP -j LOG --log-prefix "$logSSI"
$IPT -A INPUT -s $EXTIP -j DROP
$IPT -A OUTPUT -d $EXTIP -j LOG --log-prefix "$logSSO"
$IPT -A OUTPUT -d $EXTIP -j DROP
$IPT -A INPUT -s $OUTIP -j LOG --log-prefix "$logSSI"
$IPT -A INPUT -s $OUTIP -j DROP
$IPT -A OUTPUT -d $OUTIP -j LOG --log-prefix "$logSSO"
$IPT -A OUTPUT -d $OUTIP -j DROP
# Stop  floods
$IPT -N flood
$IPT -A INPUT -p tcp --syn -j flood
$IPT -A flood -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPT -A flood -j DROP
# DROP all incomming traffic
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

if [ -f /root/scripts/blocked.ips.txt ];
then
# create a new iptables list
  $IPT -N $SPAMLIST

for ipblock in $BADIPS
do
  $IPT -A $SPAMLIST -s $ipblock -j LOG --log-prefix "$SPAMDROPMSG"
  $IPT -A $SPAMLIST -s $ipblock -j DROP
done

  $IPT -I INPUT -j $SPAMLIST
  $IPT -I OUTPUT -j $SPAMLIST
  $IPT -I FORWARD -j $SPAMLIST
fi

# Block sync
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync"
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Block Fragments
$IPT -A INPUT -f -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"
$IPT -A INPUT -f -j DROP

# Block bad stuff
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets"
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets"
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS
$IPT -A INPUT -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan"
$IPT -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scans
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP


# Allow full outgoing connection but no incomming stuff
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#

#### Kippo Honeypot (Can't say I recommend this) ####
#$IPT -A FORWARD -i venet0 -d $EXTIP -p tcp --dport 22 -m state --state NEW -j ACCEPT
#$IPT -t nat -A PREROUTING -p tcp -d $EXTIP --dport 22 -j REDIRECT --to-ports 2222
#$IPT -A INPUT -i venet0 -d $EXTIP -p tcp --dport 2222 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -o venet0 -p tcp --sport 2222 -m owner --uid-owner kippo -m state --state RELATED,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -m owner --uid-owner kippo -j LOG --log-prefix "logHNY"
#$IPT -A OUTPUT -m owner --uid-owner kippo -j REJECT

# allow incomming ICMP ping pong stuff
$IPT -A INPUT -i venet0 -d  $EXTIP -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT
#### VPN ####
$IPT -A INPUT -i venet0 -d $EXTIP -p udp -m udp --dport $VPN_PRT -j ACCEPT
$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --dport $VPN_PRT -j ACCEPT

## Port Forwarding From Server Public IP to a VPN Client ##
fwd_EN="false" # Change to 'true' to enable
ext_if="venet0" # 
int_if="tun0" # 
int_ip="10.9.0.6" # client to forward to
int_PRT="8080" # port to forward

if [[ $fwd_EN == "true" ]]; then

  echo Warning: Port Forwarding enabled

  $IPT -t nat -A PREROUTING -p tcp -i $ext_if --dport $int_PRT -j DNAT --to-dest $int_ip:$int_PRT
  $IPT -A FORWARD -p tcp -i $ext_if -o $int_if -d $int_ip --dport $int_PRT -m state --state NEW -j ACCEPT
  $IPT -A FORWARD -i $ext_if -o $int_if -d $int_ip -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IPT -A FORWARD -i $int_if -s $int_ip -o $ext_if -m state --state ESTABLISHED,RELATED -j ACCEPT

else 
  echo Info: Port Forwarding Disabled
fi

#### Incoming Services ####
## SSH
$IPT -A INPUT -i venet0 -s $staticIP -d $EXTIP -p tcp -m tcp --dport $SSH_PRT -j ACCEPT
$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $SSH_PRT -j ACCEPT
# Add Your Own Rules Here, see example below:

#### Transmission Peer Port (not necessary)
#$IPT -A INPUT -i venet0 -p tcp --dport 51413 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
#$IPT -A INPUT -i venet0 -p udp --dport 51413 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

####### VPN REACHABLE SERVICES ####
# Add your own rules here. Some example common services below:

#### Transmission Web ####
#$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport 9091 -j ACCEPT
#$IPT -A OUTPUT -o tun+ -s $VPNSRVR -d $VPN_SN -p tcp --sport 9091 -m owner --uid-owner debian-transmission -j ACCEPT
#$IPT -A OUTPUT -o tun+ -d $VPN_SN -m owner --uid-owner debian-transmission -j LOG --log-prefix "$logTMS"
#$IPT -A OUTPUT -o tun+ -d $VPN_SN -m owner --uid-owner debian-transmission -j REJECT
#### Apache (Serving VPN clients only) ####
$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport 80 -j ACCEPT
$IPT -A OUTPUT -o tun+ -s $VPNSRVR -d $VPN_SN -p tcp --sport 80 -j ACCEPT
$IPT -A OUTPUT -o tun+ -m owner --uid-owner www-data -j LOG --log-prefix "$loghttp"
$IPT -A OUTPUT -o tun+ -m owner --uid-owner www-data -j REJECT
#### Tor/Privoxy (run Tor in a chroot)
#$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport 8118 -j ACCEPT
#$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport 9050 -j ACCEPT
# Allow port 53 tcp/udp (Dnsmasq/Unbound)
$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp --destination-port 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#### DNSCRYPT/VPN (limit to 443/udp @ resolver) ####
$IPT -A OUTPUT -p udp -m owner --uid-owner dnscrypt -m udp -d $DNS_1 --sport 1024:65535 --dport 443 -j ACCEPT
$IPT -A OUTPUT -p udp -m owner --uid-owner dnscrypt -m udp -d $DNS_2 --sport 1024:65535 --dport 443 -j ACCEPT
$IPT -A OUTPUT -m owner --uid-owner dnscrypt -j LOG --log-prefix "$logDNSC"
$IPT -A OUTPUT -m owner --uid-owner dnscrypt -j DROP
#### VPN TUNNEL ####
$IPT -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT -A FORWARD -s $VPN_SN -j ACCEPT
$IPT -A FORWARD -j LOG --log-prefix "$logFW"
$IPT -A FORWARD -j REJECT
$IPT -t nat -A POSTROUTING  -s $VPN_SN -o venet0 -j SNAT --to-source $OUTIP
# Drop incoming traffic on outgoing IP 
$IPT -A INPUT -i venet0 -d $OUTIP -j LOG --log-level 4 --log-prefix "$logIO"
$IPT -A INPUT -i venet0 -d $OUTIP -j DROP
# Drop Windows BS
$IPT -A INPUT -p tcp -i venet0 -d $EXTIP --dport 137:139 -j DROP
$IPT -A INPUT -p udp -i venet0 -d $EXTIP --dport 137:139 -j DROP
$IPT -A INPUT -p udp -i venet0 -d $EXTIP --dport 445 -j DROP
# Log UPNP Packets
$IPT -A INPUT -p udp --dport 1900 -j LOG --log-prefix "$logUNPN "
# log everything else and drop
$IPT -A INPUT -j LOG
$IPT -A FORWARD -j LOG
$IPT -A INPUT -j DROP
exit 0
