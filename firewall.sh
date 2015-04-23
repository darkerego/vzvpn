#!/bin/bash
# A linux iptables script for openvpn servers running inside openvz containers with restricted kernels.
# Inside openvz we cannot referance interfaces like a physical server (ie: '-i eth1')
# so intead we use -i venet0 -d your.ip.addrs.here, we also use source routing
# instead of masquerading for the vpn.
# 
# Credits to author of original script:
# -------------------------------------------------------------------------
# Copyright (c) 2004 nixCraft project <http://cyberciti.biz/fb/>
# This script is licensed under GNU GPL version 2.0 or above
# -------------------------------------------------------------------------
# Modified by Darkerego for OpenVPN servers inside OpenVZ containers
# 
#
IPT="/sbin/iptables" # Point to iptables
#IPT6="/sbin/ip6tables" # Ip6tables, if you need them
SPAMLIST="blockedip" # List of blocked IPs if applicable
SPAMDROPMSG="BLOCKED IP DROP" # Log with

# Variables to make life easier
# Edit the ports yourself

in_IP=1.2.3.4 # interace of ip openvpn listens on
out_IP=4.3.2.1 # interface of outgoing ip

vpn_IF="tun+" # tun/tap interface of vpn


in_ITF="-i venet0 -d $in_IP" # Because in openvz we cannot use eth0/eth1,
				# we use destination IP as a workaround

alt_IN="-i venet0 -d $out_IP" # Incoming services on 2nd (outgoing) ip




vpn_SN1="10.8.0.0/24" # subnet mask of vpn(s)
vpn_SN2="10.9.0.0/24"

vpn_IN1="-i vpnIF -s vpn_SN1"
vpn_IN2="-i vpnIF -s vpn_SN2"

echo "Starting IPv4 Wall..." 
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
#modprobe ip_conntrack

[ -f /root/scripts/blocked.ips.txt ] && BADIPS=$(egrep -v -E "^#|^$" /root/scripts/blocked.ips.txt)



#unlimited
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

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
 
# Block sync on all interfaces
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync"
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
 
# Block Fragments on all interfaces

$IPT -A INPUT -f -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"
$IPT -A INPUT -f -j DROP
 
# Block bad stuff on all interfaces

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

######## Incoming Services ########

#### SSH ####
$IPT -A INPUT $in_ITF -p tcp -m tcp --dport 22 -j ACCEPT

#### VPN  ####
$IPT -A INPUT $in_ITF -p udp -m udp --dport 1194 -j ACCEPT
$IPT -A INPUT $in_ITF -p tcp -m tcp --dport 1194 -j ACCEPT

#### TCP VPN ####

$IPT -A INPUT $in_ITF -p tcp -m tcp --dport 443 -j ACCEPT
$IPT -A INPUT $in_ITF -p udp -m udp --dport 443 -j ACCEPT

#### Add custom services here ####
#$IPT -A INPUT $in_ITF -p udp -m udp --dport 9001 -j ACCEPT
#$IPT -A INPUT $in_ITF -p tcp -m tcp --dport 25 -j ACCEPT


#### Ports to open on the secondary interface ####

#$IPT -A INPUT $alt_IN -p udp -m udp --dport 57148 -j ACCEPT
#$IPT -A INPUT $alt_IN -p tcp -m tcp --dport 80 -j ACCEPT
#$IPT -A INPUT $alt_IN -p udp -m udp --dport 6881 -j ACCEPT

#### VPN Reachable Services ####


$IPT -A INPUT -i tun+ -p tcp -m tcp --dport 80 -j ACCEPT
$IPT -A INPUT -i tun+ -p tcp -m tcp --dpor 443 -j ACCEPT

#$IPT -A INPUT $vpn_IN1  -p tcp -m tcp --dport 2222 -j ACCEPT

#$IPT -A INPUT $vpn_IN2 -p tcp -m tcp --destination-port 4567 -j ACCEPT
#$IPT -A INPUT -i $vpn_IN2 -p tcp -m tcp --dport 1234 -j ACCEPT


#### VPN TUNNEL - ####


iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD $vpn_IN1 -j ACCEPT
iptables -A FORWARD $vpn_IN2 -j ACCEPT
iptables -A FORWARD -j REJECT

#### Can't masquerade in a container, so we use source routing ####
iptables -t nat -A POSTROUTING  -s $vpn_SN1 -o venet0 -j SNAT --to-source $out_IP
iptables -t nat -A POSTROUTING  -s $vpn_SN2 -o venet0 -j SNAT --to-source $out_IP
#### VPN Input ####


# allow incomming ICMP ping pong stuff
$IPT -A INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS Server, reachable only from within the tunnel(s)
$IPT -A INPUT $vpn_IN1 -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT $vpn_IN2 -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i $VPN_IN1 -p tcp --destination-port 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i $VPN_IN2 -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

$IPT -A OUTPUT -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Do not log smb/windows sharing packets - too much logging
$IPT -A INPUT -p tcp --dport 137:139 -j REJECT
$IPT -A INPUT -p udp --dport 137:139 -j REJECT
$IPT -A INPUT -p udp --dport 445 -j REJECT

# log everything else and drop

$IPT -A INPUT -j LOG
$IPT -A FORWARD -j LOG
$IPT -A INPUT -j DROP

exit 0
