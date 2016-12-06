#!/bin/bash
#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@
# Beta Version - source config from /etc/firewall.conf
# A linux iptables script for openvpn servers running inside openvz containers with restricted kernels,
# with multiple IP addresses, OpenVPN, dnscrypt-proxy to server the clients, and some other VPN reachable
# services. Inside openvz CTs we cannot referance interfaces like a physical server (ie: -i eth0)
# so intead we use -i venet0 -d your.ip.addrs.here, we also use source routing instead of masquerading.
# Thanks to Cyberbiz/nixCraft for the original fw template!
# -------------------------------------------------------------------------
# Copyright (c) 2004 nixCraft project <http://cyberciti.biz/fb/>
# This script is licensed under GNU GPL version 2.0 or above
# -------------------------------------------------------------------------
# Author : Darkerego, 2015 <https://the-resistance.net> - GPL Liscense :
# Modify, redistribute, do whatever but please give credit to the authors!
#--------------------------------------------------------------------------
# I've heavily commented the script to help out  new users of openvz with advice based on my experience,
# hopefully someone finds that helpful and avoids a compromise. If you've suggestions please do add them.
#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@
IPT="/sbin/iptables"
SPAMLIST="blockedip"
SPAMDROPMSG="BLOCKED IP DROP"
SYSCTL="/sbin/sysctl"
BLOCKEDIPS="/root/Scripts/blocked.ips"
#@#@#@#@#@#@#@
echo "Starting IPv4 Wall... Flushing current rules..."
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
#@#@#@#@#@#@#@

[ -f "$BLOCKEDIPS" ] && BADIPS=$(egrep -v -E "^#|^$" "${BLOCKEDIPS}")
#### Define Variables (These are overriden in /etc/firewall.conf) ####
VPNIF="tun+"
VPN_PRT="1194"
SSH_PRT="122"
SSH_ALT=""
EXTIF="venet0"
EXTIP="12.34.56.67"
OUTIP="2.34.56.69"
VPN_SN="10.8.0.0/24"
VPN_SN2="10.0.1.0/24"
VPNSRVR="10.8.0.1"
VPNSRVR2="10.8.1.1"
DNS_1="77.66.84.233"
DNS_2="176.56.237.171"
transPEER="12345"
transRPC="9777"
chat="6697"
tor="9100"
torproxy=9100
privoxy="8118"
SHELL_PORT="4444"
HTTP_PORT="8000"
# leave unset to disble these
transweb=""
kippo="1"
bitlbee_on=""
dropIO_enabled=""
httpd_vpn=""
allow_icmp=""
mosh_enabled=""
# 

if [[ -f /etc/firewall.conf ]] ; then
  echo "Sourceing config from /etc/firewall.conf"
  . /etc/firewall.conf
  [[ "$?" -eq "0" ]] && echo 'Success!' ||   (echo 'Fail! Wtf?';exit 1)
  echo $chat
fi


#@#@# Log Messages #@#@#@#@#
logSSI="Dropped Incoming source spoof!"
logSSO="Dropped Outgoing soure spoof!"
logDNSC="Dropped invalid from dnscrypt!"
logFW="Invalid FWD packet"
logIO="Dropped incoming on $OUTIP"
logTMS="Transmission-Daemon"
loghttp="Dropped invalid apache"
logHNY="Honey Pot Break?"
logUNPN="UPNP Traffic"
#@#@#@#@#@#@#
## Local host, you can further restrict with source or dest rules, i.e. -s 127.0.0.1
echo "Allowing local connections..."
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
#@#@#@#@#@#@#@ Protect Source Spoof Attacks
echo Log Drop Source Spoofing...
$IPT -A INPUT -s $EXTIP -j LOG --log-prefix "$logSSI"
$IPT -A INPUT -s $EXTIP -j DROP
$IPT -A OUTPUT -d $EXTIP -j LOG --log-prefix "$logSSO"
$IPT -A OUTPUT -d $EXTIP -j DROP
$IPT -A INPUT -s $OUTIP -j LOG --log-prefix "$logSSI"
$IPT -A INPUT -s $OUTIP -j DROP
$IPT -A OUTPUT -d $OUTIP -j LOG --log-prefix "$logSSO"
$IPT -A OUTPUT -d $OUTIP -j DROP
#@#@#@#@#@#@#@ Stop floods
echo "Anti Flood Rules..."
$IPT -N flood
$IPT -A INPUT -p tcp --syn -j flood
$IPT -A flood -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPT -A flood -j DROP
# DROP all incomming traffic
echo "Setting defaults..."
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP
#@#@#@#@#@#@#@ SPAM LIST #@#@#@#@#@#@#@
if [ -f "${BLOCKEDIPS}" ];
then
# create a new iptables list
$IPT -N $SPAMLIST
#
for ipblock in $BADIPS
do
$IPT -A $SPAMLIST -s $ipblock -j LOG --log-prefix "$SPAMDROPMSG "
$IPT -A $SPAMLIST -s $ipblock -j DROP
done
#
$IPT -I INPUT -j $SPAMLIST
$IPT -I OUTPUT -j $SPAMLIST
$IPT -I FORWARD -j $SPAMLIST
fi

echo Blocking bad packets...
#@#@#@#@#@#@#@ Things that should never exist #@#@#@#@#@#@#@
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




#@#@#@#@#@#@#@ Don't delete this one! #@#@#@#@#@#@#@
echo "Allowing already established traffic..."
# Allow full outgoing connection but no incomming stuff
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#

#@#@#@#@#@# Kippo Honeypot -- Can't say I recommend this, #@#@#@#@#@#@#
# but here's the correct way to do it.. at least audit the kippo acct
# with auditd or something... and don't do this on a production server
# , rather place it nearby on a dedicated VM is my advice.
#

if [[ ! -z "$kippo" ]] ; then

  $IPT -A FORWARD -i venet0 -d $EXTIP -p tcp --dport 22 -m state --state NEW -j ACCEPT
  $IPT -t nat -A PREROUTING -p tcp -d $EXTIP --dport 22 -j REDIRECT --to-ports 2222
  $IPT -A INPUT -i venet0 -d $EXTIP -p tcp --dport 2222 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
  $IPT -A OUTPUT -o venet0 -p tcp --sport 2222 -m owner --uid-owner kippo -m state --state RELATED,ESTABLISHED -j ACCEPT
  $IPT -A OUTPUT -m owner --uid-owner kippo -j LOG --log-prefix "logHNY"
  $IPT -A OUTPUT -m owner --uid-owner kippo -j REJECT

fi
#
#
#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@

if [[ ! -z "$allow_icmp" ]]; then

  echo "Allowing ICPM 8 and 0 ..."
  # allow incomming ICMP ping pong stuff
  $IPT -A INPUT -i venet0 -d  $EXTIP -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
  $IPT -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT
fi
#
#@#@#VPN TUNNEL#@#@#@
$IPT -A INPUT -i venet0 -d $EXTIP -p udp -m udp --dport $VPN_PRT -j ACCEPT
#$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --dport $VPN_PRT -j ACCEPT
#@#@#@#@#@#@#@#@#@#@#@
#
#@#@#@#@#@#@#@--VPN-to-Client Port Forwarding--#@#@#@#@#@#@#@#@#@#@#
# Forward From Server Public IP to a VPN Client. This can be securely
# accomplished with a client connect script rather than left open.
fwd_EN="true" # Change to 'true' to enable
ext_if="venet0"
int_if="tun0"
int_ip="10.98.76.2" # client to forward to
int_PRT="50000" # port to forward
int_PRT2=""

if [[ $fwd_EN == "true" ]]; then

  echo Warning: Port Forwarding enabled
  # TCP
  $IPT -t nat -A PREROUTING -p tcp -i $ext_if --dport $int_PRT -j DNAT --to-dest $int_ip:$int_PRT
  $IPT -A FORWARD -p tcp -i $ext_if -o $int_if -d $int_ip --dport $int_PRT -m state --state NEW -j ACCEPT
  # RAT
  if [[ ! -z $int_PRT2 ]] ; then 
    $IPT -t nat -A PREROUTING -p tcp -i $ext_if --dport $int_PRT2 -j DNAT --to-dest $int_ip:$int_PRT2
    $IPT -A FORWARD -p tcp -i $ext_if -o $int_if -d $int_ip --dport $int_PRT2 -m state --state NEW -j ACCEPT
  fi

  # UDP
  $IPT -t nat -A PREROUTING -p udp -i $ext_if --dport $int_PRT -j DNAT --to-dest $int_ip:$int_PRT
  $IPT -A FORWARD -p udp -i $ext_if -o $int_if -d $int_ip --dport $int_PRT -m state --state NEW -j ACCEPT
  # Established Traffic
  $IPT -A FORWARD -i $ext_if -o $int_if -d $int_ip -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IPT -A FORWARD -i $int_if -s $int_ip -o $ext_if -m state --state ESTABLISHED,RELATED -j ACCEPT
#
else
  echo Info: Port Forwarding Disabled
fi

#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@

echo "Allowing ssh from venet0..."

#@#@#@--Incoming Services--#@#@#@#
## SSH
#$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --dport $SSH_PRT -j ACCEPT
#$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --dport $SSH_ALT -j ACCEPT
# HTTP
#$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --dport 80 -j ACCEPT

if [[ ! -z "$mosh_enabled" ]] ; then
  echo "Allowing ssh from vpn..."
  echo "Allowing mosh..."
  $IPT -A INPUT -p udp --dport 60000:61000 -j ACCEPT
fi

#$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --dport $chat -j ACCEPT
#$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --dport $SSH_PRT -j ACCEPT
# OR (if you're aware, err paranoid)

#$IPT -A INPUT -i $EXTIF -d $EXTIT -s $staticIP -p tcp --dport $SSH_PORT -j ACCEPT
# or from vpn...
$IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $SSH_PRT -j ACCEPT

if [[ ! -z "$SSH_ALT" ]] ; then
  echo "Allowing to alternate ssh port $SSH_ALT "
  $IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $SSH_ALT -j ACCEPT
fi

#$IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $SHELL_PORT -j ACCEPT
#$IPT -A INPUT -i $EXTIF -d $EXTIP -p tcp -m tcp --dport $SHELL_PORT -j ACCEPT
#$IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $HTTP_PORT -j ACCEPT
#$IPT -A INPUT -i $EXTIF -d $EXTIP -p tcp -m tcp --dport $HTTP_PORT -j ACCEPT
#$IPT -A INPUT -i $VPNIF -s $VPN_SN2 -d $VPNSRVR2 -p tcp -m tcp --dport $SSH_PRT -j ACCEPT

# Add Your Own Rules Here, see example below:
#$IPT -A INPUT -i venet0 -p udp --dport 443 -j ACCEPT
#### Transmission Peer Port (not necessary but helps speed)
$IPT -A INPUT -i venet0 -p tcp --dport $transPEER -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i venet0 -p udp --dport $transPEER -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@
#### VPN REACHABLE SERVICES ####
#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@

# Add your own rules here. Some example common services below:
if [[ ! -z $transWeb ]]; then
  echo "Allowing transmission web..."
  ## Transmission Web ####
  $IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $transRPC -j ACCEPT
  $IPT -A OUTPUT -o $VPNIF -s $VPNSRVR -d $VPN_SN -p tcp -m tcp --sport $transRPC -m owner --uid-owner debian-transmission -j ACCEPT
  $IPT -A OUTPUT -o $VPNIF -d $VPN_SN -m owner --uid-owner debian-transmission -j LOG --log-prefix "$logTMS"
  $IPT -A OUTPUT -o $VPNIF -d $VPN_SN -m owner --uid-owner debian-transmission -j REJECT
fi

if [[ ! -z $bitlbee_on ]] ; then
echo "Allowing bitlbee from vpn..."
  $IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $chat -j ACCEPT
  $IPT -A OUTPUT -o $VPNIF -s $VPNSRVR -d $VPN_SN -p tcp --sport $chat -j ACCEPT
fi

if [[ ! -z "httpd_vpn" ]] ; then

  echo "Allowing apache (to vpn)..."
  ##  Apache (Serving VPN clients only) ####
  $IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport 80 -j ACCEPT
  $IPT -A OUTPUT -o $VPNIF -s $VPNSRVR -d $VPN_SN -p tcp --sport 80 -j ACCEPT
  $IPT -A OUTPUT -o $VPNIF -m owner --uid-owner www-data -j LOG --log-prefix "$loghttp"
  $IPT -A OUTPUT -o $VPNIF -m owner --uid-owner www-data -j REJECT
fi

##Tor/Privoxy (I recommend running Tor in a chroot)

echo 'Allowing tor gateway from vpns..'
$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $privoxy -j ACCEPT
$IPT -A INPUT -i tun+ -s $VPN_SN2 -d $VPNSRVR2 -p tcp -m tcp --dport $pridebug2: channel 0: window 995464 sent adjust 53112
voxy -j ACCEPT
$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --dport $torproxy -j ACCEPT
$IPT -A OUTPUT -o $EXTIF -p tcp -m owner --uid-owner tor -j ACCEPT

## Incoming to dnsmasq
# Allow port 53 tcp/udp (Dnsmasq/Unbound)
echo "Allowing DNS to vpn..."
##$IPT -t nat -A PREROUTING -p udp -i tun+ --dport 53 -j DNAT --to-dest 127.0.0.1:53
##$IPT -A FORWARD -p udp -i tun+ -o $EXTIF --dport 53 -m state --state NEW -j ACCEPT
##$IPT -t nat -A PREROUTING -p tcp -i tun+ --dport 53 -j DNAT --to-dest 127.0.0.1:53
##$IPT -A FORWARD -p tcp -i tun+ -o $EXTIF --dport 53 -m state --state NEW -j ACCEPT
$IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i $VPNIF -s $VPN_SN -d $VPNSRVR -p tcp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A INPUT -i $VPNIF -s $VPN_SN2 -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A INPUT -i $VPNIF -s $VPN_SN2 -p tcp --destination-port 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


## DNSCRYPT/VPN (limit to 443/udp @ resolver) ####
echo "Setting dnscrypt-proxy rules..."
$IPT -A OUTPUT -p udp -m owner --uid-owner dnscrypt -m udp --sport 1024:65535 --dport 443 -j ACCEPT
$IPT -A OUTPUT -p udp -m owner --uid-owner dnscrypt -m udp --sport 1024:65535 --dport 443 -j ACCEPT
$IPT -A OUTPUT -m owner --uid-owner dnscrypt -j LOG --log-prefix "$logDNSC"
$IPT -A OUTPUT -m owner --uid-owner dnscrypt -j DROP
echo Setting VPN tunnel rules...

#@#@#@#@#@#@#@#@
## VPN TUNNEL ##
$IPT -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT -A FORWARD -s $VPN_SN -j ACCEPT
$IPT -A FORWARD -s $VPN_SN2 -j ACCEPT

#$IPT -A FORWARD -s ! $VPN_SN -j LOG --log-prefix "$logFW"
#$IPT -A FORWARD -s ! $VPN_SN2 -j LOG --log-prefix "$logFW"
$IPT -A FORWARD -j REJECT
$IPT -t nat -A POSTROUTING  -s $VPN_SN -o venet0 -j SNAT --to-source $OUTIP
$IPT -t nat -A POSTROUTING  -s $VPN_SN2 -o venet0 -j SNAT --to-source $OUTIP
# Forward to dnscrypt
#echo "Forwarding dns queries on tun+ to lo..."
#iptables -t nat -I PREROUTING -i tun+ -p tcp --dport 53 -j DNAT --to 127.0.0.1:53
#iptables -t nat -I PREROUTING -i tun+ -p udp --dport 53 -j DNAT --to 127.0.0.1:53
#@#@#@#@#@#@#@#@

## Staying Stealthy


if [[ ! -z "$dropIO_enabled" ]] ; then
  echo Dropping incoming on out IP...
  $IPT -A INPUT -i venet0 -d $OUTIP -j LOG --log-level 4 --log-prefix "$logIO"
  $IPT -A INPUT -i venet0 -d $OUTIP -j DROP

fi

# Drop Windows BS
echo Dropping windows bs...
$IPT -A INPUT -p tcp -i venet0 -d $EXTIP --dport 137:139 -j DROP
$IPT -A INPUT -p udp -i venet0 -d $EXTIP --dport 137:139 -j DROP
$IPT -A INPUT -p udp -i venet0 -d $EXTIP --dport 445 -j DROP
# Log UPNP Packets
echo Logging UPNP...
$IPT -A INPUT -p udp --dport 1900 -j LOG --log-prefix "$logUNPN "
# log everything else and drop
echo "Logging and dropping everything else..."
$IPT -A INPUT -j LOG
$IPT -A FORWARD -j LOG
$IPT -A INPUT -j DROP

echo "Done!"

exit 0

