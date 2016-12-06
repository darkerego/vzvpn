#!/bin/bash
###########################
# Prevent vpn leaks - requires ufw 
if [[ "id -u" -ne "0" ]] ; then
  echo This script must be ran as root.
  exit 1
fi


vpn_host='your.vpnserver.com' # vpn server
vpn_sn='10.8.0.0/24' # vpn subnet
host_ssh='22' # vpn server ssh port 
host_btn='54321' # what port your torrent client listens on



ufw reset
ufw default deny outgoing

ufw allow out to $vpn_host
ufw allow out on tun0
ufw allow in on tun0 to any port $host_ssh proto tcp from $vpn_sn
ufw allow in on tun0 to any port $host_btn proto tcp
ufw allow in on tun0 to any port $host_btn proto udp

ufw enable
ufw status verbose

