#!/bin/bash

echo "set port forwarding: sudo sysctl -w net.ipv4.ip_forward=1"

#create alice_routing table
sudo nft add table nat 2>/dev/null
echo "alice nat table created"

#add chain to alice_routing table and masquerade rule
sudo nft add chain ip nat POSTROUTING { type nat hook postrouting priority 100 \; } 2>/dev/null
sudo nft add rule ip nat POSTROUTING oifname "enp0s8" masquerade 2>/dev/null
echo "alice chain and rule created"


#create censor table 
# 2>/dev/null silences error if table already exists - run repeatedly w/o failing
sudo nft add table inet censor_table 2>/dev/null
echo "censor_table created"

#add chain fwd_ports to table - {type = filter | hook = forward | priority = 0 (neutral)}
sudo nft add chain inet censor_table fwd_ports { type filter hook forward priority 0 \;} 2>/dev/null
sudo nft add chain inet censor_table ssh_in { type filter hook input priority 0 \;} 2>/dev/null
sudo nft add chain inet censor_table ssh_out { type filter hook output priority 0 \;} 2>/dev/null

echo "fwd_ports chain added to table"

#add specific rule to chain w/ associated nfq number
sudo nft add rule inet censor_table fwd_ports ip protocol tcp counter tcp dport 80 queue num 1
sudo nft add rule inet censor_table fwd_ports udp dport 53 queue num 2
sudo nft add rule inet censor_table fwd_ports ip protocol tcp tcp dport 53 queue num 2
#force tcp - block QUIC (UDP 443)
sudo nft add rule inet censor_table fwd_ports udp dport 443 drop
sudo nft add rule inet censor_table ssh_in ip protocol tcp counter tcp dport 22 queue num 3
sudo nft add rule inet censor_table ssh_out ip protocol tcp tcp sport 22 queue num 3
echo "rules added to chain"

#monitor counter
sudo nft -a list chain inet censor_table fwd_ports
echo "monitoring incoming packets w/"
echo "sudo nft -a list chain inet censor_table fwd_ports"

#tear down - delete chain
echo " Delete table w/:"
echo "sudo nft delete chain inet censor_table fwd_ports"