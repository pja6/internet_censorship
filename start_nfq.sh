#!/bin/bash

#create alice_routing table
#sudo nft add table nat 2>/dev/null

#add chain to alice_routing table and masquerade rule
#sudo nft add chain ip nat POSTROUTING { type nat hook postrouting priority 100 \; } 2>/dev/null
#sudo nft add rule ip nat POSTROUTING oifname "enp0s8" masquerade 2>/dev/null



#create censor table 
# 2>/dev/null silences error if table already exists - run repeatedly w/o failing
sudo nft add table inet censor_table 2>/dev/null

#add chain fwd_ports to table - {type = filter | hook = forward | priority = 0 (neutral)}
sudo nft add chain inet censor_table fwd_ports { type filter hook forward priority 0 \;} 2>/dev/null

#add specific rule to chain w/ associated nfq number
sudo nft add rule inet censor_table fwd_ports tcp dport 80 queue num 1 2>/dev/null
sudo nft add rule inet censor_table fwd_ports tcp dport 443 queue num 2 2>/dev/null
sudo nft add rule inet censor_table fwd_ports tcp dport 22 queue num 3 2>/dev/null

#tear down - delete chain
#sudo nft delete chain inet censor_table fwd_ports