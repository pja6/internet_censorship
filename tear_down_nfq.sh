#!/bin/bash

sudo nft list ruleset
echo "current rules"
#tear down - delete chain
#echo " Delete table w/:"
sudo nft delete chain inet censor_table fwd_ports
echo "fwd_ports chain deleted"
sudo nft delete chain inet censor_table ssh_in
echo "ssh_in chain deleted"
sudo nft delete chain inet censor_table ssh_out
echo "ssh_out chain deleted"
sudo nft list ruleset
#flush conntrack state
sudo conntrack -F
