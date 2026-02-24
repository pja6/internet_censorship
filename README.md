# internet_censorship
lab7 - implement 3 types of censorship


Forward machine setup


1) set up TPROXY 
    
    `sudo modprobe nft_tproxy`

- can check set up with 
    
    `lsmod | grep tproxy`

2) set up alice ip table rules
 
    `sudo nft add table nat`

    `sudo nft 'add chain ip nat POSTROUTING { type nat hook postrouting priority 100; }'`    
    `sudo nft add rule ip nat POSTROUTING oifname "enp0s8" masquerade`

3) run bash script

4) run ip table rules for bash script
    Add listening rules as follow:

    # TPROXY incoming TCP packets on port 80 to vethrelay on port 8080
    iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080 --on-ip 2.2.2.2

    # Listen on wlp4s0 for incoming packets on port 80 (on the interface where it really comes from)
    iptables -A INPUT -i wlp4s0 -p tcp --dport 80 -j ACCEPT

5) run forwarding machine