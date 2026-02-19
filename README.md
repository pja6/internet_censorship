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

5) run forwarding machine