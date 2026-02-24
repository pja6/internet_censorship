# internet_censorship
lab7 - implement 3 types of censorship


VM/NFQ Set-Up

1) set up alice ip table rules
 
    `sudo nft add table nat`

    `sudo nft 'add chain ip nat POSTROUTING { type nat hook postrouting priority 100; }'`    
    `sudo nft add rule ip nat POSTROUTING oifname "enp0s8" masquerade`

2) run NFQ rules: `sudo bash start_nfq.sh`

- to install:
    - sudo apt install build-essential python3-dev \
                 libnetfilter-queue-dev \
                 libnfnetlink-dev
    - sudo .venv/bin/pip3 install NetfilterQueue

3) Start censor.py

4) Test

5) Stop censor.py : `ctrl+c`

6) teardown nft chain: `sudo nft delete chain inet censor_table fwd_ports`