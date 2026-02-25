
from scapy.all import *
#import TLS without multiple layers for handshake and record
from scapy.layers.tls.all import *
from scapy.layers.http import HTTP,HTTPRequest
from netfilterqueue import NetfilterQueue as nfq
import time


class CensorMachine():
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.debug = False
        #http.path stored in bytes
        self.ban_list=["frankenstien", "httpforever"]
        self.sni=""
        self.domain_list=["wikipedia.org", "npr.org"]
        self.censor_dict={}        
        self.censor_rules=[
            self.keyword_censor,
            self.domain_censor,
            self.protocol_censor
            ]
        bind_layers(TCP, TLS, dport=443)
        bind_layers(TCP, TLS, sport=443)

    #convert nfq packet into scapy version
    def scapy_pkt(self, nfq_pkt):
        print("here: scapy")
        return IP(nfq_pkt.get_payload())
    

    #censor list helper method
    def tuple_ban(self, pkt):
       print("here: ban")

       #tuple logic based on residual censorship paper - broadens censorship after new attempt detected
       #ban that specific tcp flow
       f_tuple=(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
       #ban any connection from ip to dst ip/port
       t_tuple=(pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
       curr_time=time.time()
       
       # add 4 tuple to censor list if not already in it
       if f_tuple not in self.censor_dict:
           self.censor_dict[f_tuple]=curr_time
           print(f"4-tuple {f_tuple} added to censor list")
        # if 3 tuple not in list and 4 tuple time limit not done, add 3 tuple to list and reset time
       elif t_tuple not in self.censor_dict and curr_time-self.censor_dict[f_tuple] >180.0:
           print(f"new attempt made before time limit expired")
           self.censor_dict[f_tuple]= curr_time
           print(f"3-tuple {t_tuple} added to censor list")

           self.censor_dict[t_tuple] = curr_time
           print(f"4-tuple {f_tuple} timer reset")

        # if 3 tuple in list and time limit not reached, reset timer
       elif t_tuple in self.censor_dict and curr_time - self.censor_dict[t_tuple] > 180.0:
            print(f"3 tuple timer reset - timer not expired")
            self.censor_dict[t_tuple]= curr_time
        #timers complete - delete tuple from list
       else:
           if t_tuple in self.censor_dict:
               del self.censor_dict[t_tuple]
           del self.censor_dict[f_tuple]
           
    
    def keyword_censor(self, nfq_pkt):
        print("here: keyword")
        pkt = self.scapy_pkt(nfq_pkt)

        #be more specific - otherwise only accepts packets that aren't HTTP and holds the rest
        if pkt.haslayer(TCP):
            
            raw = bytes(pkt[TCP].payload)
            if raw:
                #ignore if not valid utf-8
                decoded_raw = raw.decode(errors='ignore')
                
                #if banned keyword in raw data - drop it
                for keyword in self.ban_list:
                    if keyword in decoded_raw:
                        print(f"Keyword: {keyword} recognized - packet dropped")
                        
                        self.tuple_ban(pkt)

                        nfq_pkt.drop()
                        return
                    
            print("Permissible packet: forwarded")
            nfq_pkt.accept()
                    
        else:
            print("Permissible packet: forwarded")
            nfq_pkt.accept()
    
    #create new RST packets    
    def create_rst(self, pkt):
        print("here: rst")

        old_IP = pkt[IP]
        old_TCP = pkt[TCP]
        
        #set fields for server packet - Scapy uses 'R' not 'RST'
        client_pkt = IP(src=old_IP.dst, dst= old_IP.src)/TCP(sport=old_TCP.dport, dport=old_TCP.sport, flags='R', seq=old_TCP.ack, ack=old_TCP.seq+len(old_TCP.payload))
        server_pkt = IP(src=old_IP.src, dst=old_IP.dst)/TCP(sport=old_TCP.sport, dport=old_TCP.dport, flags='R', seq=old_TCP.seq)
           

        return server_pkt, client_pkt
    

    def domain_censor(self, nfq_pkt):
        
        pkt=self.scapy_pkt(nfq_pkt)
        if pkt.haslayer(TCP):
            tls_layer = pkt[TLS]
            for msg in tls_layer.msg:
                 if isinstance(msg, TLSClientHello):
                    print("here: clienthello")
            #scapy's current way to work with TLS
            #TLSClientHello signals the start of TLS, catches it before encryption 
                
                 for ext_type in msg.ext:
                    if isinstance(ext_type, TLSExtServerName): 
                            #need to use SNI for domain info       
                        self.sni=ext_type.servernames[0].servername.decode('utf-8')
                        print("here sni")
                        print(f"sni:{self.sni}")
                        for url in self.domain_list:
                            if url in self.sni:
                                print(f"Attempted access of restricted site{url}")
                                #create new packets for server/client with RST flags
                                server_pkt, client_pkt = self.create_rst(pkt)
                                print("reset sent")
                                #could make this helper method
                                send(server_pkt, verbose=False)
                                send(client_pkt, verbose=False)
                            
                            self.tuple_ban(pkt)
                            nfq_pkt.drop()
                            return
                            
            print(f"Allowed site {self.sni} request: forwarded")
            #else forward pkt
            nfq_pkt.accept()


    #Use protocol to block SSH instead of trying to block smtp email - specific test/less work?
    def protocol_censor(self, nfq_pkt):
        print ("here: protocol")
        pkt = self.scapy_pkt(nfq_pkt)

        if pkt.haslayer(TCP):
            #using the port instead of protocol is coarse censorship - easier to circumvent later
            if pkt[TCP].dport==22 or pkt[TCP].sport == 22: 
                print("Attempted connection to restricted service: SSH")
                
                self.tuple_ban(pkt)
                #connection times out
                nfq_pkt.drop()
                return
            
        nfq_pkt.accept()
    
    def nfq_pipeline(self, q1, q2, q3):
       print("here: pipeline")
       http_queue = nfq()
       https_queue = nfq()
       ssh_queue = nfq()

    
       http_queue.bind(q1, self.keyword_censor)
       https_queue.bind(q2, self.domain_censor)
       ssh_queue.bind(q3, self.protocol_censor)

       try:
           #http_queue.run()
           https_queue.run()
           #ssh_queue.run()
       except KeyboardInterrupt:
           nfq.unbind(https_queue)
           
    def log_packet(self, packet):
        print(packet.summary())

        
            
def main():
    censor=CensorMachine()

    #useful for logging but not routing
    sniffer=AsyncSniffer(iface="enp0s3", prn=censor.log_packet)
    sniffer.start()

    censor.nfq_pipeline(1,2,3)

if __name__ == "__main__":
    main()