
from scapy.all import *
#import TLS without multiple layers for handshake and record
load_layer("tls")
from scapy.layers.http import HTTP,HTTPRequest
import NetfilterQueue as nfq
import time


class CensorMachine():
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.debug = False
        #http.path stored in bytes
        self.ban_list=[b"frankenstien", b"httpforeveer"]
        
        self.domain_list=[b"wikipedia.org", b"npr.org"]
        self.censor_dict={}        
        self.censor_rules=[
            self.keyword_censor,
            self.domain_censor,
            self.protocol_censor
            ]

    #convert nfq packet into scapy version
    def scapy_pkt(self, nfq_pkt):
        return IP(nfq_pkt.get_payload())
    

    #censor list helper method
    def tuple_ban(self, nfq_pkt):
       
       pkt = self.scapy_pkt(nfq_pkt)

       #tuple logic based on residual censorship paper - broadens censorship after new attempt detected
       #ban that specific tcp flow
       f_tuple=(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
       #ban any connection from ip to dst ip/port
       t_tuple=(pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
       curr_time=time.time()
       
       if f_tuple not in self.censor_dict:
           self.censor_dict[f_tuple]=curr_time
       elif t_tuple not in self.censor_dict and curr_time-self.censor_dict[f_tuple] >180.0:
           self.censor_dict[f_tuple]= curr_time
           self.censor_dict[t_tuple] = curr_time
       elif t_tuple in self.censor_dict and curr_time - self.censor_dict[t_tuple] > 180.0:
            self.censor_dict[t_tuple]= curr_time
       else:
           if t_tuple in self.censor_dict:
               del self.censor_dict[t_tuple]
           del self.censor_dict[f_tuple]
           
    
    def keyword_censor(self, nfq_pkt):

        pkt = self.scapy_pkt(nfq_pkt)

        if pkt.haslayer(HTTPRequest):
            
            http = pkt[HTTPRequest]
            
            for keyword in self.ban_list:
                if keyword in http.Path:
                    print(f"Keyword: {keyword} recognized - ")
                    
                    self.tuple_ban(pkt)

                    nfq_pkt.drop()
                
        else:
            nfq_pkt.accept()
    
    #create new RST packets    
    def create_rst(self, nfq_pkt):

        pkt=self.scapy_pkt(nfq_pkt)

        old_IP = pkt[IP]
        old_TCP = pkt[TCP]
        
        #set fields for server packet - Scapy uses 'R' not 'RST'
        client_pkt = IP(src=old_IP.dst, dst= old_IP.src)/TCP(sport=old_TCP.dport, dport=old_TCP.sport, flags='R', seq=old_TCP.ack, ack=old_TCP.seq+len(old_TCP.payload))
        server_pkt = IP(src=old_IP.src, dst=old_IP.dst)/TCP(sport=old_TCP.sport, dport=old_TCP.dport, flags='R', seq=old_TCP.seq)
           

        return server_pkt, client_pkt
    

    def domain_censor(self, nfq_pkt):

        pkt=self.scapy_pkt(nfq_pkt)
        
        #create new packets for server/client with RST flags
        server_pkt, client_pkt = self.create_rst(pkt)
        sni_info=[]


        #TLSClientHello signals the start of TLS, catches it before encryption 
        if pkt.haslayer(TLSClientHello):
            #need to update rst pkt w/ SNI info instead of IP
            client_hello= pkt[tls.TLSClientHello]
            for ext_type, ext_data in client_hello.extensions:
                if ext_type == tls.TLSExtensionType.SERVER_NAME:
                    sni_info=tls.TLSServerName.parse(ext_data)
            
            #need to use SNI for domain info       
            if sni_info:
                sni=sni_info[0].data.decode("utf-8")
                for url in self.domain_list:
                    if url in sni:
                        print(f"Attempted access of restricted site{url}")
                        #could make this helper method
                        send(server_pkt, verbose=False)
                        send(client_pkt, verbose=False)
                        
                        self.tuple_ban(pkt)
                        nfq_pkt.drop()

        #else forward pkt
        nfq_pkt.accept()


    #Use protocol to block SSH instead of trying to block smtp email - specific test/less work?
    def protocol_censor(self, nfq_pkt):

        pkt = self.scapy_pkt(nfq_pkt)

        if pkt.haslayer(TCP):
            #using the port instead of protocol is coarse censorship - easier to circumvent later
            if pkt[TCP].dport==22:
                print("Attempted connection to restricted service: SSH")
                
                self.tuple_ban(pkt)
                #connection times out
                nfq_pkt.drop()
            
        nfq_pkt.accept()
    
    def nfq_pipeline(self, q1, q2, q3):
       http_queue = nfq()
       https_queue = nfq()
       ssh_queue = nfq()

    
       http_queue.bind(q1, self.keyword_censor)
       https_queue.bind(q2, self.domain_censor)
       ssh_queue.bind(q3, self.protocol_censor)

       try:
           http_queue.run()
           https_queue.run()
           ssh_queue.run()
       except KeyboardInterrupt:
           nfq.unbind()
           


        
            
def main():
    censor=CensorMachine()

    #useful for logging but not routing
    #sniffer=AsyncSniffer(iface=None, prn=censor.pipeline_callback)
    #sniffer.start()

    censor.nfq_pipeline(1,2,3)

if __name__ == "__main__":
    main()