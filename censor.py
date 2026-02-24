#https://scapy.readthedocs.io/en/latest/advanced_usage/fwdmachine.html

from scapy.all import *
#import TLS without multiple layers for handshake and record
load_layer("tls")
from scapy.layers.http import HTTP,HTTPRequest
import NetfilterQueue
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
            self.domain_censor_server,
            self.protocol_censor
            ]

    
    #censor list helper method
    def tuple_ban(self, pkt):
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
           
    
    def keyword_censor(self, pkt):
       
        if pkt.haslayer(HTTPRequest):
            
            http = pkt[HTTPRequest]
            
            for keyword in self.ban_list:
                if keyword in http.Path:
                    print(f"Keyword: {keyword} recognized - ")
                    
                    self.tuple_ban(pkt, ctx)

                    return "DROP"
                
        return
    
    #create new RST packets    
    def create_rst(self, pkt):

        old_IP = pkt[IP]
        old_TCP = pkt[TCP]
        
        #set fields for server packet - Scapy uses 'R' not 'RST'
        client_pkt = IP(src=old_IP.dst, dst= old_IP.src)/TCP(sport=old_TCP.dport, dport=old_TCP.sport, flags='R', seq=old_TCP.ack, ack=old_TCP.seq+len(old_TCP.payload))
        server_pkt = IP(src=old_IP.src, dst=old_IP.dst)/TCP(sport=old_TCP.sport, dport=old_TCP.dport, flags='R', seq=old_TCP.seq)
           

        return server_pkt, client_pkt
    

    def domain_censor_server(self, pkt):
        
        #create new packets for server/client with RST flags
        server_pkt, client_pkt = self.create_rst(pkt)
        sni_info=[]

        if pkt.haslayer(HTTPRequest):
            host =  pkt[HTTPRequest].Host
            
            for url in self.domain_list:
                if host and url in host:
                    print(f"Attempted access of restricted site{url}")
                    
                    #send RST to server - use verbose so you don't print every injection
                    send(server_pkt, verbose=False)
                    #send RST to client
                    send(client_pkt, verbose=False)
                    
                    self.tuple_ban(pkt)
                    
                    return "DROP"
                
        #TLSClientHello signals the start of TLS, catches it before encryption 
        elif pkt.haslayer(TLSClientHello):
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
                        return "DROP"

        #else callback will forward packet
        return


    #Use protocol to block SSH instead of trying to block smtp email - specific test/less work?
    def protocol_censor(self, pkt):
        if pkt.haslayer(TCP):
            #using the port instead of protocol is coarse censorship - easier to circumvent later
            if pkt[TCP].dport==22:
                print("Attempted connection to restricted service: SSH")
                
                self.tuple_ban(pkt)
                #connection times out
                return "DROP"
            
        return
    
    def pipeline_callback(self, pkt):
        for rule in self.censor_rules:
            result = rule(pkt)

            if result == "DROP":
                #interact w/ nfqueue for dropping.
                nfqueue_packet.drop()
            return
    nfqueue_packet.accept()


        
            
def main():
    censor=CensorMachine()
    sniffer=AsyncSniffer(iface=None, prn=censor.pipeline_callback)
    sniffer.start()