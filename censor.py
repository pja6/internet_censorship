#https://scapy.readthedocs.io/en/latest/advanced_usage/fwdmachine.html

from scapy.all import *
#import TLS without multiple layers for handshake and record
load_layer("tls")
from scapy.fwdmachine import ForwardMachine
from scapy.layers.http import HTTP,HTTPRequest
import socket
import time

class NOPFwdMachine(ForwardMachine):
    
    
    #client-server dispatcher - doesn't handle protocols just checks against egress rules
    def xfrmcs(self, pkt, ctx):
      
        #strategy model pipeline
        for rule in self.outbound_rules:
            result = rule( pkt, ctx)

            if isinstance(result, Exception):
                raise result
            
            #ignore if rule returns none
            if result is not None:
                pkt = result

        #show final mutate packet - doesn't print for intermediate states
        if self.debug:
            pkt.show()  


        raise self.FORWARD(pkt)

    

    
    #server-client dispatcher - doesn't handle protocols just checks against ingress rules
    def xfrmsc(self, pkt, ctx):
        #strategy model pipeline
        for rule in self.inbound_rules:
            result = rule( pkt, ctx)

            if isinstance(result, Exception):
                raise result
            
            #ignore if rule returns none
            if result is not None:
                pkt = result

        #show final mutate packet - doesn't print for intermediate states
        pkt.show()  


        raise self.FORWARD(pkt)


class CensorMachine(NOPFwdMachine):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.debug = False
        #http.path stored in bytes
        self.ban_list=[b"frankenstien", b"httpforeveer"]
        
        self.domain_list[b"wikipedia.org", b"npr.org"]
        self.censor_dict={}
        self.inbound_rules=[]
        
        self.outbound_rules=[
            self.keyword_censor,
            self.domain_censor_server
            ]

    
    #censor list helper method
    def tuple_ban(self, pkt, ctx):
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
           
    
    def keyword_censor(self, pkt, ctx):
       
        if pkt.haslayer(HTTPRequest):
            
            http = pkt[HTTPRequest]
            
            for keyword in self.ban_list:
                if keyword in http.Path:
                    print(f"Keyword: {keyword} recognized - ")
                    
                    self.tuple_ban(pkt, ctx)

                    return self.DROP()
                
        return pkt
    
    #create new RST packets    
    def create_rst(self, pkt):

        old_IP = pkt[IP]
        old_TCP = pkt[TCP]
        
        #set fields for server packet - Scapy uses 'R' not 'RST'
        client_pkt = IP(src=old_IP.dst, dst= old_IP.src)/TCP(sport=old_TCP.dport, dport=old_TCP.sport, flags='R', seq=old_TCP.ack, ack=old_TCP.seq+len(old_TCP.payload))
        server_pkt = IP(src=old_IP.src, dst=old_IP.dst)/TCP(sport=old_TCP.sport, dport=old_TCP.dport, flags='R', seq=old_TCP.seq)
           

        return server_pkt, client_pkt
    

    def domain_censor_server(self, pkt, ctx):
        
        #create new packets for server/client with RST flags
        server_pkt, client_pkt = self.create_rst(pkt)

        if pkt.haslayer(HTTPRequest):
            host =  pkt[HTTPRequest].Host
            
            for url in self.domain_list:
                if host and url in host:
                    print(f"Attempted access of restricted site{url}")
                    
                    #can't stack FORWARD_REPLACEx2 and DROP - have to manually inject w/ scapy's send()
                    #send RST to server - use verbose so you don't print every injection
                    send(server_pkt, verbose=False)
                    #send RST to client
                    send(client_pkt, verbose=False)
                    
                    self.tuple_ban(pkt,ctx)
                    
                    return self.DROP()
                
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
                    if host and url in sni:
                        print(f"Attempted access of restricted site{url}")
                        send(server_pkt, verbose=False)
                        send(client_pkt, verbose=False)
                        
                        self.tuple_ban(pkt,ctx)
                        return self.DROP()

        #else dispatcher will forward packet
        return pkt


    #Use protocol to block SSH instead of trying to block smtp email - specific test/less work?




# run forwarding machine
# current setup - ip table rules route both port 80 and 443 traffic through 8080 - have to handle both
CensorMachine(
    mode=ForwardMachine.MODE.TPROXY,
    port=8080,
    cls=HTTP,
    af=socket.AF_INET
).run()