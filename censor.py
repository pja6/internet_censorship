#https://scapy.readthedocs.io/en/latest/advanced_usage/fwdmachine.html

from scapy.all import *
print("Loaded from:", scapy.__file__)
from scapy.fwdmachine import ForwardMachine
from scapy.layers.http import HTTP,HTTPRequest,HTTPResponse
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
        self.inbound_rules=[
            self.domain_censor_client,
        ]
        
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
                
    def create_rst(self, pkt):
        #create new packet
        tcp_packet = TCP()
        ip_packet = IP()

        old_IP = pkt[IP]
        old_TCP = pkt[TCP]
        
        #set fields for server packet
        server_ip=pkt[IP]
        server_tcp=pkt[TCP]
        
        server_tcp.flags = 'RST'
        
        server_pkt= server_ip/server_tcp

        #set fields for client packet

        tcp_packet.sport = old_TCP.dport
        tcp_packet.flags = 'RST'
        tcp_packet.dport = old_TCP.sport
        tcp_packet.seq = old_TCP.seq
        tcp_packet.ack = old_TCP.ack

        ip_packet.src = old_IP.dst
        ip_packet.dst = old_IP.src
   

        client_pkt = ip_packet/tcp_packet

        return server_pkt, client_pkt
    
    def recalc_pkt(self,pkt):
        #delete lengths/checksums so scapy recalculates
        if pkt.haslayer("IP"):
                del pkt["IP"].len
                del pkt["IP"].chksum
        if pkt.haslayer("TCP"):
            del pkt["TCP"].chksum
        return pkt
    

    def domain_censor_server(self, pkt, ctx):
        
        pkt=self.recalc_pkt(pkt)
        
        #create new packets for server/client with RST flags
        server_pkt, client_pkt = self.create_rst(pkt)
        
        if pkt.haslayer(HTTPRequest):
            host =  pkt[HTTPRequest].Host
            
            for url in self.domain_list:
                if host and url in host:
                    print(f"Attempted access of restricted site{url}")
                    #send RST to server
                    return self.FORWARD_REPLACE(server_pkt)
                    #send RST to client
                    
                    
        #TODO HTTPS
        #elif 
        #else dispatcher will forward packet
        return pkt
    
    def domain_censor_client(self, pkt, ctx):
        pkt = self.recalc_pkt(pkt)
        
        #create new packets for server/client with RST flags
        server_pkt, client_pkt = self.create_rst(pkt)
        
        if pkt.haslayer(HTTPResponse):
            host =  pkt[HTTPResponse].Host
            
            for url in self.domain_list:
                if host and url in host:
                    print(f"Attempted access of restricted site{url}")
                    #send RST to client
                    return self.FORWARD_REPLACE(client_pkt)                    
        #TODO HTTPS
        #elif 
        #else dispatcher will forward pkt                    
        return pkt





# run forwarding machine
# current setup - ip table rules route both port 80 and 443 traffic through 8080 - have to handle both
CensorMachine(
    mode=ForwardMachine.MODE.TPROXY,
    port=8080,
    cls=HTTP,
    af=socket.AF_INET
).run()