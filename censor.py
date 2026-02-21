#https://scapy.readthedocs.io/en/latest/advanced_usage/fwdmachine.html

from scapy.all import *
print("Loaded from:", scapy.__file__)
from scapy.fwdmachine import ForwardMachine
from scapy.layers.http import HTTP,HTTPRequest
import socket
import time

class NOPFwdMachine(ForwardMachine):
    
    
    #client-server dispatcher - doesn't handle protocols just checks against egress rules
    def xfrmcs(self, pkt, ctx):
      
        #strategy model pipeline
        for rule in self.outbound_rules:
            result = rule( pkt, ctx, self)

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
            result = rule( pkt, ctx, self)

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
        self.censor_dict={}
        self.inbound_rules=[]
        self.outbound_rules=[
            self.keyword_censor,
            
            ]

    
    #censor list helper method
    def tuple_ban(self, pkt, ctx):
       f_tuple=(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
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
           
    
    def keyword_censor(self, pkt, ctx, machine):
       
        if pkt.haslayer(HTTPRequest):
            
            http = pkt[HTTPRequest]
            
            for keyword in self.ban_list:
                if keyword in http.Path:
                    print(f"Keyword: {keyword} recognized - ")
                    
                    self.tuple_ban(pkt, ctx)

                    return machine.DROP()
                
        return pkt
                
            




# run forwarding machine
# current setup - ip table rules route both port 80 and 443 traffic through 8080 - have to handle both
CensorMachine(
    mode=ForwardMachine.MODE.TPROXY,
    port=8080,
    cls=HTTP,
    af=socket.AF_INET
).run()