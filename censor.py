#https://scapy.readthedocs.io/en/latest/advanced_usage/fwdmachine.html

from scapy.all import *
print("Loaded from:", scapy.__file__)
from scapy.fwdmachine import ForwardMachine
from scapy.layers.http import HTTP
import socket

class NOPFwdMachine(ForwardMachine):
    def xfrmcs(self, pkt, ctx):
        pkt.show()  # we print the client->server packets
        raise self.FORWARD()

    def xfrmsc(self, pkt, ctx):
        pkt.show()  # we print the server->client packets
        raise self.FORWARD()

NOPFwdMachine(
    mode=ForwardMachine.MODE.TPROXY,
    port=8080,
    cls=HTTP,
    af=socket.AF_INET
).run()