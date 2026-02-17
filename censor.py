#https://scapy.readthedocs.io/en/latest/advanced_usage/fwdmachine.html

from scapy.fwdmachine import ForwardMachine
from scapy.layers.http import HTTP

class NOPFwdMachine(ForwardMachine):
    def xfrmcs(self, pkt, ctx):
        pkt.show()  # we print the client->server packets
        raise self.FORWARD()

    def xfrmsc(self, pkt, ctx):
        pkt.show()  # we print the server->client packets
        raise self.FORWARD()

# Run it
NOPFwdMachine(
    mode=ForwardMachine.MODE.TPROXY,
    port=80,
    cls=HTTP,  # we specify the class of the payload we are receiving
).run()

# Run it
NOPFwdMachine(
    mode=ForwardMachine.MODE.TPROXY,
    port=443,
    cls=HTTP,
    ssl=True,
).run()