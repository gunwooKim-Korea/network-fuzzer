import sys
from scapy.all import *

packet = IP(dst=sys.argv[1])/TCP(sport=RandShort(), dport=[22,23,53,80], flags="S")
print "+-------- Sending Packet INFO"
packet.show()
result = sr(packet, timeout=1)
if result:
    print "+-------- Receiving Packet INFO"
    ans,unans=result
    ans.summary()
