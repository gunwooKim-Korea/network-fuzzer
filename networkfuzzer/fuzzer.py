import sys
from scapy.all import *

ip_TOS = [111, 110, 101, 100, 011, 010, 001, 000]
ip_Flags = [0,1,2]
ip_Protocol = []

tcp_Control = ["U", "A", "P", "R", "S", "F"] #itertools.permutations(tcp_Control)
#for combi_Cont in
#    tcp_Control =

for tos_i in ip_TOS:
    packet = IP(dst=sys.argv[1], tos=ip_TOS)/ \
    TCP(sport=RandShort(), dport=RandShort(), \
    flags= itertools.permutations(tcp_Control))

    result = sr(packet, timeout=1)

    if result:
        print "+-------- Receiving Packet INFO"
        ans,unans=result
        ans.summary()
