#-*- coding: utf-8 -*-
import sys
import socket
import random
from scapy.all import *
import binascii

#                     FlagsField('present', None, -64,
#                                ['Ext2', 'Vendor2', 'Reset2', 'b282', 'b272', 'b262', 'b252', 'b242', 'b232', 'b222',
#                                 'VHT2', 'A-MPDU_Status2', 'MCS2', 'b182', 'b172', 'b162', 'b152', 'RX_Flags2',
#                                 'dB_AntNoise2', 'dB_AntSignal2', 'Antenna2', 'dBm_TX_Power2',
#                                 'dB_TX_Attenuation2', 'TX_Attenuation2', 'Lock_Quality2','dBm_AntNoise2', 'dBm_AntSignal2',
#                                 'FHSS2', 'Channel2', 'Rate2', 'Flags2', 'TSFT2',
#                                 #################################################################################
#                                 'Ext', 'Vendor', 'Reset', 'b28', 'b27', 'b26', 'b25', 'b24', 'b23', 'b22',
#                                 'VHT', 'A-MPDU_Status', 'MCS', 'b18', 'b17', 'b16', 'b15', 'RX_Flags',
#                                 'dB_AntNoise', 'dB_AntSignal', 'Antenna', 'dBm_TX_Power',
#                                 'dB_TX_Attenuation', 'TX_Attenuation', 'Lock_Quality', 'dBm_AntNoise', 'dBm_AntSignal',
#                                 'FHSS', 'Channel', 'Rate', 'Flags', 'TSFT']),
from scapy.layers.dot11 import Dot11AssoReq

class RadioTap2(Packet):
    name = "RadioTap dummy"
    fields_desc = [ ByteField('version', 0),
                    ByteField('pad', 0),
                    FieldLenField('len', None, 'notdecoded', '<H', adjust=lambda pkt,x:x+8),
#                    StrLenField('present', "", length_from= lambda pkt:pkt.len-8),
                    FlagsField('present', None, -64, ['TSFT2','Flags2','Rate2','Channel2','FHSS2','dBm_AntSignal2', # 0-5
                                                     'dBm_AntNoise2','Lock_Quality2','TX_Attenuation2','dB_TX_Attenuation2', # 6-9
                                                      'dBm_TX_Power2', 'Antenna2', 'dB_AntSignal2', 'dB_AntNoise2', # 10-13
                                                     'RX_Flags2', 'b152','b162','b172','b182','MCS2','A-MPDU_Status2','VHT2', # 14-21
                                                     'b222','b232','b242','b252','b262','b272','b282','Reset2','Vendor2','Ext2',
                                                     #################################################################################
                                                     'TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',# 0-5
                                                     'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation', 'dB_TX_Attenuation',  # 6-9
                                                     'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',  # 10-13
                                                     'RX_Flags', 'b15', 'b16', 'b17', 'b18', 'MCS', 'A-MPDU_Status', 'VHT',  # 14-21
                                                     'b22', 'b23', 'b24', 'b25', 'b26', 'b27', 'b28', 'Reset', 'Vendor', 'Ext']),
                    ByteField('flags', 0),
                    ByteField('DataRate', 0),
                    ShortField('Channel_freq', 0),
                    FlagsField('Channel_flags', None, -16, ['turbo' ,'CCK' ,'OFDM' ,'2GHz' ,'5GHz' ,'passive', 'dynamic', 'GFSK', 'GSM'
                                                            'staticturbo', 'halfrate', 'quarterrate']),
                    ByteField('SSIsignal1', 0),
                    ShortField('RX_Flags', 0),
                    ByteField('A', 0),
                    ByteField('SSIsignal2', 0),
                    ByteField('Antenna', 0),
                    StrLenField('notdecoded', "", length_from= lambda pkt:pkt.len-8)]

# bind_layers(RadioTap2, Dot11, )

KUAP = "90:9f:33:e7:bf:38"
gggg = "88:36:6c:33:ad:7c"

wlx909f330d5fd9 = "90:9f:33:0d:5f:d9" #LAN card can be monitor mode
wlp1s0 = "a0:d3:7a:21:17:1d" #LAN card embeded laptop

Broadcast = "ff:ff:ff:ff:ff:ff"
KITRI09_5G = "90:9F:33:D6:F1:82"
KITRI09 = "90:9F:33:D6:F1:80"

probelist = []
authlist = []
assolist = []
alive = False
times = 0
def packet_handler(pkt) :
    global alive
    global times
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
        if dot11.type == 0 and (dot11.subtype == 5 or dot11.subtype == 0 or dot11.subtype == 11 or dot11.subtype == 4) \
                and dot11.addr2 == KUAP and (dot11.addr1 == wlp1s0 or dot11.addr1 == wlx909f330d5fd9):
            times += 1
            alive = True

def fuzzSuccess(list):
    hexdump(list[0])
    list[0].pdfdump("crush.pdf")

#wlx->kuap->wlp

DA = KUAP
SA = wlp1s0
BSSId = Broadcast

radiohead = RadioTap2(\
    version=0,\
    pad=0,\
    len=24,\
    present=4294967296*775946400+537395200,\
    flags=0,\
    DataRate=2,\
    Channel_freq=27657,
    Channel_flags=160,\
    SSIsignal1=203,\
    RX_Flags=0,\
    SSIsignal2=203)

prbhead = Dot11(type=0,\
                subtype=4,\
                proto=0,\
                FCfield=0,\
                addr1=DA,\
                addr2=SA,\
                addr3=BSSId,\
                SC=300)

authhead = Dot11(type=0,\
          subtype=11,\
          proto=0,\
          FCfield=0,\
          ID=12,\
          addr1=DA,\
          addr2=SA, \
          addr3=BSSId,\
          SC=1234)

authbody = Dot11Auth(algo=0,seqnum=1)


hex = codecs.getdecoder("hex_codec")
HTprb = HTauth = hex("2d1a6e1117ff00000000000000000096000100000000000000000000")[0]

vendorwps = hex("0050f204104a000110103a000100100800023148104700104b11ed7071b5517ab20bafb7d02dfc31105400080000000000000000103c00010310020002000010090002000010120002000010210001201023000120102400012010110001201049000600372a000120")[0]
vendorp2p = hex("506f9a0902020025000605005858045101")[0]

prbelt = Dot11Elt(ID="SSID",info="KUAP")/\
Dot11Elt(ID="Rates",info='\x02\x04\x0b\x16\x0c\x12\x18\x24')/\
Dot11Elt(ID="ESRates",info="\x30\x48\x60\x6c")/HTprb/\
Dot11Elt(ID="vendor", info=vendorwps)/\
Dot11Elt(ID="vendor", info=vendorp2p)


# DA = KUAP
# SA = wlp1s0
# BSSId = Broadcast

HTasso = hex("2d1a661117ff00000000000000000096000100000000000000000000")[0]
EXC = hex("7f080400000000000040")[0]


assohead = Dot11(
    type=0,\
    subtype=0,\
    proto=1,\
    FCfield=0,\
    addr1=DA,\
    addr2=wlp1s0,\
    addr3=DA,\
    ID=315,\
    SC=80)

assobody = Dot11AssoReq(
        cap=8452,\
        listen_interval=10)


assoelt = Dot11Elt(ID="SSID",info="KUAP")/\
Dot11Elt(ID="Rates",info='\x02\x04\x0b\x16\x0c\x12\x18\x24')/\
Dot11Elt(ID="ESRates",info="\x30\x48\x60\x6c")/HTasso/EXC/\
Dot11Elt(ID="vendor", info="\x00\x50\xf2\x02\x00\x01\x00")

prbSeed = prbMutate = radiohead/prbhead/Dot11ProbeReq()/prbelt#/('a'*100)
authSeed = authMutatePacket = radiohead/authhead/authbody#/('a'*100)
assoSeed = assoMutatePacket = radiohead/assohead/assobody/assoelt

# wireshark(prbPacket)

# wlp1s0
# wlx909f330d5fd9

# rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))

for i in range(100):
    prbMutate.SC = random.randrange(30, 65536)
    prbMutate.Id = random.randrange(30, 65536)
    prbMutate.proto = random.randrange(30, 65536)
    prbMutate.FCfield = random.randrange(30, 65536)
    prbMutate.FCS = random.randrange(30, 65536)
    probereqPacket = prbMutate/ ('a' * 1290)
    probelist.append(probereqPacket)
    result = sendp(probereqPacket, iface="wlx909f330d5fd9", verbose=3)
    time.sleep(0.1)

prbMutate.SC = 65535
prbMutate.Id = 65535
prbMutate.proto = 65535
prbMutate.FCfield = 65535
prbMutate.FCS = 65535
probereqPacket = prbMutate / ('a' * 1290)
probelist.append(prbMutate)
result = sendp(prbMutate, iface="wlx909f330d5fd9", verbose=3)
result = sendp(prbSeed, iface="wlx909f330d5fd9", verbose=3)


# result = sendp(prbSeed, iface="wlx909f330d5fd9", verbose=3)
# result = sendp(authPacket, iface="wlx909f330d5fd9", verbose=3, count=5)
# result = sendp(assoPacket, iface="wlx909f330d5fd9", verbose=3, count=5)

# result = srp(prbPacket, iface="wlx909f330d5fd9", verbose=3, timeout=10, retry=True)

# result = srploop(prbPacket, verbose=1, iface="wlx909f330d5fd9", count=10)
# time.sleep(10)

# receivedPacket=rawSocket.recv(4096)
# hexdump(receivedPacket)

# rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
# rawSocket.bind(("wlx909f330d5fd9", 0x0003))
# ap_list = set()
# while True :
#     pkt = rawSocket.recvfrom(2048)[0]
#     if pkt[26] == "\x80" :
# 	    if pkt[36:42] not in ap_list and ord(pkt[63]) > 0:
# 		    ap_list.add(pkt[36:42])
# 		    print ("SSID: %s  AP MAC: %s" % (pkt[64:64 +ord(pkt[63])], pkt[36:42].encode('hex')))
print("waiting packet")
time.sleep(40)

sniff(iface="wlx909f330d5fd9", prn=packet_handler, timeout = 30)

if alive :
    print("fuzz false")
else :
    print("fuzz success")
    fuzzSuccess(probelist)




# rersult = srp(authPacket, iface="wlx909f330d5fd9", verbose=1)


# result = sendp(prbPacket, iface="wlp1s0", verbose=1)
# result = sendp(authPacket, iface="wlp1s0", verbose=1)
# result = sendp(assoPacket, iface="wlp1s0", verbose=1)



    # s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    # s.bind(("wlp1s0", ETH_P_ALL))
    # for i in range(100):
    # s.send(auth, ETH_P_ALL)
    # revpacket = s.recv(2048)[0]
    # print("4")
    # print(revpacket)
    # print("5")
    #
    # for i in range(1000000) :
    #     s.sendto(radio, ("192.168.0.1", 0))
