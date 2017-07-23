#-*- coding: utf-8 -*-
import sys
import socket
from scapy.all import *

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

bind_layers(RadioTap2, Dot11, )

KUAP = "90:9f:33:e7:bf:38"
gggg = "88:36:6c:33:ad:7c"

wlx909f330d5fd9 = "90:9f:33:0d:5f:d9" #LAN card can be monitor mode
wlp1s0 = "a0:d3:7a:21:17:1d" #LAN card embeded laptop

Broadcast = "ff:ff:ff:ff:ff:ff"
KITRI09_5G = "90:9F:33:D6:F1:82"
KITRI09 = "90:9F:33:D6:F1:80"

def packet_handler(pkt) :
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
        if dot11.subtype == 5 and dot11.addr2 == KUAP and dot11.addr1 == wlp1s0:
            print("come resp !")

#wlx->kuap->wlp


DA = KUAP
SA = wlx909f330d5fd9
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

authhead = Dot11(type=0,\
          subtype=11,\
          proto=0,\
          FCfield=0,\
          ID=1,\
          addr1=DA,\
          addr2=SA, \
          addr3=BSSId,\
          SC=123)
authbody = Dot11Auth(algo=0,seqnum=1)

prbhead = Dot11(type=0,\
                subtype=4,\
                proto=0,\
                FCfield=0,\
                addr1=DA,\
                addr2=SA,\
                addr3=BSSId,\
                SC=300)

hex = codecs.getdecoder("hex_codec")
HTauth = hex("2d1a621117ff00000000000000000096000100000000000000000000")[0]

prbelt = Dot11Elt(ID="SSID",info="KUAP")/\
Dot11Elt(ID="Rates",info='\x02\x04\x0b\x16\x0c\x12\x18\x24')/\
Dot11Elt(ID="ESRates",info="\x30\x48\x60\x6c")/HTauth


DA = KUAP
SA = wlp1s0
BSSId = Broadcast

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

prbPacket = radiohead/prbhead/Dot11ProbeReq()/prbelt
authPacket = radiohead/authhead/authbody#/('a'*100)
assoPacket = radiohead/assohead/assobody/assoelt

# hexdump(prbPacket)
# wireshark(prbPacket)
# wlp1s0
# wlx909f330d5fd9

# result = srp(prbPacket, iface="wlx909f330d5fd9", verbose=1)

# sendp(authPacket, iface="wlx909f330d5fd9", verbose=1, count=100)
result = srp(authPacket, verbose=3, iface="wlx909f330d5fd9")

# sniff(iface="wlx909f330d5fd9", prn=packet_handler)
print("1")
if result:
    print("+-------- Receiving Packet INFO")
    ans, unans = result
    ans.summary()
# print("2")
# rersult = srp(authPacket, iface="wlx909f330d5fd9", verbose=1)
# if result:
#     print("+-------- Receiving Packet INFO")
#     ans, unans = result
#     ans.summary()
#
# for i in range(100):
#     result = srp(assoPacket, iface="wlx909f330d5fd9", verbose=1)
#
#     if result:
#         print("+-------- Receiving Packet INFO")
#         ans, unans = result
#         ans.summary()

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
# tmp = hex("000018002e4000a02008000000026c09a000dd000000dd0040000000ffffffffffffa0d37a21171dffffffffffff80080000010802040b160c12182432043048606c2d1a621117ff00000000000000000096000100000000000000000000")[0]
# tmp2 = hex("6c09a000dd000000dd0040000000ffffffffffffa0d37a21171dffffffffffff80080000010802040b160c12182432043048606c2d1a621117ff00000000000000000096000100000000000000000000")[0]
# auth = hex("000018002e4000a02008000000026c09a000df000000df00b0003a01909f33e7bf38a0d37a21171d909f33e7bf387000000001000000")[0]
