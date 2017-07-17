#-*- coding: utf-8 -*-


import sys
from socket import *
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

class RadioTap2(Packet):
    name = "RadioTap2 dummy"
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

def packet_handler(pkt) :
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11):
        # do your stuff here
        print(pkt.show())

#authPacket
KUAP = "90:9F:33:E7:BF:38"
gggg = "88:36:6C:33:AD:7C"

wlx909f330d5fd9 = "90:9F:33:0D:5F:D9"
wlp1s0 = "A0:D3:7A:21:17:1D"

Broadcast = "FF:FF:FF:FF:FF:FF"
kitri = "90:9F:33:D6:F1:82"
#wlx->kuap->wlp


DA = KUAP
SA = wlp1s0
BSSId = KUAP

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
HT = hex("2d1a621117ff00000000000000000096000100000000000000000000")[0]

elt = Dot11Elt(ID="SSID",info="KITRI_5G")/\
Dot11Elt(ID="Rates",info='\x02\x04\x0b\x16\x0c\x12\x18\x24')/\
Dot11Elt(ID="ESRates",info="\x30\x48\x60\x6c")/HT


#radio = "\x00\x00\x18\x00\x2e\x40\x00\xa0\x20\x08\x00\x00\x00\x02\x6c\x09\xa0\x00\xcb\x00\x00\x00\xcb\x00"

radio = hex("000018002e4000a02008000000026c09a000cb000000cb00")[0]

#4294967295, 775946400, 537395200
#'Flags+Rate+Channel+dBm_AntSignal+RX_Flags+Reset+Ext+dBm_AntSignal2+Antenna2',\
radioHead2 = RadioTap2(\
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

# prbreq = prbhead/Dot11ProbeReq()/elt/('a'*100)#/elt/('a'*100)
# prbreq.show()
# hexdump(prbreq)

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

#
# for i in range(1000000) :
#     s.sendto(radio, ("192.168.0.1", 0))


# wireshark(prbreq)
authPacket = radioHead2/authhead/authbody#/('a'*1000)

hexdump(authPacket)
# wireshark(authPacket)
#
authPacket.show()
# prbhead.show()
result = sr(authPacket, iface="wlx909f330d5fd9")

if result:
    print("+-------- Receiving Packet INFO")
    ans,unans=result
    ans.summary()
