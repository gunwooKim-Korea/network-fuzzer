#-*- coding: utf-8 -*-

#https://mrncciew.files.wordpress.com/2014/10/cwap-mgmt-auth-01.png
'''
	01: Frame Control
	02: Duration/ID
	03: Address 1
	04: Address 2
	05: Address 3
	06: Sequence Control
	07: Address 4
	08: QoS Control
	09: HT Control
	10: Fixed Parameters
'''

'''
Dot11AssoReq
Dot11Auth

Dot11
subtype    : BitField             = (0)
type       : BitEnumField         = (0)
해당 프레임이 control( RTS, CTS, ACK ),
management( authentication, association ),
data Frame인지를 구분하는 비트

00 : Management Frame
subtype :
0000 Association request
0001 Association Response
1011 Authentication

01 : Control Frame
10 : Data Frame
11 : Unused

proto      : BitField             = (0)
FCfield    : FlagsField           = (0) ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]
ID         : ShortField           = (0)
addr1      : MACField             = ('00:00:00:00:00:00')//BSSID (보낼AP의 MAC 주소)
addr2      : Dot11Addr2MACField   = ('00:00:00:00:00:00')//SA (STA의 MAC 주소)
addr3      : Dot11Addr3MACField   = ('00:00:00:00:00:00')//DA (최종 목적지의 MAC 주소)
SC         : Dot11SCField         = (0) //Squence Control
addr4      : Dot11Addr4MACField   = ('00:00:00:00:00:00') // unuse, 경유할 때만 사용
FCS        : FCSField             = (None) //오류제어 필드

algo       : LEShortEnumField     = (0) // 128:NetWork EAP
seqnum     : LEShortField         = (0) //
status     : LEShortEnumField     = (0) // success:00

Dot11AssoReq
cap        : FlagsField           = (0)
listen_interval : LEShortField         = (200)
'''


import sys
from scapy.all import *

class Dot11EltRates(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Rates Information Element"
    # Our Test STA supports the rates 6, 9, 12, 18, 24, 36, 48 and 54 Mbps
    supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(index + 1),
                                     rate))


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

#wlx->kuap->wlp

authhead = Dot11(type=0,\
          subtype=11,\
          proto=1,\
          FCfield='to-DS',\
          ID=1,\
          addr1=wlp1s0,\
          addr2=KUAP, \
          addr3=KUAP,\
          SC=123)
authbody = Dot11Auth(algo=128,seqnum=1)

prbhead = Dot11(type=0,\
                subtype=4,\
                proto=0,\
                FCfield=0,\
                addr1=wlp1s0,\
                addr2=KUAP,\
                addr3=Broadcast,\
                SC=3000)

c = Dot11Elt(ID="SSID",info="KUAP")/\
Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16\x0c\x12\x18\x24')/\
Dot11Elt(ID="DSset",info="\x03\x48\x60\x6c")/\
Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")

c2 = Dot11Elt(ID="SSID",info="")/\
Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16\x0c\x12\x18\x24')/\
Dot11Elt(ID="ESRates",info="\x03\x48\x60\x6c")
#Dot11Elt(ID="HT Capabilites",info="\x00\x01\x00\x00")

tmp = "000018002e4000a02008000000026c09\
a000cb000000cb0040000000ffffffff\
ffffa0d37a21171dffffffffffff2028\
0000010802040b160c12182432043048\
606c2d1a621117ff0000000000000000\
0096000100000000000000000000"

hex = codecs.getdecoder("hex_codec")
s = hex(tmp)[0]

#radio = "\x00\x00\x18\x00\x2e\x40\x00\xa0\x20\x08\x00\x00\x00\x02\x6c\x09\xa0\x00\xcb\x00\x00\x00\xcb\x00"
HT = hex("2d1a621117ff00000000000000000096000100000000000000000000")[0]
HT = hex("2d1a621117ff00000000000000000096000100000000000000000000")[0]
radio = hex("000018002e4000a02008000000026c09a000cb000000cb00")[0]

radioHead = RadioTap(\
    version=0,\
    pad=0,\
    len=24,\
    flags=1,\
    rate=1,\
    tsft=0,\
    dbm_antsignal = 1,\
    dbm_antnoise=0,\
    lock_quality=0,\
    tx_attenuation=0,\
    db_tx_attenuation=0,\
    dbm_tx_power=0,\
    antenna=0,\
    db_antsignal=0,\
    db_antnoise=0)

d = Dot11EltRates()
authPacket = authhead/authbody

prbhead = radio/prbhead/c2/HT

#authPacket.show()
prbhead.show()
result = sendp(prbhead, iface='wlp1s0')
wireshark(prbhead)
if result:
    print("+-------- Receiving Packet INFO")
    ans,unans=result
    ans.summary()
