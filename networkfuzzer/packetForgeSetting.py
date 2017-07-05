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
#90:9F:33:E7:BF:39 KUAP
#88:36:6C:33:AD:7C gggg

#90:9F:33:0D:5F:D9 wlx909f330d5fd9
#A0:D3:7A:21:17:1D wlp1s0

dstAddr = '90:9F:33:E7:BF:39'
srcAddr = '90:9F:33:0D:5F:D9'
fdstAddr = '90:9F:33:E7:BF:39'

a = Dot11(type=00,\
          subtype=1011,\
          proto=4,\
          FCfield="to-DS",\
          ID=1,\
          addr1=dstAddr,\
          addr2=srcAddr,\
          addr3=fdstAddr)
b = Dot11Auth(algo=128,seqnum=1)

c = Dot11Elt(ID="SSID",info=RandString(RandNum(1,50)))/\
Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/\
Dot11Elt(ID="DSset",info="\x03")/\
Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")

d = Dot11EltRates()
packet = a/b/('a'*500)
t = fuzz(packet)
#packet.show()
t.show()
result = srp(t)

if result:
    print("+-------- Receiving Packet INFO")
    ans,unans=result
    ans.summary()
