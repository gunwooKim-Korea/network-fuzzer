#-*- coding: utf-8 -*-
import sys
from scapy.all import *

'''
tcp_sport = range(0, 2**16) #16bit
tcp_dport = range(0, 2**16) #16bit
tcp_seq = range(0, 2**23) #23bit
#tcp_ack = range(0, 2**32) #32bit
tcp_Control = ["U", "A", "P", "R", "S", "F"] #itertools.permutations(tcp_Control)
#tcp_reserved =
#tcp_flags =
tcp_window = range(0, 2**16) #16bit
tcp_chksum = range(0, 2**16)  #16bit
tcp_urgPos = range(0, 2**16)  #16bit
tcp_option = range(0, 2**24)  # 24bit TCP options
'''
'''
SEG_SEQ : 패킷의 일련 번호
SEG_ACK : 패킷의 확인번호
SEG_FLAG : 제어비트
'''
tcp_padding = range(0, 2**8)  # 8bit

def forgeVersion(dstAddr) :
    ip_version = range(0, 2**4) #4bit
    for i in ip_version:
        packet = IP(dst=dstAddr, version=i)#/TCP(sport=RandShort(), dport=[22,23,53,80], flags="S")
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()


def forgeTos(dstAddr) :
    ip_tos = range(0, 2**8)

    for i in ip_tos:
        packet = IP(dst=dstAddr, tos=i)/TCP(sport=RandShort(), dport=[22,23,53,80], flags="S")
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()


def forgeLen(dstAddr) :
    ip_len = range(0, 2**16) #16bit

    for i in ip_len:
        packet = IP(dst=dstAddr, len=ip_len)
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()

def forgeID(dstAddr) :
    ip_id = range(0, 2**16) #16bit

    for i in ip_id:
        packet = IP(dst=dstAddr, id=ip_id)
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()

def forgeFlags(dstAddr) :
    ip_flags = range(0, 2**3) #3bit

    for i in ip_flags:
        packet = IP(dst=dstAddr, flags=ip_flags)
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()

def forgeFragoffset(dstAddr) :
    ip_fragsOffset = range(0, 2**13) #13bit

    for i in ip_fragsOffset:
        packet = IP(dst=dstAddr, flags=ip_flags)
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()

def forgeProto(dstAddr) :
    ip_protocol = range(0, 2**8) #8bit

    for i in ip_protocol:
        packet = IP(dst=dstAddr, proto=ip_protocol)
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()

'''
def forgeChksum(dstAddr) :
    ip_chksum = range(0, 2**31) #32bit

    for i in ip_chksum:
        packet = IP(dst=dstAddr, chksum=ip_chksum)
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()
'''

def forgeOption(dstAddr) :
    ip_option = range(0, 2**27) #27bit

    for i in ip_option:
        packet = IP(dst=dstAddr, options=ip_option)
        packet.show()
        resultSend = send(packet, inter=0.01)
        resultRecv = sr(packet, timeout=0.1)
        if resultRecv:
            ans,unans=resultRecv
            ans.summary()
'''
packet = IP(dst=sys.argv[1])
packet.show()
result = sr(packet, timeout=1)

if result:
    ans,unans=result
    ans.summary()
'''
forgeVersion(sys.argv[1])
'''
if result:
    ans,unans=result
    ans.summary()
'''
