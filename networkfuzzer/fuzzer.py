#-*- coding: utf-8 -*-
import sys
from scapy.all import *
from itertools import combinations
import random

'''
#tcp_reserved =
#tcp_flags =
'''
'''
SEG_SEQ : 패킷의 일련 번호
SEG_ACK : 패킷의 확인번호
SEG_FLAG : 제어비트
'''
tcp_padding = range(0, 2**8)  # 8bit

#IP forge Method
###############################################################################
def forgeIpVersion(packetIP) :
    ip_version = range(0, 2**4) #4bit
    i = random.choice(ip_version)
    packetIP = IP(version=i)#/TCP(sport=RandShort(), dport=[22,23,53,80], flags="S")
    return packetIP

def forgeIpTos(packetIP) :
    ip_tos = range(0, 2**8)
    i = random.choice(ip_tos)
    packetIP = IP(tos=i)
    return packetIP

def forgeIpLen(packetIP) :
    ip_len = range(0, 2**16) #16bit
    i = random.choice(ip_len)
    packetIP = IP(len=i)
    return packetIP

def forgeIpID(packetIP) :
    ip_id = range(0, 2**16) #16bit
    i = random.choice(ip_id)
    packetIP = IP(id=i)
    return packetIP

def forgeIpFlags(packetIP) :
    ip_flags = range(0, 2**3) #3bit
    i = random.choice(ip_flags)
    packetIP = IP(flags=i)
    return packetIP

def forgeIpFragoffset(packetIP) :
    ip_fragsOffset = range(0, 2**13) #13bit
    i = random.choice(ip_fragsOffset)
    packetIP = IP(flags=i)
    return packetIP

def forgeIpProto(packetIP) :
    ip_protocol = range(0, 2**8) #8bit
    i = random.choice(ip_protocol)
    packetIP = IP(proto=i)
    return packetIP

def forgeIpChksum(packetIP) :
    ip_chksum = range(0, 429496700L) #32bit
    i = random.choice(ip_chksum)
    packetIP = IP(chksum=i)
    return packetIP

def forgeIpOption(packetIP) :
    ip_option = range(0, 2**27) #27bit
    i = random.choice(ip_option)
    packetIP = IP(options=i)
    return packetIP

###############################################################################



#TCP forge Method
###############################################################################
def forgeTCPSport(packetTCP):
    tcp_sport = range(0, 2**16) #16bit
    i = random.choice(tcp_sport)
    packetTCP = TCP(sport=i)
    return packetTCP

def forgeTCPDport(packetTCP):
    tcp_dport = range(0, 2**16) #16bit
    i = random.choice(tcp_dport)
    packetTCP = TCP(dport=i)
    return packetTCP

def forgeTCPSeq(packetTCP):
    tcp_seq = range(0, 2**23) #23bit
    i = random.choice(tcp_seq)
    packetTCP = TCP(seq=i)
    return packetTCP

def forgeTCPAck(packetTCP):
    tcp_ack = range(0, 2**32) #32bit
    i = random.choice(tcp_ack)
    packetTCP = TCP(ack=i)
    return packetTCP

def forgeTCPFlags(packetTCP):
    tcp_flags = ["U", "A", "P", "R", "S", "F"] #itertools.permutations(tcp_Control)    i = random.choice(tcp_ack)
    i = random.choice(tcp_flags)
    packetTCP = TCP(flags=i)
    return packetTCP

def forgeTCPWindow(packetTCP):
    tcp_window = range(0, 2**16) #16bit
    i = random.choice(tcp_window)
    packetTCP = TCP(window=i)
    return packetTCP

def forgeTCPChksum(packetTCP):
    tcp_chksum = range(0, 2**16) #16bit
    i = random.choice(tcp_chksum)
    packetTCP = TCP(chksum=i)
    return packetTCP

def forgeTCPUrgPos(packetTCP):
    tcp_urgPos= range(0, 2**16) #16bit
    i = random.choice(tcp_urgPos)
    packetTCP = TCP(urgptr=i)
    return packetTCP

def forgeTCPOptions(packetTCP):
    tcp_option = range(0, 2**24)  # 24bit TCP options
    i = random.choice(tcp_option)
    packetTCP = TCP(options=i)
    return packetTCP
###############################################################################

packetIP = IP()
packetIP.dst = sys.argv[1]
method = None;

#IP setting
while method != 0:
    method = input("input IP method \n")
    if (method == 1):
        packetIP = forgeIpVersion(packetIP)
    elif (method == 2):
        packetIP = forgeIpTos(packetIP)
    elif (method == 3):
        packetIP = forgeIpLen(packetIP)
    elif (method == 4):
        packetIP = forgeIpID(packetIP)
    elif (method == 5):
        packetIP = forgeIpFlags(packetIP)
    elif (method == 6):
        packetIP = forgeIpFragoffset(packetIP)
    elif (method == 7):
        packetIP = forgeIpProto(packetIP)
    elif (method == 8):
        packetIP = forgeIpChksum(packetIP)
    elif (method == 9):
        packetIP = forgeIpOption(packetIP)

packetTCP = TCP();

method = None;

#TCP setting
while method != 0:
    method = input("input TCP method \n")
    if (method == 1):
        packetTCP = forgeTCPSport(packetTCP)
    elif (method == 2):
        packetTCP = forgeTCPDport(packetTCP)
    elif (method == 3):
        packetTCP = forgeTCPSeq(packetTCP)
    elif (method == 4):
        packetTCP = forgeTCPAck(packetTCP)
    elif (method == 5):
        packetTCP = forgeTCPFlags(packetTCP)
    elif (method == 6):
        packetTCP = forgeTCPWindow(packetTCP)
    elif (method == 7):
        packetTCP = forgeTCPChksum(packetTCP)
    elif (method == 8):
        packetTCP = forgeTCPUrgPos(packetTCP)
    elif (method == 9):
        packetTCP = forgeTCPOptions(packetTCP)


packet = packetIP/packetTCP

packet.show()
resultRecv = sr(packet, timeout=0.1)
if resultRecv:
    ans,unans=resultRecv
    ans.summary()
