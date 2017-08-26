#-*- coding: utf-8 -*-
import sys
import socket
import random
import subprocess
from scapy.all import *
import numpy.random as np

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

bind_layers(RadioTap2, Dot11, )

def mutate_packet(pkt, state, lan):
    radiohead = pkt.getlayer(RadioTap2)

    mutateDot11Body = pkt.getlayer(Dot11)
    mutateDot11Body.proto = np.random_integers(0, 256 ** 2 - 1, 1)[0]
    mutateDot11Body.FCfield = np.random_integers(0, 256 - 1, 1)[0]
    mutateDot11Body.ID = np.random_integers(0, 256 ** 2 - 1, 1)[0]
    mutateDot11Body.SC = np.random_integers(0, 256 ** 2 - 1, 1)[0]

    returnPkt = None
    if (state == 0):
        mutatePrbElt = np.bytes(np.random_integers(0, 1514 - 424, 1)[0])
        returnPkt = radiohead/mutateDot11Body/mutatePrbElt

    if (state == 1):

        mutateAuthBody = pkt.getlayer(Dot11Auth)
        mutateAuthBody.algo = np.random_integers(0, 256 ** 2 - 1, 1)[0]
        mutateAuthBody.sequm = np.random_integers(0, 256 ** 2 - 1, 1)[0]
        mutateAuthBody.status = np.random_integers(0, 256 ** 2 - 1, 1)[0]
        # mutateAuthElt = np.bytes(1514 - 54) #not necessary

        returnPkt = radiohead/mutateDot11Body/mutateAuthBody

    if (state == 2):
        mutateAssoBody = pkt.getlayer(Dot11AssoReq)
        mutateAssoBody.cap = np.random_integers(0, 256 ** 2 - 1, 1)[0]
        mutateAssoElt = np.bytes(np.random_integers(0, 1514 - 424, 1)[0])

        returnPkt = radiohead/mutateDot11Body/mutateAssoBody/mutateAssoElt

    sendp(returnPkt, iface=lan, verbose=3)
    mutateList.append(returnPkt)
    return mutateList


# wlp1s0
# wlx909f330d5fd9

def packet_handler(pkt) :

    global alive
    global state
    global lan2
    global KUAP

    # print(lan2.getclass)
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
        if dot11.type == 0 :
            if dot11.addr2 == KUAP and (dot11.addr1 == "a0:d3:7a:21:17:1d"):
                dot11.show()
                if state == 0 and dot11.subtype == 5 :
                    state = 1
                    alive = True
                if state == 1 and dot11.subtype == 11:
                    state = 2
                    alive = True
                if state == 2 and (dot11.subtype == 13):
                    state = 3
                    alive = True
        elif triger and dot11.type == 1 and state == 2 and  (dot11.subtype == 13):
            state = 3
            alive = True

def packetSetting(state, targetAP, lan) :
    DA = targetAP
    SA = lan
    BSSId = Broadcast
    testPacket = None

    radiohead = RadioTap2( \
        version=0, \
        pad=0, \
        len=24, \
        present=4294967296 * 775946400 + 537395200, \
        flags=0, \
        DataRate=2, \
        Channel_freq=27657,
        Channel_flags=160, \
        SSIsignal1=203, \
        RX_Flags=0, \
        SSIsignal2=203)

    prbhead = Dot11(type=0, \
                    subtype=4, \
                    proto=0, \
                    FCfield=0, \
                    addr1=DA, \
                    addr2=SA, \
                    addr3=BSSId, \
                    SC=288)

    DA = targetAP
    BSSId = targetAP
    authhead = Dot11(type=0, \
                     subtype=11, \
                     proto=0, \
                     FCfield=0, \
                     ID=12, \
                     addr1=DA, \
                     addr2=SA, \
                     addr3=BSSId, \
                     SC=288)

    authbody = Dot11Auth(algo=0, seqnum=1)

    hex = codecs.getdecoder("hex_codec")
    HTprb = hex("2d1a6e1117ff00000000000000000096000100000000000000000000")[0]
    #0802 # 0050f204104a000110103a000100100800023148104700106876989b82e8525788e06f19ccfcd79e105400080000000000000000103c00010310020002000010090002000010120002000010210001201023000120102400012010110001201049000600372a000120

    #0806 # 0050f204104a000110103a000100100800023148104700106876989b82e8525788e06f19ccfcd79e105400080000000000000000103c00010310020002000010090002000010120002000010210001201023000120102400012010110001201049000600372a000120
    vendorwps = hex(
        "0050f204104a000110103a000100100800023148104700106876989b82e8525788e06f19ccfcd79e105400080000000000000000103c00010310020002000010090002000010120002000010210001201023000120102400012010110001201049000600372a000120")[
        0]

    #0802 # 506f9a0902020025000605005858045101
    #0806 # 506f9a0902020025000605005858045101
    vendorp2p = hex("506f9a0902020025000605005858045101")[0]
    prbelt = Dot11Elt(ID="SSID", info="KUAP") / \
             Dot11Elt(ID="Rates", info='\x02\x04\x0b\x16\x0c\x12\x18\x24') / \
             Dot11Elt(ID="ESRates", info="\x30\x48\x60\x6c") / HTprb / \
             Dot11Elt(ID="vendor", info=vendorwps) / \
             Dot11Elt(ID="vendor", info=vendorp2p)

    # DA = KUAP
    # SA = wlp1s0
    # BSSId = Broadcast

    HTasso = hex("2d1a661117ff00000000000000000096000100000000000000000000")[0]
    EXC = hex("7f0804000a0200000040")[0]

    assohead = Dot11(
        type=0, \
        subtype=0, \
        proto=0, \
        FCfield=8, \
        addr1=DA, \
        addr2=SA, \
        addr3=BSSId, \
        ID=315, \
        SC=288)

    assobody = Dot11AssoReq(
        cap=8452, \
        listen_interval=10)

    assoelt = Dot11Elt(ID="SSID", info="KUAP") / \
              Dot11Elt(ID="Rates", info='\x02\x04\x0b\x16\x0c\x12\x18\x24') / \
              Dot11Elt(ID="ESRates", info="\x30\x48\x60\x6c") / HTasso / EXC / \
              Dot11Elt(ID="vendor", info="\x00\x50\xf2\x02\x00\x01\x00")

    prbMutatePacket = radiohead / prbhead / Dot11ProbeReq() / prbelt  # /('a'*100) #except elt len= 48
    authMutatePacket = radiohead / authhead / authbody  # /('a'*100) #except elt len= 54
    assoMutatePacket = radiohead / assohead / assobody / assoelt #except elt len= 52

    if(state == 0):
        testPacket = prbMutatePacket
        # print("probe")
        # hexdump(testPacket)
    elif(state == 1):
        print("auth")
        testPacket = authMutatePacket
        # hexdump(testPacket)
    elif(state == 2):
        print("asso")
        testPacket = assoMutatePacket
        # hexdump(testPacket)

    return testPacket

def isAlive(alive):
    if state-1 == 0:
        packetState = "probe packet"
    if state-1 == 1:
        packetState = "auth packet"
    if state-1 == 2:
        packetState = "asso packet"
    if alive:
        print("fuzz false in state " + str(state-1) + packetState)
        mutateList.clear()
        return False
    else:
        print("fuzz success")
        fuzzSuccess()
        return True

def fuzz(testPacket, state, lan):
    mutatePacket = mutate_packet(testPacket, state, lan)

def fuzzSuccess():
    hexdump(mutateList[0])
    mutateList[0].pdfdump("crush2.pdf")

def boundaryMinChk(pkt, state, lan):

    returnPkt = pkt.getlayer(RadioTap2)
    # print("=============================================================================")
    returnPkt[2] = b"0"
    # returnPkt[0].show()
    # print("=============================================================================")
    returnPkt.proto = 0
    returnPkt.FCfield = 0
    returnPkt.ID = 0
    returnPkt.SC = 0

    if (state == 0):
        # np.bytes(0)
        returnPkt = returnPkt/np.bytes(0)
        # mutatePrbElt = 0
        # returnPkt = radiohead/mutateDot11Body#/mutatePrbElt

    if (state == 1):

        returnPkt = pkt.getlayer(Dot11Auth)
        returnPkt.algo = 0
        returnPkt.sequm = 0
        returnPkt.status = 0
        # mutateAuthElt = np.bytes(1514 - 54) #not necessary

        # returnPkt = radiohead/mutateDot11Body/mutateAuthBody

    if (state == 2):
        # returnPkt = pkt.getlayer(Dot11AssoReq)
        returnPkt.cap = 0
        returnPkt.interval_listen = 0
        # mutateAssoElt = 0

        returnPkt = returnPkt/np.bytes(0)

    sendp(returnPkt, iface=lan, count=3)
    mutateList.append(returnPkt)

def boundaryMaxChk(pkt, state, lan):
    returnPkt = pkt.getlayer(RadioTap2)
    # print("=============================================================================")
    returnPkt[2] = b"0"
    # print("=============================================================================")

    returnPkt.proto = 256**2 - 1
    returnPkt.FCfield = 256-1
    returnPkt.ID = 256**2 - 1
    returnPkt.SC = 256**2 - 1

    if (state == 0):
        mutatePrbElt = np.bytes(1514-424)
        returnPkt = returnPkt/mutatePrbElt

    if (state == 1):
        returnPkt = pkt.getlayer(Dot11Auth)
        returnPkt.algo = 256**2 - 1
        returnPkt.sequm = 256**2 - 1
        returnPkt.status = 256**2 - 1
        # mutateAuthElt = np.bytes(1514 - 54) #not necessary

        # returnPkt = radiohead/mutateDot11Body/mutateAuthBody

    if (state == 2):
        # returnPkt = pkt.getlayer(Dot11AssoReq)
        returnPkt.cap = 256**2 - 1
        returnPkt.interval_listen = 256**2 - 1
        returnPkt = returnPkt/np.bytes(1514-424)

        # returnPkt = radiohead/mutateDot11Body/mutateAssoBody/mutateAssoElt

    # returnPkt.show()
    print(lan)
    sendp(returnPkt, iface=lan, count=3)
    mutateList.append(returnPkt)


if __name__ == "__main__":

    triger = False
    KUAP = "90:9f:33:e7:bf:38"
    gggg = "88:36:6c:33:ad:7c"

    lan1 = open('/sys/class/net/%s/address' % sys.argv[1]).read()
    lan2 = open('/sys/class/net/%s/address' % sys.argv[2]).read()[:-1]
    monitorlan = sys.argv[1] #"90:9f:33:0d:5f:d9"  # LAN card can be monitor mode
    notelan = sys.argv[2] #"a0:d3:7a:21:17:1d"  # LAN card embeded laptop

    Broadcast = "ff:ff:ff:ff:ff:ff"

    KITRI09_5G = "90:9F:33:D6:F1:82"
    KITRI09 = "90:9F:33:D6:F1:80"

    mutateList = []

    alive = False
    state = 0

    os.system("sudo ifconfig " + monitorlan + " down")
    os.system("sudo iwconfig " + monitorlan +" mode monitor")
    os.system("sudo ifconfig " + monitorlan + " up")
    os.system("sudo ifconfig " + notelan + " down")
    os.system("iwconfig")

    while True:
        alive = False
        testPacket = packetSetting(state, sys.argv[3], lan2)
        seedPacket = packetSetting(state, sys.argv[3], lan2)

        boundaryMaxChk(testPacket, state, monitorlan)

        sendp(seedPacket, iface=monitorlan, count=2)

        print("waiting packet at state : " + str(state))
        sniff(iface=monitorlan, prn=packet_handler, timeout=30)

        if (state == 2):
            triger = True
        if isAlive(alive) or state == 3:
            break

    while True:
        alive = False
        testPacket = packetSetting(state, sys.argv[3], lan2)
        seedPacket = packetSetting(state, sys.argv[3], lan2)

        boundaryMinChk(testPacket, state, monitorlan)

        sendp(seedPacket, iface=monitorlan, count=2)

        print("waiting packet at state : " + str(state))

        sniff(iface=monitorlan, prn=packet_handler, timeout=30)
        if (state == 2):
            triger = True
        if isAlive(alive) or state == 3:
            break


    while True:
        alive = False
        testPacket = packetSetting(state, sys.argv[3], lan2)
        seedPacket = packetSetting(state, sys.argv[3], lan2)

        for i in range(10):
            fuzz(testPacket, state, monitorlan)
            time.sleep(0.2)
        sendp(seedPacket, iface=monitorlan, verbose=3, count=3)

        print("waiting packet at state : " + str(state))

        sniff(iface=monitorlan, prn=packet_handler, timeout=10)
        if (state == 2):
            triger = True
        if isAlive(alive) or state == 3:
            break
    os.system("sudo ifconfig " + notelan + " up")
    # subprocess.call("toor")
