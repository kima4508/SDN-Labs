from scapy.all import *
import binascii,json,time,requests
from datetime import datetime
import os,json
from threading import Thread, Lock

typeCodes={
   "00": "Openflow Hello Message",
   "01": "Openflow Error Message",
   "05": "Openflow Feature Request",
   "06": "Openflow Feature Reply",
   "14": "Openflow Modification",
   "0a": "Openflow Packet-In"
}
blockedPorts = {}
packetIns= {}
prevTime = datetime.now()

def checkPacketInMessages(packet):
    #print("Processing new packet")
    if TCP in packet and (packet[TCP].dport==6633 or packet[TCP].dport==6653):
        if Raw in packet:
            payload = binascii.hexlify(packet[Raw].load).decode("utf-8")
            if payload[2:4] == "0a":
                global packetIns
                print("Packet In detected ---> "+datetime.now().strftime("%H:%M:%S"))
                socket = (packet[IP].src,packet[TCP].sport)
                lock.acquire()
                if not socket in packetIns:
                    packetIns[(socket)] = 0
                else:
                    packetIns[(socket)] = packetIns[socket] + 1
                lock.release()
                #print("Packet In Count = "+str(packetIns[socket]))
                #print(packetIns)

#Thread Func1  - Detect Packet- In messages
def sniffPacketIn():
    sniff(filter='tcp',prn=checkPacketInMessages , iface='enp0s3')

#thread Func2  - Reset the Packet -In otherwise every Ip will be blocked
def reset():        
    while(True):
        currenTime = datetime.now()
        difference = prevTime - currenTime
        diffMin = difference.total_seconds()/60
        if diffMin > 5:
            global packetIns
            packetIns = {}
            print(" Packet In count set to zero ")
        else:
            time.sleep(10)
        
#thread Func3 - If 100 Packet -In received in 5 minutes then install ip table rule
def blockAttacker():
    while (True):
        lock.acquire()
        for ip,port in packetIns.keys():
            if packetIns[(ip,port)] > 100 and port not in blockedPorts:
                blockedPorts[port]= True
                print(ip+" "+str(port))
                print("Attack detected from socket - "+ ip +": "+str(port))
                os.system("sudo iptables -A INPUT -p tcp --sport "+str(port)+" -j DROP")
                print("#################### Blocking source Port ==> "+str(port))
        lock.release()
#MAIN
print("Tracking Pakcet - In")
lock = Lock()
thread = Thread(target=sniffPacketIn,)
thread.start()
thread = Thread(target=reset,)
thread.start()
thread = Thread(target=blockAttacker,)
thread.start()