from scapy.all import *
import binascii,json,time,requests
import datetime
from threading import Thread, Lock

typeCodes={
   "00": "Openflow Hello Message",
   "01": "Openflow Error Message",
   "05": "Openflow Feature Request",
   "06": "Openflow Feature Reply",
   "14": "Openflow Modification",
   "0a": "Openflow Packet-In"
}

#Mutex Object
countEvery5seconds = 0

totalPackets =0 


def checkPacketInMessages(packet):
    #print("Processing new packet")
    global countEvery5seconds
    if TCP in packet and (packet[TCP].dport==6633 or packet[TCP].dport==6653):
        if Raw in packet:
            payload = binascii.hexlify(packet[Raw].load).decode("utf-8")
            if payload[2:4] == "0a":
                global totalPackets
                print("Packet In detected ---> "+datetime.datetime.now().strftime("%H:%M:%S") +"   #Total =>"+ str(totalPackets))
                lock.acquire()
                print("Packet In")
                print(packet)
                print(payload)
                countEvery5seconds = countEvery5seconds+1 
                lock.release()
                totalPackets = totalPackets + 1
#Thread Func1 
def sniffPacketIn():
    sniff(filter='tcp',prn=checkPacketInMessages , iface='enp0s3')


#Thread Func2
def sendInfoToFlask():
    while(True):
        global countEvery5seconds
        lock.acquire()
        info = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "count": countEvery5seconds
        }  
        countEvery5seconds = 0
        lock.release()
        response = requests.request("POST", "http://192.168.100.254:9000/updatePacketInCount", 
                                    headers={ 'Content-Type': 'application/json'},  
                                    data=json.dumps(info))
        print(response.text)
        time.sleep(5)

   

#MAIN
print("Client Initiated")
lock = Lock()
thread = Thread(target=sniffPacketIn,)
thread.start()
thread = Thread(target=sendInfoToFlask,)
thread.start()




