from scapy.all import *
import binascii,json
typeCodes={
   "00": "Openflow Hello Message",
   "01": "Openflow Error Message",
   "05": "Openflow Feature Request",
   "06": "Openflow Feature Reply",
   "14": "Openflow Modification"
}

controllerIP = "192.168.56.103"
count = 1
connections = {}
dpids = {}
switchRecords ={}
def checkOpenFlowConnection(packet):
    global count
    #print("Processing Packet "+ str(count))
    if TCP in packet:
       if packet[TCP].dport==6653 or packet[TCP].sport==6653:
          if Raw in packet:   # Process Openflow payload
             #extract Openflow type of message
             payload = binascii.hexlify(packet[Raw].load).decode("utf-8")
             if (payload[0:2]=="04" or payload[0:2]=="01") and payload[2:4] in typeCodes:
                print(packet[IP].src +" -----------"+typeCodes[payload[2:4]]+"-----------> "+packet[IP].dst)
                if (payload[2:4] == "05" or payload[2:4] == "14") and packet[IP].src == controllerIP:
                   tupple = (str(packet[IP].dst),str(packet[TCP].dport))
                   connections[tupple]="Connected"
                   #print(connections)
                elif payload[2:4] == "01" and packet[IP].dst == controllerIP:
                   tupple = (str(packet[IP].src),str(packet[TCP].sport))
                   connections[tupple]="Not Connected"
                elif payload[2:4] == "06" and packet[IP].dst == controllerIP:
                   tupple = (str(packet[IP].src), str(packet[TCP].sport))
                   dpids[tupple] = payload[16:32]
                if connections:
                   print(connections)
                if dpids:
                   print(dpids)
                updateDataToFile()
    count = count + 1

def updateDataToFile():
    for key in connections.keys():
       switchIP,switchPort = key
       if key not in dpids:
          return
       switchdpid = dpids[key]
       switchRecords[switchdpid] = { "ip_address": switchIP, "socket_port": switchPort ,"status": connections[key] }
    json.dumps(switchRecords)
    with open("switch_Records.json",'w') as f:
       json.dump(switchRecords,f,indent=4)
    return
packets = sniff(filter='tcp',prn=checkOpenFlowConnection , iface='enp0s3')


