import requests
import json,time

#ports to path mapping
portsToPathMapping={
        (1,2) : "ovs1-ovs6-ovs7-ovs5",
        (2,3) : "ovs1-ovs8-ovs5",
        (3,4) : "ovs1-ovs2-ovs3-ovs4-ovs5"
    }

urlR1 = "http://192.168.56.103:8080/stats/port/0000000000000001"
urlR5 = "http://192.168.56.103:8080/stats/port/0000000000000005"
headers = {
  'Content-Type': 'application/json'
}

def getPath(changeRate):

    egressPortOnR1 = -1
    rxDelta,txDelta = changeRate["R1"][4]
    if rxDelta > 0 and txDelta >0 :
        for i in [1,2,3]:
            rxDelta,txDelta = changeRate["R1"][i]
            if rxDelta >0 and txDelta >0:
                egressPortOnR1 = i

    egressPortOnR5 = -1
    rxDelta,txDelta = changeRate["R5"][1]
    if rxDelta > 0 and txDelta >0 :
        for i in [2,3,4]:
            rxDelta,txDelta = changeRate["R5"][i]
            if rxDelta >0 and txDelta > 0:
                egressPortOnR5 = i

    if (egressPortOnR1,egressPortOnR5) in portsToPathMapping:
        return portsToPathMapping[(egressPortOnR1,egressPortOnR5)]
    else:
        print("Change Logic")
        print((egressPortOnR1,egressPortOnR5))
        return ""

def getChange(beforeTraffic,afterTraffic):
    changeRate={}
    changeRate["R1"]=dict()
    changeRate["R5"]=dict()

    print("INPUT")
    print(beforeTraffic)
    print(afterTraffic)
    
    for router in changeRate.keys():
        newDict = dict()
        for i in range(1,5):
            bRX,bTX = beforeTraffic[router][i]
            aRX,aTX = afterTraffic[router][i]

            newDict[i] = tuple([aRX-bRX,aTX-bTX])
        changeRate[router]=newDict
    print("Change Rate is ")
    print(changeRate)

    return changeRate

def capturePortStats():
    responseR1 = requests.request("GET", urlR1, headers=headers)
    responseR5 = requests.request("GET", urlR5, headers=headers)
    #process Response R1
    statsR1={}
    statsR5={}
    data = responseR1.json()
    for portDescription in data["1"]:
        if portDescription["port_no"] == 'LOCAL':
            continue
        rxCount = int(portDescription["rx_packets"])
        txCount = int(portDescription["tx_packets"])
        statsR1[portDescription["port_no"]]= (rxCount,txCount)

    #process response of R5
    data = responseR5.json()
    for portDescription in data["5"]:
        if portDescription["port_no"] == 'LOCAL':
            continue
        rxCount = int(portDescription["rx_packets"])
        txCount = int(portDescription["tx_packets"])
        statsR5[portDescription["port_no"]]= (rxCount,txCount)
    print("R1 port stats") 
    print(statsR1)
    print("R5 port stats")
    print(statsR5)

    finalDict = dict()
    finalDict["R1"]=statsR1
    finalDict["R5"]=statsR5

    return finalDict

    








# def checkTrafficPath():
#     currentR1={}
#     currentR5={}
#     flagR1=flagR5=True
#     changeR1={} 
#     changeFoundR1 = False
#     changeR5={}
#     changeFoundR5 = False
#     while True:
#         #print("-----------------------------------------------------------------------------------------------------------------")
#         responseR1 = requests.request("GET", urlR1, headers=headers)
#         responseR5 = requests.request("GET", urlR5, headers=headers)
#         dataR1 = responseR1.json()
#         dataR5 = responseR5.json()
#         for d in dataR1['1']:
#             if changeFoundR1:
#                 break
#             if d["port_no"] == 'LOCAL':
#                 continue
#             if flagR1:
#                 currentR1[int(d["port_no"])]= (int(d["rx_packets"]),int(d["tx_packets"]))
#                 continue
        
#             rx,tx = currentR1[int(d["port_no"])]

#             if int(d["rx_packets"])-rx > 0 and int(d["tx_packets"])-tx >0:
#                 changeR1[int(d["port_no"])] = (int(d["rx_packets"])-rx,int(d["tx_packets"])-tx)
#                 changeFoundR1=True

            
#             currentR1[int(d["port_no"])]= (int(d["rx_packets"]),int(d["tx_packets"]))
#         flagR1=False

#         for d in dataR5['5']:
#             if changeFoundR5:
#                 break
#             if d["port_no"] == 'LOCAL':
#                 continue
#             if flagR5:
#                 currentR5[int(d["port_no"])]= (int(d["rx_packets"]),int(d["tx_packets"]))
#                 continue
        
#             rx,tx = currentR5[int(d["port_no"])]

#             if int(d["rx_packets"])-rx > 0 and int(d["tx_packets"])-tx >0:
#                 changeR5[int(d["port_no"])] = (int(d["rx_packets"])-rx,int(d["tx_packets"])-tx)
#                 changeFoundR5=True

#             #print(str(d["port_no"])+"             "+str(int(d["rx_packets"])-rx)+"                 "+str(int(d["tx_packets"])-tx)+"     ")

#             currentR5[int(d["port_no"])]= (int(d["rx_packets"]),int(d["tx_packets"]))
#         flagR5=False

#         if changeFoundR1 and changeFoundR5:
#             print(changeR1)
#             print(changeR5)
#             break

#     print("Change Set")
#     print(changeR1)
#     print(changeR5)
#     for ports in portsToPathMapping:
#         r1port,r5port = ports
#         print(ports)
        
#         if changeR1[r1port] - changeR5[r5port] < 10:
#             print("Path taken -->"+portsToPathMapping[(r1port,r5port)])
#     return portsToPathMapping[(r1port,r5port)]

# #checkTrafficPath()