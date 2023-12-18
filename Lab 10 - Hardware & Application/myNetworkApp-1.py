# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import warnings 
warnings.filterwarnings(action='ignore',module='.*CryptographyDeprecationWarning.*')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from ryu.base import app_manager
from binascii import hexlify
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3,ether,ofproto_parser
from ryu.lib.packet import packet as ryuPacket
from ryu.lib.packet import ethernet as ryuEthernet
from ryu.lib.packet import ether_types 
from ryu.lib.packet import udp,arp,ipv4,icmp
import time,dpkt,requests,json
from scapy.all import *

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dhcpServerIP = "10.0.0.1"
        
        # maintain a ARP table to avoid broadcasts
        self.arp_table = {
                            self.dhcpServerIP : "00:16:9d:e5:c6:21"
                        }
        
        # a map of ports facing the DHCP server from perspective of the host
        self.portTowardsDHCPServer = {
            "172.16.10.1": [5,2],
            "172.16.10.2": [2],
            "172.16.10.3": [2],
            "172.16.10.4": [18], 
            "172.16.10.5": [17]
        }

        # a map of ports facing away from DHCp server from the perspective of the host
        self.portFromDHCPServer = {
            "172.16.10.1": [4],
            "172.16.10.2": [1,3],
            "172.16.10.3": [1],
            "172.16.10.4": [17], 
            "172.16.10.5": [18]
        }

        # a state of ports on each switch either Up/Down
        self.ports = {
            "172.16.10.1": {
                5: True,
                2: True,
                4: True
            },
            "172.16.10.2": {
                1: True,
                2: True,
                3: True
            },
            "172.16.10.3": {
                2: True,
                1: True
            },
            "172.16.10.4": {
                18: True,
                17: True
            }, 
            "172.16.10.5": {
                17: True,
                18: True
            }
        }

        # a network map to make sense of which ports connects a switch to which other switch
        self.networkMap = {
            "172.16.10.1": {
                5: "172.16.10.2",
                2: "172.16.10.3",
                4: "Edge"
            },
            "172.16.10.2": {
                1: "172.16.10.1",
                2: "172.16.10.5",
                3: "172.16.10.4"
            },
            "172.16.10.3": {
                2: "172.16.10.4",
                1: "172.16.10.1"
            },
            "172.16.10.4": {
                18: "172.16.10.2",
                17: "172.16.10.3"
            }, 
            "172.16.10.5": {
                17: "Gateway",
                18: "172.16.10.2"
            }  
        }

        #Variable to keep track of the path taken for reaching the internet
        self.icmpPath = ""

        # mapping of IP Address to hostnames
        self.switchHostNames = {
            "172.16.10.1": "OVS - ABMX",
            "172.16.10.2": "OVS - Dell",
            "172.16.10.3": "OVS - HP",
            "172.16.10.4": "OVS - HP (Arista Switch) ", 
            "172.16.10.5": "OVS - Arista (Towards Gateway)"
        }


        self.Edge=False
        # a local map of which sites are allowed 
        self.allowedSites = {
            "google": True,
            "youtube": True,
            "pict": True,
            "colorado.edu": True
        }

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_change_status(self,ev):
        datapath = ev.msg.datapath
        ofp_parser = datapath.ofproto_parser


        # function is triggered when a async event is recevied from switch to the controller
        # about a port state change

        print("-----------------Port State Changed-----------------------")
        time.sleep(4)
        print("* Fetch Stats of ports")


        #generate a request to fetch all the ports stats on the switch.
        requestStatus = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(requestStatus)
            
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def check_port_status(self, ev):
        msg = ev.msg
        print(msg)
        datapath = msg.datapath
        mgmtAddress = datapath.address[0]   # management address fetched from packetIn
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #fetch all the ports stats in the reply of the switch
        for port in msg.body:
            print("* PORT STATE Change Received from "+str(mgmtAddress))

            #if port is Down mark it as DOWN in the dictionary of port states
            if port.port_no in self.ports[mgmtAddress].keys() and port.state == 1:
                print("* PORT " +str(port.port_no)+ "  Down")
                self.ports[mgmtAddress][port.port_no]= False

            #if port is Up mark it as Up in the dictionary of port states
            elif port.port_no in self.ports[mgmtAddress].keys() and port.state == 4 :
                print("* PORT " +str(port.port_no)+ " Up")
                self.ports[mgmtAddress][port.port_no]= True


            #delete the  DHCP flows
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ip_proto=17,  
                                            udp_dst=67)
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,match=match, \
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
            print("DHCP Flow deleted")

            #delete DHCP reverse flows
            datapath.send_msg(mod)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ip_proto=17,  
                                            udp_src=67)

            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,match=match, \
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
            print("DHCP Reverse Flow deleted")
            datapath.send_msg(mod)




            # Delete DNS Flow 
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                ip_proto=17, \
                                udp_src=53)
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,match=match, \
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
            datapath.send_msg(mod)
            print("DNS  Flow deleted")




            # Delte ARP Flows
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,match=match, \
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
            print("ARP  Flow deleted")
            datapath.send_msg(mod)



            #Delete ICMP Flows for Echo Replies
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                    ip_proto=1 )
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,match=match, \
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
            print("ICMP Reverse Flow deleted")
            datapath.send_msg(mod)


            #Delete TCP Flow
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                    ip_proto=6)
            
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,match=match, \
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
            print("TCP  Flow deleted")
            datapath.send_msg(mod)


        print("* Status of Ports ")
        print(json.dumps(self.ports,indent=3))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):


        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = format(datapath.id, "d").zfill(16)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        mgmtAddress = datapath.address[0]   # management address fetched from packetIn
        pkt = ryuPacket.Packet(msg.data)
        ethPkt = pkt.get_protocols(ryuEthernet.ethernet)[0]
        actions = []
        dst = ethPkt.dst                # fetch the destination MAC address
        src = ethPkt.src                # fetch the source MAC address

        if '5c' not in src:             # donot server anything other than DELL laptops/dell hosts
            return

        if ethPkt.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        #ARP request 
        if ethPkt.ethertype == ether_types.ETH_TYPE_ARP and pkt.get_protocol(arp.arp).dst_ip == "10.0.0.1":          
            

            # Install ARP flow match
            # check if the request is for default gatewat then send it towards the default gateway
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa="10.0.0.1")
            actions=[]
            priority = 3000 # install the first flow with 3000 priority
            for outport in self.portTowardsDHCPServer[mgmtAddress]: # extract all the ports facing towards Gateway
                if not self.ports[mgmtAddress][outport]:    # check if the port is UP before installing the flow
                    continue
                actions.append(parser.OFPActionOutput(outport))
                self.add_flow(datapath, priority, match, actions)   # install ARP flow host -> Gateway
                priority = priority - 100   # install consecutive flow with priority in decremental order of 100

            #ARP reply flow
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, \
                                    eth_dst=pkt.get_protocol(ryuEthernet.ethernet).src)
            actions=[]
            priority = 3000 # install the first flow with 3000 priority
            for outport in self.portFromDHCPServer[mgmtAddress]:  # extract all the ports facing away from  Gateway
                if not self.ports[mgmtAddress][outport]:  # check if the port is UP before installing the flow
                    continue

                actions.append(parser.OFPActionOutput(outport))
                self.add_flow(datapath, priority, match, actions)
                priority = priority - 100  # install consecutive flow with priority in decremental order of 100
            #send pakcet unicast on the port which is up
            actions=[]
            for outport in self.portTowardsDHCPServer[mgmtAddress]:
                if self.ports[mgmtAddress][outport]: # send the packet out on the shortest path if port is UP, else to next shortest
                    actions.append(parser.OFPActionOutput(outport))
                    break
                 #send pakcet unicast on the port which is up
            pkt.serialize()        

            outPacket = parser.OFPPacketOut(    
                                                    datapath=datapath, 
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER, 
                                                    actions=actions, 
                                                    data=pkt.data
                                                )
            datapath.send_msg(outPacket)        # send the packet out
            return


        # TCP handler
        if ethPkt.ethertype == ether_types.ETH_TYPE_IP and  \
            pkt.get_protocol(ipv4.ipv4).proto == 6 and\
            pkt.get_protocol(ryuEthernet.ethernet).dst == self.arp_table["10.0.0.1"]:
                
                dstIp =   pkt.get_protocol(ipv4.ipv4).dst
                srcIp =   pkt.get_protocol(ipv4.ipv4).src

                actions=[]
                #install flow for TCP traffic to DHCP server 
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                        ip_proto=6, \
                                        eth_dst=pkt.get_protocol(ryuEthernet.ethernet).dst)
                priority = 5000     #install the first flow with 5000 priority
                for outport in self.portTowardsDHCPServer[mgmtAddress]:   # extract all the ports facing towards Gateway
                    if not self.ports[mgmtAddress][outport]:
                        continue
                    actions = [parser.OFPActionOutput(outport)]
                    self.add_flow( datapath, priority, match, actions)
                        
                    priority = priority - 100 # install consecutive flow with priority in decremental order of 100
                
                actions=[]
                #install flow for reverese Traffic     
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                        ip_proto=6, \
                                        eth_src=pkt.get_protocol(ryuEthernet.ethernet).dst, \
                                        eth_dst=pkt.get_protocol(ryuEthernet.ethernet).src \
                                    )
                priority = 5000     #install the first flow with 5000 priority
                for outport in self.portFromDHCPServer[mgmtAddress]:
                    if not self.ports[mgmtAddress][outport]:
                        continue
                    actions.append(parser.OFPActionOutput(outport))
                    self.add_flow(datapath, priority, match, actions)
                    priority = priority - 100 # install consecutive flow with priority in decremental order of 100

                #send pakcet unicast on the port which is up
                actions=[]
                for outport in self.portTowardsDHCPServer[mgmtAddress]:  # extract all the ports facing towards Gateway
                    if self.ports[mgmtAddress][outport]:
                        actions.append(parser.OFPActionOutput(outport))
                        break
                     #send pakcet unicast on the port which is up
                pkt.serialize()        

                outPacket = parser.OFPPacketOut(    
                                                        datapath=datapath, 
                                                        buffer_id=ofproto.OFP_NO_BUFFER,
                                                        in_port=ofproto.OFPP_CONTROLLER, 
                                                        actions=actions, 
                                                        data=pkt.data
                                                    )
                datapath.send_msg(outPacket)
                return


        # broadcast DNS REQUEST
        if ethPkt.ethertype == ether_types.ETH_TYPE_IP and  \
            pkt.get_protocol(ipv4.ipv4).proto == 17 and \
            pkt.get_protocol(udp.udp).dst_port == 53:
            
            ethernetPacket = dpkt.ethernet.Ethernet(bytes(msg.data))
            ip = ethernetPacket.data
            udpPacket = ip.data

            #parse DNS layer
            dns = dpkt.dns.DNS(udpPacket.data)

            # for all domains in the request iterate
            for domainName in dns.qd:

                print("* DNS Request received for - "+ str(domainName.name))
                #REST call to checker website

                # check if the site is allowed to remote lookup from sitechecker
                # this is done just to stop overwhelming of the flask application
                # the moment the DHCP IP and gateway address is received the HOST sends 100-200s of DNS queries.

                # set allowed checking from remote Sitechecker
                allowChecking = False

                #chreck if the url/site is present in local dictionary
                for site in self.allowedSites.keys():
                    if site in domainName.name:
                        #print("Site found in the list")
                        allowChecking = True    # allow checking on remote server, if url is present locally
                        break


                        
                isAllowed = False
                if allowChecking:

                    # generate a POST request to check if the site is allowed by site checker
                    print("Allowed checking from remote site checker")
                    response = requests.request("POST", "https://192.168.1.5:443/checksite", 
                                headers={ 'Content-Type': 'application/json'},  
                                    data=json.dumps({"url": domainName.name}),verify=False)
                    responseData = response.json()
                    isAllowed = responseData["status"]
                    if isAllowed:
                        print("Flask Application allows domain")
                    else:
                        print("Flask app rejected the domain")

                print("* Site Checker response - "+str(isAllowed))#"+str(responseData['status']))

                # If DNS url is allowed 
                if isAllowed:
                    print("* DNS Query received on - "+str(mgmtAddress))
                    print("* Received on Port "+str(in_port))
                    print("* Allowing DNS query - "+domainName.name)
                    #allow traffic

                    #install flow for traffic from DNS server
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                    eth_dst=pkt.get_protocol(ryuEthernet.ethernet).src, \
                                    ip_proto=17, \
                                    udp_src=53)
                    priority = 2000 #install the first flow with 2000 priority
                    actions=[]
                    for outport in self.portFromDHCPServer[mgmtAddress]:  # extract all the ports facing away from Gateway
                        #print(str(outport)+" : "+str(self.ports[mgmtAddress][outport]))
                        if not self.ports[mgmtAddress][outport]:
                            #print("Down - "+str(outport))
                            continue
                        actions.append(parser.OFPActionOutput(outport))
                        self.add_flow(datapath, priority, match, actions)
                        priority = priority - 100 # install consecutive flow with priority in decremental order of 100


                    #send pakcet unicast on the port which is up
                    actions=[]
                    
                    # send the DNS request to next hop on the shortest path
                    for outport in self.portTowardsDHCPServer[mgmtAddress]:  # extract all the ports facing towards Gateway
                        #print(str(outport)+" : "+str(self.ports[mgmtAddress][outport]))
                        if self.ports[mgmtAddress][outport]: # check if the port is UP before sending the packet
                            #print("UP - "+str(outport))
                            print("* DNS request sent to outPort "+str(outport))
                            actions.append(parser.OFPActionOutput(outport))
                            break
                         #send pakcet unicast on the port which is up
                    pkt.serialize()   

                    outPacket = parser.OFPPacketOut(    
                                                    datapath=datapath, 
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER, 
                                                    actions=actions, 
                                                    data=pkt.data
                                                )
                    
                    datapath.send_msg(outPacket)
                    return
                else:
                    
                    # if the sitechecker denies the request
                    #craft a DNS packet
                    ethLayer = Ether(
                        src=pkt.get_protocol(ryuEthernet.ethernet).dst,
                        dst=pkt.get_protocol(ryuEthernet.ethernet).src
                    )

                    # Construct the IP header by looking at the sniffed packet
                    ipLayer = IP(
                        src=pkt.get_protocol(ipv4.ipv4).dst,
                        dst=pkt.get_protocol(ipv4.ipv4).src
                    )

                    # Construct the UDP header by looking at the sniffed packet
                    udpLayer = UDP(
                        dport=pkt.get_protocol(udp.udp).src_port,
                        sport=pkt.get_protocol(udp.udp).dst_port
                    )
                    query_id = hexlify(pkt.data[42:44]) # fetch the query ID in the DNS packet
                    query_id = int(query_id.decode(), 16)
                    # Construct the DNS response by looking at the sniffed packet and manually
                    #print(dns.id)
                    dnsLayer = DNS(
                        opcode = 0,
                        id=dns.id,
                        qr=1,
                        rd=1,        # no recursion
                        ra=1,
                        aa=0,        #  this response is authoritative
                        tc=0,
                        z=0,
                        ad=0,
                        cd =0,
                        rcode=0,     # rcode =0 mean the answer is provided
                        qdcount=1,   # one question
                        ancount=1,   # one answer IP = controller IP
                        nscount=1,    # number of name server resource code
                        arcount=0,   # number of addditonal resource codes
                        qd=DNSQR(qname=domainName.name), 
                        an=DNSRR(rrname=domainName.name,ttl=60,rdata="192.168.1.5"),  # send controller IP as resolution to redirect the TCP request
                        ns=DNSRR(rrname=domainName.name,type=2,ttl=60,rdata="ns1."+domainName.name),
                        ar=None
                    )
                    responsePacket = ethLayer / ipLayer / udpLayer / dnsLayer
                    actions=[]
                    actions.append(parser.OFPActionOutput(in_port))
                    outPacket = parser.OFPPacketOut(    
                                                    datapath=datapath, 
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER, 
                                                    actions=actions, 
                                                    data=bytes(responsePacket)
                                                )
                    # send the packet to the source interface
                    print("* URL denied access "+domainName.name) 
                    datapath.send_msg(outPacket)
            return


        # broadcast DISCOVER DISCOVER/REQUEST
        if ethPkt.ethertype == ether_types.ETH_TYPE_IP and \
            pkt.get_protocol(ipv4.ipv4).dst == "255.255.255.255" and \
            pkt.get_protocol(ipv4.ipv4).proto == 17 and \
            pkt.get_protocol(udp.udp).dst_port == 67:

            dst = ethPkt.dst
            src = ethPkt.src

            print("* DHCP DISCOVER/REQUEST Packet In Received from "+str(mgmtAddress))
            print(" destination.MAC = "+str(dst)+"     source.MAC = "+str(src))
            dstIp =   pkt.get_protocol(ipv4.ipv4).dst   
            srcIp =   pkt.get_protocol(ipv4.ipv4).src
            print(" destination.IP  = "+str(dstIp)+"   source IP = "+str(srcIp))
            print(" dataPathId "+str(dpid))
            print(" InPort "+str(in_port))

            actions=[]
            #install flow for traffic to DHCP server 
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=17, eth_src=pkt.get_protocol(ryuEthernet.ethernet).src, udp_dst=67)
            priority = 1500 #install the first flow with 1500 priority
            for outport in self.portTowardsDHCPServer[mgmtAddress]: # extract all the ports facing towards Gateway
                if not self.ports[mgmtAddress][outport]: # check if the port is UP before installing the flow
                    continue
                actions = [parser.OFPActionOutput(outport)]
                self.add_flow( datapath, priority, match, actions)
                    
                priority = priority - 100  # install consecutive flow with priority in decremental order of 100
               
            actions=[]
            #install flow for reverese Traffic  
                 
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                    eth_dst=pkt.get_protocol(ryuEthernet.ethernet).src, \
                                    ip_proto=17, \
                                    udp_src=67)
            priority = 1500
            for outport in self.portFromDHCPServer[mgmtAddress]:
                print("* From DHCP")
                print(outport)
                if not self.ports[mgmtAddress][outport]:
                    continue
                actions.append(parser.OFPActionOutput(outport))
                self.add_flow(datapath, priority, match, actions)
                priority = priority - 100  # install consecutive flow with priority in decremental order of 100

            #self.flows[mgmtAddress].append([ether_types.ETH_TYPE_IP,pkt.get_protocol(ethernet.ethernet).src,67])
            print(" * Adding flow for reverse traffic from DHCP Server directly to client:"+ \
                    "\n   Switch: [ "+str(mgmtAddress)+" ] "+self.switchHostNames[mgmtAddress]+ \
                    "\n   DPID: "+str(dpid)+\
                    "\n   Match Criteria: "+ \
                    "\n        MAC Destination: "+pkt.get_protocol(ryuEthernet.ethernet).src+ \
                    "\n        Protocol: UDP"+ \
                    "\n        UDP Source Port: 67"+ \
                    "\n   Actions: "+ \
                    "\n        Out Port: "+str(in_port) 
                    )

            #send pakcet unicast on the port which is up
            actions=[]
            for outport in self.portTowardsDHCPServer[mgmtAddress]: # extract all the ports facing towards Gateway
                if self.ports[mgmtAddress][outport]: # check if the port is UP before installing the flow
                    actions.append(parser.OFPActionOutput(outport))
                    break
                 #send pakcet unicast on the port which is up
            pkt.serialize()        

            outPacket = parser.OFPPacketOut(    
                                                    datapath=datapath, 
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER, 
                                                    actions=actions, 
                                                    data=pkt.data
                                                )
            print(" * Packet sent out on Port "+str(outport))
            datapath.send_msg(outPacket)
            return

        #ICMP packets
        if ethPkt.ethertype == ether_types.ETH_TYPE_IP and \
            pkt.get_protocol(ipv4.ipv4).proto == 1 and \
            pkt.get_protocol(icmp.icmp).type == 8:

            actions=[]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, \
                                    ip_proto=1,icmpv4_type=0, eth_src=pkt.get_protocol(ryuEthernet.ethernet).dst,\
                                    eth_dst=pkt.get_protocol(ryuEthernet.ethernet).src)   


            #install flow only for reverse traffic
            # if flow is installed for ECHO REQUEST as well the path tracker won't be able to track PATH in the controller   
            priority = 6500 #install the first flow with 65000 priority
            for outport in self.portFromDHCPServer[mgmtAddress]:
                if not self.ports[mgmtAddress][outport]: # check if the port is UP before installing the flow
                    continue
                actions = [parser.OFPActionOutput(outport)]
                self.add_flow( datapath, priority, match, actions)
                    
                priority = priority - 100 # install consecutive flow with priority in decremental order of 100

            print("ICMP ECHO detected on "+mgmtAddress)
            print(" In Port : "+str(in_port))
            actions=[]

            #send port on the next hop towards the Gateway router
            outPort = -1
            for outport in self.portTowardsDHCPServer[mgmtAddress]: # extract all the ports facing towards Gateway
                if self.ports[mgmtAddress][outport]: 
                    actions.append(parser.OFPActionOutput(outport))
                    print(" Out Port : "+str(outport))
                    outPort = outport   # record the outPort to track path
                    break
            pkt.serialize()
                    
            
            # if the packet is from a Edge port, such as from a host, printer connected to a switch
            if  self.networkMap[mgmtAddress][in_port] == "Edge":
                print("---------------"+ mgmtAddress)

                #record the inport, switch and outport in ICMP_PATH variable
                self.icmpPath +=  "HOST < -- > (" + str(in_port) +") "+ self.switchHostNames[mgmtAddress] +" ("+ str(outPort) +  ")"

            # if the packet is sent out towards the Gateway
            elif self.networkMap[mgmtAddress][outPort] == "Gateway":

                 #record the inport, switch and outport in ICMP_PATH variable
                self.icmpPath +=  " (" + str(in_port) +") "+ self.switchHostNames[mgmtAddress] +" ("+ str(outPort) +  ") < -- > Gateway(Internet) "
                #make post request to update the flask application of the tracked path
                requests.request("POST", "https://192.168.1.5:443/updatetopopath", 
                            headers={ 'Content-Type': 'application/json'},  
                            data=json.dumps({"icmpPath": self.icmpPath }),verify=False)
                
                # flush the ICMP path in the controller
                self.icmpPath = ""

                print("---------------"+ mgmtAddress)
            
            # if the packet is just sent to a next hop from a switch to next switch
            else:
                print("---------------"+ mgmtAddress)
                 #record the inport, switch and outport in ICMP_PATH variable
                self.icmpPath +=   " < -- > (" + str(in_port) +") "+ self.switchHostNames[mgmtAddress] +" ("+ str(outPort) +  ") < -- >"

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            outPacket = parser.OFPPacketOut(    
                                                    datapath=datapath, 
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER, 
                                                    actions=actions, 
                                                    data=data
                                                )
            
            datapath.send_msg(outPacket)        # send the packet out to the next hop
            return
