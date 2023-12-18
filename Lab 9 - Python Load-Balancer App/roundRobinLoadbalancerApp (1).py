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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3,ether,ofproto_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp,ipv4,tcp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.serverIPAddress =["10.0.0.1","10.0.0.2","10.0.0.3"]
        self.serverMACAddress = []
        self.loadBalancerIP = "10.0.0.100"
        self.arp_table = {
                            self.loadBalancerIP : "00:00:00:00:00:64",
                            "10.0.0.1": "00:00:00:00:00:01",
                            "10.0.0.2": "00:00:00:00:00:02",
                            "10.0.0.3": "00:00:00:00:00:03",
                          }

        # Socket connection to Server IP
        self.socketConnection={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = format(datapath.id, "d").zfill(16)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        actions = []


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP and \
            pkt.get_protocol(arp.arp).dst_ip == self.loadBalancerIP and  \
            pkt.get_protocol(arp.arp).opcode == 1 :

            #handle ARP replies for 10.0.0.100
            print("\n----------- Handling ARP Request for LoadBalancer IP-----------------")

            #fetch arp request layer from the Ethernet frame
            arp_layer = pkt.get_protocol(arp.arp)
            print(" * Received ARP Request: Who has "+self.loadBalancerIP+" ? from "+arp_layer.src_ip)
            #generate a ARP response skeleton
            arpResponsePacket = packet.Packet()

            #add values to the skeleton of ETHER LAYER
            arpResponsePacket.add_protocol(ethernet.ethernet(   ethertype=eth.ethertype,  #ARP as ether type
                                                                dst=eth.src,    # set the destination MAC
                                                                src=self.arp_table[arp_layer.dst_ip]   # set the source MAC
                                                            ))
            

            # add values to the skeleton of ARP LAYER
            arpResponsePacket.add_protocol( arp.arp(    opcode=arp.ARP_REPLY,
                                                        src_mac=self.arp_table[arp_layer.dst_ip],  # set the Source MAC as LoadBalancer's MAC
                                                        src_ip=arp_layer.dst_ip,                   # set the Source IP as Load Balancer's IP
                                                        dst_mac=arp_layer.src_mac,                 # set the Destination MAC as Client MAC
                                                        dst_ip=arp_layer.src_ip                 # set the Destination IP as Client IP
                                            )) 
            #Serialise the data to be added as Payload for OpenFlow packet OUT
            arpResponsePacket.serialize()


            #Set action to send packet on port from where it came from
            
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))

            #learn source MAC
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][eth.src] = in_port

            match = parser.OFPMatch(eth_dst=eth.src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                #msg.buffer_id == ofproto.OFP_NO_BUFFER
                self.add_flow(datapath, 1, match, actions)
            
            print(" * Adding flow to install MAC table in the switch:"+ \
                          "\n   DPID: "+str(dpid)+\
                          "\n   Match Criteria: "+ \
                          "\n        MAC Destination: "+eth.src+ \
                          "\n   Actions: "+\
                          "\n        Out Port: "+str(in_port)
            )
            outPacket = parser.OFPPacketOut(    datapath=datapath, 
                                                buffer_id=ofproto.OFP_NO_BUFFER,
                                                in_port=ofproto.OFPP_CONTROLLER, 
                                                actions=actions, 
                                                data=arpResponsePacket
                                            )
            print(" * Send ARP Reply to "+arp_layer.src_ip+ \
                  "\n      Answer:  "+arp_layer.dst_ip+" has "+self.arp_table[arp_layer.dst_ip])
            print(arpResponsePacket)
            datapath.send_msg(outPacket)
            return
    
        # handling ARP response [record mapping] from server to controller
        if eth.ethertype == ether_types.ETH_TYPE_ARP and \
            pkt.get_protocol(arp.arp).dst_ip == self.loadBalancerIP and  \
            pkt.get_protocol(arp.arp).opcode == 2 :

            arp_layer = pkt.get_protocol(arp.arp)
            self.arp_table[arp_layer.src_ip]=arp_layer.src_mac
            print(" * MAC learnt from response")
            print(arp_layer.src_ip+" --> "+arp_layer.src_mac)
            return

        # handling IP packet TCP request to a port   
        if eth.ethertype == ether_types.ETH_TYPE_IP and pkt.get_protocol(ipv4.ipv4).dst == self.loadBalancerIP:
            if pkt.get_protocol(tcp.tcp).dst_port == 8080:
                print("\n----------- Handling TCP packet for port 8080 -----------------")
                sourceIP = pkt.get_protocol(ipv4.ipv4).src
                destinationIP = pkt.get_protocol(ipv4.ipv4).dst
                sourcePort = pkt.get_protocol(tcp.tcp).src_port
                destinationPort= pkt.get_protocol(tcp.tcp).dst_port
                socket = (sourceIP,sourcePort,destinationIP,destinationPort)
                print(" * Processing Packet-In for client "+sourceIP)
                serverIP = None
                serverMAC = None
                if socket in self.socketConnection:
                    #send the request to the server  
                    serverIP = self.socketConnection[socket]
                    serverMAC = self.arp_table[serverIP] 
                    print(" * Server already selected for socket connection"+str(socket))
                    print(" * Consecutive TCP packets for same socket - SYN/ACK, FIN, mapped to the same server")
                else:
                    print(" * New HTTP request received ") 
                    print(" * New Socket connection request")
                    
                    self.socketConnection.clear()


                    serverIP = self.serverIPAddress.pop(0)
                    self.serverIPAddress.append(serverIP)
                    serverMAC = self.arp_table[serverIP]
                    
                    self.socketConnection[socket] = serverIP
                       
                    #install flow to send response directly to client
                    match = parser.OFPMatch(eth_type=0x800,ipv4_dst=pkt.get_protocol(ipv4.ipv4).src, \
                                            ipv4_src=serverIP, \
                                            ip_proto=6,tcp_src=8080)
                    actions=[]

                    actions.append(parser.OFPActionSetField(ipv4_src=self.loadBalancerIP))
                    actions.append(parser.OFPActionOutput(in_port))
                    self.add_flow(datapath, 20, match, actions)
                    print(" * Adding flow for reverse traffic from server directly to client:"+ \
                          "\n   DPID: "+str(dpid)+\
                          "\n   Match Criteria: "+ \
                          "\n        IPv4 Destination: "+pkt.get_protocol(ipv4.ipv4).src+ \
                          "\n        IPv4 Source: "+serverIP + \
                          "\n        Protocol: TCP"+ \
                          "\n        TCP Source Port: 8080"+ \
                          "\n   Actions: "+ \
                          "\n        Set Field: IPv4 Source - "+self.loadBalancerIP+ \
                          "\n        Out Port: "+str(in_port)
                          )

                print(" * "+sourceIP+" ==> LoadBalancer("+self.loadBalancerIP+") -----> "+serverIP)
                print(" * Request sent to backend server "+serverIP)
                #send the request to the server                
                pkt.get_protocol(ipv4.ipv4).dst = serverIP
                pkt.get_protocol(ethernet.ethernet).dst = serverMAC
                actions=[]
                outport = self.mac_to_port[dpid][serverMAC]
                actions.append(parser.OFPActionOutput(outport))
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

        
        dst = eth.dst
        src = eth.src
        
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)