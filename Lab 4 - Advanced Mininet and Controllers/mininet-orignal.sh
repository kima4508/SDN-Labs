#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    ODL=net.addController(name='ODL',
                      controller=RemoteController,
                      ip='10.224.76.18',
                      protocol='tcp',
                      port=6653)

    info( '*** Add switches\n')
    OVS2 = net.addSwitch('OVS2', cls=OVSKernelSwitch)
    OVS1 = net.addSwitch('OVS1', cls=OVSKernelSwitch)
    OVS3 = net.addSwitch('OVS3', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    Computer4 = net.addHost('Computer4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    Computer1 = net.addHost('Computer1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    Computer2 = net.addHost('Computer2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    Computer3 = net.addHost('Computer3', cls=Host, ip='10.0.0.3', defaultRoute=None)

    info( '*** Add links\n')
    Computer1OVS2 = {'bw':10}
    net.addLink(Computer1, OVS2, cls=TCLink , **Computer1OVS2)
    Computer2OVS2 = {'bw':10}
    net.addLink(Computer2, OVS2, cls=TCLink , **Computer2OVS2)
    Computer3OVS3 = {'bw':10}
    net.addLink(Computer3, OVS3, cls=TCLink , **Computer3OVS3)
    Computer4OVS3 = {'bw':10}
    net.addLink(Computer4, OVS3, cls=TCLink , **Computer4OVS3)
    OVS2OVS1 = {'bw':10}
    net.addLink(OVS2, OVS1, cls=TCLink , **OVS2OVS1)
    OVS1OVS3 = {'bw':10}
    net.addLink(OVS1, OVS3, cls=TCLink , **OVS1OVS3)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('OVS2').start([ODL])
    net.get('OVS1').start([ODL])
    net.get('OVS3').start([ODL])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

