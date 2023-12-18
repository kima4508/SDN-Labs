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
    POX=net.addController(name='POX',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    OVS4 = net.addSwitch('OVS4', cls=OVSKernelSwitch)
    OVS3 = net.addSwitch('OVS3', cls=OVSKernelSwitch)
    OVS1 = net.addSwitch('OVS1', cls=OVSKernelSwitch)
    OVS2 = net.addSwitch('OVS2', cls=OVSKernelSwitch)
    OVS5 = net.addSwitch('OVS5', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)

    info( '*** Add links\n')
    OVS4OVS5 = {'bw':20}
    net.addLink(OVS4, OVS5, cls=TCLink , **OVS4OVS5)
    h1OVS3 = {'bw':20}
    net.addLink(h1, OVS3, cls=TCLink , **h1OVS3)
    h2OVS3 = {'bw':20}
    net.addLink(h2, OVS3, cls=TCLink , **h2OVS3)
    OVS3OVS1 = {'bw':20}
    net.addLink(OVS3, OVS1, cls=TCLink , **OVS3OVS1)
    h3OVS4 = {'bw':20}
    net.addLink(h3, OVS4, cls=TCLink , **h3OVS4)
    h4OVS4 = {'bw':20}
    net.addLink(h4, OVS4, cls=TCLink , **h4OVS4)
    h5OVS5 = {'bw':20}
    net.addLink(h5, OVS5, cls=TCLink , **h5OVS5)
    h6OVS5 = {'bw':20}
    net.addLink(h6, OVS5, cls=TCLink , **h6OVS5)
    OVS1OVS2 = {'bw':20}
    net.addLink(OVS1, OVS2, cls=TCLink , **OVS1OVS2)
    OVS1OVS4 = {'bw':20}
    net.addLink(OVS1, OVS4, cls=TCLink , **OVS1OVS4)
    OVS4OVS2 = {'bw':20}
    net.addLink(OVS4, OVS2, cls=TCLink , **OVS4OVS2)
    OVS5OVS2 = {'bw':20}
    net.addLink(OVS5, OVS2, cls=TCLink , **OVS5OVS2)
    OVS3OVS4 = {'bw':20}
    net.addLink(OVS3, OVS4, cls=TCLink , **OVS3OVS4)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('OVS4').start([POX])
    net.get('OVS3').start([POX])
    net.get('OVS1').start([POX])
    net.get('OVS2').start([POX])
    net.get('OVS5').start([POX])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

