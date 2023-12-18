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
    RyuRemoteController=net.addController(name='RyuRemoteController',
                      controller=RemoteController,
                      ip='192.168.56.103',
                      protocol='tcp',
                      port=6653)

    info( '*** Add switches\n')
    ovs3 = net.addSwitch('ovs3', cls=OVSKernelSwitch)
    ovs4 = net.addSwitch('ovs4', cls=OVSKernelSwitch)
    ovs1 = net.addSwitch('ovs1', cls=OVSKernelSwitch)
    ovs6 = net.addSwitch('ovs6', cls=OVSKernelSwitch)
    ovs2 = net.addSwitch('ovs2', cls=OVSKernelSwitch)
    ovs5 = net.addSwitch('ovs5', cls=OVSKernelSwitch)
    ovs7 = net.addSwitch('ovs7', cls=OVSKernelSwitch)
    ovs8 = net.addSwitch('ovs8', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    server = net.addHost('server', cls=Host, ip='1.1.1.1/24', defaultRoute='via 1.1.1.254')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute='via 10.0.0.254')

    info( '*** Add links\n')
    net.addLink(ovs5, server)
    s1s6 = {'delay':50}
    net.addLink(ovs1, ovs6, cls=TCLink, **s1s6)
    net.addLink(ovs6, ovs7)
    net.addLink(ovs7, ovs5)
    s1s8 = {'delay':100}
    net.addLink(ovs1, ovs8, cls=TCLink, **s1s8)
    net.addLink(ovs8, ovs5)
    net.addLink(ovs1, ovs2)
    net.addLink(ovs2, ovs3)
    net.addLink(ovs3, ovs4)
    net.addLink(ovs4, ovs5)
    net.addLink(ovs1, h1)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('ovs3').start([RyuRemoteController])
    net.get('ovs4').start([RyuRemoteController])
    net.get('ovs1').start([RyuRemoteController])
    net.get('ovs6').start([RyuRemoteController])
    net.get('ovs2').start([RyuRemoteController])
    net.get('ovs5').start([RyuRemoteController])
    net.get('ovs7').start([RyuRemoteController])
    net.get('ovs8').start([RyuRemoteController])

    info( '*** Post configure switches and hosts\n')
    info('*** Starting http server on SERVER node on port 8080')

    print(h1.cmd("ip -6 addr add 5501::1/64 dev h1-eth0"))
    print(server.cmd("ip -6 addr add 5501::2/64 dev server-eth0"))

    print(server.cmd('python3 -m http.server 8080 &'))
    print(server.cmd('netstat -plant'))
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

