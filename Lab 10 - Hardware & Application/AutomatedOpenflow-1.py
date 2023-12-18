from netmiko import ConnectHandler
import time,os

#maintaina dictionary to perform SSH into Arista switces
switches = [
    {
        'device_type': 'arista_eos',
        'ip': '172.16.10.4',
        'username': 'admin',
        'password': 'admin',
        'secret': 'admin'
    },
    {
        'device_type': 'arista_eos',
        'ip': '172.16.10.5',
        'username': 'admin',
        'password': 'admin',
        'secret': 'admin'
    },
]

#maintaining a dictionary to perform SSH into Linux boxes
routers = {
    "ABMX":{ 
            "device_type": "linux",
            "host": "172.16.10.1",
            "username": "team2",
            "password": "team2",
            "secret": "team2"
        },
    "DELL":{ 
            "device_type": "linux",
            "host": "172.16.10.2",
            "username": "team2",
            "password": "team2",
            "secret": "team2"
        },
    "HP":{ 
            "device_type": "linux",
            "host": "172.16.10.3",
            "username": "team2",
            "password": "team2",
            "secret": "team2"
        },
    "Controller": {
            "device_type": "linux",
            "host": "172.16.10.100",
            "username": "team2",
            "password": "team2",
            "secret": "team2"
        }
}

#code to configure the controller
def configureController():
    # Run Controller 
    connectionController = ConnectHandler(**routers["Controller"])
    connectionController.enable(cmd="sudo su",pattern="password")                                      # login as root user
    connectionController.send_command_timing("sudo python /home/willy/ryu/ryu/appsiteChecker.py &")    #start SiteChecker APP in  background
    output = connectionController.send_command_timing("sudo ryu run /home/willy/ryu/ryu/appmyApp.py &")#start RYU APP in background
    #output = connectionController.send_command_timing(" sudo ryu-manager /home/willy/ryu/ryu/app/simple_switch_13.py &")
    print("Waiting for  Ryu to warm up")                                                            
    time.sleep(15)
    print(output)


def configureServers():
# Run ABMX
    connS1 = ConnectHandler(**routers["ABMX"])
    connS1.enable(cmd="sudo su",pattern="password")
    # configure OVS
    output = connS1.send_command("sudo ovs-vsctl add-br mybridge")                                          # create a bridge 
    output = connS1.send_command("sudo ovs-vsctl add-port mybridge eno3 -- set Interface eno3 ofport=2")    # add a port to the bridge
    output = connS1.send_command("sudo ovs-vsctl add-port mybridge eno4 -- set Interface eno4 ofport=5")    # add a port to the bridge
    output = connS1.send_command("sudo ovs-vsctl add-port mybridge enp5s0f1 -- set Interface enp5s0f1 ofport=4") # add a port to bridge
    output = connS1.send_command("sudo ovs-vsctl set bridge mybridge protocols=OpenFlow13") # set the bridge to use OpenFlow version 13
    output = connS1.send_command("sudo ovs-vsctl set-controller mybridge tcp:"+routers["Controller"]["host"]+":6633") #specify the controller socket
    print("OvS in ABMX server is configured!")
    output = connS1.send_command("sudo ovs-vsctl show")
    time.sleep(3)
    print(output)

 # Run DELL 
    connS2 = ConnectHandler(**routers["DELL"])
    connS2.enable(cmd="sudo su",pattern="password")
    # configure OVS
    output = connS2.send_command("sudo ovs-vsctl add-br mybridge")                                          # create a bridge 
    output = connS2.send_command("sudo ovs-vsctl add-port mybridge eno3 -- set Interface eno3 ofport=2")    # add a port to the bridge
    output = connS2.send_command("sudo ovs-vsctl add-port mybridge eno4 -- set Interface eno4 ofport=3")    # add a port to the bridge
    output = connS2.send_command("sudo ovs-vsctl add-port mybridge enp5s0f1 -- set Interface enp5s0f1 ofport=5")# add a port to the bridge
    output = connS2.send_command("sudo ovs-vsctl set bridge mybridge protocols=OpenFlow13")         # set the bridge to use OpenFlow version 13
    output = connS2.send_command("sudo ovs-vsctl set-controller mybridge tcp:"+routers["Controller"]["host"]+":6633") #specify the controller socket
    print("OvS in Dell server is configured!")
    output = connS2.send_command("sudo ovs-vsctl show")
    time.sleep(3)
    print(output)

# Run HP 
    connS3 = ConnectHandler(**routers["HP"])
    connS3.enable(cmd="sudo su",pattern="password")
    # configure OVS
    output = connS3.send_command("sudo ovs-vsctl add-br mybridge")
    output = connS3.send_command("sudo ovs-vsctl add-port mybridge eno2 -- set Interface eno2 ofport=1")
    output = connS3.send_command("sudo ovs-vsctl add-port mybridge eno3 -- set Interface eno3 ofport=2")
    output = connS3.send_command("sudo ovs-vsctl set bridge mybridge protocols=OpenFlow13")
    output = connS3.send_command("sudo ovs-vsctl set-controller mybridge tcp:"+routers["Controller"]["host"]+":6633")
    print("OvS in HP server is configured!")
    output = connS3.send_command("sudo ovs-vsctl show")
    time.sleep(3)
    print(output)

def configurePhySwitches():
    config_commands = [
        'configure terminal',
        'openflow',
        'bind interface Et17-19',
        'no shutdown',
        'controller tcp:172.16.10.100:6633',
        'exit',  # conf
        'exit'   # cli
    ]
    try:
        for switch in switches:
            ssh = ConnectHandler(**switch)  # login to Arista switch
            ssh.enable()                    # enter enable mode
            output = ssh.send_config_set(config_commands,cmd_verify=False)  # send the entire Openflow configSet to switch
            print(output)
            ssh.disconnect()
    except Exception as e:
        print(f"An error occurred: {e}")



if __name__ =="__main__":
    configureController()
    configureServers()
    configurePhySwitches()

