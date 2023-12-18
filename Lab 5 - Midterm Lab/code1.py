from netmiko import ConnectHandler
import time,os
routers = {
    "R1":{
            "device_type": "cisco_ios",
            "host": "192.168.100.1",
            "username": "admin",
            "password": "password", 
            "secret": "password" 
        },
    "R2":{
            "device_type": "cisco_ios",
            "host": "192.168.200.2",
            "username": "admin",
            "password": "password", 
            "secret": "password" 
        },
    "R4":{
            "device_type": "cisco_ios",
            "host": "172.16.100.1",
            "username": "admin",
            "password": "password", 
            "secret": "password" 
        },
    "Mininet":{ 
            "device_type": "linux",
            "username": "mininet",
            "password": "mininet",
            "secret": "mininet"
        },
    "Controller": {
            "device_type": "linux",
            "host": "10.20.30.2",
            "username": "sdn",
            "password": "sdn",
            "secret": "sdn"
        }
}

connectionR1 = ConnectHandler(**routers["R1"])
connectionR1.enable()
R1dhcpConfig = ["ip dhcp pool MininetPool", \
                "network 192.168.100.0 255.255.255.0", \
                "default-router 192.168.100.1", \
                "ip dhcp excluded-address 192.168.100.254"]
print("Starting DHCP server on R1")
connectionR1.send_config_set(R1dhcpConfig)
print("Waiting for Mininet VM to fetch the IP fro dhcp")
time.sleep(40)
R1dhcpBindings = connectionR1.send_command("sh ip dhcp binding")
print(R1dhcpBindings)
mininetIP = R1dhcpBindings.split('\n')[4].split()[0]
print("Mininet IP --> "+mininetIP)
routers["Mininet"]["host"]=mininetIP

print("\nConfiguring R1 with OSPF")
R1OSPF = ["router ospf 1", \
          "network 192.168.100.1 0.0.0.255 area 0", \
          "network 192.168.200.1 0.0.0.255 area 0" ]

output = connectionR1.send_config_set(R1OSPF)
print(output)
output = connectionR1.send_command("ssh -l "+routers["R2"]["username"]+" "+routers["R2"]["host"],expect_string='.*:')
print(output)
output = connectionR1.send_command_timing(routers["R2"]["password"],read_timeout=2)
output = connectionR1.send_command("enable",read_timeout=2,expect_string='.*:')
output = connectionR1.send_command_timing(routers["R2"]["password"],read_timeout=2)
output = connectionR1.send_command("conf t",expect_string=".*#")
print("Configuring R2 with OSPF")
R2OSPF = ["router ospf 1",  \
          "network 192.168.200.2 0.0.0.255 area 0",  \
          "network 172.16.100.2 0.0.0.255 area 0", \
           "end" ]

for command in R2OSPF:
    output=connectionR1.send_command(command,expect_string='R2.*#')

#configure ospf in R4
output = connectionR1.send_command("ssh -l "+routers["R4"]["username"]+" "+routers["R4"]["host"],expect_string='.*:')
output = connectionR1.send_command_timing(routers["R4"]["password"],read_timeout=2)
output = connectionR1.send_command("enable",read_timeout=2,expect_string='.*:')
output = connectionR1.send_command_timing(routers["R4"]["password"],read_timeout=2)
output = connectionR1.send_command("conf t",expect_string=".*#")

print("Configuring R4 with OSPF")
R4OSPF = ["router ospf 1", \
          "network 172.16.100.1 0.0.0.255 area 0", \
          "network 10.20.30.1 0.0.0.255 area 0" ]
for command in R4OSPF:
    output=connectionR1.send_command(command,expect_string='R4.*#')

connectionR1.disconnect()
print("Waiting for OSPF to converge.....")
time.sleep(60)

connectionR1 = ConnectHandler(**routers["R1"])
connectionR1.enable()
output = connectionR1.send_command("sh ip route")
print("Routes learnt via OSPF")
print(output)

# controller
connectionController = ConnectHandler(**routers["Controller"])
connectionController.enable(cmd="sudo su",pattern="password")
output = connectionController.send_command_timing("sudo ryu run ryu/ryu/app/simple_switch_13.py &")
print("Waiting for  Ryu to warm up")
time.sleep(15)
print(output)
print("Url - http://10.20.30.2:8080")


#clean up before config
connectionMininet = ConnectHandler(**routers["Mininet"])
connectionMininet.enable(cmd="sudo su",pattern="password")
#clean up before config
output = connectionMininet.send_command("sudo mn --clean",expect_string='.*#')
#run topology
print(output)
output = connectionMininet.send_command("sudo mn",expect_string=r'mininet>')
print(output)

connectionMininet2 = ConnectHandler(**routers["Mininet"])
connectionMininet2.enable(cmd="sudo su",pattern="password")

output = connectionMininet2.send_command("sudo ovs-vsctl set bridge s1 protocols=OpenFlow13")
output = connectionMininet2.send_command("sudo ovs-vsctl set-controller s1 tcp:"+routers["Controller"]["host"]+":6633")
print("Waiting for the switch to connect to the controller")
time.sleep(60)
########################################################################################################
output = connectionMininet2.send_command("sudo ovs-vsctl list controller s1")
output = output.split('\n')

for line in output:
    if 'is_connected' in line:
        if 'true' in line:
            print("OVS Bridge <---------- CONNECTED ------> controller")
        else:
            print("OVS Bridge <---------- X NOT CONNECTED ------> controller")



#execute flask
print("Starting Flask .....")
output  = os.system("/usr/bin/python3.8 /home/kiran/SDNcodes/stats.py &")
time.sleep(5)
print(output)

print("Installing client on the remote machine to capture packets")
output = os.system("sshpass -p "+routers["Controller"]["password"]+ \
          " scp /home/kiran/SDNcodes/pythonClient.py "+\
            routers["Controller"]["username"]+"@"+routers["Controller"]["host"]+ \
            ":/home/sdn/pythonClient.py")
print(output)

print("Staring the client on the Controller")
connectionController2 = ConnectHandler(**routers["Controller"])
connectionController2.enable(cmd="sudo su",pattern="password")
output = connectionController2.send_command_timing("sudo python3 pythonClient.py &")
print(output)
time.sleep(5)

#Git push
os.system("cd /home/kiran/sdn-midterm")
os.system("/usr/bin/python3.8 /home/kiran/SDNcodes/git-tester.py")
# os.system("cd /home/kiran/sdn-midterm/")
# os.system("git pull")
# os.system("cp -r /home/kiran/SDNcodes/. /home/kiran/sdn-midterm/.")
# output = os.system("git status")
# print(output)
# os.system("git add .")
# os.system("git commit -m 'Pushed via code'")
# output = os.system("git push origin master")
# print(output)


print("Issuing packet in messaages")
output = connectionMininet.send_command_timing("pingall")
print(output)

print("RYU - http://10.20.30.2:8080")
print("Dashboard - http://10.20.30.2:9000/")
while(True):
    continue






