import os
import time

bridgeName = "ovsbridge"
interfaces = ["eno1","eno2"]
controllerIP="192.168.1.7"
controllerPort="6633"

print("Creating a new bridge - "+bridgeName)
code = os.system("sudo ovs-vsctl add-br "+bridgeName)
print("Executed - sudo ovs-vsctl add-br "+bridgeName + " : "+ str(code))

for i in interfaces:
    code = os.system("sudo ovs-vsctl add-port "+bridgeName+" "+i)
    print("Executed - sudo ovs-vsctl add-port "+bridgeName+" "+i+ " : "+ str(code))

code = os.system("sudo ovs-vsctl set-fail-mode "+bridgeName+" secure")
print("Executed - sudo ovs-vsctl set-fail-mode "+bridgeName+" secure : "+ str(code))

code = os.system("sudo ovs-vsctl set-controller "+bridgeName+" tcp:"+controllerIP+":"+controllerPort)
print("Executed - sudo ovs-vsctl set-controller "+bridgeName+" tcp:"+controllerIP+":"+controllerPort+" : "+ str(code))

print(bridgeName+" is created")
print("Wait for the switch to connect to the controller "+ controllerIP+":"+controllerPort)
time.sleep(7)
print("###### STATUS ###############")
# print if the ovs switch is connected to the controller
code = os.system("sudo ovs-vsctl list controller ovsbridge | grep  -q -e 'is_connected.*: true'")
if code == 0:
   print("OVS Bridge "+bridgeName+" connected to the conroller sucessfully")
else:
   print("OVS Bridge "+bridgeName+" NOT connected to the conroller")
#print if the switch allows fail-safe secure mode
code = os.system("sudo ovs-vsctl get-fail-mode "+bridgeName+" | grep -q secure")
if code == 0:
   print("OVS Bridge "+bridgeName+" fail-mode set to SECURE")
else:
   print("OVS Bridge "+bridgeName+" fail-mode set to NOT secure")
   

