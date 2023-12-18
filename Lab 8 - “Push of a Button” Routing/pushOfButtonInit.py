import requests,json
from netmiko import ConnectHandler
from flask import Flask,render_template, request
import datetime,json,time,sys
from collections import deque
from tester import *
ryuController = "192.168.56.103"
ryuPort = "8080"


devices ={
    "Mininet":{
        "device_type": "linux",
        "host": "192.168.56.102",
        "username": "mininet",
        "password": "mininet",
        "secret": "mininet"
    },
    "Controller": {
        "device_type": "linux",
        "host": ryuController,
        "username": "sdn",
        "password": "sdn",
        "secret": "sdn"
    }
}

dpids = {}
ipAddressTopology = {
    #interfaces on routers
    "r1": ["10.0.0.254/24","2.2.2.1/24","3.3.3.1/24","4.4.4.1/24"],
    "r2": ["3.3.3.2/24","7.7.7.2/24"],
    "r3": ["7.7.7.1/24","8.8.8.1/24"],
    "r4": ["8.8.8.2/24","9.9.9.2/24"],
    "r5": ["10.10.10.2/24","9.9.9.1/24","5.5.5.1/24","1.1.1.254/24"],
    "r6": ["2.2.2.2/24","6.6.6.2/24"],
    "r7": ["6.6.6.1/24","10.10.10.1/24"],
    "r8": ["4.4.4.2/24","5.5.5.2/24"]
}
routes = {
    #prefix
    "1.1.1.0/24": {
        #nexthop
        "r1": ["2.2.2.2","3.3.3.2","4.4.4.2"],
        "r2": ["7.7.7.1"],
        "r3": ["8.8.8.2"],
        "r4": ["9.9.9.1"],
        "r6": ["6.6.6.1"],
        "r7": ["10.10.10.2"],
        "r8": ["5.5.5.1"]
    },
    #prefix
    "10.0.0.0/24": {
        #next hops
        "r2": ["3.3.3.1"],
        "r3": ["7.7.7.2"],
        "r4": ["8.8.8.1"],
        "r5": ["10.10.10.1","9.9.9.2","5.5.5.2"],
        "r6": ["2.2.2.1"],
        "r7": ["6.6.6.2"],
        "r8": ["4.4.4.1"]
    }
}

intentFlows = []
def deleteflows(flows=intentFlows):
    apiEndpoint= "http://"+ryuController+":"+ryuPort+"/stats/flowentry/delete"
    for flow in flows:
        response = requests.request("POST", url=apiEndpoint, \
                                    headers={'Content-Type': 'application/json'}, \
                                    data=json.dumps(flow))
        if response.status_code == 200:
            print("Flow removed - "+str(json.dumps(flow)))
            flows.remove(flow)
        else:
            print("Flow couldn't be deleted")
            sys.exit()
    return

def deleteStaticRoute(router,prefix,nextHop):

    response = requests.request("GET", url="http://"+ryuController+":"+ryuPort+"/router/"+dpids[router], headers={'Content-Type': 'application/json'})
    data = response.json()[0]
    topo = data["internal_network"][0]
    for route in topo['route']:
        if route["destination"] == prefix and route["gateway"] == nextHop:
            payload={"route_id": str(route["route_id"]) }
            response = requests.request("DELETE", url="http://"+ryuController+":"+ryuPort+"/router/"+dpids[router], \
                                        headers={'Content-Type': 'application/json'}, \
                                        data=json.dumps(payload))
            print(response)
            return


connController = None
connMininet = None
def initalizeTopology():
    global connController, connMininet
    connMininet=ConnectHandler(**devices["Mininet"])
    connMininet.enable(cmd="sudo su",pattern="password")
    output = connMininet.send_command_timing("sudo mn -c")
    print(output)
    print("Clearing mininet")
    time.sleep(4)
    print("Starting the controller")
    connController=ConnectHandler(**devices["Controller"])
    connController.enable(cmd="sudo su",pattern="password")
    output = connController.send_command_timing("sudo ryu run /home/sdn/ryu/ryu/app/rest_router.py /home/sdn/ryu/ryu/app/ofctl_rest.py")
    print(output)
    time.sleep(5)
    output = connMininet.send_command_timing("sudo python /home/mininet/lab8.py")
    print(output)
    time.sleep(3)
    output = connMininet.send_command_timing("links")
    print(output)
    output = connMininet.send_command_timing("net")
    print(output)

    #generate DPIDs
    global dpids
    for i in range(1,9):
        dpids["r"+str(i)] = "000000000000000"+str(i)
    print("Following dpids are mapped to routers")
    print(json.dumps(dpids,indent=4), )
    for router in dpids.keys():
        apiEndpoint = "http://"+ryuController+":"+ryuPort+"/router/"+dpids[router]
        #install ips
        for ipAddr in ipAddressTopology[router]:
            payload = json.dumps({ "address": ipAddr })
            response = requests.request("POST", url=apiEndpoint, \
                                        headers={'Content-Type': 'application/json'}, \
                                        data=payload)
            print(response)
            #time.sleep(2)
            if response.status_code == 200:
                print("Router: "+router+" --> "+ payload+" ip addresses configured")
            else:
                sys.exit()
            
        #install static routes
        for prefix in routes.keys():
            if router not in routes[prefix]:
                continue
            
            nextHops = routes[prefix][router]
            #prefix
            #nextHops
            for nexthop in nextHops:
                payload = json.dumps({"destination": prefix, "gateway": nexthop })
                response = requests.request("POST", url=apiEndpoint, \
                                        headers={'Content-Type': 'application/json'}, \
                                        data=payload)
                #time.sleep(2)
                if response.status_code == 200:
                    print("Router: "+router+" --> "+ payload+" route configured")
                else:
                    sys.exit()
                break
        print("---------------------------------------------------------------------")
    time.sleep(10)
    output = connMininet.send_command_timing("h1 ping -c 5 server")
    print(output)
    return

def installShortestPathFlowHTTP():
    apiEndpoint = "http://"+ryuController+":"+ryuPort+"/stats/flowentry/add"
    print("Setting path h1 - ovs1-ovs8-ovs5 - server:8080 for http traffic")
    # on ovs1
    route1= {
        "dpid": 1,
        "cookie": 30,
        "priority": 1000,
        "match":{
            "dl_type":2048, #ipv4
            "in_port":4,    
            "tp_dst":8080,
            "nw_dst":"1.1.1.1/24",
            "nw_proto":6  #tcp
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 2
            }
        ]
    }
    # on ovs5
    route2= {
        "dpid": 5,
        "cookie": 30,
        "priority": 1000,
        "match":{
            "dl_type":2048, #ipv4
            "in_port":1,    
            "tp_src":8080,
            "nw_dst":"10.0.0.1/24",
            "nw_proto":6  #tcp
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 3
            }
        ]
    }
    output = requests.request("POST", url=apiEndpoint, \
                                headers={'Content-Type': 'application/json'}, \
                                data=json.dumps(route1))
    print(output)
    output = requests.request("POST", url=apiEndpoint, \
                                headers={'Content-Type': 'application/json'}, \
                                data=json.dumps(route2))
    print(output)
    global intentFlows
    intentFlows.append(route1)
    intentFlows.append(route2)
    return

def installLongestPathFlowHTTP():
    apiEndpoint = "http://"+ryuController+":"+ryuPort+"/stats/flowentry/add"
    print("Setting path h1 - ovs1-ovs2-ovs3-ovs4-ovs5 - server:8080 for http traffic")
    # on ovs1
    route1= {
        "dpid": 1,
        "cookie": 30,
        "priority": 1000,
        "match":{
            "dl_type":2048, #ipv4
            "in_port":4,    
            "tp_dst":8080,
            "nw_dst":"1.1.1.1/24",
            "nw_proto":6  #tcp
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 3
            }
        ]
    }
    # on ovs5
    route2= {
        "dpid": 5,
        "cookie": 30,
        "priority": 1000,
        "match":{
            "dl_type":2048, #ipv4
            "in_port":1,    
            "tp_src":8080,
            "nw_dst":"10.0.0.1/24",
            "nw_proto":6  #tcp
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 4
            }
        ]
    }
    output = requests.request("POST", url=apiEndpoint, \
                                headers={'Content-Type': 'application/json'}, \
                                data=json.dumps(route1))
    print(output)
    output = requests.request("POST", url=apiEndpoint, \
                                headers={'Content-Type': 'application/json'}, \
                                data=json.dumps(route2))
    print(output)
    global intentFlows
    intentFlows.append(route1)
    intentFlows.append(route2)
    # check if it takes the desired path
    return

def installDefaultPathFlowHTTP():
    apiEndpoint = "http://"+ryuController+":"+ryuPort+"/stats/flowentry/add"
    print("Setting path h1 - ovs1-ovs2-ovs3-ovs4-ovs5 - server:8080 for http traffic")
    # on ovs1
    route1= {
        "dpid": 1,
        "cookie": 30,
        "priority": 1000,
        "match":{
            "dl_type":2048, #ipv4
            "in_port":4,    
            "tp_dst":8080,
            "nw_dst":"1.1.1.1/24",
            "nw_proto":6  #tcp
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 1
            }
        ]
    }
    # on ovs5
    route2= {
        "dpid": 5,
        "cookie": 30,
        "priority": 1000,
        "match":{
            "dl_type":2048, #ipv4
            "in_port":1,    
            "tp_src":8080,
            "nw_dst":"10.0.0.1/24",
            "nw_proto":6  #tcp
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 2
            }
        ]
    }
    output = requests.request("POST", url=apiEndpoint, \
                                headers={'Content-Type': 'application/json'}, \
                                data=json.dumps(route1))
    print(output)
    output = requests.request("POST", url=apiEndpoint, \
                                headers={'Content-Type': 'application/json'}, \
                                data=json.dumps(route2))
    print(output)
    global intentFlows
    intentFlows.append(route1)
    intentFlows.append(route2)
    # check if it takes the desired path
    return

#any ipv6 takes shortest path h1 - ovs1-ovs8-ovs5 - server
def installIpv6PathFlow():
    apiEndpoint = "http://"+ryuController+":"+ryuPort+"/stats/flowentry/add"
    print("Setting path h1 - ovs1-ovs8-ovs5 - server for IPV6 traffic")
    # on ovs1
    routes = []
    routes.append({
        "dpid": 1,
        "cookie": 30,
        "priority": 4000,
        "match":{
            "dl_type":34525, #ipv6
            "in_port":4
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 2
            }
        ]
    })
    #ovs1
    routes.append({
        "dpid": 1,
        "cookie": 30,
        "priority": 4000,
        "match":{
            "dl_type":34525, #ipv6
            "in_port":2
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 4
            }
        ]
    })
    #ovs8
    routes.append({
        "dpid": 8,
        "cookie": 30,
        "priority": 4000,
        "match":{
            "dl_type":34525, #ipv6
            "in_port":1
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 2
            }
        ]
    })
    #ovs8
    routes.append({
        "dpid": 8,
        "cookie": 30,
        "priority": 4000,
        "match":{
            "dl_type":34525, #ipv6
            "in_port":2
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 1
            }
        ]
    })
    # on ovs5
    routes.append({
        "dpid": 5,
        "cookie": 30,
        "priority": 4000,
        "match":{
            "dl_type":34525, #ipv6
            "in_port":1   
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 3
            }
        ]
    })
    # on ovs5
    routes.append({
        "dpid": 5,
        "cookie": 30,
        "priority": 4000,
        "match":{
            "dl_type":34525, #ipv6
            "in_port":3  
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": 1
            }
        ]
    })
    for route in routes:
        output = requests.request("POST", url=apiEndpoint, \
                                headers={'Content-Type': 'application/json'}, \
                                data=json.dumps(route))
        print(output)
    # check if it takes the desired path
    return

app = Flask(__name__)
@app.route("/", methods=["GET"])
def staticflows():
    return render_template("index.html",routing_status="",visibility="hidden")


@app.route("/shortestPath", methods=["GET"])
def shortestPath():

    deleteflows()
    installShortestPathFlowHTTP()
    shortestPath = "h1 - ovs1-ovs8-ovs5 - server"
    print("Configured shortest path -"+shortestPath)

    return render_template("index.html", routing_status="Successfully configured routing http traffic via - Shortest path",route=shortestPath,visibility="")


@app.route("/longestPath", methods=["GET"])
def longestPath():
    deleteflows()
    installLongestPathFlowHTTP()
    longestPath = "h1 - ovs1-ovs2-ovs3-ovs4-ovs5 - server" 
    print("Configured longest path -"+longestPath)
    return render_template("index.html", routing_status="Successfully configured routing http traffic via - Longest path",route=longestPath,visibility="")

@app.route("/bestDelay", methods=["GET"])
def bestDelay():
    deleteflows() #remove intent flows

    #test default path delay
    output = connMininet.send_command_timing("h1 ping -c 5 server")
    rtt_line = output.split("rtt ")[1]
    rtt_line=rtt_line.split()[2]
    defaultPathAverageRTT = float(rtt_line.split('/')[1])
    print("Delay on path ==> h1 - ovs1-ovs6-ovs7-ovs5 -server"+str(defaultPathAverageRTT)+" milliseconds")
    deleteStaticRoute("r1",prefix="1.1.1.0/24",nextHop=routes["1.1.1.0/24"]["r1"][0])
    deleteStaticRoute("r5",prefix="10.0.0.0/24",nextHop=routes["10.0.0.0/24"]["r5"][0])


    # test longest path delay
    apiEndpointR1 = "http://"+ryuController+":"+ryuPort+"/router/"+dpids["r1"]
    apiEndpointR5 = "http://"+ryuController+":"+ryuPort+"/router/"+dpids["r5"]   
    payload = json.dumps({"destination": "1.1.1.0/24", "gateway": routes["1.1.1.0/24"]["r1"][1]} )
    requests.request("POST", url=apiEndpointR1, \
                    headers={'Content-Type': 'application/json'},
                    data=payload)
    payload = json.dumps({"destination": "10.0.0.0/24", "gateway": routes["10.0.0.0/24"]["r5"][1]} )
    requests.request("POST", url=apiEndpointR5, \
                    headers={'Content-Type': 'application/json'},
                    data=payload)

    output = connMininet.send_command_timing("h1 ping -c 5 server")
    rtt_line = output.split("rtt ")[1]
    rtt_line=rtt_line.split()[2]
    longestPathAverageRTT = float(rtt_line.split('/')[1])
    print("Delay on path ==> h1 - ovs1-ovs2-ovs3-ovs4-ovs5 - server"+str(longestPathAverageRTT)+" milliseconds")
    deleteStaticRoute("r1",prefix="1.1.1.0/24",nextHop=routes["1.1.1.0/24"]["r1"][1])
    deleteStaticRoute("r5",prefix="10.0.0.0/24",nextHop=routes["10.0.0.0/24"]["r5"][1])


    #test shortest path delay
    payload = json.dumps({"destination": "1.1.1.0/24", "gateway": routes["1.1.1.0/24"]["r1"][2]} )
    requests.request("POST", url=apiEndpointR1, \
                    headers={'Content-Type': 'application/json'},
                    data=payload)
    payload = json.dumps({"destination": "10.0.0.0/24", "gateway": routes["10.0.0.0/24"]["r5"][2]} )
    requests.request("POST", url=apiEndpointR5, \
                    headers={'Content-Type': 'application/json'},
                    data=payload)
    output = connMininet.send_command_timing("h1 ping -c 5 server")
    rtt_line = output.split("rtt ")[1]
    rtt_line=rtt_line.split()[2]
    shortestPathAverageRTT = float(rtt_line.split('/')[1]) 
    print("Delay on path ==> h1 - ovs1-ovs8-ovs5 - server"+str(shortestPathAverageRTT)+" milliseconds")
    deleteStaticRoute("r1",prefix="1.1.1.0/24",nextHop=routes["1.1.1.0/24"]["r1"][2])
    deleteStaticRoute("r5",prefix="10.0.0.0/24",nextHop=routes["10.0.0.0/24"]["r5"][2])


    #add default route back again
    payload = json.dumps({"destination": "1.1.1.0/24", "gateway": routes["1.1.1.0/24"]["r1"][0]} )
    requests.request("POST", url=apiEndpointR1, \
                    headers={'Content-Type': 'application/json'},
                    data=payload)
    payload = json.dumps({"destination": "10.0.0.0/24", "gateway": routes["10.0.0.0/24"]["r5"][0]} )
    requests.request("POST", url=apiEndpointR5, \
                    headers={'Content-Type': 'application/json'},
                    data=payload)

    curentBestDelayPath = ""
    if defaultPathAverageRTT > longestPathAverageRTT:
        if longestPathAverageRTT > shortestPathAverageRTT:
            #install shortest path for http
            installShortestPathFlowHTTP()
            curentBestDelayPath="ovs1-ovs8-ovs5"
        else:
            # install the longest path for http
            installLongestPathFlowHTTP()
            curentBestDelayPath="ovs1-ovs2-ovs3-ovs4-ovs5"
    else:
        if defaultPathAverageRTT > shortestPathAverageRTT:
            #install shortest path
            installShortestPathFlowHTTP()
            curentBestDelayPath="ovs1-ovs8-ovs5"
        else:
            #install defaultpath path for http traffic
            installDefaultPathFlowHTTP()
            curentBestDelayPath="ovs1-ovs6-ovs7-ovs5"
    curentBestDelayPath = "h1 - "+curentBestDelayPath+" server"  
    print("Selecting low latency path ---> "+curentBestDelayPath) 
    return render_template("index.html", routing_status="Successfully configured routing http traffic via - Best Delay Path",route=curentBestDelayPath,visibility="")

@app.route("/ipv6", methods=["GET"])
def ipv6Routing():
    installIpv6PathFlow()
    print("IPV6 path configured")
    ipv6PingTest = connMininet.send_command_timing("h1 ping6 -c 10 5501::2")
    print(ipv6PingTest)
    route = " (IPV6) h1 -ovs1-ovs8-ovs5 - server (IPv6)"
    return render_template("index.html", routing_status="        Successfully configured routing for IPV6 traffic           ",route=route,visibility="",route_icmp=ipv6PingTest)

@app.route("/testTraffic" ,methods=["GET"])
def testTraffic():


    beforeTraffic = capturePortStats()
    connMininet.send_command_timing("h1 ping -c 10 server")
    afterTraffic = capturePortStats()

    print(beforeTraffic)
    print(afterTraffic)
    

    changeRate =getChange(beforeTraffic=beforeTraffic,afterTraffic=afterTraffic)
    routeICMP = getPath(changeRate)

    print("------Change Rate")
    print(changeRate)
    print("ICMP Path is ---> "+routeICMP)

    print("--------------------- http -----------------------------")
    beforeTraffic = capturePortStats()
    connMininet.send_command_timing("h1 curl http://1.1.1.1:8080")
    afterTraffic = capturePortStats()

    changeRate =getChange(beforeTraffic,afterTraffic)
    routeHTTP = getPath(changeRate)
    return render_template("index.html", routing_status="        Successfully tested traffic           ", \
                            route_icmp=routeICMP, \
                            route_http=routeHTTP, \
                            visibility="")

if __name__ == "__main__":
    initalizeTopology()
    app.run(host='0.0.0.0',port=9000)


