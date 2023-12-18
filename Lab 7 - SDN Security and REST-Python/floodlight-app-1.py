from flask import Flask,render_template, request
import datetime,json
from collections import deque

app = Flask(__name__)
showdatapoints = 10
timestamps = deque(maxlen=showdatapoints)
counts = deque(maxlen=showdatapoints)

totalCount = 0
flowCount = 0
firewallEnabled = False
import requests
import json

addFlowURL = "http://192.168.56.101:8080/wm/staticentrypusher/json"
enableFirewallUrl = "http://192.168.56.101:8080/wm/firewall/module/enable/json"
addRule = "http://192.168.56.101:8080/wm/firewall/rules/json"
clearSwitchUrl="http://192.168.56.101:8080/wm/staticflowpusher/clear/all/json"
headers = {
  'Content-Type': 'application/json'
}

@app.route("/staticflows", methods=["GET"])
def staticflows():
    return render_template("static_flow_form.html",success="")

@app.route("/staticflows", methods=["POST"])
def staticflows_submit():
    data =  request.form
    
    payload ={}
    global flowCount
    if data['ethType'] == "0x800":
        payload = json.dumps({
            "switch": data['dpid'],
            "name": "flows"+str(flowCount) ,
            "cookie": "100",
            "priority": data['priority'],
            "in_port": data['inPort'],
            "eth_type": data['ethType'],
            "ipv4_dst": data['destintionIp'],
            "active": "true",
            "actions": data["action"]
        })
    elif  data['ethType'] == "0x806":
        payload = json.dumps({
            "switch": data['dpid'],
            "name": "flows"+str(flowCount) ,
            "cookie": "100",
            "priority": data['priority'],
            "in_port": data['inPort'],
            "active": "true",
            "actions": data["action"]
        })  
    flowCount = flowCount + 1 
    response = requests.request("POST", addFlowURL, headers=headers, data=payload)
    if response.status_code == 200 :
        return render_template("static_flow_form.html",success="Static Flow entry added")
    else:
       return render_template("static_flow_form.html",success="Static Flow entry add faile. Error code -"+response.status_code)        

@app.route("/firewall", methods=["GET"])
def firewall():
    global firewallEnabled
    if not firewallEnabled:
        response = requests.request("PUT", enableFirewallUrl, headers="", data="")
        response = requests.request("GET", clearSwitchUrl ,headers="")
        firewallEnabled = True
        if response.status_code == 200:
            return render_template("firewall_forms.html",success="Firewall enable. Everything blocked by default")
        else:
            return render_template("firewall_forms.html",success="Firewall  falied to enable. Error code - "+response.status_code)
    return render_template("firewall_forms.html",success="")
@app.route("/firewall", methods=["POST"])
def firewall_submit():
    global flowCount
    data =  request.form
    print(data)
    protoMap = {
        "ICMP": 1,
        "TCP": 6,
        "UDP": 17
    }
    print("hello")
    payload = json.dumps({
        "switch": data['dpid'],
        "name": "rule"+str(flowCount),
        "cookie": "120",
        "priority": data['priority'],
        "in_port": data['inPort'],
        "eth_type": data['ethType'],
        "ipv4_src": data['sourceIp'],
        "ipv4_dst": data['destinationIp'],
        "ip_proto": protoMap[data['protocol']],
        "actions": "output=FLOOD"
    })
    
    print(payload)
    response = requests.request("POST", addFlowURL, headers=headers, data=payload)
    flowCount =flowCount + 1
    if response.status_code == 200:
        return render_template("firewall_forms.html",success="Firewall rule added.")
    else:
        return render_template("firewall_forms.html",success="Firewall rule add failed. Error code - "+response.status_code)

@app.route("/", methods=["GET"])
def indexPage():
    return render_template("index.html")

if __name__ == "__main__":
    time = datetime.datetime.now()
    app.run(host='0.0.0.0',port=9000)