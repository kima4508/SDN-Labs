from flask import Flask,render_template, request
import datetime,json
from collections import defaultdict
import requests
import json,logging

allowedSites = {
    "google": True,
    "youtube": True,
    "pict": True,
    "colorado.edu": True
}



app = Flask(__name__)
# log = logging.getLogger('werkzeug')
# log.disabled = True


# initial value of ICMP PATH is not fixed
icmpPath = "Path not detected yet"


# index page for forbidden
# when a site is rejected  it gets controllers IP, and thus a forbidden page is displayed on the browser
@app.route("/", methods=["GET"])
def forbiddenSite_():
    return render_template("forbidden.html")


# when the ICMP PATH is newly formed on the controller the controller sends a POST request to update the
# icmp path in the flask APP
@app.route("/updatetopopath", methods=["POST"])
def icmpPathFunc_():
    global icmpPath
    icmpPath = request.json['icmpPath']
    print(icmpPath)
    return {"status": True }


# Fetch the topoPath to be disaplyed in the browser
@app.route("/topopath", methods=["GET"])
def showTopoPath_():
    global icmpPath
    print(icmpPath)
    return render_template("topopath.html",icmpPath=icmpPath)


# Endpoint to check if th sit is bad or good
@app.route("/checksite",methods=["POST"])
def checkSite_():
    url =  request.json['url']
    print("Checking for url"+url)
    for sites in allowedSites.keys():
        if sites in url:
            return {"status": True }, 200   # site is good
    return {"status": False}, 200   # sit is bad

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=443,ssl_context='adhoc')

