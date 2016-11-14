#!/usr/bin/python
import cherrypy
import json
import os
import time
from cherrypy.process.plugins import Daemonizer
import datetime

class ElvisBrowser(object):
  def __init__(self,datafile):
    self.datafile = datafile
  @cherrypy.expose
  def index(self):
    with open(self.datafile) as jsonfile:
        dataset = json.load(jsonfile)
    results="<H3>ElvisScan results</H3><ul>"
    for entry in dataset:
        results=results + "<li>" + entry["mac"] + " : " + entry["ring"] + " ring "
        lastseen = 0
        for k in entry["lastseen"].keys():
            if entry["lastseen"][k] > lastseen:
                lastseen = entry["lastseen"][k]
        ls = str(int(time.time() - lastseen))
        results += "(" + ls + " seconds ago) <ul>"
        for event in entry["history"]:
            w = datetime.datetime.fromtimestamp(int(event["when"])).strftime('%Y-%m-%d %H:%M:%S')
            r = event["ring"]
            results += "<li>" + r + " starting " + w + "<ul>"
            for ap in event["aps"]:
                 results += "<li>" + ap
            results += "</ul>"              
        results += "</ul>"                    
    return results

if __name__ == '__main__':
    datapath = os.getcwd() +"/elvisscan.json"
    #with open(datapath) as jsonfile:
    #  dataset = json.load(jsonfile)
    d = Daemonizer(cherrypy.engine)
    d.subscribe()
    cherrypy.config.update({'server.socket_host': '0.0.0.0'}) 
    cherrypy.quickstart(ElvisBrowser(datapath))
