#!/usr/bin/python
import netifaces
import os
from pythonwifi.iwlibs import Wireless
from scapy.all import *
import time
import threading
import json
import datetime

class HistoryElement:
  def __init__(self,ring,rset,moment):
      self.ring=ring
      self.rset=list(rset)
      self.rset.sort()
      self.when=moment

class Client:
  def __init__(self,mac):
      self.mac=mac
      self.lastseen={}
      self.lastseen["home"]=time.time()
      self.ring="inner"
      self.possible="inner"
      self.reexamine = False
      self.outerset = set()
      self.middleset = set()
      self.history = list()
      s = set()
      s.add("home") 
      self.addhistory("inner",s,time.time())
      self.report("non","inner",s,time.time())
  def addhistory(self,ring,rset,moment):
      self.history.append(HistoryElement(ring,rset,moment))
      self.history=self.history[-10:]
  def report(self,oldring,ring,rset,moment):
      dt = datetime.datetime.fromtimestamp(int(moment)).strftime('%Y-%m-%d %H:%M:%S')
      print dt,self.mac,
      if ring != oldring:
          if oldring == "missing":
              print " reapeared in the " + ring + " ring.",
          else: 
              if ring == "missing":
                  print " not seen sinse 30 minutes",
              else:
                  print " went from ",oldring," to ",ring," ring.", 
      else :
          print "remains in ",ring," ring.",
      if ring == "outer" or ring == "middle":
         print "Access points :", list(rset),
      print  
  def home(self):
      #Seen by own access point
      self.lastseen["home"]=time.time()
      s = set()
      s.add("home")
      self.newring("inner",s,time.time())
  def mon(self):
      #Seen by monitor (us)
      self.lastseen["mon"]=time.time()
      if self.ring != "inner":
          s = set()
          s.add("mon")
          self.newring("middle",s(),time.time())
      else:
          if self.reexamine == False or self.possible != "middle":
              self.reexamine = True
              self.possible = "middle"
  def other(self,other):
      #Seen by some nearby access point
      self.lastseen[other]=time.time()
      if self.ring == "missing":
          s = set()
          s.add(other)
          self.newring("outer",s,time.time())
      else:
          if self.reexamine == False or self.possible != "outer":
              self.reexamine = True
  def tick(self):
      now = time.time()
      newest = 0
      last = None
      for key in self.lastseen.keys():
          if self.lastseen[key] > newest:
              newest = self.lastseen[key]
              last = key
      if now - newest > 1800:
          self.newring("missing",set(),newest)
      else:
          if self.reexamine == True and now - newest > 3:
              aplist = set()
              windowstart = newest - 4
              for key in self.lastseen.keys():
                  if self.lastseen[key] > windowstart:
                      aplist.add(key)
              newring = "outer"
              if "mon" in aplist:
                  newring = "middle"
              if "home" in aplist:
                  newring = "inner"
              self.newring(newring,aplist,newest)
  def newring(self,ring,rset,moment):
      updated = False
      oldring = ring
      if ring != self.ring:
          self.ring = ring 
          updated = True
      if ring == "outer":
          if rset != self.outerset:
              self.outerset = rset
              updated = True
      if ring == "middle":
          if rset != self.middleset:
              self.middleset = rset
              updated = True
      if updated == True:
          self.addhistory(ring,rset,moment)
          self.report(oldring,ring,rset,moment)
      self.reexamine = False
  def asobj(self):
      obj = dict()
      obj["mac"] = self.mac
      obj["ring"] = self.ring
      obj["lastseen"] = self.lastseen
      obj["history"] = list()
      for event in self.history:
          subobj = dict()
          subobj["when"] = event.when
          subobj["ring"] = event.ring
          subobj["aps"] = event.rset
          obj["history"].append(subobj)
      return obj 

class ChipWifi:
  def __init__(self):
      self.clients = dict()
      w = Wireless("wlan0")
      ap = w.getAPaddr()
      self.AP = ap.lower()
      self.freq=w.getFrequency()
      self.ifname = "wlan1"
      os.system("/sbin/ifconfig %s down" % (self.ifname))
      self.wifi = Wireless(self.ifname)
      self.oldmode = self.wifi.getMode()
      self.wifi.setMode("monitor")
      os.system("/sbin/ifconfig %s up" % (self.ifname)) 
      self.wifi.setFrequency(self.freq)
  def __del__(self):
      os.system("/sbin/ifconfig %s down" % (self.ifname))
      self.wifi.setMode(self.oldmode)
  def run(self):
      sniff(iface=self.ifname,prn=self.packet,store = 0)
  def probe(self,client):
      if client in self.clients.keys():
         self.clients[client].mon()
  def presponse(self,server,client):
      if client in self.clients.keys():
          if server == self.AP:
              self.clients[client].home()
          else:
              self.clients[client].other(server)
  def activeclient(self,client):
      if not client in self.clients.keys():
          self.clients[client]=Client(client)
      self.clients[client].home()
  def packet(self,p):
      if p.haslayer(Dot11ProbeReq):
          if p[Dot11].addr2 in self.clients:
              self.probe(p[Dot11].addr2)
      else:
          if p.haslayer(Dot11ProbeResp):
              self.presponse(p[Dot11].addr2,p[Dot11].addr1)
          else: 
              if p[Dot11].addr1 == self.AP and p[Dot11].addr2 != None and p[Dot11].type == 2:
                  self.activeclient(p[Dot11].addr2)
  def tick(self):
      for mac in self.clients.keys():
          self.clients[mac].tick()
      data = list()
      for mac in self.clients.keys():
          data.append(self.clients[mac].asobj())
      content = json.dumps(data,indent=4, separators=(',', ': '))
      with open('elvisscan.json', 'w') as f:
          f.write(content)

def tick():
  global wifi
  threading.Timer(5.0, tick).start()
  wifi.tick()

wifi = ChipWifi()
tick()
wifi.run()
