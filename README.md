# elvisscan
ElvisScan Wifi network member vicinity scaner.

This set of two simple scripts allows you to keep tabs on other wifi clients on your wifi network.
The elvisscan script will monotor the wifi channel used by your access point.

The script defines four rings:

* The "inner" ring where data is communicated with the client and where the AP responds to probe requests.
* The "middle" ring where the AP does not respond to probe requests from the client, yet probes are observed directly.
* The "outer" ring where the clinet is only visible through probe responses from vicinity APs.
* The "missing" ring where any clint will end up after 30 minutes of not having been seen in any oth the real rings.

Elvisscan will output events on stdout and will create a fresh json file every five seconds. A simple cherypy script will
parse the json and display a simple html version of the data.

Elvisscan was developed on C.H.I.P device with an ALFA Network AWUS036NH as secondary WiFi device, but should in theory 
run on other setups as well with minor alterations. ElvisScan expects an active wifi connection on the device named wlan0,
and it expects a device named wlan1 to be evailable for usage in monitor mode. It is sugested that the device running
ElvisScan should be placed in such a way as to maximize reception range for the monitor mode wifi device.

Usage:

    ./esserver.py
    sudo ./elvisscan.py

The server will run on port 8080 of your monitoring appliance.

## NOTE:

There currently is a major but in elvisscan that makes it simply stop working after running for an amount of time ranging from a number of hours upto a little over a day. I've not yet been able to track down the bug that is causing this behaviour. If you happen to be a python expert with scapy/threading experience experience, I could really use some help on this one. Until this bug is fixed, ElvisScan should be considered seriously broken. 
