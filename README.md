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
