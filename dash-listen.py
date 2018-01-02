# sudo apt-get install python-scapy tcpdump tcpreplay wireshark

# Note that wireshark prompts during installation if non-root users
# should be allowed to perform packed capture.

from scapy.all import *
import os
import requests

DASH_MAC_ADDRESS=os.environ.get('DASH_MAC_ADDRESS')
HA_API_BASE=os.environ.get('HA_API_BASE')
HA_SERVICE=os.environ.get('HA_SERVICE')
HA_ENTITY_ID=os.environ.get('HA_ENTITY_ID')
HA_PASSWORD=os.environ.get('HA_PASSWORD')

URL_CALLBACK=HA_API_BASE + "/services/" + HA_SERVICE.replace('.', '/')
CALL_BODY='{"entity_id":"' + HA_ENTITY_ID + '"}'
HEADERS={'X-HA-access': HA_PASSWORD}

def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      if pkt[ARP].hwsrc == DASH_MAC_ADDRESS:
        requests.get(URL_CALLBACK, headers=HEADERS, data=CALL_BODY)
      else:
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc


while True:
    try:
        print sniff(prn=arp_display, filter="arp", store=0, count=10)
    except:
        pass
