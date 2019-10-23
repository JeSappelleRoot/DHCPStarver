import netaddr
import argparse
from scapy.all import *
import re


def makeDHCPRequest(ipRequested, interface, nb, timeOut):
# Function to craft simple DHCP discover request
    
    conf.checkIPaddr = False

    # Get a random MAC address
    randomMac = RandMAC()
    # Craft DHCP discover request
    ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=randomMac)
    ip       = IP(src ='0.0.0.0', dst='255.255.255.255')
    udp      = UDP (sport=68, dport=67)
    bootp    = BOOTP(op=1, chaddr=randomMac)
    dhcp     = DHCP(options=[("message-type","discover"),('end')])
    packet   = ethernet / ip / udp / bootp / dhcp

    # Send DHCP discover request through specified interface
    for i in range(nb):
        answer, unanwser = srp(packet,iface = interface, multi = True, verbose = True, timeout = timeOut)
        # If an answer is given, quit the for loop
        # Sometime, Scapy don't receive answer, but Wireshark does...
        if answer:
            break

    # If no answer received
    if not answer:
        print("[-] No DHCP offer from a DHCP server...")
    # Else if we have an answer from a DHCP server
    else:
        # Loop on the answer, to extract send/receive part
        for snd,rcv in answer:
            # Extract IP of DHCP server
            ipSrv = rcv.sprintf(r"%IP.src%")
            # Extract offered IP
            ipOffer = rcv.sprintf(r"%IP.dst%"))
        
        # Regex from D@d@ 
        # re.findall('([0-9]*.[0-9]*.[0-9]*.[0-9]*):bootpc /', str(answer))
        
    return

# --------------------------------------------------------
# ------------------------- Main -------------------------
# --------------------------------------------------------

# Define a network in CIDR notation
network = '10.0.10.0/24'

# Try/Except to avoid error in network notation
try:
    netAddress = netaddr.IPNetwork(network,implicit_prefix=False)

    # If the network CIDR is greater or equal to 31
    # /31 allow only 2 hosts in the network
    # /32 don't allow any hosts in network...
    if netAddress.prefixlen >= 31:
        print("[!] Please specify a CIDR lower than 31 or 32")
        exit()
except netaddr.AddrFormatError as e:
    print("[!] Please specify a valid network address : ")
    print(f"[!] {e}")
    exit()



# Define interface used for dhcp spoofed request
interface = 'vboxnet0'
# Number of request by mac address
nb = 3
# Define timeout (in seconds) for each DHCP discover request
timeOut = 2


# Get ip range with netaddr library
# .iter_host() allow to get only 'hostable' ip
ipRange = netaddr.IPNetwork(network).iter_hosts()

# Simple loop to make DHCP discover request on the IP range
for index,ip in enumerate(ipRange):
    print(f"[+] DHCP discover {index + 1}/{len(list(ipRange))}")
    makeDHCPRequest(ip, interface, nb, timeOut)
    break

# Futur DHCP server 
# http://pydhcplib.tuxfamily.org/pmwiki/index.php?n=Site.ServerExample

# Answer analyzing from 
# https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html