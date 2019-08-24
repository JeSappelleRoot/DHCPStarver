import scapy
import netaddr
import configparser




# Define a network in CIDR notation
network = '172.16.0.0/24'
# Get ip range with netaddr library
# .iter_host() allow to get only 'hostable' ip
ipRange = netaddr.IPNetwork(network).iter_hosts()


for ip in ipRange:







print('ok!')