

# DHCPStarver


DHCPstarver is a tool to perform a DHCP starvation attack.

**This tool is designed for educational purposes only**


- [DHCPStarver](#dhcpstarver)
- [Requirements](#requirements)
  - [Requirement file](#requirement-file)
- [Some sources - Thanks to](#some-sources---thanks-to)
  - [Special thanks](#special-thanks)
- [Command line arguments](#command-line-arguments)
- [How DHCPstarver make DHCP discover](#how-dhcpstarver-make-dhcp-discover)
- [Differents modes of use](#differents-modes-of-use)
  - [Slow mode](#slow-mode)
    - [Exemple](#exemple)
  - [fast mode](#fast-mode)
    - [Exemple](#exemple-1)
- [How to test DHCPstarver on your own DHCP server](#how-to-test-dhcpstarver-on-your-own-dhcp-server)






# Requirements

DHCPstarver use differents libraries :  
- **netaddr** to manage subnet and iterate availables hosts  
- **argparse** to manage command line arguments  
- **netifaces** to get all available interfaces  
- **scapy** to craft DHCP discover request
- **termcolor** to add color in your bland and dull terminal (huhu, just kidding)

## Requirement file

```
netaddr==0.7.19
argparse==1.2.1
netifaces==0.10.4
scapy==2.4.3
termcolor==1.1.0
```


Just run `pip3 install -r requirements.txt` to install all modules needed by DHCPstarver

# Some sources - Thanks to

- About DHCP starvation attack :  
http://www.omnisecu.com/ccna-security/dhcp-starvation-attacks-and-dhcp-spoofing-attacks.php

- Answer checking in scapy :  
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html

- Scapy documentation :  
https://scapy.readthedocs.io/en/latest/introduction.html

- Formatting DHCP discover request :  
https://www.riccardoancarani.it/playing-with-dhcp/

- Another good website to understand DHCP starvation :  
https://cabeggar.github.io/2016/02/21/DHCP-starvation-with-ScaPy/  


## Special thanks

Thanks to D@da for his regex (unfortunately not used), but appreciated it !   

`re.findall('([0-9]*.[0-9]*.[0-9]*.[0-9]*):bootpc /', str(answer))`

*View the end of makeDHCPRequest() function*

# Command line arguments 

DHCPstarver needs some arguments :  
- `-i` to specify interface which will be use to make DHCP discover request  
  DHCPstarver check if the interface exist before make request

- `-s` to specify a subnet, **with CIDR notation**  
  A DHCP discover request implies that the client doesn't have a IP address yet, **but the subnet will be used to loop on each available IP address availables in a DHCP server**

- `-t` to add a specific timeout for each DHCP discover request (**default is 0**)  

- `-r` to add a number of retry to each DHCP discover request (**default is 0, only 1 DHCP discover**)  
  If the number of retry is equal to 0, **this value will be increased to 1**, Scapy needs to make at least one request

- `-d` to make Scapy more verbose, it only add `verbose = True` in Scapy crafted requests

# How DHCPstarver make DHCP discover

DHCP discover is the first request of an host when no IP address is set.  
The client craft a request with :   

**At layer 2**  
- hardware MAC address source (random mac with DHCPstarver, *with RandMAC() function in Scapy*)  
- ff:ff:ff:ff:ff:ff destination MAC address (broadcast address for 2nd layer)

**At layer 3**
- 0.0.0.0 source IP address  
- 255.255.255.255 destination IP address (broadcast for 3rd layer)




# Differents modes of use

DHCPstarver can be used in fast or slow and more verbose mode.  

>The slow mode is only available if the timeout is greater than 4 and the number of retry is greater than 1  

>**It is arbitrarily assumed that without timeout and without retry specifieds, we want the minimum amount of information**

## Slow mode 

To use DHCPstarver in fast mode, just specify :  
- a timeout greater than 4, at minimum `-t 5`  
- a number of retry greater than 1, at minimum `-r 1`

The slow mode increase automatically the verbosity, to display a received DHCP offer with :  
- offered IP address
- informations about DHCP server (mac address, IP address)
> Notes that several DHCP servers can respond due to the `multi = True` in the crafted request in Scapy

Sometimes, Scapy doesn't seem to receive DHCP offers, but can be view with a standard sniffer (TCPDump, Wireshark...)

### Exemple

With command line `sudo python3 DHCPStarver.py -i vboxnet0 -r 3 -s 10.0.10.0/24 -t 5 -r 3` : 

```
     _____  _    _  _____ _____     _                            
    |  __ \| |  | |/ ____|  __ \   | |                           
    | |  | | |__| | |    | |__) |__| |_ __ _ _ ____   _____ _ __ 
    | |  | |  __  | |    |  ___/ __| __/ _` | '__\ \ / / _ \ '__|
    | |__| | |  | | |____| |   \__ \ || (_| | |   \ V /  __/ |   
    |_____/|_|  |_|\_____|_|   |___/\__\__,_|_|    \_/ \___|_|   
                                                                        
    
[+] Craft and send frame with 73:81:34:af:8f:fe mac address
- send frame [1/3]
[+] DHCP offer : 10.0.10.180 (from 08:00:27:00:8c:ce - 10.0.10.10)

[+] Craft and send frame with f9:f1:ee:0c:b0:f4 mac address
- send frame [1/3]
[+] DHCP offer : 10.0.10.181 (from 08:00:27:00:8c:ce - 10.0.10.10)

[+] Craft and send frame with e0:c5:a7:bb:98:38 mac address
- send frame [1/3]
- send frame [2/3]
- send frame [3/3]
[-] Scapy failed to recover DHCP offer, may be with another sniffer...

[+] Craft and send frame with 4e:c3:fe:ac:f5:02 mac address
- send frame [1/3]
- send frame [2/3]
- send frame [3/3]
[-] Scapy failed to recover DHCP offer, may be with another sniffer...

[+] Craft and send frame with e5:02:46:3d:3d:a4 mac address
- send frame [1/3]
[+] DHCP offer : 10.0.10.188 (from 08:00:27:00:8c:ce - 10.0.10.10)

[...]
```

## fast mode

The fast can be used with :  
- a timeout set lower than 5, at minimum `-t 4`  
- a number of retry lower than 2, at minimum `-r 1`

### Exemple 

With command line `sudo python3 DHCPStarver.py -i vboxnet0 -r 3 -s 10.0.10.0/24` : 

```

     _____  _    _  _____ _____     _                            
    |  __ \| |  | |/ ____|  __ \   | |                           
    | |  | | |__| | |    | |__) |__| |_ __ _ _ ____   _____ _ __ 
    | |  | |  __  | |    |  ___/ __| __/ _` | '__\ \ / / _ \ '__|
    | |__| | |  | | |____| |   \__ \ || (_| | |   \ V /  __/ |   
    |_____/|_|  |_|\_____|_|   |___/\__\__,_|_|    \_/ \___|_|   
                                                                        
    
[+] Craft and send frame with 4d:f0:3a:fa:ca:4b mac address
[+] Craft and send frame with c3:ab:d6:82:4d:d6 mac address
[+] Craft and send frame with fa:7d:53:4c:e6:24 mac address
[+] Craft and send frame with 29:d8:93:c5:16:28 mac address
[+] Craft and send frame with 14:fe:ad:5b:00:ca mac address
[+] Craft and send frame with 94:04:0e:e8:17:92 mac address
[+] Craft and send frame with c7:6e:bc:62:3f:56 mac address
[+] Craft and send frame with 8a:b8:a9:4b:b0:47 mac address
[+] Craft and send frame with 0c:db:96:03:c6:e8 mac address
[+] Craft and send frame with 4a:f0:38:98:14:fd mac address
[+] Craft and send frame with 74:a9:87:14:9e:ba mac address
[+] Craft and send frame with d4:81:9d:1f:a3:da mac address

[...]
```

# How to test DHCPstarver on your own DHCP server

On your favorite Linux distribution, you can install **isc-dhcp-server**  
On a Debian distrib, just run `apt-get install isc-dhcp-server` to install it



