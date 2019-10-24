# DHCPStarver


DHCPstarver is a tool to perform a DHCP starvation attack.

**This tool is designed for educational purposes only**

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

- `-s` to specify a subnet  
  A DHCP discover request implies that the client doesn't have a IP address yet, **but the subnet will be used to loop on each available IP address availables in a DHCP server**

- `-t` to add a specific timeout for each DHCP discover request (**default is 0**)  

- `-r` to add a number of retry to each DHCP discover request (**default is 0, only 1 DHCP discover**)  
  If the number of retry is equal to 0, **this value will be increased to 1**, Scapy needs to make at least one request

- `-d` to make Scapy more verbose, it only add `verbose = True` in Scapy crafted requests

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

```
Capture d'écran du slow mode ICI
```

## fast mode

The fast can be used with :  
- a timeout set lower than 5, at minimum `-t 4`  
- a number of retry lower than 2, at minimum `-r 1`

### Exemple 

```
Capture d'écran du slow mode ICI
```

# How to test DHCPstarver on your own DHCP server

On your favorite Linux distribution, you can install **isc-dhcp-server**  
On a Debian distrib, just run `apt-get install isc-dhcp-server` to install it



