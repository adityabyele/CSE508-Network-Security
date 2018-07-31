### DNS Cache Poisoning and Detection
---
#### DNS Inject:

* Monitors traffic from a list of specified hosts in promiscus mode and injects forged responses for DNS A requests. thus poisoning the resolvers cache.
* After capturing a packet, checks if it has a DNS layer with a Question record and query type 0
* Forges a new DNS packet by swapping source and destination IP addresses, ports from the captured packet. 
* Creates a DNS Resource record setting the transaction id equal to the transaction id of the captured packet and the qr as 1 indicating an answer.
* After this all the requests sent by the victim to the original server are actually sent to the IP addresses specified by the attacker. 

##### Usage:
python dnsinject.py [-i interface] [-h hostnames] expression

-i&nbsp;&nbsp;&nbsp;  Listen on network device <interface> (e.g., eth0). If not specified, dnsinject selects a default interface to listen on. The same
interface is used for packet injection.

-h&nbsp;&nbsp;&nbsp;Reads a list of IP address and hostname pairs specifying the hostnames to be hijacked. If '-h' is not specified, dnsinject forges replies for all observed requests with the local machine's IP address as an answer.
    
<expression\> is a BPF filter that specifies a subset of the traffic to be
monitored. This option is useful for targeting a single or a set of particular
victims.
***
#### DNS Detect:

 * DNS detect sniffs traffic in promiscus mode on the given interface
 * If packet found on network then it checks if it has a DNS layer with a answer record, query type 1.
 * Then it checks if an answer to that request with the same transaction id already exists
 * If there is no record then it stores the ip addresses mentioned in the answer record.
 * If another response with same transaction id arrives it compares the IP address in the packet with the stored IP and alerts the user if no match found.
 * Prints an alert containing a printout of both the spoofed and legitimate responses including the detected DNS transaction ID, attacked domain name, and the original and malicious IP addresses.

##### Usage:
python dnsdetect.py

-i&nbsp;&nbsp;&nbsp;Listen on network device <interface> (e.g., eth0). If not specified,selects a default interface to listen on.

-r&nbsp;&nbsp;&nbsp;Read packets from <tracefile\> (tcpdump format). Useful for detecting DNS poisoning attacks in existing network traces.

<expression\> is a BPF filter that specifies a subset of the traffic to be
monitored.

**Output Example:**

2017-12-10 23:30:47.824089 DNS Poisoning attempt  
TXID 64165 Request yandex.com.  
Answer1 ['10.6.6.6']  
Answer2 ['213.180.204.62']    

***
#### Requirements:

* python 2.7.12
* scapy 2.3.2 

#### References
* https://docs.python.org/3/library/argparse.html
* http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
* http://www.secdev.org/projects/scapy/files/scapydoc.pdf
* https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
* https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
