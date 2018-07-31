### mytcpdmp
---
* mytcpdmp is a passive network monitoring tool along the lines of tcpdmp
* It captures traffic from a network interface in promiscuous mode.
* It can also read data from pcap trace file
* The user can specify a [BPF filter](http://biot.com/capstats/bpf.html) to capture a subset of traffic or a string pattern to capture matching packets
* Prints the timestamp, source & destination MAC and IP addresses,  ethertype, packet length, port, protocol type and the payload.



#### Usage:
./mydump


-i&nbsp;&nbsp;&nbsp;Live capture from the network device <interface>. If not specified,  automatically selects a default interface to listen. Capture continues indefinitely until the user terminates the program.

-r&nbsp;&nbsp;&nbsp;read packets from <pcap trace file\>.

-s&nbsp;&nbsp;&nbsp;Keep only packets that contain <string> in their payload (after any BPF filter is applied).

<expression\> is a BPF filter that specifies which packets will be dumped. If no filter is given, all packets seen on the interface (or contained in the trace) are dumped. Otherwise, only packets matching <expression> are dumped.

Priority is given to -r over -i. If -r is present -i is ignored. If there is a error in r, program stops execution with error message. After that it checks for -i , if -i is not present then opens default device otherwise the specified device.

**Output Example:**

2013-01-12 11:38:02.227995 c4:3d:c7:17:6f:9b -> c4:3d:c7:17:6f:9b type 8 len 342  
192.168.0.1:1901 -> 192.168.0.1:1900 UDP  
00000  4e 4f 54 49 46 59 20 2a  20 48 54 54 50 2f 31 2e    NOTIFY * HTTP/1.  
00016  31 0d 0a 48 4f 53 54 3a  20 32 33 39 2e 32 35 35    1..HOST: 239.255  
00032  2e 32 35 35 2e 32 35 30  3a 31 39 30 30 0d 0a 43    .255.250:1900..C  
00048  61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma  
00064  78 2d 61 67 65 3d 33 36  30 30 0d 0a 4c 6f 63 61    x-age=3600..Loca  
00080  74 69 6f 6e 3a 20 68 74  74 70 3a 2f 2f 31 39 32    tion: http://192  
00096  2e 31 36 38 2e 30 2e 31  3a 38 30 2f 52 6f 6f 74    .168.0.1:80/Root  
00112  44 65 76 69 63 65 2e 78  6d 6c 0d 0a 4e 54 3a 20    Device.xml..NT:  
00128  75 75 69 64 3a 75 70 6e  70 2d 49 6e 74 65 72 6e    uuid:upnp-Intern  
00144  65 74 47 61 74 65 77 61  79 44 65 76 69 63 65 2d    etGatewayDevice-  
00160  31 5f 30 2d 63 34 33 64  63 37 31 37 36 66 39 62    1_0-c43dc7176f9b  
00176  0d 0a 55 53 4e 3a 20 75  75 69 64 3a 75 70 6e 70    ..USN: uuid:upnp  
00192  2d 49 6e 74 65 72 6e 65  74 47 61 74 65 77 61 79    -InternetGateway  
00208  44 65 76 69 63 65 2d 31  5f 30 2d 63 34 33 64 63    Device-1_0-c43dc  
00224  37 31 37 36 66 39 62 0d  0a 4e 54 53 3a 20 73 73    7176f9b..NTS: ss  
00240  64 70 3a 61 6c 69 76 65  0d 0a 53 65 72 76 65 72    dp:alive..Server  
00256  3a 20 55 50 6e 50 2f 31  2e 30 20 55 50 6e 50 2f    : UPnP/1.0 UPnP/  

---  

#### Requirement:
* gcc

#### References:

* http://www.tcpdump.org/pcap.html  
* http://tonylukasavage.com/blog/2010/12/19/offline-packet-capture-analysis-with-c-c----amp--libpcap/  
* https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html#Example-of-Getopt  
* https://stackoverflow.com/   
