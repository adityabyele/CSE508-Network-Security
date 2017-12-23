from scapy.all import *
import argparse
import socket
import fcntl
import struct
import copy
from datetime import datetime as dtm

class myCache:
	def __init__(self, hostName, ipAddr):
		self.hostName = hostName
		self.ipAddr = copy.deepcopy(ipAddr)

def get_ip_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])


def packetSniff(interface, bpf_filt, offline, pcapFile):
	host_dict={}
	count = 0
	conf.sniff_promisc = True
	if(offline == True):
		pkts = sniff(offline = pcapFile, prn = lambda x: showPkts(x, interface, host_dict), iface = interface, count=0)
	else:
		pkts = sniff(filter = bpf_filt, prn = lambda x: showPkts(x, interface, host_dict), iface = interface, count = 0)

def showPkts(pkt, iface, host_dict):
    	if(pkt.haslayer(DNS)):		
		if(pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1 and pkt.getlayer(DNS).ancount >= 1 and pkt[DNSRR][0].type == 1):
			tmp = list()
			for i in range(pkt['DNS'].ancount):
				tmp.append(pkt[DNSRR][i].rdata)
			cacheObj = host_dict.get(pkt[DNS].id)
			if cacheObj == None:				
				host_dict[pkt[DNS].id]  = myCache(str(pkt[DNSRR][0].rrname), tmp)
			else:
				for ip1 in cacheObj.ipAddr:
					for ip2 in tmp:
						if(ip1 == ip2):
							return
				print "--------------------------------------------------------------"
				print dtm.now(), "DNS Poisoning attempt"
				print "TXID", pkt[DNS].id, "Request", cacheObj.hostName
				print "Answer1", cacheObj.ipAddr
				print "Answer2", tmp
				print "--------------------------------------------------------------"


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='inject fake dns response', add_help=False)
	parser.add_argument("-i","--interface", help="interface to sniff on")
	parser.add_argument("-r","--pcapFile", help="path to pcap trace file")
	parser.add_argument('bpf', nargs=argparse.REMAINDER)
	args = parser.parse_args()
	if(args.interface):
		iface = args.interface
	else:
		iface = conf.iface	
	if(args.pcapFile):
		offline = True
		filePath = args.pcapFile
	else:
		offline = False
		filePath = None
	filterExp = " ".join(args.bpf)
	packetSniff(interface = iface, bpf_filt = filterExp,offline=offline,pcapFile=filePath)
