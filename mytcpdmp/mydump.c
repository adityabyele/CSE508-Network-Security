#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<netinet/ether.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<time.h>
#include<unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


void print_hex_ascii_line(const u_char *payload,int len, int offset){
	int i;
	int gap;
	const u_char *ch;

	printf("%05d  ", offset);

	ch = payload;
	for(i = 0;i < len;i++){
		printf("%02x ", *ch);
		ch++;
		if(i == 7)
			printf(" ");
	}

	if(len < 8)
		printf(" ");

	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}


void print_payload(const u_char *payload, int len){
	int len_rem = len;
	int line_width = 16;
	int line_len;
	int offset = 0;

	const u_char *ch = payload;

	if(len <= 0)
		return;
	if(len <= line_width){
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	for(;;){
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if(len_rem <= line_width){
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}

	}
return;
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	//static int count = 1;
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
  const struct udphdr *udp;
  const struct icmp *icmphdr;
	const char *payload;

  /*search string*/
  char* srch_str = (char*)args;
  char* fnl_pyld = NULL;
  int to_print = 0;
  /*variables for printing time*/
  char timeStr[100];
  struct tm *tmInfo;

	int size_ip;
	int size_tcp;
  int size_udp = 8;
	int size_payload;
  int proto = -1;
	//printf("\nPacket number %d:\n", count);
	//count++;
  /*get ethernet info*/
	ethernet = (struct sniff_ethernet*)(packet);
  tmInfo = localtime((time_t*)&(header->ts.tv_sec));
  strftime(timeStr, 100,  "%Y-%m-%d %I:%M:%S.",tmInfo);
  //snprintf(timeStr, sizeof timeStr, "%s%s", timeStr, );


  if(ETHERTYPE_ARP == ntohs(ethernet->ether_type)){
    printf("OTHER\n");
    return;
  }
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20){
		printf("* Invalid IP header length:%u bytes\n", size_ip);
		return;
	}

	switch(ip->ip_p){
		case IPPROTO_TCP:
      proto = 1; //if proto cal tcp
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      if(size_tcp < 20){
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
      }
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			break;
		case IPPROTO_UDP:
      proto = 2; //if protocol udp
      udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
    	size_payload = ntohs(ip->ip_len) - (size_ip + 8);
			break;
		case IPPROTO_ICMP:
			//printf(" ICMP\n");
      proto = 3; //if proto cal icmp
      icmphdr = (struct icmp*)(packet + SIZE_ETHERNET + size_ip + 8);
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
    	size_payload = ntohs(ip->ip_len) - (size_ip + 8);
			break;
		default:
      proto =4;
			break;
	}

//	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
//	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

  if(srch_str != NULL){
    if(strstr(payload, srch_str)!=NULL)
      to_print = 1;
  }
  else{
    to_print = 1;
  }

  if(to_print){
    printf("%s%ld",timeStr,header->ts.tv_usec);
  	printf(" %s -> %s type %x len %d", ether_ntoa((struct ether_addr*)ethernet->ether_shost),ether_ntoa((struct ether_addr*)ethernet->ether_dhost), ethernet->ether_type, header->len);

    switch(proto){
      case 1:
        printf("\n%s:%d -> %s:%d TCP\n",inet_ntoa(ip->ip_src),ntohs(tcp->th_sport),inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
        break;
      case 2:
        printf("\n%s:%d -> %s:%d UDP\n",inet_ntoa(ip->ip_src),ntohs(udp->uh_sport),inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
        break;
      case 3:
        printf("\n%s -> %s ICMP\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
        break;
      case 4:
        printf("OTHER Protocol\n");
        break;
      default: break;
    }
    if(size_payload > 0){
  		//printf(" Payload(%d bytes):\n", size_payload);
  		print_payload(payload, size_payload);
  	}
  }

	return;
}




int main(int argc, char* argv[]){
	/*device variables*/
	char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = NULL; //session handler

  /*variables for command line options*/
  char *srch_str = NULL; //string to be searched passed as arguement after -s
  char *pcap_fname = NULL; //pcap file to be read passed as arguement after -r
  int option, i;
	/*variables for filtering*/
	struct bpf_program fp;
	char* filter_exp = NULL; //filter expression
	bpf_u_int32 mask; //netmask of device
	bpf_u_int32 net; //IP of device
	int num_packets = 10;
  int filter_on = 0; //tells if bpf filter was passed as an arguement

/*parsing input*/
  while((option = getopt(argc, argv, "i:r:s:"))!=-1){
    switch(option){
      case 'i':
        dev = optarg; //get device name
        //printf("iDevice: %s\n", dev);
        break;
      case 'r':
        pcap_fname = optarg; //get pacp file name
        //printf("read from file: %s\n", pcap_fname);
        break;
      case 's':
        srch_str = optarg; //get string to search
        //printf("search string: %s\n", srch_str);
        break;
      case '?':
        if (optopt == 'i'|| optopt == 'r'||optopt == 's')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
        return (2);
     default:
      abort();
    }
  }

  /*get bpf filter*/
  for (i = optind; i < argc; i++){
    filter_exp = argv[i];
    filter_on = 1;
    printf ("Non-option argument %s\n", filter_exp);
    break;

  }

  /*read file if -r specified*/
  if(pcap_fname != NULL){
    handle = pcap_open_offline(pcap_fname, errbuf);

    if (handle == NULL) {
     fprintf(stderr, "Failed to process file %s\n%s\n", pcap_fname, errbuf);
     return(2);
    }
  }


  if(handle == NULL){ //if -r not specified


    if(dev == NULL) // if -i not specified
      /*getting default device*/
      dev = pcap_lookupdev(errbuf);
  	if(dev == NULL){
  		fprintf(stderr, "Could'nt find default device: %s\n", errbuf);
  		return(2);
  	}

    /*opening up the device*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
      fprintf(stderr, "Could'nt open device %s: %s\n", dev, errbuf);
      return(2);
    }

    /*get IP and netmask*/
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
       fprintf(stderr, "Can't get netmask for device %s\n", dev);
       net = 0;
       mask = 0;
    }

    printf("device open for sniffing\n");
    if(pcap_datalink(handle) != DLT_EN10MB){
      fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
      return(2);
    }

  }

	/*compile and set filter expression*/
  if(filter_on){
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
  		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
  		return(2);
  	}

    if(pcap_setfilter(handle, &fp) == -1){
  		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
  		return(2);
  	}

  }

	/*capture packet*/
	//packet = pcap_next(handle, &header);
	//printf("Jacked a packet with length of [%d]\n", header.len);
	//printf("going in pcap_loop\n");
	if(pcap_loop(handle, 0, got_packet, srch_str) < 0){
    fprintf(stderr, "Pcap_loop failed, %s\n", pcap_geterr(handle));
  }

	/* close the session */
  if(filter_on)
	 pcap_freecode(&fp); //free bpf_program struct memory

	pcap_close(handle);

	return(0);
}
