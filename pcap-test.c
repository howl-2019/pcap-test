#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ether.h>

#define ETHERTYPE_IP 0x0800
#define IPPROTO_TCP 6

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

struct ethheader {
    u_char  ether_dhost[6];    // destination host address
    u_char  ether_shost[6];    // source host address
    u_short ether_type;        // IP? ARP? RARP? etc
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, 	//IP header length
                     iph_ver:4;		//IP version
  unsigned char      iph_tos;		//Type of service
  unsigned short int iph_len;		//IP Packet length (data + header)
  unsigned short int iph_ident;		//Identification
  unsigned short int iph_flag:3,	//Fragmentation flags
                     iph_offset:13;	//Flags offset
  unsigned char      iph_ttl;		//Time to Live
  unsigned char      iph_protocol;	//Protocol type
  unsigned short int iph_chksum;	//IP datagram checksum
  struct  in_addr    iph_sourceip;	//Source IP address
  struct  in_addr    iph_destip;	//Destination IP address
};

//TCP
struct tcpheader {
    u_short tcp_sport;               // source port
    u_short tcp_dport;               // destination port
    u_int   tcp_seq;                 // sequence number
    u_int   tcp_ack;                 // acknowledgement number
    u_char  tcp_offx2;               // data offset, rsvd
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 // window
    u_short tcp_sum;                 // checksum
    u_short tcp_urp;                 // urgent pointer
};

int is_tcp_packet(const u_char *packet) {
    // Ethernet Header
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return 0;
    }

    // IP Header
    struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip_header->iph_protocol != IPPROTO_TCP) {
        return 0;
    }
    return 1;
}
void print_mac_address(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
void print_tcp_info(const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct ethheader));
	int ip_header_length = ip_header->iph_ihl * 4;
	struct tcpheader *tcp_header = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length);
	
    int tcp_header_length = (tcp_header->tcp_offx2 >> 4) * 4;
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_length + tcp_header_length;
    int payload_length = ntohs(ip_header->iph_len) - (ip_header_length + tcp_header_length);
    
    
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf(" dst mac: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("\n");
	printf("src ip: %s dst ip: %s", inet_ntoa(ip_header->iph_sourceip), inet_ntoa(ip_header->iph_destip));
	printf("\n");
	printf("src port: %d dst port: %d", tcp_header->tcp_sport, tcp_header->tcp_dport);
	printf("\n");

    printf("Payload : ");
    for (int i = 0; i < payload_length && i < 20; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");

}

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// printf("%u bytes captured\n", header->caplen);
		if (is_tcp_packet(packet)) {
            printf("This is a TCP packet.\n");
			print_tcp_info(packet);
        } else {
            printf("This is not a TCP packet.\n");
        }
	}

	pcap_close(pcap);
}

