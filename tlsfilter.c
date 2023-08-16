#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

/* Ethernet addresses are 6 bytes */

#define ETHER_ADDR_LEN		6

/* Ethernet header */

struct sniff_ethernet 
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */

struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */

typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* ethernet headers are always exactly 14 bytes */

#define SIZE_ETHERNET 14
#define OFFSET_HELLO_VERSION	9
#define OFFSET_SESSION_LENGTH	43
#define OFFSET_CIPHER_LIST	44
#define TLS_HANDSHAKE		22
#define TLS_CLIENT_HELLO	1

struct file_and_version
{
	char *file_name;
	u_short version;
};

char*
ssl_version(u_short version) {
	static char hex[7];
	switch (version) 
	{
		case 0x002: return "SSLv2";
		case 0x300: return "SSLv3";
		case 0x301: return "TLSv1";
		case 0x302: return "TLSv1.1";
		case 0x303: return "TLSv1.2";
		case 0x304: return "TLSv1.3";
	}
	snprintf(hex, sizeof(hex), "0x%04hx", version);
	return hex;
}

void
print_app_usage();

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

u_short 
get_version(char *version);

void
print_app_usage()
{
	pcap_if_t *interfaces, *temp;
	char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];
	printf("The call should be like this: \n ./tlsfilter ETH VERSION LOGFILE\n");
	printf("\nVERSION (valid values): 1.0, 1.1, 1.2, 1.3\n");
	
	if (pcap_findalldevs(&interfaces,errbuf) == -1)
	{
		printf("Couldn't find any default devices");
		fprintf(stderr, "Couldn't find default devices: %s\n", errbuf);
		return;
	}
	printf("\nThe interfaces present on the system (ETH) are:\n");
	int i = 0;
    	for(temp = interfaces; temp; temp = temp->next)
    	{
		printf("%d  :  \'%s\'\n",i++,temp->name);
    	}
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct file_and_version *fv;
	fv = (struct file_and_version*)args;
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	int size_ip;
	int size_tcp;
	int size_payload;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	
	size_ip = IP_HL(ip) * 4;
	
	if (size_ip < 20) /* Invalid IP header length*/
	{
		return;
	}

	/* retrieve source and destination IP addresses */
	char src_buffer[18];
	char *bytes = (unsigned char *) &ip->ip_src;
 	snprintf (src_buffer, sizeof (src_buffer), "%d.%d.%d.%d",
	      bytes[0], bytes[1], bytes[2], bytes[3]);
	      
	char* ip_src = src_buffer;
	char* ip_dest = inet_ntoa(ip->ip_dst);

	if (ip->ip_p != IPPROTO_TCP) /*Not TCP protocol*/
	{
		return;
	}
	
	/*OK, This packet is TCP*/

	/* define/compute tcp header offset */

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) /* Invalid TCP header length.*/
	{
		return;
	}

	/* define/compute tcp payload (segment) offset */

	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */

	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	if (payload[0] != TLS_HANDSHAKE) /*Not a TLS handshake */
	{
		return;
	}
	
	if (payload[5] != TLS_CLIENT_HELLO) /*Not a TLS client hello packet */
	{
		return;
	}

	u_short hello_version = payload[OFFSET_HELLO_VERSION] * 256 + payload[OFFSET_HELLO_VERSION + 1];

	if (hello_version < fv->version) /*Log if the hello version of the client is smaller than the value given*/
	 {
		 time_t tmi;
		 struct tm* utc_time;
		 time(&tmi);
		 utc_time = gmtime(&tmi);
		 
		 char* tls_hello_version = ssl_version(hello_version);
		 FILE* file_to_write;
		 file_to_write = fopen(fv->file_name, "a");

		 printf("[%2d/%2d/%4d %2d:%02d:%02d] source ip: %s, dest ip: %s, version: %s\n", utc_time->tm_mday, utc_time->tm_mon + 1, 1900 + utc_time->tm_year, (utc_time->tm_hour) % 24, utc_time->tm_min, utc_time->tm_sec, ip_src, ip_dest, tls_hello_version);
		 fprintf(file_to_write, "[%2d/%2d/%4d %2d:%02d:%02d] source ip: %s, dest ip: %s, version: %s\n", utc_time->tm_mday, utc_time->tm_mon + 1, 1900 + utc_time->tm_year, (utc_time->tm_hour) % 24, utc_time->tm_min, utc_time->tm_sec, ip_src, ip_dest, tls_hello_version);
		 
		 fclose(file_to_write);
	}
	return;
}

u_short 
get_version(char *version)
{
	if (strcmp(version, "1.0") == 0)
	{
		return 769;
	}

	if (strcmp(version, "1.1") == 0)
	{
		return 770;
	}

	if (strcmp(version, "1.2") == 0)
	{
		return 771;
	}

	if (strcmp(version, "1.3") == 0)
	{
		return 772;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	printf("Running...\n");
	printf("This program's pid: %d\n", getpid());
	char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];
	short control_value = -1;

	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "tcp port 443";	/* The filter expression */
	FILE *stderr;
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	const u_char *packet;
	struct pcap_pkthdr header;	/* The header that pcap gives us */

	u_int size_ip;
	u_int size_tcp;

	if (argc == 4)
	{
		dev = argv[1];
		if (strcmp(argv[2] , "1.0") != 0 && strcmp(argv[2] , "1.1") != 0 && strcmp(argv[2] , "1.2") != 0 && strcmp(argv[2] , "1.3") != 0)
		{
			printf("Invalid version!");
			print_app_usage();
			exit(-1);
		}

		control_value = get_version(argv[2]);
	}
	else 
	{
		print_app_usage();
		exit(-1);
	}

	char* file_name = argv[3];
	stderr = fopen("errorLogs.txt", "a");
	
	struct file_and_version fv;
	fv.file_name = file_name;
	fv.version = control_value;
	u_char* serialized;
	serialized = (char*)&fv;

	pcap_t *handle;
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) 
	{
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		print_app_usage();
		return(-1);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
	{
		printf("Can't get netmask for device %s\n", dev);
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
	{
		printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(-1);
	}

	if (pcap_setfilter(handle, &fp) == -1) 
	{
		printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(-1);
	}

	pcap_loop(handle, 0, got_packet, serialized);

	pcap_freecode(&fp);
	pcap_close(handle);
	fclose(stderr);

  	return 0;
}

