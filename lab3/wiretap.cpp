#include<iostream>
#include <pcap.h> //header file required for pcap...
#include <sys/socket.h>
#include <netinet/in.h>
#include <iomanip>
#include <ctime>
using namespace std;

#include<string.h>
#include<stdlib.h>



//define structures....
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
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
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src; /* source and dest address */
		struct in_addr ip_dst;
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

//moooore structs
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
u_char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

void usage()
{
	cout<<"Invoke this application as: ./wiretap [option1, ..., optionN]"<<endl;
	cout<<"Available Options are:\n";
	cout<<"-help : Prints out the help screen\n\t\tExample: ./wiretap --help"<<endl;
	cout<<"-open <capture file to open>. : Opens an offline file.\n\t\tExample: ./wiretap --open capture.pcap"<<endl;
	exit(1);
}

char* parseArguments(int argc, char* argv[])
{
	int i=1;
	if(argc==1 || argc>3)
	{
		usage();
	}
	for(int i=1;i<argc;i++)
	{
		if(strcmp(argv[i],"--help")==0)
		{
			usage();
		}
	}
	if(strcmp(argv[1],"--open")!=0)
	{
		usage();
	}
	return argv[2];
}

int numPackets=0;
float sumPacketLength=0;
int smallestPacketLength=10000;
int largestPacketLength=0;
timeval startTime;
timeval endTime;
bool isTimeInit=false;

void callback(u_char *, const struct pcap_pkthdr *header, const u_char *packet) //the first argument is NULL in our case..
{
	if(isTimeInit==false)
	{
		isTimeInit=true;
		startTime=header->ts;
	}
	endTime=header->ts;
	
	sumPacketLength+=header->len;
	if(header->len<smallestPacketLength)
	{
		smallestPacketLength=header->len;		
	}
	if((header->len)>largestPacketLength)
	{		
		largestPacketLength=header->len;
	}
	numPackets++;
	
	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) 
	{
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);TODO
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) 
	{
		//printf("   * Invalid TCP header length: %u bytes\n", size_tcp); TODO
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	
}

void printSummary()
{
	cout<<"\n=== Summary ===\n\n";
	cout<<"Number of Packets processed is "<<numPackets<<endl;
	cout<<"Smallest Packet length is "<<smallestPacketLength<<" bytes"<<endl;
	cout<<"Largest Packet length is "<<largestPacketLength<<" bytes"<<endl;
	cout<<"Average Packet length is "<<(sumPacketLength/numPackets)<<endl;

	//compute the start time stamp..
	char timestamp[64] = {0};
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&startTime.tv_sec));
	cout<<"Start Time is "<<timestamp<<endl;
	float time=(endTime.tv_sec-startTime.tv_sec)+ (endTime.tv_usec-startTime.tv_usec)/1000000;
	cout<<"Duration is "<<time<<" seconds"<<endl;
}

int main(int argc, char* argv[])
{
	char* fileName=parseArguments(argc, argv);
	cout<<"Evaluating file: "<<fileName<<endl;

	char errbuf[PCAP_ERRBUF_SIZE]; //will hold the error messages..
	
	//opening the offline tcp dump.
	pcap_t *handle=pcap_open_offline(fileName, errbuf);
	if(handle==NULL)
	{
		cout<<"Error reading the tcp dump"<<endl;
		exit(1);
	}

	//Check that the data you are provided has been captured from Ethernet
	int linkLayerHeaderType=pcap_datalink(handle);
	if(linkLayerHeaderType==PCAP_ERROR_NOT_ACTIVATED)
	{
		cout<<"Error getting the link layer header type"<<endl;
		exit(1);
	}
	if(linkLayerHeaderType!=DLT_EN10MB)	
	{
		cout<<"The data provided has not been captured from Ethernet"<<endl;
		exit(1);
	}

	//apply filter
	const char filter[]="not ip6"; //filter out the ipv6 packets...
	struct bpf_program fp;		/* The compiled filter */
	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) 
	{
		printf("Unable to parse filter %s: %s\n", filter, pcap_geterr(handle));
		exit(1);
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		printf("Unable to apply filter %s: %s\n", filter, pcap_geterr(handle));
		exit(1);
 	}	
	

	//call the loop back function...
	int returnVal = pcap_loop(handle, -1, callback, NULL); //-1 here implies all the packets...
	if(returnVal==-1)
	{
		printf("Error occurred in pcap_loop %s\n",pcap_geterr(handle));
		exit(1);
	}
	printSummary();	
	//close the handle
	pcap_close(handle);
	return 0;
}
