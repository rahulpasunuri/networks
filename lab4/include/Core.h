#include<getopt.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> //header file required for pcap...
#include <sys/socket.h>
#include <netinet/in.h>
#include <iomanip>
#include <ctime>
#include <algorithm>  
#include <vector> 
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <string>
#include <linux/if_ether.h> //contains ethhdr struct...
#include <netinet/udp.h> //contains udphdr struct
#include <netinet/tcp.h> //contains tcphdr struct
#include <netdb.h> //for getting the protocol type tcp, udp and icmp
//#include<net/if_arp.h> //header file for arp header and arp constants.
#include<netinet/ip_icmp.h> //header file for icmp header.
#include <unistd.h>
#include<fstream>
#include "HelperClass.h"

enum StandardServices
{
	SSH=22,
	SMTP=24, //TODO try other ports 24, 25, and 587
	WHOIS=43,
	HTTP=80,
	POP=110,
	IMAP=143
};

class Core
{
	private:
		args_t args;
		string interfaceName;
		void SendSinPacket(unsigned short srcPort, string dstIp, unsigned short dstPort);
		void PerformSynScan(string dstIp, unsigned short dstPort);
		uint16_t computeHeaderCheckSum(uint16_t* words, unsigned int size);
		uint16_t computeTCPHeaderCheckSum(struct iphdr ip,struct tcphdr tcp);
		const u_char* readPacketOnPort(int port);
		
	public:
		Core(args_t,string);
		void Start();
};

