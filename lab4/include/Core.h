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
#include<map>
enum StandardServices
{
	SSH=22,
	SMTP=24, //TODO try other ports 24, 25, and 587
	WHOIS=43,
	HTTP=80,
	POP=110,
	IMAP=143
};

struct packet
{
	const u_char* pointer;
	unsigned short length;		
};

class Core
{
	private:
		Mutex lPortMutex;
		std::map<unsigned short, vector<struct packet> > portMap;
		//vector<unsigned short> lPorts;

		void addPacketToPort(unsigned short port, struct packet p);
		void removePacketFromPort(unsigned short port, struct packet p);
		bool addPortToList(unsigned short port);		
		void removePortFromList(unsigned short port);
		args_t args;
		string interfaceName;
		void SendSinPacket(unsigned short srcPort, string dstIp, unsigned short dstPort);
		void PerformSynScan(string dstIp, unsigned short dstPort);
		uint16_t computeHeaderCheckSum(uint16_t* words, unsigned int size);
		uint16_t computeTCPHeaderCheckSum(struct iphdr ip,struct tcphdr tcp);
		void readPacketOnPort();
		
	public:
		Core(args_t,string);
		void Start();
};

