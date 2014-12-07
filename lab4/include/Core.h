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

class Core
{
	private:
		Mutex lPortMutex;
		Mutex workMutex;
		Mutex printMutex;
		Mutex packetSnifferMutex;
		bool shldPacketSnifferExit;
		Mutex addResultsMutex;
		vector<struct target> targets;
		std::map<unsigned short, vector<struct packet> > portMap;
		vector<combo> aggResults;

		//add a packet to the queue..
		void addPacketToPort(unsigned short port, struct packet p);
		
		//remove a packet from the queue.
		void removePacketFromPort(unsigned short port, struct packet p);

		struct packet fetchPacketFromPort(unsigned short port);

		//adds a new mappings, and port sniffer will start save packets for this port.
		bool addPortToList(unsigned short port);	
		
		//packet sniffer will stop saving packets for this port.		//removes the queue for the port.
		void removePortFromList(unsigned short port);
		args_t args;

		void SendTCPPacket(unsigned short srcPort, string dstIp, unsigned short dstPort, scanTypes_t);
		
		void SendUDPPacket(unsigned short srcPort, string dstIp, unsigned short dstPort);

		void PerformTCPScan(string dstIp, unsigned short dstPort, scanTypes_t);
		
		void PerformUDPScan(string dstIp, unsigned short dstPort, scanTypes_t);
		
		string getServiceInfo(unsigned short port,string dstIp);
	
		//computes the header checksum
		uint16_t computeHeaderCheckSum(uint16_t* words, unsigned int size);
		
		//computes the tcp header checksum.
		uint16_t computeTCPHeaderCheckSum(struct iphdr ip,struct tcphdr tcp);
		
		//computes the UDP header checksum.
		uint16_t computeUDPHeaderCheckSum(struct iphdr ip,struct udphdr udp);

		//this is done by the individual thread, and they read packets which belong to their port..
		struct packet readPacketFromList(unsigned short port);
		struct target getWork();
		void scheduler();


	public:
		string interfaceName;
		void printResult(vector<struct results> list);
		void addResult(struct results r);
		
		//this is port sniffer which will save packets
		void readPacketOnPort();
		static void *threadhelper(void *context);
		static void *workhelper(void *context);
		void doWork(); //the work done by the threads...		
		//the constructor..
		Core(args_t,string);
		
		//this starts the port scanning process...
		void Start();
};

