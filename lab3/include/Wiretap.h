#pragma once
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
#include</usr/include/netinet/if_ether.h>  // contains arp_header structure
#include <linux/if_ether.h> //contains ethhdr struct...
#include <netinet/udp.h> //contains udphdr struct
#include <netinet/tcp.h> //contains tcphdr struct
#include <netdb.h> //for getting the protocol type tcp, udp and icmp
#include<netinet/ip_icmp.h> //header file for icmp header.
#include<fstream>
using namespace std;

#include<string.h>
#include<stdlib.h>

// CONSTANTS...
#define NUM_TCP_FLAGS 6
#define NETWORK_A_LEN 4 
#define WORD_SIZE 4
#define MIN_TCP_HEADER_SIZE 5

//global variables init statements..
int numPackets=0;
float sumPacketLength=0;
int smallestPacketLength=10000; //init it to a very high value
int largestPacketLength=0; //init to a low value.
timeval startTime;
timeval endTime;
bool isTimeInit=false;
bool isIcmp= false;
bool isTcp = false;
bool isUdp= false;

bool isIP=false;
bool isARP=false;


//below vector will hold transport layer protocols.
vector<string> transportLayerProtocols;
vector<int> networkLayerProtocols;
vector<string> arpAddresses;

//below two vectors will hold source and destination tcp ports..
vector<unsigned short> sourcePorts;
vector<unsigned short> destinationPorts;

//below two vectors will hold source and destination udp ports.
vector<unsigned short> sourceUdpPorts;
vector<unsigned short> destinationUdpPorts;

vector<string> tcpFlags; //has all the tcp flags
vector<unsigned short> tcpOptions; //has all the tcp options.
//below vector will hold TTL of IP packets.
vector<int> timeToLive;

//below two will hold icmp codes and types respectively...
vector<unsigned short> icmpCodes;
vector<unsigned short> icmpTypes;


class vAddress
{
	private:
		int numInstances;
		int size;
		//matches an input address with current address.. //it is of type ETH_ALEN by default.
		bool isAddressMatch(unsigned char* a,int size);

	public:
		unsigned char* addr;
		~vAddress();
		vAddress(unsigned char* addr, int size);
		
		void printReadableEthernetAddress();
		
		void printReadableNetworkAddress();
		
		bool updateCountIfMatch(unsigned char* a,int size); //returns true on succesfull updation..

	    vAddress* nextAddress;
};
void printLinkLayerInfo();
void usage();
void computeLinkLayerInfo(const u_char *packet);
void printSummary();
void callback(u_char *, const struct pcap_pkthdr *header, const u_char *packet);
char* parseArguments(int argc, char* argv[]);
void computeSummary(const struct pcap_pkthdr *header, const u_char *packet);
void computeTransportLayerInfo(const u_char * packet);
void computeNetworkLayerInfo(const u_char * packet );
bool CheckIfFileExists(const char* fileName)
{
	ifstream f(fileName);
	if (f.good()) 
	{
		//file exists...
		f.close();
		return true;
	} 
	else 
	{
		//file doesnt exist...
		f.close();
		return false;
	}
}
