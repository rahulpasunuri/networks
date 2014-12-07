#pragma once
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
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <pcap.h>
#include<sstream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include<string>
#include<time.h>
#include<vector>
#include<pthread.h>

using namespace std;

//define some constants...
#define WORD_SIZE 4
#define MAX_RETRANSMISSIONS 3
#define TCP_WINDOW_SIZE 29200
enum scanTypes_t
{
	TCP_SYN,
	TCP_NULL,
	TCP_FIN,
	TCP_XMAS,
	TCP_ACK,
	UDP,
	MISC
};
enum StandardServices
{
	SSH=22,
	PRIVATE_MAIL=24,
	SMTP=25, //TODO try other ports 24, 25, and 587
	WHOIS=43,
	HTTP=80,
	POP=110,
	IMAP=143,
	SMTP1=587
};
struct DNS_HEADER                     // dns header
{  
    unsigned short id;   // identification number
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct QUESTION                   // question struct
{
    unsigned short qtype;
    unsigned short qclass;
};


struct packet
{
	u_char* pointer;
	unsigned short length;		
};


enum portState
{
	OPEN,
	CLOSED,
	FILTERED,
	UNFILTERED,
	OPEN_OR_FILTERED,
	MISC_PORT_STATE
};

struct results
{
	string ip;
	scanTypes_t scanType;
	portState state;
	int port;
};

struct args_t
{
       vector<int> portNumbers;
       vector<string> ipAddresses;
       bool verboseMode;
       int numThreads;
       vector<scanTypes_t> scanTypes;
};

struct target
{
	string ip;
	unsigned short port;
	scanTypes_t scanType;
};

class combo
{
	public:
		string ip;
		unsigned short port;
		vector<struct results> res;
};

class Mutex
{
	private:
		pthread_mutex_t m;
	public:
		Mutex();
		void lock();
		void unlock();
};


class Thread
{
	private:
		pthread_t t;
	public:
		Thread(void *(*start_routine)(void *), void *arg);
		int join();
};

class HelperClass
{	
	public:
		static unsigned short getSourcePortForICMP(const u_char* packet);
		static string srcIp;
		static void TerminateApplication(string);
		static bool CheckIfFileExists(const char* fileName);
		static bool isValidPortNumber(int portNum);
		static bool isValidIpAddress(string ip);
		static bool isNumber(string s);
		static const char* getScanTypeName(scanTypes_t inp);
		static const char* getPortTypeName(portState inp);
		static scanTypes_t getScanTypeId(string s);
		static string GetPortName(unsigned short port);
		//static void* threadhelper(void *context);
};
