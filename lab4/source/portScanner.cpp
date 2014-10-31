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
using namespace std;

enum scanTypes_t
{
	TCP_SYN,
	TCP_NULL,
	TCP_FIN,
	TCP_XMAS,
	TCP_ACK,
	UDP
};

struct args_t
{
	vector<int> portNumbers;
	vector<string> ipAddresses;
	bool verboseMode;
	int numThreads;
	vector<scanTypes_t> scanTypes;
};

void printArguments(args_t args)
{
	cout<<"Num threads is "<<args.numThreads<<endl;
	cout<<"verbose Mode is "<<args.verboseMode<<endl;
}

void usage()
{
	cout<<"• --help. Print out the message. \n\
• --verbose. Runs in a verbose Mode. --\n\
• --ports <ports to scan>. Specify the ports and range of ports to scan(using -) \n\
• --ip <IP address to scan>. Specify the ip address to scan \n\
• --prefix <IP prefix to scan>. Specify the ip prefix to scan \n\
• --file <file name containing IP addresses to scan>. specify the file name containing the ip addresses \n\
• --speedup <parallel threads to use>. Specify number of  threads to use \n\
• --scan <one or more scans>. Specify the scans (each separated by a space)\n";
}

//method which parses arguments..
args_t parseArguments(int argc, char** argv)
{
	int c;
	args_t args;
	//init some arguments
	args.verboseMode=false;
	args.numThreads=0;
		static struct option long_options[] =
		{
		  /* These options set a flag. */
		  /* These options don’t set a flag.
			 We distinguish them by their indices. */
		  {"ip", 1, 0, 'a'},
		  {"prefix", 1, 0, 'b'},
		  {"speedup", 1, 0, 'c'},
		  {"file", 1, 0, 'd'},
		  {"scan", 1, 0, 'e'},
		  {"ports", 1, 0, 'f'},
		  {"verbose", 0, 0, 'g'},
	      { NULL, 0, NULL, 0   } 
		};
	
	while (1)
	{

		  /* getopt_long stores the option index here. */
		c = getopt_long (argc, argv, "a:b:c:d:e:f:g", long_options, NULL);

		  /* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{        
			case 'a':
				if(optarg==NULL)
				{
					usage();
					exit(1);
				}
				printf("ip\n");	
				cout<<optarg<<endl;			
				break;

			case 'b':
				if(optarg==NULL)
				{
					usage();
					exit(1);
				}
				printf("prefix is ");
				cout<<optarg<<endl;
				break;

			case 'c':
				if(optarg==NULL)
				{
					usage();
					exit(1);
				}
				args.numThreads=atoi(optarg);
				break;

			case 'd':
				if(optarg==NULL)
				{
					usage();
					exit(1);
				}
				cout<<"Filename to scan is "<<optarg;
				break;

			case 'e':
				if(optarg==NULL)
				{
					usage();
					exit(1);
				}
				cout<<"Scan Types is "<<optarg;
				break;
			  
			case 'f':
				if(optarg==NULL)
				{
					usage();
					exit(1);
				}
				cout<<"Ports is "<<optarg<<endl;
				break;

			case 'g':
				args.verboseMode=true;
				break;
			  
			default:
			  usage();
			  exit(1);
		}
	}
	return args;
}

//the main method...
int main(int argc, char** argv)
{
	args_t args=parseArguments(argc,argv);
	printArguments(args);
	return 0;
}
