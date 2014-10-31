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

bool isNumber(string s)
{
	if(s.empty())
	{
		return false;
	} 
	string::iterator it = s.begin();
	
	//skip starting white spaces;
	while(isspace(*it))
	{
		it++;
	}

	while(it!=s.end())
	{
		//if a non digit is encountered then return false.
		if(!isdigit(*it))
		{
			return false;
		}
		it++;
	}
	return true;	
}

bool isValidIpAddress(string ip)
{
	//TODO
	return true;
}

bool isValidPortNumber(int portNum)
{
	if(portNum>65535)
	{		
		return false;
	}
	else return true;
}

const char* getScanTypeName(scanTypes_t inp)
{
	if(inp==TCP_SYN)
	{
		return "SYN";
	}
	if(inp==TCP_NULL)
	{
		return "NULL";
	}
	if(inp==TCP_FIN)
	{
		return "FIN";
	}
	if(inp==TCP_XMAS)
	{
		return "XMAS";
	}
	if(inp==TCP_ACK)
	{
		return "ACK";
	}
	if(inp==UDP)
	{
		return "UDP";
	}
	return "MISC";

}

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
	
	cout<<"Printing Scan types"<<endl;
	vector<scanTypes_t>::iterator it=args.scanTypes.begin();
	while(it!=args.scanTypes.end())
	{
		cout<<getScanTypeName(*it)<<endl;
		it++;
	}
	cout<<endl;
	
	cout<<"Printing ip addresses"<<endl;
	vector<string>::iterator it1=args.ipAddresses.begin();
	while(it1!=args.ipAddresses.end())
	{
		cout<<*it1<<endl;
		it1++;
	}
	cout<<endl;	
	
	cout<<"Printing port numbers"<<endl;
	vector<int>::iterator it2=args.portNumbers.begin();
	while(it2!=args.portNumbers.end())
	{
		cout<<*it2<<"	";
		it2++;
	}
	cout<<endl;	
	
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
					cout<<"IP address is not specified"<<endl;
					usage();
					exit(1);
				}
				if(isValidIpAddress(optarg))
				{
					args.ipAddresses.push_back(optarg);
				}
				else
				{
					cout<<"Ip address mentioned is not a valid ip address"<<endl;
					exit(1);
				}				
				break;

			case 'b':
				if(optarg==NULL)
				{
					cout<<"IP prefix is not specified"<<endl;
					usage();
					exit(1);
				}
				printf("prefix is ");
				cout<<optarg<<endl;
				break;

			case 'c':
				if(optarg==NULL)
				{
					cout<<"Number of threads is not specified"<<endl;
					usage();
					exit(1);
				}
				args.numThreads=atoi(optarg);
				break;

			case 'd':
				if(optarg==NULL)
				{
					cout<<"File name of ip addressed is not specified"<<endl;
					usage();
					exit(1);
				}
				cout<<"Filename to scan is "<<optarg;
				break;

			case 'e':
				if(optarg==NULL)
				{
					cout<<"Scan Types not specified"<<endl;
					usage();
					exit(1);
				}
				cout<<"Scan Types is "<<optarg;
				break;
			  
			case 'f':
			{
				if(optarg==NULL)
				{
					cout<<"Port Numbers not specified"<<endl;
					usage();
					exit(1);
				}
				
				vector<string> ranges;
				
				//port numbers are specified in a range or comma-separated.				
				string temp1=optarg;
				
				while(temp1.find(',')!=string::npos)
				{
					int index=temp1.find(',');
					ranges.push_back(temp1.substr(0,index));
					temp1=temp1.substr(index+1);;
				}
				ranges.push_back(temp1); //push the last range into the list...

				vector<string>::iterator it=ranges.begin();
				while(it!=ranges.end())
				{
					if((*it).find('-')!=string::npos)
					{				
						int index=(*it).find('-');
						string start=(*it).substr(0,index);
						string end=(*it).substr(index+1);
						if(!isNumber(start) || !isNumber(end))
						{
							cout<<"syntax of range in ports is wrong"<<endl;
							exit(1);
						}
						else
						{
							int startIndex=atoi(start.c_str());
							int endIndex=atoi(end.c_str());
							for(int i=startIndex;i<=endIndex;i++)
							{
								args.portNumbers.push_back(i);
							}
						}
					}
					else if(isNumber(*it))
					{
						//this happens when a single port number is mentioned
						if(isValidPortNumber(atoi(optarg)))
						{
							args.portNumbers.push_back(atoi(optarg));
						}
						else
						{
							cout<<"Invalid port number specified"<<endl;
							exit(1);
						}
					}
					else
					{
						cout<<"syntax of range in ports is wrong"<<endl;
						exit(1);
					}
					it++;
						
				}								
			}
				break;

			case 'g':
				args.verboseMode=true;
				break;
			  
			default:
			  usage();
			  exit(1);
		}
	}
	//assign default values for port numbers.
	if(args.portNumbers.empty())
	{
		for(int i=1;i<=1024;i++)
		{
			args.portNumbers.push_back(i);
		}
	}
	
	//assign default values for scan types..
	if(args.scanTypes.empty())
	{
		args.scanTypes.push_back(TCP_SYN);
		args.scanTypes.push_back(TCP_NULL);
		args.scanTypes.push_back(TCP_FIN);
		args.scanTypes.push_back(TCP_XMAS);
		args.scanTypes.push_back(TCP_ACK);
		args.scanTypes.push_back(UDP);
	}
	
	//check for the presence of atleast one ip address..	
	if(args.ipAddresses.empty())
	{
		cout<<"IP Address not specified"<<endl;
		usage();
		exit(1);
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
