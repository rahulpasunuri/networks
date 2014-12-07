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
#include "../include/HelperClass.h"
#include "../include/Core.h"
using namespace std;

void printArguments(args_t args)
{
	cout<<"\n----------------------------"<<endl;	
	cout<<"Printing Arguments"<<endl;
	cout<<"----------------------------"<<endl;	
	cout<<"Num threads is "<<args.numThreads<<endl;
	cout<<"verbose Mode is "<<args.verboseMode<<endl;
	cout<<"\n----------------------------"<<endl;	
	cout<<"Printing Scan types"<<endl;
	cout<<"----------------------------"<<endl;	
	vector<scanTypes_t>::iterator it=args.scanTypes.begin();
	while(it!=args.scanTypes.end())
	{
		cout<<HelperClass::getScanTypeName(*it)<<endl;
		it++;
	}
	cout<<endl;
	cout<<"----------------------------"<<endl;	
	cout<<"Printing ip addresses"<<endl;
	cout<<"----------------------------"<<endl;	
	vector<string>::iterator it1=args.ipAddresses.begin();
	while(it1!=args.ipAddresses.end())
	{
		cout<<*it1<<endl;
		it1++;
	}
	cout<<endl;	
	
	cout<<"----------------------------"<<endl;	
	cout<<"Printing port numbers"<<endl;
	cout<<"----------------------------"<<endl;		
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
	args.numThreads=1; //default 1 thread...
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
					HelperClass::TerminateApplication("IP address is not specified");
				}
				if(HelperClass::isValidIpAddress(optarg))
				{
					args.ipAddresses.push_back(optarg);
				}
				else
				{
					HelperClass::TerminateApplication("Ip address mentioned is not a valid ip address");
				}				
				break;

			case 'b':
			{
				if(optarg==NULL)
				{
					usage();
					HelperClass::TerminateApplication("IP prefix is not specified");
				}
				string t=optarg;
				unsigned int index=t.find('/');
				if(index==string::npos)
				{
					HelperClass::TerminateApplication("No mask specified in ip prefix");
				}
				string baseIp=t.substr(0,index);
				string mask=t.substr(index+1);
				if(!HelperClass::isNumber(mask))				
				{
					HelperClass::TerminateApplication("Specified mask is not valid");
				}
				if(!HelperClass::isValidIpAddress(baseIp))
				{
					HelperClass::TerminateApplication("Base IP address mentioned in prefix is not a valid IP");
				}
				//let ip be in a.b.c.d format..
				struct sockaddr_in sa;
				inet_pton(AF_INET, baseIp.c_str(), &(sa.sin_addr));
				unsigned int maskLen = atoi(mask.c_str());
				unsigned int maskInt = 0;
				maskInt = ~maskInt;
				maskInt=maskInt>>(32-maskLen);
				maskInt=maskInt<<(32-maskLen);
				char s1[INET_ADDRSTRLEN];
				unsigned int baseIpInt=ntohl(sa.sin_addr.s_addr);
				baseIpInt=baseIpInt & maskInt;

				unsigned int maxTail= 0;
				maxTail = ~maxTail;
				maxTail = maxTail>>maskLen;				
				
				unsigned int start=0;
				for(;start<=maxTail;start++)
				{				
					sa.sin_addr.s_addr=htonl(baseIpInt+start);
					inet_ntop(AF_INET, &(sa.sin_addr), s1, INET_ADDRSTRLEN);
					args.ipAddresses.push_back(s1);
				}			
			}
				break;

			case 'c':
				if(optarg==NULL)
				{
					usage();
					HelperClass::TerminateApplication("Number of threads is not specified");
				}
				if(!HelperClass::isNumber(optarg))
				{
					HelperClass::TerminateApplication("Number of threads is not an integer..");
				}
				args.numThreads=atoi(optarg);
				if(args.numThreads < 1)
				{
					HelperClass::TerminateApplication("Number of threads must be greater than 0");
				}
				break;

			case 'd':
			{
				if(optarg==NULL)
				{
					usage();
					HelperClass::TerminateApplication("File name of ip addressed is not specified");
				}
				if(!HelperClass::CheckIfFileExists(optarg))
				{
					HelperClass::TerminateApplication("File containing ip addresses does not exist");
				}
				fstream f;
				f.open(optarg,ios::in);
				string ip;
				while(!f.eof()) 
				{
					ip.clear();
					f>>ip;
					if(ip!="")
					{
						if(HelperClass::isValidIpAddress(ip))
						{
							args.ipAddresses.push_back(ip);
						}
						else
						{
							HelperClass::TerminateApplication("Some Ip addresses in file are not valid");
						}
					}
				}				
			}
				break;

			case 'e':
				if(optarg==NULL)
				{
					usage();
					HelperClass::TerminateApplication("Scan Types not specified");
				}
				else
				{
					int i=0;
					for(;i<argc;i++)
					{
						if(strcmp(argv[i],"--scan")==0)
						{
							break;							
						}
					}
					i++;
					int j=i;
					while(j<argc)
					{						
						if(argv[j][0] == '-')
						{
							break;
						}
						j++;
					}
					vector<string> scanTypes;
					for(int k=i;k<j;k++)
					{
						scanTypes.push_back(argv[k]);
					}

					vector<string>::iterator it = scanTypes.begin();
					while(it!=scanTypes.end())
					{
						if((*it)!="")
						{
							args.scanTypes.push_back(HelperClass::getScanTypeId(*it));	
						}
						it++;
					}
				}
				break;
			  
			case 'f':
			{
				if(optarg==NULL)
				{
					usage();
					HelperClass::TerminateApplication("Port Numbers not specified");
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
						//split the ranges	
						int index=(*it).find('-');
						string start=(*it).substr(0,index);
						string end=(*it).substr(index+1);
						if(!HelperClass::isNumber(start) || !HelperClass::isNumber(end))
						{
							HelperClass::TerminateApplication("syntax of range in ports is wrong");
						}
						else
						{
							// add all the ports derived from range...
							int startIndex=atoi(start.c_str());
							int endIndex=atoi(end.c_str());
							for(int i=startIndex;i<=endIndex;i++)
							{
								args.portNumbers.push_back(i);
							}
						}
					}
					else if(HelperClass::isNumber(*it))
					{
						//this happens when a single port number is mentioned
						if(HelperClass::isValidPortNumber(atoi((*it).c_str())))
						{
							args.portNumbers.push_back(atoi((*it).c_str()));
						}
						else
						{
							HelperClass::TerminateApplication("Invalid port number specified");
						}
					}
					else
					{
						HelperClass::TerminateApplication("syntax of range in ports is wrong");
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
    		  HelperClass::TerminateApplication("Arguments are not specified in the right syntax");
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
		usage();
		HelperClass::TerminateApplication("IP Address not specified");	
	}
	
	return args;
}

//the main method...
int main(int argc, char** argv)
{
  char   buf[1024] = {0};
  struct ifconf ifc = {0};
  struct ifreq *ifr = NULL;
  int           sock = 0;
  int           nInterfaces = 0; // no. of interfaces active
  int           i = 0;
  bool up_and_running = false;  // It tells if the interface is active
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  sock= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(ioctl(sock, SIOCGIFCONF, &ifc) <0) 
  {
    perror("ioctl(SIOCGIFCONF)");
    return 1;
  }
  string interfaceName="";
  ifr = ifc.ifc_req;
  nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
  for(i = 0; i<nInterfaces; i++)
  {
      struct ifreq *item = &ifr[i];
      if( ioctl( sock, SIOCGIFFLAGS,item ) != -1 )
      {
        up_and_running = (item->ifr_flags & ( IFF_UP | IFF_RUNNING )) == ( IFF_UP | IFF_RUNNING );
      }
      else
      {
         cout<<"error\n"; exit(0);
      }

      if(up_and_running)
      interfaceName=string(item->ifr_name);

  }    

  args_t args=parseArguments(argc,argv);
  printArguments(args);	
  srand (time(NULL)); 
  Core c(args, interfaceName);
  c.Start();
  return 0;
}
