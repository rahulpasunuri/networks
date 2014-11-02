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

#define WORD_SIZE 4

string dstIp="129.79.247.87"; //ip address of dagwood.soic.indiana.edu
//string dstIp="127.0.0.1"; //local ip address

bool isBlondie=false;

string interfaceName="eth0";
//string interfaceName="wlan0";

//working check sum method...
uint16_t computeHeaderCheckSum(uint16_t* words, unsigned int size)
{	 
	//The checksum field is the 16-bit one's complement of the one's complement sum of all 16-bit words in the header.  (source -WIKIPEDIA)
	unsigned int numWords = size/2; // 16 bits is 2 bytes...
	uint32_t temp=0;
	uint32_t sumWords = 0;
	
	temp=~temp; //temp is all 1's now..
	uint16_t lowEnd = temp>>16; //low end 16 bits are 1..
	uint16_t wordLeft;
	for(unsigned int i=0;i<numWords;i++)
	{
		sumWords += words[i];
		wordLeft = sumWords >>16; //get the left break up of sum/			
		while(wordLeft!=0)
		{
			sumWords = sumWords & lowEnd;
			sumWords += wordLeft;
			wordLeft = sumWords>>16; //get the left break up of sum/
		}
	}	
	return ~(sumWords&lowEnd);	
}

void readPacketOnPort(int port)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	std::ostringstream o;
	o << "port " << port; //create the filter expression...
	string filter = o.str();	
	//filter=""; //TODO
	
	pcap_t *handle;			/* Session handle */
	struct bpf_program fp;		/* The compiled filter */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	const u_char *packet;		/* The actual packet */

	/* Find the properties for the device */
	if (pcap_lookupnet(interfaceName.c_str(), &net, &mask, errbuf) == -1) 
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interfaceName.c_str(), errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", interfaceName.c_str(), errbuf);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
	}
	struct pcap_pkthdr *hdr;
	
    /* Retrieve the packets */
    int res;
    while((res = pcap_next_ex(handle, &hdr, &packet)) >= 0)
    {
        if(res == 0)
        {
            continue;            
        }
        cout<<"recieved a packet"<<endl;
        break;
        /* convert the timestamp to readable format */
        //local_tv_sec = header->ts.tv_sec;
        //ltime=localtime(&local_tv_sec);
        //strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);        
        //printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }
    
    if(res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(handle));
    }
    
	
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", hdr->len);
	/* And close the session */
	pcap_close(handle);

	//return pkt_data; //TODO
}

uint16_t computeTCPHeaderCheckSum(struct iphdr ip,struct tcphdr tcp)
{	 
	unsigned int size=12;
	unsigned short segSize= sizeof(tcphdr);
	u_char* t=new u_char[size+segSize];
	memcpy(t, &ip.saddr, 4);
	memcpy(t+4, &ip.daddr, 4);
	t[8]=0;
	t[9]=IPPROTO_TCP;

	unsigned short segmentSize=htons(segSize);

	memcpy(t+10, &segmentSize, 2);
	memcpy(t+size, &tcp,segSize);
	//The checksum field is the 16-bit one's complement of the one's complement sum of all 16-bit words in the header.  (source -WIKIPEDIA)
	unsigned int numWords = (size+segSize)/2; // 16 bits is 2 bytes...
	uint32_t temp=0;
	uint32_t sumWords = 0;
	uint16_t *words = (uint16_t*) t;
	
	temp=~temp; //temp is all 1's now..
	uint16_t lowEnd = temp>>16; //low end 16 bits are 1..
	uint16_t wordLeft;
	for(unsigned int i=0;i<numWords;i++)
	{
		sumWords += words[i];
		wordLeft = sumWords >>16; //get the left break up of sum/			
		while(wordLeft!=0)
		{
			sumWords = sumWords & lowEnd;
			sumWords += wordLeft;
			wordLeft = sumWords>>16; //get the left break up of sum/
		}
	}	
	return ~(sumWords&lowEnd);	
}

void play(unsigned int srcPort = 99999, unsigned int dstPort= 22)
{	
	int sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)  //create a raw socket
	{
		HelperClass::TerminateApplication("socket() failed ");
	}

	struct ifreq ifr;
	memset (&ifr, 0, sizeof (ifr));
	//char interfaceName[]="eth0";
	size_t if_name_len=strlen(interfaceName.c_str());
	
	if (if_name_len-1<sizeof(ifr.ifr_name)) 
	{
		memcpy(ifr.ifr_name,interfaceName.c_str(),if_name_len);
		ifr.ifr_name[if_name_len]='\0'; // terminate the string with a null character...
	} 
	else 
	{
		HelperClass::TerminateApplication("Name of interface exceeds the limit!!!");
	}
	if (ioctl(sock,SIOCGIFADDR,&ifr)==-1) 
	{
		close(sock);
		HelperClass::TerminateApplication("ioctl() failed!!!");	
	}

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	string srcIp = inet_ntoa(ipaddr->sin_addr);
	struct iphdr ip;
	memset (&ip, 0, sizeof (struct iphdr));	
	//fill the iphdr info...
	ip.ihl = sizeof(struct iphdr)/sizeof (uint32_t); //# words in ip header.
	ip.version = 4; //IPV4


	ip.tos = 0; //tos stands for type of service (0 : Best Effort)
	ip.tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));  //as we dont have any application data..size here is size of tcp + ip.
	ip.id = htons (0); //can we use this in a intelligent way ??? it is unused...
	ip.frag_off=0; // alll flags are 0, and the fragment offset is 0 for the first packet.
	ip.ttl = 0;
	ip.ttl = ~ip.ttl; //set it to all 1's
	ip.protocol = IPPROTO_TCP; //as transport layer protocol is tcp..
    
	  // Source IPv4 address (32 bits)
	if (inet_pton (AF_INET, srcIp.c_str(), &(ip.saddr)) != 1 || inet_pton (AF_INET, dstIp.c_str(), &(ip.daddr)) != 1) 
	{
		HelperClass::TerminateApplication("inet_pton() failed!!");
	}
	ip.check=0; //init
    ip.check=computeHeaderCheckSum((uint16_t *) & ip, sizeof(struct iphdr)); //this is the last step..
    //lets create a tcp packet now..
	struct tcphdr tcp;		
	tcp.source = htons(srcPort);
	tcp.dest = htons(dstPort);
	tcp.seq = htonl(0); // note that its a 32 bit integer...could be a random number...
	tcp.ack_seq = htonl(0);		
	tcp.res1 = 0;// reserved and unused bits..
	tcp.res2 = 0;
	tcp.fin = 0;
	tcp.syn = 1; //set only the syn flag..
	tcp.rst = 0;
	tcp.psh = 0;
	tcp.ack = 0;
	tcp.urg = 0;
	tcp.window = ntohs(29200); //setcomputeTCPHeaderCheckSum all bits to 1 => max size..TODO
	unsigned int optSize=0;
	tcp.doff = (sizeof(struct tcphdr)+optSize)/WORD_SIZE; //so no options..	
	tcp.urg_ptr= 0; 	
	
	//*******************************************************
	/*
	u_char* opt=new u_char[optSize]; //TODO..
	u_char* backup=opt;
	memset(opt,0,optSize);
	
	//window scale
	*opt=2;	
	opt++;
	
	*opt=4;	
	opt++;

	*opt=5;	
	opt++;

	*opt=180;
	opt++;
	
	*opt=4;
	opt++;

	*opt=2;
	opt++;

	*opt=8;
	opt++;

	*opt=10;
	opt++;	

	*opt=0;
	opt++;			

	*opt=120;
	opt++;

	*opt=209;
	opt++;

	*opt=237;
	opt++;	

	*opt=0;
	opt++;

	*opt=0;
	opt++;

	*opt=0;
	opt++;

	*opt=0;
	opt++;

	*opt=1;
	opt++;	

	*opt=3;
	opt++;

	*opt=3;
	opt++;	

	*opt=7;
	opt++;
	*/
	u_char* temp=new u_char[sizeof(tcphdr) + optSize]; //TODO 20 for options.
	memcpy(temp, &tcp, sizeof(tcphdr));
	//memcpy(temp+sizeof(tcphdr),backup,optSize);
	
	tcp.check = 0;
	//tcp.check = computeHeaderCheckSum((uint16_t*) &tcp, sizeof(struct tcphdr));	 //this works for now, as we have no payload and no options..TODO
	//tcp.check = computeHeaderCheckSum((uint16_t*)&temp, sizeof(struct tcphdr)+optSize);	 //this works for now, as we have no payload and no options..TODO
	tcp.check=computeTCPHeaderCheckSum(ip,tcp);
	//lets build the packet..
	u_char* packet = new u_char[sizeof(struct iphdr)+sizeof(struct tcphdr)+optSize]; //this works because we have no tcp options and no tcp payload //TODO
	memcpy(packet, &ip, sizeof(iphdr));
	memcpy(packet+sizeof(iphdr), &tcp, sizeof(struct tcphdr));
	//memcpy(packet+sizeof(iphdr)+sizeof(tcphdr),backup,optSize);
	
	struct sockaddr_in sin;
	memset (&sin, 0, sizeof (struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.daddr; //set the destination address here..

	int flag = 1;
	// IP_HDRINCL setting this flag, as we are adding our own ip header..though it is set in most machines.
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, (char *) &flag, sizeof(int)) < 0) 
	{
		HelperClass::TerminateApplication("send() failed!!");
	}

	// Bind socket to interface index.
	if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) 
	{
		HelperClass::TerminateApplication("bind() failed!!");
	}
	
	// Send packet.
	if (sendto (sock, packet, sizeof(iphdr) + sizeof(tcphdr)+optSize, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)   //TODO 20 for options
	{
		HelperClass::TerminateApplication("send() failed!!");
	}
	
	//receive reply now..
	readPacketOnPort(srcPort);
	
	close (sock);// closing the socket.
}


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
				args.numThreads=atoi(optarg);
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
						if(HelperClass::isValidPortNumber(atoi(optarg)))
						{
							args.portNumbers.push_back(atoi(optarg));
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
	args_t args=parseArguments(argc,argv);
	printArguments(args);
	if(!isBlondie) //TODO
	{
		interfaceName="wlan0";
	}
	else
	{
		interfaceName="eth0";
	}
	dstIp="74.125.225.19";
	play(12124,80);	
	
	return 0;
}
