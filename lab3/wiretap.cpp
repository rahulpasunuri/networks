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

using namespace std;

#include<string.h>
#include<stdlib.h>
#define NUM_TCP_FLAGS 6
#define NETWORK_A_LEN 4 //TODO find the correct var



class vAddress
{
	private:
		int numInstances;
		int size;
		//matches an input address with current address.. //it is of type ETH_ALEN by default.
		bool isAddressMatch(unsigned char* a,int size=ETH_ALEN)
		{
			int i=0;
			for(;i<size;i++)
			{   
				if(a[i]!=addr[i])
				{
					return false;
				}
			}		
			return true;
		}

	public:
		unsigned char* addr;
		~vAddress()
		{
			delete[] addr;//free memory.
		}
		vAddress(unsigned char* addr, int size=ETH_ALEN)
		{
			int i=0;
			numInstances=1;
			nextAddress=NULL;
			this->size=size;
			this->addr=new unsigned char[size];			
			for(int i=0;i<size;i++)
			{
				this->addr[i]=addr[i];
			}
		}
		
		void printReadableEthernetAddress()
		{
			if(size!=ETH_ALEN)
			{
				cout<<"Cannot print in ethernet format"<<endl;
				return;
			}
			int i=0;
			for(;i<ETH_ALEN-1;i++)
			{
				printf("%02x:",addr[i]);
			}
			printf("%02x",addr[i]);
			cout<<"\t"<<numInstances<<endl;		
		}
		
		void printReadableNetworkAddress()
		{			
			if(size!=NETWORK_A_LEN)
			{
				cout<<"Cannot print in network format"<<endl;
				return;
			}			
			cout<<(short)addr[3]<<"."<<(short)addr[2]<<"."<<(short)addr[1]<<"."<<(short)addr[0]<<"\t"<<numInstances<<endl;			
		}
		
		bool updateCountIfMatch(unsigned char* a,int size=ETH_ALEN) //returns true on succesfull updation..
		{   
			bool b=isAddressMatch(a,size);
			if(!b)
			{				
				return false;
			}
			numInstances++; 
			return true;
		}
	    vAddress* nextAddress;
};

/* structure for storing arp header data*/
typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
             
    u_char shrd[ETH_ALEN];      /* Sender hardware address */ 
    u_char spad[NETWORK_A_LEN];      /* Sender IP address       */ 
    u_char dhrd[ETH_ALEN];      /* Target hardware address */ 
    u_char dpad[NETWORK_A_LEN];      /* Target IP address       */ 
}arphdr_t; 

class Arp
{
	public:
	u_char ethrd[ETH_ALEN] ;   
	u_char iprd[NETWORK_A_LEN];
	
	Arp(u_char *ethrd, u_char *iprd)
	{		
		memcpy(this->ethrd,ethrd,ETH_ALEN);
		memcpy(this->iprd,iprd,NETWORK_A_LEN);
	}	
	
	void printReadableArpAddress()
	{		
		int i=0;
		for(;i<ETH_ALEN-1;i++)
		{
			printf("%02x:",ethrd[i]);
		}
		printf("%02x / ",ethrd[i]);	
		cout<<(short)iprd[3]<<"."<<(short)iprd[2]<<"."<<(short)iprd[1]<<"."<<(short)iprd[0];			
	}
		
};

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


bool sortVectors(const Arp obj1,const Arp obj2)
{
  if(strcmp((char*)obj1.ethrd,(char*)obj2.ethrd)<0)
  	return true;
  else if(strcmp((char*)obj1.ethrd,(char*)obj2.ethrd)>0)
  	return false;
  else if(strcmp((char*)obj1.iprd,(char*)obj2.iprd)<0)
  	return true;
  else 
  	return false;
}

bool equalVectors(const Arp obj1,const Arp obj2)
{
	if((strcmp((char*)obj1.ethrd,(char*)obj2.ethrd)==0)&&(strcmp((char*)obj1.iprd,(char*)obj2.iprd)==0))
		return true;
	else 
		return false;
}

vAddress* headSrcEthernetAddress=NULL;
vAddress* tailSrcEthernetAddress=NULL;
vAddress* headRmtEthernetAddress=NULL;
vAddress* tailRmtEthernetAddress=NULL;
vAddress* headSrcNetworkAddress=NULL;
vAddress* tailSrcNetworkAddress=NULL;
vAddress* headRmtNetworkAddress=NULL;
vAddress* tailRmtNetworkAddress=NULL;

//below vector will hold transport layer protocols.
vector<string> transportLayerProtocols;

vector<Arp> arpAddresses;

//below two vectors will hold source and destination tcp ports..
vector<unsigned short> sourcePorts;
vector<unsigned short> destinationPorts;

//below two vectors will hold source and destination udp ports.
vector<unsigned short> sourceUdpPorts;
vector<unsigned short> destinationUdpPorts;

vector<unsigned short> tcpFlags;
//below vector will hold TTL of IP packets.
vector<int> timeToLive;
vector<unsigned short> icmpCodes;
vector<unsigned short> icmpTypes;


//this  method prints out the proper usage of this program.
void usage()
{
	cout<<"Invoke this application as: ./wiretap [option1, ..., optionN]"<<endl;
	cout<<"Available Options are:\n";
	cout<<"-help : Prints out the help screen\n\t\tExample: ./wiretap --help"<<endl;
	cout<<"-open <capture file to open>. : Opens an offline file.\n\t\tExample: ./wiretap --open capture.pcap"<<endl;
	exit(1);
}

//this method is used to parse the command line arguments.
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

//this method will compute the information required by summary
void computeSummary(const struct pcap_pkthdr *header, const u_char *packet)
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
}

//below method is used to decode link layer information.
void computeLinkLayerInfo(const u_char *packet)
{
	struct ethhdr *e=(struct ethhdr*) packet;
	isIP=false;
	isARP=false;
	if(ntohs(e->h_proto)==ETH_P_IP)  //not sure whether its correct...?
	{
		isIP=true;
	}
	else if(ntohs(e->h_proto)==ETH_P_ARP)
	{
		isARP=true;
	}	
	
	if(headSrcEthernetAddress==NULL)
	{
		headSrcEthernetAddress=new vAddress(e->h_source);
		headSrcEthernetAddress->nextAddress=NULL;
		tailSrcEthernetAddress=headSrcEthernetAddress;		
	}
	else
	{
		bool ret=false;
		vAddress* p=headSrcEthernetAddress;
		while(p!=NULL&&!ret)
		{
			ret=p->updateCountIfMatch(e->h_source);
			p=p->nextAddress; //move p
		}
		if(ret==false)
		{
			vAddress* p1=new vAddress(e->h_source);
			p1->nextAddress=NULL;
			tailSrcEthernetAddress->nextAddress=p1;
			tailSrcEthernetAddress=p1;
		}
	}
	
	if(headRmtEthernetAddress==NULL)
	{
		headRmtEthernetAddress=new vAddress(e->h_dest);
		headRmtEthernetAddress->nextAddress=NULL;
		tailRmtEthernetAddress=headRmtEthernetAddress;		
	}	
	else
	{
		bool ret=false;
		vAddress* p=headRmtEthernetAddress;
		//cout<<"deadroof"<<endl;
		while(p!=NULL && !ret)
		{
			ret=p->updateCountIfMatch(e->h_dest);
			p=p->nextAddress; //move p
		}
		if(ret==false)
		{		
			vAddress* p1=new vAddress(e->h_dest);
			p1->nextAddress=NULL;
			tailRmtEthernetAddress->nextAddress=p1;
			tailRmtEthernetAddress=p1;
		}
	}
		
}


//below method is used to print out the statistics of link layer.
void printLinkLayerInfo()
{
	cout<<"\n\n=== Link layer ===\n\n";
	cout<<"--- Source ethernet addresses ---\n";
	//print source ethernet addresses here..
	vAddress* p=headSrcEthernetAddress;
	while(p!=NULL)
	{	
		p->printReadableEthernetAddress();				
		p=p->nextAddress;
	}
	
	cout<<"\n--- Destination ethernet addresses ---\n";
	//print destination addresses here..
	p=headRmtEthernetAddress;	
	while(p!=NULL)
	{
		p->printReadableEthernetAddress();	
		p=p->nextAddress;
	}
	
	//destruct network layer info..
	p=headSrcEthernetAddress;
	vAddress* q;
	while(p!=NULL)
	{
		q=p->nextAddress;
		delete p;
		p=q;
	}
	
	p=headRmtEthernetAddress;
	while(p!=NULL)
	{
		q=p->nextAddress;
		delete p;
		p=q;
	}	
	cout<<"\n";
}

//compute network layer statistics.
void computeNetworkLayerInfo(const u_char * packet )
{
	isIcmp= false;
	isTcp= false;
	isUdp= false;
	if(isIP)
	{
		struct iphdr *ip=(struct iphdr*)(packet+sizeof(struct ethhdr));
		//to find the type of next level protocol 
		unsigned int proto=(unsigned int)ip->protocol;
		unsigned int ttl = (unsigned int)ip->ttl;
		struct protoent *protocol=getprotobynumber(proto);
		if(protocol!=NULL)
		{	
			char* name=getprotobynumber(proto)->p_name;
			if(strcmp(name,"icmp")==0 )
			{
				isIcmp= true;
				transportLayerProtocols.push_back(string(getprotobynumber(proto)->p_name));	
				timeToLive.push_back(ttl);		
			}
			else if(strcmp(name,"udp")==0)
			{
				isUdp= true;
				transportLayerProtocols.push_back(string(getprotobynumber(proto)->p_name));	
				timeToLive.push_back(ttl);
		
			}
			else if(strcmp(name,"tcp")==0)
			{
				isTcp= true;
				transportLayerProtocols.push_back(string(getprotobynumber(proto)->p_name));	
				timeToLive.push_back(ttl);
		
			}	
			else
			{	
				transportLayerProtocols.push_back(to_string((long long int)proto));
				timeToLive.push_back(ttl);
			}						
		}
		else
		{	
			transportLayerProtocols.push_back(to_string((long long int)proto));
			timeToLive.push_back(ttl);
		}

		unsigned int temp=0;
		temp=~temp;
		temp=temp>>24;

		unsigned char byte[4];
		byte[0]= ip->saddr>>24;                 // to use ntohs here ...???
		byte[1]= ip->saddr>>16 & temp;	
		byte[2]= ip->saddr>>8 & temp;
		byte[3]= ip->saddr & temp;			

		unsigned char rbyte[4];
		rbyte[0]= ip->daddr>>24;
		rbyte[1]= ip->daddr>>16 & temp;	
		rbyte[2]= ip->daddr>>8 & temp;
		rbyte[3]= ip->daddr & temp;			

		if(headSrcNetworkAddress==NULL)
		{
			headSrcNetworkAddress=new vAddress(byte,sizeof(byte));
			headSrcNetworkAddress->nextAddress=NULL;
			tailSrcNetworkAddress=headSrcNetworkAddress;		
		}
		else
		{
			bool ret=false;
			vAddress* p=headSrcNetworkAddress;
			while(p!=NULL&&!ret)
			{
				ret=p->updateCountIfMatch(byte,sizeof(byte));
				p=p->nextAddress; //move p
			}
			if(ret==false)
			{
				vAddress* p1=new vAddress(byte,sizeof(byte));
				p1->nextAddress=NULL;
				tailSrcNetworkAddress->nextAddress=p1;
				tailSrcNetworkAddress=p1;
			}
		}
	
		if(headRmtNetworkAddress==NULL)
		{
			headRmtNetworkAddress=new vAddress(rbyte,sizeof(rbyte));
			headRmtNetworkAddress->nextAddress=NULL;
			tailRmtNetworkAddress=headRmtNetworkAddress;		
		}	
		else
		{
			bool ret=false;
			vAddress* p=headRmtNetworkAddress;
			//cout<<"deadroof"<<endl;
			while(p!=NULL && !ret)
			{
				ret=p->updateCountIfMatch(rbyte,sizeof(rbyte));
				p=p->nextAddress; //move p
				//cout<<"deadbeef"<<endl;
			}
			if(ret==false)
			{		
				vAddress* p1=new vAddress(rbyte,sizeof(rbyte));
				p1->nextAddress=NULL;
				tailRmtNetworkAddress->nextAddress=p1;
				tailRmtNetworkAddress=p1;
			}
		}		
	}
	else if(isARP)
	{
		arphdr_t *ap=(arphdr_t*)(packet+sizeof(struct ethhdr));
		if(ap!=NULL)
		{
			 //printf("Protocol type: %s\n", (ntohs(ap->ptype) == 0x0800) ? "IPv4" : "Unknown");
			if (ntohs(ap->htype) == 1 && ntohs(ap->ptype) == 0x0800)
			{ 
				 
				//  MAC Addresses
				arpAddresses.push_back(Arp(ap->shrd,ap->spad));
				arpAddresses.push_back(Arp(ap->dhrd,ap->dpad));						
			}		 
				 			  
		}
		
		
		//TODO
		
	}
	else
	{
		
	}				
}


//print network layer statistics..
void  printNetworkLayerInfo()
{
	cout<<"\n\n=== Network layer ===\n\n";
	
	cout<<"--- Source IP addresses ---\n";
	//print source ethernet addresses here..
	vAddress* p=headSrcNetworkAddress;
	while(p!=NULL)
	{	
		p->printReadableNetworkAddress();				
		p=p->nextAddress;
	}
	
	cout<<"\n--- Destination IP addresses ---\n";
	//print destination addresses here..
	p=headRmtNetworkAddress;	
	while(p!=NULL)
	{
		p->printReadableNetworkAddress();	
		p=p->nextAddress;
	}
	
	//destruct network layer info..
	p=headSrcNetworkAddress;
	vAddress* q;
	while(p!=NULL)
	{
		q=p->nextAddress;
		delete p;
		p=q;
	}
	
	p=headRmtNetworkAddress;
	while(p!=NULL)
	{
		q=p->nextAddress;
		delete p;
		p=q;
	}
		
	cout<<"\n--- Printing unique TTL values --- \n";
	cout<<"TTL\t\tFrequency\n";
	sort(timeToLive.begin(),timeToLive.end());
	vector<int> bckup=timeToLive;
	std::vector<int>::iterator it;
	it=unique(timeToLive.begin(),timeToLive.end());
	timeToLive.resize(std::distance(timeToLive.begin(),it));	
	
	for (int i=0;i<	timeToLive.size();i++)
    {    
        std::cout << timeToLive[i]<<"\t\t"<<count(bckup.begin(),bckup.end(),timeToLive[i])<<endl;
	}
	cout<<"\n\n.... unique arp participants....\n\n";
	vector<Arp>::iterator it1;
		
	vector<Arp> backup1 = arpAddresses;
	//sort(arpAddresses.begin(), arpAddresses.end(),sortVectors);	
	//it1= unique(arpAddresses.begin(),arpAddresses.end(),equalVectors);

	for(int i=0;i<arpAddresses.size();i++)   //printing arpAddresses
	{
		arpAddresses[i].printReadableArpAddress();
		int count=0;
		for(int j=0;j<arpAddresses.size();j++)
		{
			if(i!=j && equalVectors(arpAddresses[i],arpAddresses[j]))
			{
				count++;
			}
		}
		cout<<"\t\t"<<count<<"\n";			
	}
}

//compute transport layer statistics...
void computeTransportLayerInfo(const u_char * packet)
{
	if(isTcp)
	{
		//TODO
		//source & destination ports..
		struct tcphdr *tcpPacket = (struct tcphdr *)(packet+sizeof(struct ethhdr)+sizeof(iphdr));
		sourcePorts.push_back(ntohs((unsigned short)tcpPacket->th_sport));
		destinationPorts.push_back(ntohs((unsigned short)tcpPacket->th_dport));
		unsigned short tempFlag=(unsigned short)tcpPacket->th_flags;
		for(int i=0;i<NUM_TCP_FLAGS;i++)
		{
			if(tempFlag & (1<<i))
				tcpFlags.push_back(pow(2,i));
		}
	}
	else if(isUdp)
	{
		struct udphdr *udpPacket=(struct udphdr *)(packet+sizeof(struct ethhdr)+sizeof(iphdr));
		sourceUdpPorts.push_back(ntohs((unsigned short)udpPacket->uh_sport));
		destinationUdpPorts.push_back(ntohs((unsigned short)udpPacket->uh_dport));		
	}
	else if(isIcmp)
	{
		struct icmphdr *icmpPacket=(struct icmphdr *)(packet+sizeof(struct ethhdr)+sizeof(iphdr));
		icmpCodes.push_back(ntohs((unsigned short)icmpPacket->code));
		icmpTypes.push_back(ntohs((unsigned short)icmpPacket->type));
	}
	else
	{
		//TODO
	}
}

const char* getTCPFlagName(unsigned short flag)
{
	if(flag==TH_FIN)
	{
		return "FIN";
	}
	else if(flag==TH_SYN)
	{
		return "SYN";
	}
	else if(flag==TH_RST)
	{
		return "RST";
	}
	else if(flag==TH_PUSH)
	{
		return "PSH";
	}
	else if(flag==TH_ACK)
	{
		return "ACK";
	}
	else if(flag==TH_URG)
	{
		return "URG";
	}
	return to_string((long long)flag).c_str();
}

//print transport layer statistics...
void printTransportLayerInfo()
{
	cout<<"\n\n=== Transport layer ===\n\n";

	//printing unique transport layer protocols.
	cout<<"--- Unique Transport Layer protocols ---\n";
	if(transportLayerProtocols.empty())
	{
		cout<<"(no results)\n";		
	}
	else
	{
		cout<<"Protocol\t\tFrequency\n";	
		sort(transportLayerProtocols.begin(),transportLayerProtocols.end());
		vector<string> bckup=transportLayerProtocols;
		std::vector<string>::iterator it;
		it=unique(transportLayerProtocols.begin(),transportLayerProtocols.end());
		transportLayerProtocols.resize(distance(transportLayerProtocols.begin(),it));

		for (int i=0;i<	transportLayerProtocols.size();i++)
		{    
			//also output the count of each unique protocol
			cout << transportLayerProtocols[i]<<"\t\t\t"<<count(bckup.begin(),bckup.end(),transportLayerProtocols[i])<<endl;
		}
	}
	
	cout<<"\n\n=========Transport layer: TCP=========\n\n";
	//Printing unique source and destination ports..
	cout<<"--- Unique Source ports ---\n";

	if(sourcePorts.empty())
	{
		cout<<"(no results)\n";	
	}
	else
	{
		sort(sourcePorts.begin(),sourcePorts.end());
		vector<unsigned short> b1=sourcePorts;
		std::vector<unsigned short>::iterator it1=unique(sourcePorts.begin(),sourcePorts.end());
		sourcePorts.resize(distance(sourcePorts.begin(),it1));
		for(int i=0;i<sourcePorts.size();i++)
		{
			//also output the count of each unique port.
			cout<<sourcePorts[i]<<"\t\t"<<count(b1.begin(),b1.end(),sourcePorts[i])<<endl;
		}
	}	
	//printing unique destination ports..
	cout<<"\n--- Unique Destination ports ---\n";
	if(destinationPorts.empty())
	{
		cout<<"(no results)\n";	
	}
	else
	{
		sort(destinationPorts.begin(),destinationPorts.end());
		vector<unsigned short> b1=destinationPorts;
		std::vector<unsigned short>::iterator it1=unique(destinationPorts.begin(),destinationPorts.end());
		destinationPorts.resize(distance(destinationPorts.begin(),it1));
		for(int i=0;i<destinationPorts.size();i++)
		{
			//also output the count of each unique port.
			cout<<destinationPorts[i]<<"\t\t"<<count(b1.begin(),b1.end(),destinationPorts[i])<<endl;
		}
	}
	
	//printing unique tcp flags...
	cout<<"\n--- TCP flags ---\n\n";
	if(tcpFlags.empty())
	{
		cout<<"(no results)\n";	
	}
	else
	{
		for(int i=0;i<NUM_TCP_FLAGS;i++)
		{
			short temp=pow(2,i);
			//also output the count of each unique port.
			cout<<getTCPFlagName(temp)<<"\t\t"<<count(tcpFlags.begin(),tcpFlags.end(),temp)<<endl;
		}
	}
	
	//printing UDP info
	cout<<"\n\n=========Transport layer: UDP=========\n\n";
	//Printing unique source and destination ports..
	cout<<"--- Unique Source ports ---\n";
	if(sourceUdpPorts.empty())
	{
		cout<<"(no results)\n";	
	}
	else
	{
		sort(sourceUdpPorts.begin(),sourceUdpPorts.end());
		vector<unsigned short> b1=sourceUdpPorts;	
		std::vector<unsigned short>::iterator it1=unique(sourceUdpPorts.begin(),sourceUdpPorts.end());
		sourceUdpPorts.resize(distance(sourceUdpPorts.begin(),it1));
		for(int i=0;i<sourceUdpPorts.size();i++)
		{
			//also output the count of each unique port.
			cout<<sourceUdpPorts[i]<<"\t\t"<<count(b1.begin(),b1.end(),sourceUdpPorts[i])<<endl;
		}
	}	

	//printing unique destination ports..
	cout<<"\n--- Unique Destination ports ---\n";
	if(destinationUdpPorts.empty())
	{
		cout<<"(no results)\n";
	}
	else
	{
		sort(destinationUdpPorts.begin(),destinationUdpPorts.end());
		vector<unsigned short> b1=destinationUdpPorts;
		vector<unsigned short>::iterator it1=unique(destinationUdpPorts.begin(),destinationUdpPorts.end());
		destinationUdpPorts.resize(distance(destinationUdpPorts.begin(),it1));
		for(int i=0;i<destinationUdpPorts.size();i++)
		{
			//also output the count of each unique port.
			cout<<destinationUdpPorts[i]<<"\t\t"<<count(b1.begin(),b1.end(),destinationUdpPorts[i])<<endl;
		}
	}	
	//printing ICMP info..
	cout<<"\n\n=========Transport layer: ICMP=========\n\n";
	cout<<"---------ICMP types---------\n\n";
	if(icmpTypes.empty())
	{
		cout<<"(no results)\n";
	}
	else
	{
		sort(icmpTypes.begin(),icmpTypes.end());
		vector<unsigned short> b1=icmpTypes;
		vector<unsigned short>::iterator it1=unique(icmpTypes.begin(),icmpTypes.end());
		icmpTypes.resize(distance(icmpTypes.begin(),it1));
		for(int i=0;i<icmpTypes.size();i++)
		{
			//also output the count of each unique port.
			cout<<icmpTypes[i]<<"\t\t"<<count(b1.begin(),b1.end(),icmpTypes[i])<<endl;
		}		
	}
	cout<<"\n---------ICMP codes---------\n\n";
	if(icmpCodes.empty())
	{
		cout<<"(no results)\n";
	}
	else
	{
		sort(icmpCodes.begin(),icmpCodes.end());
		vector<unsigned short> b1=icmpCodes;
		vector<unsigned short>::iterator it1=unique(icmpCodes.begin(),icmpCodes.end());
		icmpCodes.resize(distance(icmpCodes.begin(),it1));
		for(int i=0;i<icmpCodes.size();i++)
		{
			//also output the count of each unique port.
			cout<<icmpCodes[i]<<"\t\t"<<count(b1.begin(),b1.end(),icmpCodes[i])<<endl;
		}			
	}
}


void callback(u_char *, const struct pcap_pkthdr *header, const u_char *packet) //the first argument is NULL in our case..
{
	//this call back function will be called for every packet..		
	computeSummary(header, packet);
	computeLinkLayerInfo(packet);		
	computeNetworkLayerInfo(packet);
	computeTransportLayerInfo(packet);
}

//the below method will print out the summary section..
void printSummary()
{
	cout<<"\n=== Summary of IPv4 packets===\n\n";
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

	//call the loop back function...
	int returnVal = pcap_loop(handle, -1, callback, NULL); //-1 here implies all the packets...
	if(returnVal==-1)
	{
		printf("Error occurred in pcap_loop %s\n",pcap_geterr(handle));
		exit(1);
	}
	//printSummary();	
	//printLinkLayerInfo();
	//printNetworkLayerInfo();
	printTransportLayerInfo();
	//close the handle
	pcap_close(handle);
	return 0;
}
