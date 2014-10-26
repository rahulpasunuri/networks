#include<iostream>
#include <pcap.h> //header file required for pcap...
#include <sys/socket.h>
#include <netinet/in.h>
#include <iomanip>
#include <ctime>
#include<linux/if_ether.h>
#include<netinet/ip.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include <inttypes.h>
#include<netdb.h>
using namespace std;

#include<string.h>
#include<stdlib.h>

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

//global variables init statements..
int numIpv6Packets=0; //this will hold the number of ipv6 packets ignored.
int numPackets=0;
int NumTcpPackets=0;
int NumUdpPackets=0;
int NumIcmpPackets=0;
float sumPacketLength=0;
int smallestPacketLength=10000; //init it to a very high value
int largestPacketLength=0; //init to a low value.
timeval startTime;
timeval endTime;
bool isTimeInit=false;
vAddress* headSrcEthernetAddress=NULL;
vAddress* tailSrcEthernetAddress=NULL;
vAddress* headRmtEthernetAddress=NULL;
vAddress* tailRmtEthernetAddress=NULL;
vAddress* headSrcNetworkAddress=NULL;
vAddress* tailSrcNetworkAddress=NULL;
vAddress* headRmtNetworkAddress=NULL;
vAddress* tailRmtNetworkAddress=NULL;




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

bool computeLinkLayerInfo(const u_char *packet)
{
	struct ethhdr *e=(struct ethhdr*) packet;
	if(ntohs(e->h_proto)!=ETH_P_IP)
	{
		return false;
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
			//cout<<"deadbeef"<<endl;
		}
		if(ret==false)
		{		
			vAddress* p1=new vAddress(e->h_dest);
			p1->nextAddress=NULL;
			tailRmtEthernetAddress->nextAddress=p1;
			tailRmtEthernetAddress=p1;
		}
	}
	
	return true;
}

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




void computeNetworkLayerInfo(const u_char * packet )
{
	struct iphdr *ip=(struct iphdr*)(packet+sizeof(struct ethhdr));
	//to find the type of next level protocol 
	unsigned int proto=(unsigned int)ip->protocol;
	if(strcmp(getprotobynumber(proto)->p_name,string("icmp").c_str())==0)
    {
      //ICMP PACKET
        NumIcmpPackets++;
    }
    else if(strcmp(getprotobynumber(proto)->p_name,string("tcp").c_str())==0)
    {
       //TCP PACKET
        NumTcpPackets++;
    }
    else if(strcmp(getprotobynumber(proto)->p_name,string("udp").c_str())==0)
    {
       //UDP PACKET
        NumUdpPackets++;  
    }
    else
		cout<< getprotobynumber(proto)->p_name<<endl;
		

	unsigned int temp=0;
	temp=~temp;
	temp=temp>>24;

	unsigned char byte[4];
	byte[0]= ip->saddr>>24;
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
	
	//cout<<(unsigned long int)<<"source address";
	//TODO
			
}

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
	cout<<"\n";//TODO
}


void computeTransportLayerInfo()
{
	//TODO
}

void printTransportLayerInfo()
{
	cout<<"\n\n=== Transport layer ===\n\n"; //TODO


}


void callback(u_char *, const struct pcap_pkthdr *header, const u_char *packet) //the first argument is NULL in our case..
{
	//this call back function will be called for every packet..	
	bool ret=computeLinkLayerInfo(packet);	
	if(ret==false) //this will happen for ipv6 packets..we just ignore them...
	{
		numIpv6Packets++;
		return;
	}
	computeSummary(header, packet);
	computeNetworkLayerInfo(packet);
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
	
	cout<<"Number of non IPv4 packets processed is "<<numIpv6Packets<<endl;
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
	printSummary();	
	printLinkLayerInfo();
	printNetworkLayerInfo();
	//close the handle
	pcap_close(handle);
	return 0;
}
