#include<iostream>
#include <pcap.h> //header file required for pcap...
#include <sys/socket.h>
#include <netinet/in.h>
#include <iomanip>
#include <ctime>
#include<linux/if_ether.h>
using namespace std;

#include<string.h>
#include<stdlib.h>


class ethernetAddress
{
	private:
		int numInstances;
	
		//matches an input address with current address..
		bool isAddressMatch(unsigned char* a)
		{
			int i=0;
			for(;i<ETH_ALEN;i++)
			{
				if(a[i]!=addr[i])
				{
					return false;
				}
			}		
			return true;
		}

	public:
		unsigned char addr[ETH_ALEN];
		ethernetAddress(unsigned char* addr)
		{
			int i=0;
			numInstances=1;
			nextAddress=NULL;
			memcpy(this->addr,addr,ETH_ALEN);	
		}
		
		void printReadableAddress()
		{
			int i=0;
			for(;i<ETH_ALEN-1;i++)
			{
				printf("%02x:",addr[i]);
			}
			printf("%02x",addr[i]);
			cout<<"\t"<<numInstances<<endl;		
		}
		
		bool updateCountIfMatch(unsigned char* a) //returns true on succesfull updation..
		{
			bool b=isAddressMatch(a);
			if(!b)
			{				
				return false;
			}
			numInstances++; 
			return true;
		}
		ethernetAddress* nextAddress;
};

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


//global variables init statements..
int numIpv6Packets=0; //this will hold the number of ipv6 packets ignored.
int numPackets=0;
float sumPacketLength=0;
int smallestPacketLength=10000; //init it to a very high value
int largestPacketLength=0; //init to a low value.
timeval startTime;
timeval endTime;
bool isTimeInit=false;
ethernetAddress* headSrcEthernetAddress=NULL;
ethernetAddress* tailSrcEthernetAddress=NULL;
ethernetAddress* headRmtEthernetAddress=NULL;
ethernetAddress* tailRmtEthernetAddress=NULL;

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
		headSrcEthernetAddress=new ethernetAddress(e->h_source);
		headSrcEthernetAddress->nextAddress=NULL;
		tailSrcEthernetAddress=headSrcEthernetAddress;		
	}
	else
	{
		bool ret=false;
		ethernetAddress* p=headSrcEthernetAddress;
		while(p!=NULL&&!ret)
		{
			ret=p->updateCountIfMatch(e->h_source);
			p=p->nextAddress; //move p
		}
		if(ret==false)
		{
			ethernetAddress* p1=new ethernetAddress(e->h_source);
			p1->nextAddress=NULL;
			tailSrcEthernetAddress->nextAddress=p1;
			tailSrcEthernetAddress=p1;
		}
	}
	
	if(headRmtEthernetAddress==NULL)
	{
		headRmtEthernetAddress=new ethernetAddress(e->h_dest);
		headRmtEthernetAddress->nextAddress=NULL;
		tailRmtEthernetAddress=headRmtEthernetAddress;		
	}	
	else
	{
		bool ret=false;
		ethernetAddress* p=headRmtEthernetAddress;
		//cout<<"deadroof"<<endl;
		while(p!=NULL && !ret)
		{
			ret=p->updateCountIfMatch(e->h_dest);
			p=p->nextAddress; //move p
			//cout<<"deadbeef"<<endl;
		}
		if(ret==false)
		{		
			ethernetAddress* p1=new ethernetAddress(e->h_dest);
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
	ethernetAddress* p=headSrcEthernetAddress;
	while(p!=NULL)
	{	
		p->printReadableAddress();				
		p=p->nextAddress;
	}
	
	cout<<"\n--- Destination ethernet addresses ---\n";
	//print destination addresses here..
	p=headRmtEthernetAddress;	
	while(p!=NULL)
	{
		p->printReadableAddress();	
		p=p->nextAddress;
	}
	
	//destruct network layer info..
	p=headSrcEthernetAddress;
	ethernetAddress* q;
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




void computeNetworkLayerInfo()
{
	//TODO
			
}

void  printNetworkLayerInfo()
{
	cout<<"\n\n=== Network layer ===\n\n";
	cout<<"--- Network layer protocols ---\n";//TODO
	
	
	cout<<"--- Source IP addresses ---\n";//TODO
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

	//close the handle
	pcap_close(handle);
	return 0;
}
