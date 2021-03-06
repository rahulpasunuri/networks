#include "../include/Wiretap.h"

using namespace std;

vAddress* headSrcEthernetAddress=NULL;
vAddress* tailSrcEthernetAddress=NULL;
vAddress* headRmtEthernetAddress=NULL;
vAddress* tailRmtEthernetAddress=NULL;
vAddress* headSrcNetworkAddress=NULL;
vAddress* tailSrcNetworkAddress=NULL;
vAddress* headRmtNetworkAddress=NULL;
vAddress* tailRmtNetworkAddress=NULL;
bool isTcpUrgSeen=false;
bool isTcpAckSeen=false;
bool isTcpPshSeen=false;
bool isTcpRstSeen=false;
bool isTcpFinSeen=false;
bool isTcpSynSeen=false;

bool vAddress::isAddressMatch(unsigned char* a,int size=ETH_ALEN)
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
vAddress::~vAddress()
{
	delete[] addr;//free memory.
}
vAddress::vAddress(unsigned char* addr, int size=ETH_ALEN)
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
	
void vAddress::printReadableEthernetAddress()
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
		
void vAddress::printReadableNetworkAddress()
{			
	if(size!=NETWORK_A_LEN)
	{
		cout<<"Cannot print in network format"<<endl;
		return;
	}			
	cout<<(short)addr[3]<<"."<<(short)addr[2]<<"."<<(short)addr[1]<<"."<<(short)addr[0]<<"\t"<<numInstances<<endl;			
}
		
bool vAddress::updateCountIfMatch(unsigned char* a,int size=ETH_ALEN) //returns true on succesfull updation..
{   
	bool b=isAddressMatch(a,size);
	if(!b)
	{				
		return false;
	}
	numInstances++; 
	return true;
}




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
	else
	{
		if(argv[2]!=NULL)
			return argv[2];
		else
			usage();
	}
	
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
	networkLayerProtocols.push_back(ntohs(e->h_proto)); //append all the network layer protocols seen...
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
		struct ether_arp *ap=(struct ether_arp*)(packet+sizeof(struct ethhdr));
		if(ap!=NULL)
		{ 
				 
				
				string s1;
				char buf[10]; int i=0; char buf1[10];
				for(;i<ETH_ALEN-1;i++)
				{
					sprintf(buf,"%02X:",ap->arp_sha[i]);
					s1.append(buf);
				}
				sprintf(buf,"%02X",ap->arp_sha[i]);
				s1.append(buf);
					i=0; string s2;
				for(;i<NETWORK_A_LEN-1;i++)
				{
					sprintf(buf1,"%d.",ap->arp_spa[i]);
					s2.append(buf1);
				}
				sprintf(buf1,"%d",ap->arp_spa[i]);
				s2.append(buf1);
					
				
				string s3 = s1+string(" / ")+s2;
				arpAddresses.push_back(s3);		 
				 			  
		}			
		
	}
	else
	{
		
	}				
}


//print network layer statistics..
void  printNetworkLayerInfo()
{
	cout<<"\n\n=== Network layer ===\n\n";
	
	cout<<"--- Unique Network Layer Protocols ---\n\n";
	if(networkLayerProtocols.empty())
	{
		cout<<"(No results)\n";
	}
	else
	{
		vector<int> b=networkLayerProtocols; //take a back up
		sort(networkLayerProtocols.begin(),networkLayerProtocols.end());
		vector<int>::iterator it=unique(networkLayerProtocols.begin(),networkLayerProtocols.end());
		networkLayerProtocols.resize(distance(networkLayerProtocols.begin(),it));
		for(int i=0;i<networkLayerProtocols.size();i++)
		{
			if(networkLayerProtocols[i]==ETH_P_ARP)
			{
				cout<<"ARP"<<"\t\t"<<count(b.begin(),b.end(),networkLayerProtocols[i])<<endl;	
			}
			else if(networkLayerProtocols[i]==ETH_P_IP)
			{
				cout<<"IP"<<"\t\t"<<count(b.begin(),b.end(),networkLayerProtocols[i])<<endl;
			}
			else
			{
				cout<<networkLayerProtocols[i]<<"  (0x"<<std::hex<<networkLayerProtocols[i]<<std::dec<<")";
				cout<<"\t"<<count(b.begin(),b.end(),networkLayerProtocols[i])<<endl;	
			}			
		}		
	}
	
	cout<<"\n--- Source IP addresses ---\n";
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
		
		sort(arpAddresses.begin(),arpAddresses.end());
		vector<string> bckup1=arpAddresses;
		std::vector<string>::iterator it1;
		it1=unique(arpAddresses.begin(),arpAddresses.end());
		arpAddresses.resize(distance(arpAddresses.begin(),it1));

		for (int h=0;h<	arpAddresses.size();h++)
		{    
		
			cout<< arpAddresses[h]<<"\t"<<count(bckup1.begin(),bckup1.end(),arpAddresses[h])<<"\n";
		}

	
}



int tempCount=0;
//compute transport layer statistics...
void computeTransportLayerInfo(const u_char * packet)
{
	if(isTcp)
	{
		//TODO
		//source & destination ports..
		struct tcphdr *tcpPacket = (struct tcphdr *)(packet+sizeof(struct ethhdr)+sizeof(struct iphdr));
		sourcePorts.push_back(ntohs((unsigned short)tcpPacket->source));
		destinationPorts.push_back(ntohs((unsigned short)tcpPacket->dest));
		
		//tcp flags..
		if((unsigned short)tcpPacket->urg & 1)
		{
			isTcpUrgSeen= true;
			tcpFlags.push_back("URG");
		}			
		if((unsigned short)tcpPacket->ack & 1)
		{
			isTcpAckSeen= true;
			tcpFlags.push_back("ACK");
		}			
		if((unsigned short)tcpPacket->psh & 1)
		{
			isTcpPshSeen= true;
			tcpFlags.push_back("PSH");
		}			
		if((unsigned short)tcpPacket->rst & 1)
		{
			isTcpRstSeen= true;
			tcpFlags.push_back("RST");
		}			
		if((unsigned short)tcpPacket->syn & 1)
		{
			isTcpSynSeen= true;
			tcpFlags.push_back("SYN");
		}					
		if((unsigned short)tcpPacket->fin & 1)
		{
			isTcpFinSeen= true;
			tcpFlags.push_back("FIN");
		}						
		//tcp options..
		//cout<<"**** is "<<(unsigned short)tcpPacket->th_off<<endl;
		unsigned short dataOffset=((unsigned short)tcpPacket->doff)*WORD_SIZE+sizeof(struct ethhdr)+sizeof(struct iphdr);
		short int start=sizeof(struct ethhdr)+sizeof(struct iphdr)+MIN_TCP_HEADER_SIZE*WORD_SIZE;		
		const u_char* opt=packet+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr);
		bool isOneSeen=false;
		
		while(start<dataOffset)
		{			
			unsigned short numBytes=0;
			unsigned short kind=opt[0];
			tcpOptions.push_back(kind);		
			opt++;
			numBytes++;
			if(kind==0)
			{
				break;
			}
			if(kind==1 && isOneSeen==false)
			{
				isOneSeen=true;
			}
			else if(kind==1 && isOneSeen==true)
			{
				tcpOptions.pop_back();
			}
			if(kind!=1)
			{
				unsigned short lengthOptions=*(opt);			//read the length field.
				opt=opt+lengthOptions-1;
				numBytes+=(lengthOptions-1);
				if(lengthOptions<2)
				{				
					cout<<"Some error occurred in reading TCP options"<<endl;
					exit(1);
				}
			}
			start+=numBytes;
		}			
	}
	else if(isUdp)
	{
		//udp source and destination ports.
		struct udphdr *udpPacket=(struct udphdr *)(packet+sizeof(struct ethhdr)+sizeof(iphdr));
		sourceUdpPorts.push_back(ntohs((unsigned short)udpPacket->source));
		destinationUdpPorts.push_back(ntohs((unsigned short)udpPacket->dest));		
	}
	else if(isIcmp)
	{
		//icmp types and codes.
		struct icmphdr *icmpPacket=(struct icmphdr *)(packet+sizeof(struct ethhdr)+sizeof(iphdr));
		icmpCodes.push_back((unsigned short)icmpPacket->code);
		icmpTypes.push_back((unsigned short)icmpPacket->type);
	}
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
		sort(tcpFlags.begin(),tcpFlags.end());
		vector<string> b1=tcpFlags;
		std::vector<string>::iterator it1=unique(tcpFlags.begin(),tcpFlags.end());
		tcpFlags.resize(distance(tcpFlags.begin(),it1));
		for(int i=0;i<tcpFlags.size();i++)
		{
			//also output the count of each unique port.
			cout<<tcpFlags[i]<<"\t\t"<<count(b1.begin(),b1.end(),tcpFlags[i])<<endl;
			
		}
		if(!isTcpUrgSeen)
		{
			cout<<"URG"<<"\t\t"<<"0"<<endl;
		}			
		if(!isTcpAckSeen)
		{
			cout<<"ACK"<<"\t\t"<<"0"<<endl;
		}			
		if(!isTcpPshSeen)
		{
			cout<<"PSH"<<"\t\t"<<"0"<<endl;
		}			
		if(!isTcpRstSeen)
		{
			cout<<"RST"<<"\t\t"<<"0"<<endl;
		}			
		if(!isTcpFinSeen)
		{
			cout<<"FIN"<<"\t\t"<<"0"<<endl;
		}					
		if(!isTcpSynSeen)
		{
			cout<<"SYN"<<"\t\t"<<"0"<<endl;
		}	
	}
	
	cout<<"\n--- TCP Options ---\n\n";
	if(tcpOptions.empty())
	{
		cout<<"(no results)\n";	
	}
	else
	{
		sort(tcpOptions.begin(),tcpOptions.end());
		vector<unsigned short> b1=tcpOptions;
		std::vector<unsigned short>::iterator it1=unique(tcpOptions.begin(),tcpOptions.end());
		tcpOptions.resize(distance(tcpOptions.begin(),it1));
		for(int i=0;i<tcpOptions.size();i++)
		{
			//also output the count of each unique port.
			cout<<tcpOptions[i]<<"\t\t"<<count(b1.begin(),b1.end(),tcpOptions[i])<<endl;
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
	cout<<"\n=== Packet Capture Summary===\n\n";
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
	string S(fileName);
	int Tag=S.find_last_of("/");
   	string NoSlash=S.substr(Tag+1);
	cout<<"Evaluating file: "<<NoSlash<<endl;
	
	if(CheckIfFileExists((const char*)fileName))
	{
		cout<<"file: "<<NoSlash<<" exists"<<endl;
	}
	else
	{
		cout<<"file: "<<NoSlash<<" does not exist"<<endl;
	}	

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
	printTransportLayerInfo();
	//close the handle
	pcap_close(handle);
	return 0;
}
