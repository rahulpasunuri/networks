#include "../include/Core.h"

struct remote
{
	string ip;
	unsigned short port;
};


bool Core::addPortToList(unsigned short port)
{
	if(port<10000) //dis allowing port below 10,000
	{
		return false;
	}
	lPortMutex.lock();
	for (std::map<unsigned short,vector<packet*> >::iterator it=portMap.begin(); it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{
			lPortMutex.unlock();
			return false;
		}
	}
	vector<packet*> newVector;
	portMap.insert ( std::pair<unsigned short,vector<packet*> >(port,newVector));
	//portMap.push_back(port,newVector);
	lPortMutex.unlock();
	return true;
}

void Core::removePortFromList(unsigned short port)
{
	//TODO
	lPortMutex.lock();
	std::map<unsigned short,vector<packet*> >::iterator it=portMap.begin();
	for (; it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{
			break;
		}
	}	
	portMap.erase(it);
	lPortMutex.unlock();
}

void Core::addPacketToPort(unsigned short port, struct packet p)
{

	//the thread inserted its source port before reaching here..
	lPortMutex.lock();
	std::map<unsigned short,vector<packet*> >::iterator it=portMap.begin();
	for (; it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{
			cout<<"Adding a packet"<<endl;
			//struct tcphdr *tcp = (struct tcphdr *)(p.pointer+sizeof(ethhdr)+sizeof(tcphdr));	
			struct packet* p1=new (struct packet);
			p1->pointer=p.pointer;
			p1->length=p.length;
			it->second.push_back(p1);
			break;
		}
	}		
	lPortMutex.unlock();
}

void Core::removePacketFromPort(unsigned short port, struct packet p)
{
	//the thread inserted its source port before reaching here..
	lPortMutex.lock();
	std::map<unsigned short,vector<packet*> >::iterator it=portMap.begin();
	for (; it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{			
			for(vector<packet*>::iterator it1 = it->second.begin(); it1!=it->second.end(); it1++)
			{
				//if(*it1 == p)
				{
					it->second.erase(it1);
					break;	
				}				
			}			
			break;
		}
	}		
	lPortMutex.unlock();
}

void Core::readPacketOnPort()
{
	cout<<"packet sniffer started"<<endl;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t *handle;			/* Session handle */
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
	
	//open pcap in non promiscous mode.
	handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", interfaceName.c_str(), errbuf);
	}
	struct pcap_pkthdr *hdr;
	
    /* Retrieve the packets */
    int res;
    while(1)
    {
		while((res = pcap_next_ex(handle, &hdr, &packet)) >= 0)
		{
		    if(res == 0)
		    {
		    	//time out for reading a packet...
		        continue;            
		    }
		    break;
		}
		
		if(res == -1)
		{
		    printf("Error reading the packets: %s\n", pcap_geterr(handle));
		}
		struct tcphdr *tcp = (struct tcphdr *)(packet+sizeof(ethhdr)+sizeof(iphdr));	
		//struct tcphdr *ip = (struct iphdr *)(packet+sizeof(ethhdr));	
		
		struct packet p;
		p.pointer=packet;
		p.length=hdr->len;
		//TODO - ignore packets with originating from this ip address..		
		addPacketToPort(ntohs(tcp->dest), p);
		/* And close the session */
	}
	pcap_close(handle);
}


//constructor of core..
Core::Core(args_t args,string interfaceName)
{
	this->args=args;
	this->interfaceName=interfaceName;
}	

void Core::SendSynPacket(unsigned short srcPort, string dstIp, unsigned short dstPort)
{	
	
	int sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)  //create a raw socket
	{
		HelperClass::TerminateApplication("socket() failed ");
	}

	struct ifreq ifr;
	memset (&ifr, 0, sizeof (ifr));
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
	if(HelperClass::srcIp=="")
	{
		HelperClass::srcIp=srcIp;
	}
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
	tcp.window = ntohs(29200); //set all bits to 1 => max size..TODO
	//tcp.window = ~0;
	unsigned int optSize=0;
	tcp.doff = (sizeof(struct tcphdr)+optSize)/WORD_SIZE; //so no options..	
	tcp.urg_ptr= 0; 	
	
	u_char* temp=new u_char[sizeof(tcphdr) + optSize]; //TODO 20 for options.
	memcpy(temp, &tcp, sizeof(tcphdr));
	//memcpy(temp+sizeof(tcphdr),backup,optSize);
	
	tcp.check = 0;
	tcp.check=computeTCPHeaderCheckSum(ip,tcp);
	//lets build the packet..
	u_char* packet = new u_char[sizeof(struct iphdr)+sizeof(struct tcphdr)+optSize]; //this works because we have no tcp options and no tcp payload
	memcpy(packet, &ip, sizeof(iphdr));
	memcpy(packet+sizeof(iphdr), &tcp, sizeof(struct tcphdr));
	
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

	// bind the socket.
	if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) 
	{
		HelperClass::TerminateApplication("bind() failed!!");
	}
	
	// Send packet.
	if (sendto (sock, packet, sizeof(iphdr) + sizeof(tcphdr)+optSize, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)
	{
		HelperClass::TerminateApplication("send() failed!!");
	}	
	
	
	//free resources///	
	delete[] temp;
	delete[] packet;		
	close (sock);// closing the socket.
}

void* Core::threadhelper(void *context)
{
    ((Core *)context)->readPacketOnPort();
    return NULL;
}

struct packet* Core::fetchPacketFromPort(unsigned short port)
{
	struct packet* p = NULL; 
	lPortMutex.lock();
	map<unsigned short, vector<struct packet*> >::iterator it=portMap.begin();
	while(it!=portMap.end())
	{
		if(it->first==port)
		{
			if(it->second.empty())
			{
				break;
			}
			p = new (struct packet);
			p = it->second[0];	
			break;
		}
		it++;
	}
	lPortMutex.unlock();
	return p;
}

struct packet* Core::readPacketFromList(unsigned short port)
{
	//we can safely remove the packet from the list after we are done.	
	struct packet* p=fetchPacketFromPort(port);
	if(p==NULL)
	{
		return NULL;
	}	
	removePacketFromPort(port, *p);
	return p;
}


void Core::PerformSynScan(string dstIp, unsigned short dstPort)
{
	unsigned short srcPort = 0;
	while(!addPortToList(srcPort)) //ensures that each thread listens on a new port...
	{	
		srcPort=rand()%64000;
	}
	cout<<"Listening on source port "<<srcPort<<endl;
	//send a syn packet.
	SendSynPacket(srcPort, dstIp, dstPort);		
	struct packet *p=NULL;
	while(1)
	{
		//loop till we get the message intended to us..
		p = readPacketFromList(srcPort);		
		if(p!=NULL)
		{
			struct tcphdr* tcp= (struct tcphdr*)(p->pointer + sizeof(ethhdr)+sizeof(iphdr));
			struct iphdr* ip= (struct iphdr*)(p->pointer + sizeof(ethhdr));
			//check the source ip address of the packet and compare it with dstIp
			//TODO
			sockaddr_in s;
			memcpy(&s.sin_addr.s_addr, &ip->daddr, 4);
			cout<<"checking the correctnes of the packet"<<inet_ntoa(s.sin_addr)<<endl;
			if(tcp!=NULL)
			{
				cout<<"recieved port is "<<ntohs(tcp->source)<<endl;				
			}

			//also check source port of the packet with dstPort
			if(ntohs(tcp->source) == dstPort)
			{
				cout<<"Correct packet recieved"<<endl;
				break;				
			}
			
		}
	}
	
	//receive reply now..
	const u_char *rcvdPacket=p->pointer;		
	struct tcphdr *rcvdTcp = (struct tcphdr *)(rcvdPacket+sizeof(ethhdr)+sizeof(iphdr));
	struct iphdr *rcvdIp = (struct iphdr *)(rcvdPacket+sizeof(ethhdr));
	cout<<endl;
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sockaddr));
	//memset();
	memcpy(&sa.sin_addr.s_addr, &rcvdIp->daddr, sizeof(rcvdIp->daddr)); //4 bytes for ip address.
	char rcvdSrcIp[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(sa.sin_addr), rcvdSrcIp, INET_ADDRSTRLEN);;	
	cout<<rcvdSrcIp<<endl;	
	
	cout<<"------------------------------------------------------------\n";
	cout<<"Port\t";
	cout<<"Service Name\t";
	cout<<"Scan Type\t";
	cout<<"Status"<<endl;
	cout<<"------------------------------------------------------------\n";
	cout<<dstPort<<"\t";
	const char* serviceName=HelperClass::GetPortName(dstPort);
	if(serviceName!=NULL)
	{
		cout<<serviceName<<"\t\t";
	}
	else
	{
		cout<<"Unassigned\t\t";
	}
	cout<<"TCP-SYN-SCAN\t";
	if(rcvdTcp->ack==1 || rcvdTcp->syn==1)
	{
		cout<<"open"<<endl;
	}
	else if(rcvdTcp->rst==1)
	{
		cout<<"closed"<<endl;		
	}	
	else
	{
		cout<<"filtered"<<endl; //TODO
	}
	
}



void Core::Start()
{
	string dstIp="129.79.247.87"; //ip address of dagwood.soic.indiana.edu
	//string dstIp="8.8.8.8"; //ip address of dagwood.soic.indiana.edu

	pthread_t t;
	int retVal=pthread_create(&t, NULL, &Core::threadhelper, this);
	if(retVal!=0)
	{
		HelperClass::TerminateApplication("Unable to create the sniffer thread");
	}
	sleep(3); //wait for the pthread to start sniffing..
	PerformSynScan(dstIp,22);	
	retVal=pthread_join(t,NULL);
	if(retVal!=0)
	{
		HelperClass::TerminateApplication("Unable to join the sniffer thread");
	}	
	
}

//working check sum method...
uint16_t Core::computeHeaderCheckSum(uint16_t* words, unsigned int size)
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


uint16_t Core::computeTCPHeaderCheckSum(struct iphdr ip,struct tcphdr tcp)
{	 
	unsigned int size=12;
	unsigned int tcpHdrSize= sizeof(tcphdr);
	unsigned int segSize= tcpHdrSize;
	u_char* t=new u_char[size+segSize];
	memcpy(t, &ip.saddr, 4);
	memcpy(t+4, &ip.daddr, 4);
	t[8]=0;
	t[9]=IPPROTO_TCP;

	unsigned short segmentSize=htons(segSize);

	memcpy(t+10, &segmentSize, 2);
	memcpy(t+size, &tcp,tcpHdrSize);
	
	//The checksum field is the 16-bit one's complement of the one's complement sum of all 16-bit words in the header.  (source -WIKIPEDIA)
	uint16_t checkSum = computeHeaderCheckSum((uint16_t*)t, size+segSize);
	delete[] t; //free memory..
	return checkSum;
}




