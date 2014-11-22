#include "../include/Core.h"
#include <signal.h>

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
	for (std::map<unsigned short,vector<packet> >::iterator it=portMap.begin(); it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{
			lPortMutex.unlock();
			return false;
		}
	}
	vector<packet> newVector;
	portMap.insert ( std::pair<unsigned short,vector<packet> >(port,newVector));
	//portMap.push_back(port,newVector);
	lPortMutex.unlock();
	return true;
}

void Core::removePortFromList(unsigned short port)
{
	lPortMutex.lock();
	bool isPortFound=false;
	std::map<unsigned short,vector<packet> >::iterator it=portMap.begin();
	for (; it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{
			isPortFound=true;
			//remove all packets from the queue..
			int size = it->second.size();
			for(int i=0; i<size; i++)
			{
				delete[] it->second[i].pointer;
			}
			break;
		}
	}
	if(isPortFound)
	{				
		portMap.erase(it);
	}
	lPortMutex.unlock();
}

void Core::addPacketToPort(unsigned short port, struct packet p)
{
	//the thread inserted its source port before reaching here..
	bool isAdded=false;
	lPortMutex.lock();
	std::map<unsigned short,vector<packet> >::iterator it=portMap.begin();
	for (; it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{
			isAdded=true;
			//struct tcphdr *tcp = (struct tcphdr *)(p.pointer+sizeof(ethhdr)+sizeof(iphdr));	
			struct packet p1;
			p1.pointer=p.pointer;
			p1.length=p.length;
			it->second.push_back(p1);
			break;
		}
	}		
	lPortMutex.unlock();
	if(!isAdded)
	{
		delete[] p.pointer;
	}
}

void Core::removePacketFromPort(unsigned short port, struct packet p)
{
	//the thread inserted its source port before reaching here..
	lPortMutex.lock();
	std::map<unsigned short,vector<packet> >::iterator it=portMap.begin();
	for (; it!=portMap.end(); ++it)
	{
		if(it->first==port)
		{			
			for(vector<packet>::iterator it1 = it->second.begin(); it1!=it->second.end(); it1++)
			{
					it->second.erase(it1);
					break;	
			}			
			break;
		}
	}		
	lPortMutex.unlock();
}

void Core::readPacketOnPort()
{
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
    	packetSnifferMutex.lock();
    	if (shldPacketSnifferExit == true)
    	{
    		packetSnifferMutex.unlock();
    		break;	
    	}
    	packetSnifferMutex.unlock();
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
		struct iphdr *ip = (struct iphdr *)(packet+sizeof(ethhdr));	
		struct protoent* protocol;
		unsigned int proto=(unsigned int)ip->protocol;
		protocol=getprotobynumber(proto);				
		bool isIcmp=false,isTcp=false,isUdp=false;
		if(protocol!=NULL)
		{
			char* name=protocol->p_name;
			if(strcmp(name,"icmp")==0 )
			{
				isIcmp=true;
			}
			else if(strcmp(name,"tcp")==0)
			{
				isTcp= true;
			}
			else if(strcmp(name,"udp")==0)
			{
				isUdp= true;
			}
		}
		struct packet p;
		p.pointer=new u_char[hdr->len];
		for(unsigned int i=0;i<hdr->len;i++)
		{
			p.pointer[i] = packet[i];
		}
		p.length=hdr->len;
		unsigned short len = (unsigned short)ip->ihl*sizeof (uint32_t);
		if(isTcp)
		{
			struct tcphdr *tcp = (struct tcphdr *)(packet+sizeof(ethhdr)+len);	
			addPacketToPort(ntohs(tcp->dest), p);
		}
		else if(isIcmp)
		{
			addPacketToPort(HelperClass::getSourcePortForICMP(packet), p);			
		}
		else if(isUdp)
		{
			struct udphdr *udp = (struct udphdr *)(packet+sizeof(ethhdr)+len);	
			addPacketToPort(ntohs((unsigned short)udp->dest), p);
		}
		else
		{
			delete[] p.pointer;		
		}
	}
	pcap_close(handle);
}


//constructor of core..
Core::Core(args_t args,string interfaceName)
{
	this->args=args;
	this->interfaceName=interfaceName;
}	

void Core::SendTCPPacket(unsigned short srcPort, string dstIp, unsigned short dstPort, scanTypes_t scanType)
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
	tcp.syn = 0; 
	tcp.rst = 0;
	tcp.psh = 0;
	tcp.ack = 0;
	tcp.urg = 0;
	if(scanType == TCP_SYN)
	{
		tcp.syn = 1; //set only the syn flag..	
	}
	else if(scanType == TCP_NULL)
	{
		//do nothing.
	}
	else if(scanType == TCP_FIN)
	{
		tcp.fin = 1;
	}
	else if (scanType == TCP_XMAS)
	{
		tcp.fin = 1;
		tcp.psh = 1;
		tcp.urg = 1;
	}
	else if (scanType==TCP_ACK)
	{
		tcp.ack =1;		
	}
	

	tcp.window = ntohs(TCP_WINDOW_SIZE);
	unsigned int optSize=0;
	tcp.doff = (sizeof(struct tcphdr)+optSize)/WORD_SIZE; //so no options..	
	tcp.urg_ptr= 0; 	
	
	u_char* temp=new u_char[sizeof(tcphdr) + optSize]; 
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

void Core::PerformTCPScan(string dstIp, unsigned short dstPort, scanTypes_t scanType)
{
	cout<<"calling tcp scan "<<endl;
	//this is the start time..
	int count=0; //this is used for the number of retransmissions
	struct results r;
	bool isPacketRcvd=false;
	r.ip = dstIp;
	//store the port of the remote..
	r.port=dstPort;	

	//store the service name of the port.
	r.scanType = scanType; //set the scan type
	for(;count < MAX_RETRANSMISSIONS;count++)
	{
		unsigned short srcPort = 0;
		while(!addPortToList(srcPort)) //ensures that each thread listens on a new port...
		{	
			srcPort=rand()%64000;
		}
		//send a ack packet.		
		SendTCPPacket(srcPort, dstIp, dstPort,scanType);		
		struct packet p;
		struct protoent *protocol;
		bool isIcmp = false;
		bool isTcp = false;
		unsigned int start = clock();
		while(1)
		{
			//loop till we get the message intended to us..
			p = readPacketFromList(srcPort);		
			if(p.pointer!=NULL)
			{
				struct iphdr* ip = (struct iphdr *)(p.pointer + sizeof(struct ethhdr));
				unsigned int proto=(unsigned int)ip->protocol;
				protocol=getprotobynumber(proto);				
				if(protocol!=NULL)
				{
					char* name=protocol->p_name;
					if(strcmp(name,"icmp")==0 )
					{
						isIcmp=true;
						isPacketRcvd=true;
						break;	
					}
					else if(strcmp(name,"tcp")==0)
					{
						unsigned short len = (unsigned short)ip->ihl*sizeof (uint32_t);	
						struct tcphdr* tcp= (struct tcphdr*)(p.pointer + sizeof(ethhdr)+len);
						//check the source ip address of the packet and compare it with dstIp
						sockaddr_in s;
						memcpy(&s.sin_addr.s_addr, &ip->saddr, 4);
						//also check source port of the packet with dstPort
						if(ntohs(tcp->source) == dstPort && (strcmp(inet_ntoa(s.sin_addr), dstIp.c_str()) ==0 ))
						{
							isTcp= true;
							isPacketRcvd=true;
							break;
						}			
					}
				}																
			}
			if(isPacketRcvd)
			{
				break;
			}
			sleep(0.1); //sleep for 100 milli sec... so that other threads will get locks..
			if(clock()-start > 8000000) //wait for 8 seconds for each packet...
			{			
				removePortFromList(srcPort); // we dont have to listen on this port again...
				isPacketRcvd=false;					
				break;			
			}
		}
		removePortFromList(srcPort); // we dont have to listen on this port again...
		if(isPacketRcvd==false)
		{
			continue;
		}
		if(isTcp)
		{
			//receive reply now..
			struct iphdr* ip = (struct iphdr *)(p.pointer+sizeof(struct ethhdr));
			unsigned short len = (unsigned short)ip->ihl*sizeof (uint32_t);	
			struct tcphdr *rcvdTcp = (struct tcphdr *)(p.pointer+sizeof(ethhdr)+len);	
			if(scanType == TCP_SYN)
			{
				if(rcvdTcp->ack==1 || rcvdTcp->syn==1)
				{
					r.state = OPEN;
				}
				else if(rcvdTcp->rst==1)
				{
					r.state = CLOSED;
				}	
				else
				{
					r.state = FILTERED;
				}
			}
			else if (scanType == TCP_ACK)
			{
				if(rcvdTcp->rst==1)
				{
					r.state = UNFILTERED;
				}
			}
			else
			{
				if(rcvdTcp->rst==1)
				{
					r.state = CLOSED;
				}	
			}			
		}
		else if(isIcmp)
		{
			struct iphdr* ip = (struct iphdr *)(p.pointer+sizeof(struct ethhdr));
			unsigned short len = (unsigned short)ip->ihl*sizeof (uint32_t);	
			struct icmphdr *icmpPacket=(struct icmphdr *)(p.pointer+sizeof(struct ethhdr)+len);
			unsigned short code = (unsigned short)icmpPacket->code;
			unsigned short type = (unsigned short)icmpPacket->type;
			if(type == 3 && (code == 1 || code == 2 ||code == 3 ||code == 9 ||code == 10 ||code == 13))
			{
				r.state = FILTERED;
			}
		}
		delete[] p.pointer;		
	}
	if(!isPacketRcvd)
	{
		if(scanType == TCP_ACK)
		{			
			r.state = FILTERED; // no packet received after several transmissions...		
		}
		else if(scanType == TCP_SYN)
		{
			r.state = FILTERED; // no packet received after several transmissions...		
		}
		else
		{
			r.state = OPEN_OR_FILTERED;
		}
	}
	addResult(r);	
}

void Core::SendUDPPacket(unsigned short srcPort, string dstIp, unsigned short dstPort)
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
	ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));  //as we dont have any application data..size here is size of udp + ip.
	ip.id = htons (0); //can we use this in a intelligent way ??? it is unused...
	ip.frag_off=0; // alll flags are 0, and the fragment offset is 0 for the first packet.
	ip.ttl = 0;
	ip.ttl = ~ip.ttl; //set it to all 1's
	ip.protocol = IPPROTO_UDP; //as transport layer protocol is udp..
    
	  // Source IPv4 address (32 bits)
	if (inet_pton (AF_INET, srcIp.c_str(), &(ip.saddr)) != 1 || inet_pton (AF_INET, dstIp.c_str(), &(ip.daddr)) != 1) 
	{
		HelperClass::TerminateApplication("inet_pton() failed!!");
	}
	ip.check=0; //init
    ip.check=computeHeaderCheckSum((uint16_t *) & ip, sizeof(struct iphdr)); //this is the last step..
    
    //lets create a udp packet now..
	struct udphdr udp;

  	udp.source = htons(srcPort);
	udp.dest = htons(dstPort);
	udp.len = htons(sizeof(udphdr));
  	udp.check=0;
	 		
	u_char* temp=new u_char[sizeof(udphdr)]; 
	memcpy(temp, &udp, sizeof(udphdr));
	
	// filling the udp.check value...
	udp.check=computeUDPHeaderCheckSum(ip,udp);
	//lets build the packet..
	u_char* packet = new u_char[sizeof(struct iphdr)+sizeof(struct udphdr)]; 
	memcpy(packet, &ip, sizeof(iphdr));
	memcpy(packet+sizeof(iphdr), &udp, sizeof(struct udphdr));
	
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
	if (sendto (sock, packet, sizeof(iphdr) + sizeof(udphdr), 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)
	{
		HelperClass::TerminateApplication("send() failed!!");
	}		
	
	//free resources///	
	delete[] temp;
	delete[] packet;		
	close (sock);// closing the socket.
}

void Core::PerformUDPScan(string dstIp, unsigned short dstPort, scanTypes_t scanType)
{
	//this is the start time..
	int count=0; //this is used for the number of retransmissions
	struct results r;
	bool isPacketRcvd=false;
	r.ip = dstIp;
	//store the port of the remote..
	r.port=dstPort;	

	//store the service name of the port.
	r.scanType = scanType; //set the scan type
	for(;count < MAX_RETRANSMISSIONS;count++)
	{
		unsigned short srcPort = 0;
		while(!addPortToList(srcPort)) //ensures that each thread listens on a new port...
		{	
			srcPort=rand()%64000;
		}
		//send a  packet.		
		SendUDPPacket(srcPort, dstIp, dstPort);		
		struct packet p;
		struct protoent *protocol;
		bool isIcmp = false;
		bool isUdp = false;
		unsigned int start = clock();
		while(1)
		{
			//loop till we get the message intended to us..
			p = readPacketFromList(srcPort);		
			if(p.pointer!=NULL)
			{
				struct iphdr* ip = (struct iphdr *)(p.pointer + sizeof(struct ethhdr));
				unsigned int proto=(unsigned int)ip->protocol;
				protocol=getprotobynumber(proto);				
				if(protocol!=NULL)
				{
					char* name=protocol->p_name;
					if(strcmp(name,"icmp")==0 )
					{
						isIcmp=true;
						isPacketRcvd=true;
						break;	
					}
					else if(strcmp(name,"udp")==0)
					{						
						unsigned short len = (unsigned short)ip->ihl*sizeof (uint32_t);	
						struct udphdr* udp= (struct udphdr*)(p.pointer + sizeof(ethhdr)+len);
						//check the source ip address of the packet and compare it with dstIp
						sockaddr_in s;
						memcpy(&s.sin_addr.s_addr, &ip->saddr, 4);
						//also check source port of the packet with dstPort
						if(ntohs(udp->source) == dstPort && (strcmp(inet_ntoa(s.sin_addr), dstIp.c_str()) ==0 ))
						{
							isUdp= true;
							isPacketRcvd=true;
							break;
						}			
					}
				}
			}
			if(isPacketRcvd)
			{
				break;
			}
			sleep(0.1); //sleep for 100 milli sec... so that other threads will get locks..
			if(clock()-start > 8000000) //wait for 8 seconds for each packet...
			{			
				removePortFromList(srcPort); // we dont have to listen on this port again...
				isPacketRcvd=false;					
				break;			
			}
		}
		removePortFromList(srcPort); // we dont have to listen on this port again...
		if(isPacketRcvd==false)
		{
			continue;
		}
		if(isUdp)
		{
			cout<<"port is open";						
		}
		else if(isIcmp)
		{
			struct iphdr* ip = (struct iphdr *)(p.pointer+sizeof(struct ethhdr));
			unsigned short len = (unsigned short)ip->ihl*sizeof (uint32_t);	
			struct icmphdr *icmpPacket=(struct icmphdr *)(p.pointer+sizeof(struct ethhdr)+len);
			unsigned short code = (unsigned short)icmpPacket->code;
			unsigned short type = (unsigned short)icmpPacket->type;
			if(type == 3 && code == 3 )
			{
				cout<<"port is closed\n";
			}
			else if(type == 3 && (code == 1||code== 2|| code==9|| code == 10|| code== 13))
			{
				cout<<"port is filtered\n";
			}
		}
		delete[] p.pointer;		
	}
	if(!isPacketRcvd)
	{
		cout<<"port is open|Filetered";
	}
	//addResult(r);	
}



void Core::addResult(struct results r)
{
	addResultsMutex.lock();
	map< struct combo, vector<struct results> >::iterator it=aggResults.begin();
	for(; it!=aggResults.end(); it++)
	{
		if(it->first.ip == r.ip && it->first.port == r.port)
		{
			break;
		}
	}
	
	it->second.push_back(r);	
	bool isComplete = false;
	for(unsigned int i=0; i < args.scanTypes.size();i++)
	{
		isComplete=false;
		for(unsigned int j=0; j < it->second.size();j++)
		{
			if(args.scanTypes[i]==it->second[j].scanType)
			{
				isComplete = true;
				break;
			}		
		}	
		if(!isComplete)
		{
			break;
		}
	}
	addResultsMutex.unlock();
	if(isComplete)
	{
		printResult(it->second);	
	}
}


void* Core::threadhelper(void *context)
{
    ((Core *)context)->readPacketOnPort();
	//exit the thread, as there is no work left to do..
	pthread_exit(NULL);
    return NULL;
}

void* Core::workhelper(void *context)
{
    ((Core *)context)->doWork();
	//exit the thread, as there is no work left to do..
	pthread_exit(NULL);
    return NULL;
}

struct packet Core::fetchPacketFromPort(unsigned short port)
{
	struct packet p; 
	p.pointer=NULL;
	lPortMutex.lock();
	map<unsigned short, vector<struct packet> >::iterator it=portMap.begin();
	while(it!=portMap.end())
	{
		if(it->first==port)
		{
			if(it->second.empty())
			{
				break;
			}
			p = it->second[0];	
			break;
		}
		it++;
	}
	lPortMutex.unlock();
	return p;
}

struct packet Core::readPacketFromList(unsigned short port)
{
	//we can safely remove the packet from the list after we are done.	
	struct packet p=fetchPacketFromPort(port);
	if(p.pointer==NULL)
	{
		return p;
	}	
	removePacketFromPort(port, p);
	return p;
}

void Core::printResult(vector<struct results> list)
{
	printMutex.lock();		
	
	cout<<"IP Address: "<<list[0].ip<<endl;
	
	unsigned short port = list[0].port;
	string serviceName = HelperClass::GetPortName(port);
	/*
	cout<<setw(20)<<r.serviceName<<"\t\t";
	cout<<setw(20)<<HelperClass::getScanTypeName(r.scanType)<<"\t\t";	
	if(r.state==OPEN)
	{
		cout<<setw(20)<<"open"<<endl;
	}
	else if(r.state==CLOSED)
	{
		cout<<setw(20)<<"closed"<<endl;		
	}	
	else if(r.state==FILTERED)
	{
		cout<<setw(20)<<"filtered"<<endl;
	}
	else if(r.state==UNFILTERED)
	{
		cout<<setw(20)<<"unfiltered"<<endl;
	}
	else if(r.state==OPEN_OR_FILTERED)
	{
		cout<<setw(20)<<"open | filtered"<<endl;
	}
	printMutex.unlock();
	*/
}

struct target Core::getWork()
{	
	struct target t;
	workMutex.lock();
	if(targets.empty())
	{
		//this means that all the work is done...
		t.scanType=MISC;
		workMutex.unlock();
	}
	else
	{
		//assign work to threads..
		t = targets[0];
		vector<target>::iterator it = targets.begin(); //remove the work allocated from the list of work..
		targets.erase(it);
	}		
	workMutex.unlock();
	return t;
}


void Core::doWork()
{
	while(1)
	{
		struct target t = getWork();
		if(t.scanType==MISC)
		{
			//exit the thread, as there is no work left to do..
			break;
		}
		else if(t.scanType == TCP_SYN)
		{
			PerformTCPScan(t.ip, t.port, TCP_SYN);
		}
		else if(t.scanType == TCP_NULL)
		{
			PerformTCPScan(t.ip, t.port, TCP_NULL);
		}
		else if(t.scanType == TCP_FIN)
		{
			PerformTCPScan(t.ip, t.port, TCP_FIN);
		}
		else if(t.scanType == TCP_XMAS)
		{
			PerformTCPScan(t.ip, t.port, TCP_XMAS);
		}
		else if(t.scanType == TCP_ACK)
		{
			PerformTCPScan(t.ip, t.port, TCP_ACK);
		}
		else if(t.scanType == UDP)
		{
			PerformUDPScan(t.ip, t.port, UDP);
		}	
	}
	//exit the thread, as there is no work left to do..
	pthread_exit(NULL);
}

void Core::Start()
{

	string dstIp="129.79.247.87"; //ip address of dagwood.soic.indiana.edu
	//string dstIp="8.8.8.8"; //ip address of dagwood.soic.indiana.edu
	shldPacketSnifferExit=false;
	//init the target list..
	
	for(unsigned int i=0;i<args.ipAddresses.size();i++)
	{
		for(unsigned  int j=0; j<args.portNumbers.size();j++)
		{
			for(unsigned  int k=0; k<args.scanTypes.size();k++)
			{
				struct target t;
				t.ip = args.ipAddresses[i];
				t.port= args.portNumbers[j];
				t.scanType = args.scanTypes[k];
				targets.push_back(t);
			}
		}
	}		
	pthread_t t;
	int retVal=pthread_create(&t, NULL, &Core::threadhelper, this);
	if(retVal!=0)
	{
		HelperClass::TerminateApplication("Unable to create the sniffer thread");
	}
	sleep(1); //wait for the pthread to start sniffing..
	
	cout<<"\n------------------------------------------------------------------------------------------------------------------------------\n";
	cout<<setw(20)<<"IP Address";
	cout<<setw(20)<<"Port";
	cout<<setw(20)<<"\tService Name\t";
	cout<<setw(20)<<"\t\tScan Type\t";
	cout<<setw(20)<<"\tStatus"<<endl;
	cout<<"------------------------------------------------------------------------------------------------------------------------------\n";
	
	pthread_t* threads = new pthread_t[args.numThreads];
	for(int i=0;i<args.numThreads;i++)
	{
		pthread_create(&threads[i], NULL, &Core::workhelper, this);
	}
	for(int i=0; i<args.numThreads; i++)
	{
		pthread_join(threads[i],NULL);
	}
	
	//TODO terminate the sniffer thread

	packetSnifferMutex.lock();
	shldPacketSnifferExit = true;
	packetSnifferMutex.unlock();
	
	retVal=pthread_join(t,NULL);		
	
	//clear all the resources..
	map<unsigned short, vector<struct packet> >::iterator it = portMap.begin();
	for(;it!=portMap.end();it++)
	{
		int size = it->second.size();
		for(int i=0;i<size;i++)
		{
			delete[] it->second[i].pointer;
		}
	}
		
	delete[] threads;
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

uint16_t Core::computeUDPHeaderCheckSum(struct iphdr ip,struct udphdr udp)
{	 
	unsigned int size=12;
	unsigned int udpHdrSize= sizeof(udphdr);
	unsigned int segSize= udpHdrSize;
	u_char* t=new u_char[size+segSize];
	memcpy(t, &ip.saddr, 4);
	memcpy(t+4, &ip.daddr, 4);
	t[8]=0;
	t[9]=IPPROTO_UDP;

	unsigned short segmentSize=htons(segSize);

	memcpy(t+10, &segmentSize, 2);
	memcpy(t+size, &udp,udpHdrSize);
	
	//The checksum field is the 16-bit one's complement of the one's complement sum of all 16-bit words in the header.  (source -WIKIPEDIA)
	uint16_t checkSum = computeHeaderCheckSum((uint16_t*)t, size+segSize);
	delete[] t; //free memory..
	return checkSum;
}

