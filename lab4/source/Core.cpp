#include "../include/Core.h"

//constructor of core..
Core::Core(args_t)
{
	this->args=args;
}	

void Core::SendSinPacket(unsigned int dstPort= 22)
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
    //ip.check=~0;
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
	
	
	//free resources///	
	delete[] temp;
	delete[] packet;		
	close (sock);// closing the socket.
}

void Core::PerformSynScan(string dstIp, port dstPort)
{
	//receive reply now..
	const u_char *rcvdPacket;

	rcvdPacket = readPacketOnPort(srcPort);
	struct tcphdr *rcvdTcp = (struct tcphdr *)(rcvdPacket+sizeof(ethhdr)+sizeof(iphdr));
	
	if(rcvdTcp->rst==1)
	{
		cout<<"Port "<<dstPort<<" is closed"<<endl;		
	}
	else if(rcvdTcp->ack==1 || rcvdTcp->sin==1)
	{
		cout<<"Port "<<dstPort<<" is open"<<endl;
	}
	else
	{
		cout<<"Port "<<dstPort<<" is filtered"<<endl;
	}	
	
}

