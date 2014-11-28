#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
//#include <openssl/sha.h>// need to add -lssl to compile
#include <string>
#include<iostream>
#include<fstream>
#include<string>
#include "../include/HelperClass.h"
#include<map>

using namespace std;

void HelperClass::TerminateApplication(string text)
{
	cout<<text<<endl<<"Terminating Application!!"<<endl;
	exit(1);
	return;
}

const char* HelperClass::getPortTypeName(portState inp)
{
	if(inp == OPEN)
	{
		return "OPEN";
	}
	else if(inp==CLOSED)
	{
		return "CLOSED";
	}
		else if(inp==FILTERED)
	{
		return "FILTERED";
	}
	else if(inp==UNFILTERED)
	{
		return "UNFILTERED";
	}
	else if(inp==OPEN_OR_FILTERED)
	{
		return "OPEN_OR_FILTERED";
	}
	return "MISC_PORT_STATE";
}

unsigned short HelperClass::getSourcePortForICMP(const u_char* packet)
{
	unsigned short port;
	struct iphdr* ip = (struct iphdr *)(packet+sizeof(struct ethhdr));
	unsigned short len = (unsigned short)ip->ihl*sizeof (uint32_t);
	const u_char* p = packet + sizeof(ethhdr) + len + sizeof(icmphdr) + sizeof(iphdr); // ip hdr is encapsulated within icmp header..
	memcpy(&port, p, 2); //read the source port..
	return ntohs(port);
}

const char* HelperClass::getScanTypeName(scanTypes_t inp)
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

string HelperClass::srcIp="";

bool HelperClass::isValidPortNumber(int portNum)
{
	if(portNum>65535 || portNum<1)
	{		
		return false;
	}
	else return true;
}

bool HelperClass::isNumber(string s)
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

bool HelperClass::isValidIpAddress(string ip)
{
	struct sockaddr_in sa;
	int retVal=inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
	if(retVal>0)
	{
		return true;
	}
	return false;
}

scanTypes_t HelperClass::getScanTypeId(string s)
{
	if(s=="SYN")
	{
		return TCP_SYN;
	}
	if(s=="NULL")
	{
		return TCP_NULL;
	}
	if(s=="FIN")
	{
		return TCP_FIN;
	}
	if(s=="XMAS")
	{
		return TCP_XMAS;
	}
	if(s=="ACK")
	{
		return TCP_ACK;
	}
	if(s=="UDP")
	 return UDP;
	HelperClass::TerminateApplication("Unknown scan Type"+ s);
	return UDP;//to make the compiler happy
}

bool HelperClass::CheckIfFileExists(const char* fileName)
{
	ifstream f(fileName);
	if (f.good()) 
	{
		//file exists...
		f.close();
		return true;
	} 
	else 
	{
		//file doesnt exist...
		f.close();
		return false;
	}
}

string HelperClass::GetPortName(unsigned short port)
{
	if(port<1 || port>1024) //we search for port numbers only in this range...
	{
		return "Unassigned";
	}
	const char* fileName="resources/service-names-port-numbers.csv";
	if(!CheckIfFileExists(fileName))
	{
		HelperClass::TerminateApplication("The port numbers file in resources doesnt exist");
	}
	ifstream file (fileName); 
	string value;	
	getline(file, value); //ignore the first line..(has headers in them)
	while (getline(file, value))
	{
		int index=value.find(',');
		if(index<0)
		{
			return "Unassigned";
		}
		
		string serviceName=value.substr(0,index);
		value=value.substr(index+1);
		index=value.find(',');
		if(index<0)
		{
			return "Unassigned";
		}
		string portChar=value.substr(0,index);
		unsigned short portNum = atoi(portChar.c_str());
		if(portNum==port)
		{
			return serviceName;
		}
	}	
	return "Unassigned";
}

Mutex::Mutex()
{
	pthread_mutex_init(&m, NULL); //init the mutex
}
void Mutex::lock()
{
	pthread_mutex_lock(&m);
}
void Mutex::unlock()
{
	pthread_mutex_unlock(&m);
}


