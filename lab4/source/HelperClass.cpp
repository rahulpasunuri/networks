#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/sha.h>// need to add -lssl to compile
#include <string>
#include<iostream>
#include<fstream>
#include<string>
#include "../include/HelperClass.h"
using namespace std;

void HelperClass::TerminateApplication(string text)
{
	cout<<text<<endl<<"Terminating Application!!"<<endl;
	exit(1);
	return;
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
	//TODO
	return true;
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
