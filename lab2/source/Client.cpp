#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include<fstream>
#include <string>
#include <openssl/hmac.h>
//include custom header files...
#include "../include/Client.h"
#include "../include/FileObject.h"
using namespace std;

Client::Client(bt_args_t args)
{
	this->verboseMode=args.verboseMode;
}

//establishes connection to a peer and sends the file to it.
void Client::sendPacket(co_peer_t* leecher)
{		
		if(leecher==NULL)
		{
			HelperClass::TerminateApplication("No leecher specified to send the file.");
		}	

		sockaddr_in destinationAddress=leecher->sockaddr;		
		// SOCKET creation.....
	 	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (sock < 0)
		{
			HelperClass::TerminateApplication("Socket Creation Failed!!");
		}

		if(verboseMode)
		{
			cout<<"Socket Creation Successfull!!"<<endl;
		}
		
		// connecting socket to the server    
		if (connect(sock, (struct sockaddr *) &destinationAddress, sizeof(destinationAddress)) < 0)
		{      
			HelperClass::TerminateApplication("connect() failed");
		}
	    
		if(verboseMode)
		{
			cout<<"Connection established successfully"<<endl;
		}
    	        
    	string fileName="input"; //TODO

		ifstream file (fileName.c_str(),ios::in|ios::ate);
		string s="";
		if (file.is_open())
		{
			int size = file.tellg();
			cout<<"Printing file size"<<size<<"\n";
			char* memblock = new char [size+1];
			file.seekg (0, ios::beg);
			file.read (memblock, size);
			memblock[size]='\0';

			s.append(memblock,size);
			cout<<"length of string s is "<<s.length()<<"\n";               
			file.close();        
			cout << "the entire file content is in memory"<<endl;

			delete[] memblock;
		}
		else
		{
			 HelperClass::TerminateApplication("Unable to open file");
		}
		
		cout<<"before sending"<<endl;		
		sendString(leecher, sock, s ,HelperClass::GetDigest(s), fileName);	       // sending loaded buffer with file name into the string...
		close(sock);	
}


void Client::sendString(co_peer_t* leecher, int sock,string message,const char * digest,string fileName="")
{         
		if(leecher==NULL)
		{
			HelperClass::TerminateApplication("Error in Send String. leecher doesn't exist");
		}
        string d(digest);       

		//TODO -- send digest as well(??? is it necessary).
        if(verboseMode)
        {
            //cout<<"Packet to be sent is:\n"<<MSG<<endl;
        }    
        int messageLen = message.length(); // determining the length of the string....
        cout<<"Length of the packet is "<<messageLen;
        ssize_t msgDesc = send(sock, message.data(), messageLen, 0);

        if(msgDesc < 1)
        {
            HelperClass::TerminateApplication("send() failed");
        }
        else if(msgDesc != messageLen)
        {
            HelperClass::TerminateApplication("send() failed due to incorrect no. of bytes");
        }
	
	    if(verboseMode)
	    {
	        cout<<"message sent successfully"<<endl;
	    }	

} 
