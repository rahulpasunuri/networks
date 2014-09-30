#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include "../include/Peer.h"
#include <openssl/sha.h> //hashing pieces

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include<iostream>
#include <thread>
using namespace std;


//code from client.cpp
//establishes connection to a peer and sends the file to it.
void Peer::sendPacket(co_peer_t* leecher)
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


void Peer::sendString(co_peer_t* leecher, int sock,string message,const char * digest,string fileName="")
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



/**code from server.cpp
*/

using namespace std;

Peer::Peer(bt_args_t input)
{		
	//intitialize the local address..		
	//zero - out all entries of client...
	verboseMode=input.verboseMode;
    localAddress=input.destaddr;
    //cout<<localAddress<<endl;
	//Any incoming interface
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		HelperClass::TerminateApplication("Socket Creation Failed!!");
	}
	if(verboseMode)
	{
		cout<<"\nSocket Creation Successfull!!"<<endl;
	}
	
	//bind to a port...
	bindToAPort();
	if(verboseMode)
	{
		cout<<"\nBinding to Port Successfull!!"<<endl;
	}
	
	thread serverThread(&Peer::startServer,this);
	serverThread.join();		
}

int Peer::getPortNumber()
{
	return portNumber;
}

void  Peer::bindToAPort()
{
	int port = (int)INIT_PORT;
	bool isBindingDone=false;
	while(port<=(int)MAX_PORT)
	{
    	localAddress.sin_port=htons(port);		  
		if(this->verboseMode)
		{
			cout<<"Trying Port: "<<port<<endl;
		}			

		if ((::bind(sock, (struct sockaddr*) &localAddress, sizeof(localAddress)))>=0)
		{
			isBindingDone=true;
			break;
		}	
		port++;
	}
	if(isBindingDone==false)
	{
		HelperClass::TerminateApplication("Binding Failed!!");
	}
	this->portNumber=port;
}

void Peer::startServer()
{
	// Mark the socket so it will listen for incoming connections
	if (listen(sock, MAXPENDING) < 0)
	{
		HelperClass::TerminateApplication("Listen Failed!!");
	}	

	for (;;) 
	{ 	// Run forever
		struct sockaddr_in clntAddr; // Client address
		// Set length of client address structure (in-out parameter)
		socklen_t clntAddrLen = sizeof(clntAddr);
		// Wait for a client to connect
		int clntSock = accept(sock, (struct sockaddr *) &clntAddr, &clntAddrLen);
		if (clntSock < 0)
		{
			HelperClass::TerminateApplication("Accept Failed!!");
		}
		if(verboseMode)
		{
			cout<<"\nConnection request accepted!!"<<endl;		
		}
		// clntSock is connected to a client!
		char clntName[INET_ADDRSTRLEN]; // String to contain client address
		if (inet_ntop(AF_INET, &clntAddr.sin_addr.s_addr, clntName, sizeof(clntName)) != NULL)
		{
			if(verboseMode)
			{
				cout<<"\nStarted handling the TCP client."<<endl;	
			}
			handleTCPClient(clntSock);
		}
		else
		{
			cout<<"\nUnable to determine Client Address\n";
		}
	 }
}

void Peer::handlePacket(string packetContents)
{
    //parse the packet...
    string fileName="savedFile"; //TODO -- take file name from torrent file...
  
  	//TODO
    //string computedDigest=HelperClass::GetDigest(packetContents);
    //cout<<"\nPrinting Packet Contents"<<packetContents<<endl;
    cout<<"Length of the message is"<<packetContents.length();
    
    //compare clients digest with computed digest...
    //TODO
    /*
    if(digest!=computedDigest)
    {
        HelperClass::TerminateApplication("\nDigest doesn't match. Packet has been modified in between.");
    }
	*/
	
    FileObject fp(fileName.c_str(),0,0,false);
	if(verboseMode)
	{
        cout<<"\nFile Name : "<<fileName<<endl;	       
	    cout<<"Writing to File:"<<endl;
	}
    	
    fp.Append(packetContents);    
}


//TODO
/*
void Server::parsePacket(string packetContents,string &fileName,string &body,string &digest)
{
    int startFileTag=packetContents.find(STARTFILENAMETAG);
    int startBodyTag=packetContents.find(STARTBODYTAG);

    if(startFileTag<0)
    {
        //packet has no file name...save it in a default file name "output.txt"
        cout<<"assigning a default filename\n";
        fileName="output.txt";
    }
    else
    {
        int endFileTag=packetContents.find(ENDFILENAMETAG);
        fileName=packetContents.substr(startFileTag,endFileTag-startFileTag);
        fileName.replace(0,STARTFILENAMETAG.length(),"");                        
    }
    
    int endBodyTag=packetContents.rfind(ENDBODYTAG);
    body=packetContents.substr(startBodyTag,endBodyTag-startBodyTag);
    body.replace(0,STARTBODYTAG.length(),"");
    
    int startDigestTag=packetContents.find(STARTDIGESTTAG);
    int endDigestTag=packetContents.rfind(ENDDIGESTTAG);
    digest=packetContents.substr(startDigestTag,endDigestTag-startDigestTag);
    digest.replace(0,STARTDIGESTTAG.length(),"");
            
}
*/

void Peer:: handleTCPClient(int clntSocket) 
{
	char buffer[BUFSIZE]; // Buffer for echo string
	// Receive message from client
    string packet="";
	ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
	if (numBytesRcvd < 0)
	{
		HelperClass::TerminateApplication("recv() failed!!");
	}
	
	while (numBytesRcvd > 0)
	{ 	// 0 indicates end of stream
        //        buffer[numBytesRcvd]='\0';     
        packet.append(buffer,numBytesRcvd);           

		// See if there is more data to receive
		numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);		

	} 
	cout<<"length of the packet is "<<packet.length();
	handlePacket(packet);					
	cout<<endl;
	if(verboseMode)
	{
		cout<<"\nClosing the connection with the client!";	
	}
	if(close(clntSocket)<0) // Close client socket
	{
		HelperClass::TerminateApplication("Some error happened while closing the socket!!");
	}
	if(verboseMode)
	{
		cout<<"\nConnection Closed Succesfully with the client!";	
	}
	
	//here.. the file objects destuctor gets called..
}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void Peer::print_peer()
{
	int i;

	//TODO
	//printf("peer: %s:%u ", inet_ntoa(this->sockaddr.sin_addr), this->getPortNumber());
	printf("id: ");
	for(i=0;i<ID_SIZE;i++)
	{
		printf("%02x",this->id[i]);
	}
	printf("\n");	  
}



