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

#include<mutex>
#include <thread>
using namespace std;

Peer::Peer()
{
//empty constructor...
//does nothing..
}

//this is used by a client to know, if it recieved the entire file...
bool Peer::hasFile()
{
	for(int i=0;i<bt_args.bt_info->num_pieces;i++)
	{
		mutexHasPieces.lock();
		if(hasPieces[i]==false)
		{
			mutexHasPieces.unlock();
			return false;
		}
		mutexHasPieces.unlock();
	}
	return true;	
}

int Peer::requestPiece()
{	
	mutexRequestPieces.lock();	
	int i=-1;
	try
	{
		if(!hasFile())
		{
			mutexRequestPieces.unlock();	
			return i;		
		}
		i=rand()%bt_args.bt_info->num_pieces;

		while(hasPieces[i]==true)
		{
			i=rand()%bt_args.bt_info->num_pieces;
		}		
		mutexHasPieces.lock();
		hasPieces[i]=true;
		mutexHasPieces.unlock();
	}
	catch(...)
	{
		mutexRequestPieces.unlock();	
		HelperClass::TerminateApplication("Error in choosing a piece");
	}	
	mutexRequestPieces.unlock();	
	return i;
}


void Peer::sendHandshakeReq(int sock, char* cli_id)
{
	char handshake[HAND_SHAKE_BUFSIZE];

	for(int i=0;i<HAND_SHAKE_BUFSIZE;i++) // Reserved bytes
	{
		handshake[i]=-1;
	}   

	handshake[0] = this->prefix;
	for(int i=0;i<this->reserved_offset-1;i++) 
	{
		handshake[i+1]=this->BitTorrent_protocol[i];
	}

	for(int i=this->reserved_offset;i<this->info_hash_offset;i++) // Reserved bytes
	{
		handshake[i]=0;
	}   

	memcpy(&handshake[this->info_hash_offset],bt_args.bt_info->infoHash ,this->peer_id_offset-this->info_hash_offset); //storing infohash into buffer
		
	memcpy(&handshake[this->peer_id_offset],cli_id, HAND_SHAKE_BUFSIZE-this->peer_id_offset); // storing peer_id into buffe
	
	 //to send handshake buffer over TCP using int sock.....
	 send(sock,handshake,HAND_SHAKE_BUFSIZE, 0); //;
	
	return;
}

//code from client.cpp
//establishes connection to a peer and sends the file to it.
void Peer::sendPacket(co_peer_t* leecher=NULL)
{	

	struct sockaddr_in adr_inet;
        socklen_t len_inet = sizeof(adr_inet);  /* length */  
	if(this->verboseMode)
	{
		cout<<"Client Started"<<endl;	
	}
	
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

	// HERE WE ARE EXTRACTING THE IP AND PORT TO WHICH THE PEER(OUR CLIENT) IS CONNECTED TO!
	if(getsockname(sock, (struct sockaddr *)&adr_inet, &len_inet)<0)  	
	{
		HelperClass::TerminateApplication("Unable to determine peer's local IP to which it is binded");
	}
	else
	{
		cout<<"IP address saved successfully"<<endl;
	}
	
	char *cli_id = new char[(int)ID_SIZE]; 
	HelperClass::calc_id(inet_ntoa(adr_inet.sin_addr),(unsigned)ntohs(adr_inet.sin_port),cli_id);          
	string packet="";
	char buffer[BUFSIZE]; // Buffer for echo string
	// hand shake protocol must take place here before file data is exchanged....
	if(leecher->isHandShakeDone==false)            
	{    	
		cout<<"Hand shake started";
		sendHandshakeReq(sock, cli_id);
		//free memory
		delete[] cli_id;
		// RECIEVING HAND SHAKE RESPONSE FROM PEER...
        usleep(100);
		ssize_t numBytesRcvd = recv(sock, buffer, BUFSIZE, 0);  int num=numBytesRcvd;
		if (numBytesRcvd < 0)
		{
			HelperClass::TerminateApplication("recv() failed!!");
		}
	
		while (num<=HAND_SHAKE_BUFSIZE)
		{
		 	// 0 indicates end of stream
			//        buffer[numBytesRcvd]='\0';     
			packet.append(buffer,numBytesRcvd);           
			num+=numBytesRcvd;
			// See if there is more data to receive
			numBytesRcvd = recv(sock, buffer, BUFSIZE, 0);		
		}
		if(packet!="")
		{
		    recvHandShakeResp(packet, (char*)leecher->id); 			
		}
		else
		HelperClass::TerminateApplication("RECEIVED EMPTY BUFFER FROM PEER");  
	}
	
	// #########........RECEIVING FILE FROM THE SERVER..................############
    ssize_t numBytesRcvd = recv(sock, buffer, BUFSIZE, 0);
	if (numBytesRcvd < 0)
	{
		HelperClass::TerminateApplication("recv() failed!! while downloading file");
	}

	while (numBytesRcvd > 0)
	{ 	// 0 indicates end of stream
        //        buffer[numBytesRcvd]='\0';     
        packet.append(buffer,numBytesRcvd);           

		// See if there is more data to receive
		numBytesRcvd = recv(sock, buffer, BUFSIZE, 0);		

	} 
	handlePacket(packet);		// SENDING THE FILE DATA RECEIVED FOR PARSING....	
	close(sock);	
}	

void Peer::handlePacket(string packetContents)
{  
    //parse the packet...
    string fileName=this->bt_info->name;
    FileObject fp(fileName.c_str(),0,0,false);
	if(verboseMode)
	{
        cout<<"\nFile Name : "<<fileName<<endl;	       
	    cout<<"Writing to File:"<<endl;
	}
    	
    fp.Append(packetContents);    
}


					
/**code from server.cpp
*/

void Peer::init(bt_args_t input)
{		
	//intitialize the local address..		
	//zero - out all entries of client...
	verboseMode=input.verboseMode;
	localAddress=input.destaddr;
	bt_args=input;
	this->bt_info=bt_args.bt_info;
		
	if(input.isSeeder==true)
	{
		
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
	else
	{   
		thread clientThread(&Peer::startClient,this);
		clientThread.join();
	}
	isInit=true;		
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
//#################.......SERVER STARTS HERE.......#####################################
void Peer::startServer()
{    
	if(this->verboseMode)
	{	 
    	cout<<"Server started"<<endl;
    }
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
			
			new thread(&Peer::handleTCPClient,this,clntSock,&clntAddr);		
		}
		else
		{
			HelperClass::TerminateApplication("\nUnable to determine Client Address");
		}
	 }
}


void Peer::sendString(co_peer_t* leecher, int sock, string message)
{         
	if(leecher==NULL)
	{
		HelperClass::TerminateApplication("Error in Send String. leecher doesn't exist");
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
	return;

} 

void Peer:: handleTCPClient(int clntSocket,struct sockaddr_in *clntAddr) 
{
	//create a new coPeer for this leecher..
	co_peer_t * leecher;
	leecher=(co_peer_t *) malloc(sizeof(co_peer_t));
	leecher->sockaddr=(*clntAddr);
	
	//add it to the list of peers for server...
	mutexConnectedPeers.lock();
	try
	{
		if(this->bt_args.n_peers>=(int)MAX_CONNECTIONS)
		{
			HelperClass::TerminateApplication("Upper bound on max connections violated!!");
		}
		
		this->bt_args.connectedPeers[this->bt_args.n_peers] = leecher;
		this->bt_args.n_peers++;			
	}
	catch(...)
	{	
		mutexConnectedPeers.unlock();
		HelperClass::TerminateApplication("Error updating the connected peers list");
	}
	mutexConnectedPeers.unlock();

	char buffer[BUFSIZE]; // Buffer for echo string
	// Receive message from client
    string packet="";
	ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);  int num=numBytesRcvd;
	if (numBytesRcvd < 0)
	{
		HelperClass::TerminateApplication("recv() failed!!");
	}

	
	if(leecher->isHandShakeDone==false)  //  INITIATING THE HAND SHAKE PROTOCOL....
	{   
		while (num<=HAND_SHAKE_BUFSIZE)
		{
		 	// 0 indicates end of stream
			//        buffer[numBytesRcvd]='\0';     
			packet.append(buffer,numBytesRcvd);           
			num+=numBytesRcvd;
			// See if there is more data to receive
			numBytesRcvd = recv(sock, buffer, BUFSIZE, 0);		
		}
        if(packet!="")
		{ 	
			if(this->verboseMode)
			{					 
				cout<<"...Handshake in process..."<<endl;
			}
			   	
			char * id = new char[ID_SIZE+1];
			char * id1 = inet_ntoa(leecher->sockaddr.sin_addr);
			cout<<inet_ntoa(leecher->sockaddr.sin_addr);		   
			unsigned short portNumber=(unsigned)ntohs(leecher->sockaddr.sin_port);
			HelperClass::calc_id(id1,portNumber,id);
		
			recvHandShakeResp(packet, id);

			char *cli_id1 = new char[(int)ID_SIZE]; // calculating the ip and port of the leecher....
			HelperClass::calc_id((string("127.0.0.1")).c_str(),(unsigned)ntohs(localAddress.sin_port),cli_id1);
			cout<<inet_ntoa(localAddress.sin_addr);
			// INITIATING HANDSHAKE 2
			sendHandshakeReq(clntSocket, cli_id1);
				       
			leecher->isHandShakeDone=true;
			delete [] id;
			delete [] cli_id1;
			if(this->verboseMode)
			{
				cout<<"Handshake successful at peer"<<endl;
			}
			leecher->isHandShakeDone= true;
			   		   		   
		}   
   		else
		{
			 HelperClass::TerminateApplication("...NO DATA RECEIVED FROM PEER...");
		}
	}
	string fileName=this->bt_info->name;     // Assigning te file name
	cout<<fileName<<"\n"; 

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
	sendString(leecher, clntSocket, s);
   	// sending loaded buffer with file name into the string...**/
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



void Peer::startClient()
{
	if(bt_args.n_peers<=0 || bt_args.n_peers>MAX_CONNECTIONS )
	{
		HelperClass::TerminateApplication("INVALID NO OF SEEDERS SPECIFIED");
	}
	else
	{
		//init arguments...		
		hasPieces=new bool[bt_args.bt_info->num_pieces];
		for(int i=0;i<bt_args.bt_info->num_pieces;i++)
		{
			hasPieces[i]=false;
		}
		
		for(int i=0; i<bt_args.n_peers;i++)
		{		 		
		 	sendPacket(bt_args.connectedPeers[i]);
		}
    }
}






void Peer::recvHandShakeResp(string packet,char* id)
{
	int i; 
	for(i=0;i<this->protocol_name_offset;i++)		
	{    
		 if(packet[i]!=19)
		 {
			   HelperClass::TerminateApplication("1st offset value did not match");
		 }
		 else if(this->verboseMode)
		 {
		 	cout<<"Handshake  stage cleared"<<endl;
		 }
	}
	for(i=0;i<this->reserved_offset-1;i++)
	{
		if(packet[i+1]!=this->BitTorrent_protocol[i])
		{
			 HelperClass::TerminateApplication("Handshake terminated because strings did not match!!!");
		}
	
	
	}
	if(this->verboseMode)
	{		
		cout<<"Handshake 1st stage cleared on peer side"<<endl;
	}  
	for(i=this->reserved_offset;i<this->info_hash_offset;i++)
	{
		if(packet[i]!=0)
		{
			 HelperClass::TerminateApplication("Handshake error");
		}
	   
	}
	if(this->verboseMode)
	{	
		cout<<" 2nd stage Handshake Completed"<<endl;
	}
	
	for(i=0;i<ID_SIZE;i++)
	{
		if(packet[i+this->info_hash_offset]!=bt_info->infoHash[i])
		{
			 HelperClass::TerminateApplication("Handshake 3rd part error");
		}
	   
	}
	if(this->verboseMode)
	{ 
		cout<<"Handshake 3rd part completed"<<'\n';
	}

	for(i=0;i<ID_SIZE;i++)
	{
	   if(id[i]!=packet[this->peer_id_offset+i])
	   {
		  //free memory of id.   		
		  cout<<"\nPeer ids not matched\n";
		  break;			 	 
		  //HelperClass::TerminateApplication("PeerID'S not matched");
	   }
	}
	if(this->verboseMode)
	{
		cout<<"PeerIDs got matched"<<endl;   
	}

	return;
}


Peer::~Peer()
{
	if(isInit)
	{
		delete[] hasPieces;
		//free all memories...
		for(int i=0; i< MAX_CONNECTIONS;i++)
		{
			free(this->bt_args.connectedPeers[i]);
		}
		//delete[] this->bt_args.connectedPeers[MAX_CONNECTIONS];			
		delete[] this->bt_args.bt_info->infoHash;
		//de-allocate piece hashes...
		for(int i=0;i<this->bt_args.bt_info->num_pieces;i++)
		{
			delete[] this->bt_args.bt_info->piece_hashes[i];	
		}
		delete[] this->bt_args.bt_info->piece_hashes;
		delete this->bt_args.bt_info;
	}
}
