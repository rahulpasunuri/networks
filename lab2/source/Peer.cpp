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
#include <unistd.h>
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

void Peer::setHasPiece(int index)
{
	mutexHasPieces.lock();
	hasPieces[index]=true;
	mutexHasPieces.unlock();
}

void Peer::unSetRequestedPieces(int index)
{
	mutexHasPieces.lock();
	requestedPieces[index]=false;
	mutexHasPieces.unlock();
}

int Peer::requestPieceIndex()
{	
	mutexRequestPieces.lock();	
	int i=-1;
	try
	{
		if(hasFile())
		{
			mutexRequestPieces.unlock();	
			return i;		
		}
		i=rand()%bt_args.bt_info->num_pieces;

		mutexHasPieces.lock();
		while(hasPieces[i]==true && requestedPieces[i]==false) //find a piece which is not present and not in progress.
		{
			i=rand()%bt_args.bt_info->num_pieces;
		}		
		requestedPieces[i]=true;
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

void Peer::requestPiece(co_peer_t* seeder)
{
	FILE *instream = fdopen(seeder->sock, "r+b");		
	
	//recieve unchoke message...
	bt_msg_t unchoke;
	readBtMsg(unchoke,instream);
	unchoke.bt_type=ntohl(unchoke.bt_type);
	
	if(verboseMode)
	{
		cout<<"Unchoke Message Recieved";
	}
	
	//receive bit field message...
	bt_msg_t bitReply;
	readBtMsg(bitReply, instream);
	
	bitReply.bt_type=ntohs(bitReply.bt_type);
	if(bitReply.bt_type!=BT_BITFILED)
	{
		HelperClass::TerminateApplication("Did not receive the bit message");
	}
	if(verboseMode)
	{
		cout<<"Bit Message Received\n";
	}
	
	//send the bit field message...
	bt_msg_t bitField;
	bitField.bt_type=htons(BT_BITFILED);
	bitField.payload.bitfiled.size=htons(bt_args.bt_info->num_pieces);	
	bitField.payload.bitfiled.bitfield = new char[bt_args.bt_info->num_pieces];
	for(int i=0;i<bt_args.bt_info->num_pieces;i++)
	{
		bitField.payload.bitfiled.bitfield[i]='1';
	}	
	if (send(seeder->sock, &bitField, sizeof(bitField), 0) != sizeof(bitField))
	{
		delete[] bitField.payload.bitfiled.bitfield;
		HelperClass::TerminateApplication("Piece Message send Failed");
	}	
	delete[] bitField.payload.bitfiled.bitfield;	
	if(verboseMode)
	{
		cout<<"Bit Field Message Sent\n";
	}
	
	while(!hasFile())
	{
		
		int numBytesRcvd=0;
		int index=requestPieceIndex();
		int offset=(bt_args.bt_info->piece_length)*index;
		while(numBytesRcvd<bt_args.bt_info->piece_length)
		{
			int packetLength=0;
			if((bt_args.bt_info->piece_length-numBytesRcvd) >=MAXBLOCKLEN)
			{
				packetLength=MAXBLOCKLEN;
			}
			else
			{
				packetLength=bt_args.bt_info->piece_length-numBytesRcvd;
			}
			if(this->verboseMode)
			{
				cout<<"Sending Request Message"<<endl;
			}		
			
			//construct the request message here..
			bt_msg_t request;
			memset(&request,0,sizeof(request));
			//convert the things into network format...
			request.bt_type = htons(BT_REQUEST);
			request.payload.request.index=htons(index); //set the piece index;;
			request.payload.request.begin=htonl(offset);
			request.payload.request.length=htonl(packetLength);			
			
			//sending the request message...
			if (send(seeder->sock, &request, sizeof(request), 0) != sizeof(request))
			{		
				HelperClass::TerminateApplication("Piece Message send Failed");
			}	
			if(this->verboseMode)
			{
				cout<<"Request Message Sent"<<endl;
			}
		
			bt_msg_t reply;
			//read the message;;;;			
			readBtMsg(reply, instream);					
			reply.bt_type = ntohl(request.bt_type);
			reply.payload.piece.index=ntohl(reply.payload.piece.index);
			reply.payload.piece.begin=ntohl(reply.payload.piece.begin);
			reply.payload.piece.length=ntohl(reply.payload.piece.length);
			if(reply.payload.piece.length==0)
			{
				break; //last piece is available...
			}

			//write the partial content into file
			FileObject::WritePartialFile(offset,reply.payload.piece.length,reply.payload.piece.data,"alpha.mp3");						
			//update parameters...
			offset+=reply.payload.piece.length;
			numBytesRcvd+=reply.payload.piece.length;

		}
		//TODO -- match hash vallues of the piece
		
		setHasPiece(index); //here we have the piece..		
		
		//send have message to all seeders...
		if(verboseMode)
		{
			cout<<"Sending Have Messages to Peers"<<endl;
		}		
		mutexConnectedPeers.lock();
		bt_msg_t haveMsg;
		haveMsg.bt_type=(int)BT_HAVE;		
		for(int i=0;i<MAX_CONNECTIONS;i++)
		{		
			if(bt_args.connectedPeers[i]!=NULL)
			{					
				HelperClass::Log("Sending Have message to", bt_args.connectedPeers[i]);
				if (send(bt_args.connectedPeers[i]->sock, &haveMsg, sizeof(haveMsg), 0) != sizeof(haveMsg))
				{		
					HelperClass::TerminateApplication("Piece Message send Failed");
				}		
			}
		}
		
		mutexConnectedPeers.unlock();
	}
	//cout<<"Total Bytes Received is "<<totalBytes<<endl;	
	//we have the entire file now...so send a cancel message...
	bt_msg_t request;
	//convert the things into network format...
	request.bt_type = htons(BT_CANCEL);
	//sending the request message...
	//fclose(instream);
	//free(instream);
	if (send(seeder->sock, &request, sizeof(request), 0) != sizeof(request))
	{
		HelperClass::TerminateApplication("Cancel Message Send Failed");
	}
	
	if(this->verboseMode)
	{
		cout<<"Cancel Message Sent"<<endl;
	}
}


void Peer::sendHandshakeReq(int sock, char* cli_id)
{
	char handshake[HAND_SHAKE_BUFSIZE];

	for(int i=0;i<HAND_SHAKE_BUFSIZE;i++) // Reserved bytes
	{
		handshake[i]=-1;
	}   

	handshake[0] = prefix;
	for(int i=0;i<reserved_offset-1;i++) 
	{
		handshake[i+1]=BitTorrent_protocol[i];
	}

	for(int i=reserved_offset;i<info_hash_offset;i++) // Reserved bytes
	{
		handshake[i]=0;
	}   

	memcpy(&handshake[info_hash_offset],bt_args.bt_info->infoHash ,peer_id_offset-info_hash_offset); //storing infohash into buffer
		
	memcpy(&handshake[peer_id_offset],cli_id, HAND_SHAKE_BUFSIZE-peer_id_offset); // storing peer_id into buffe
	
	 //to send handshake buffer over TCP using int sock.....
	send(sock,handshake,HAND_SHAKE_BUFSIZE, 0); //;
	if(verboseMode)
	{
		cout<<"Message Sent Succesfull\n";
	}
	return;
}

//code from client.cpp
void Peer::SendConnectionRequests(co_peer_t* seeder=NULL)
{	

	struct sockaddr_in adr_inet;
    socklen_t len_inet = sizeof(adr_inet);  /* length */  
	if(this->verboseMode)
	{
		cout<<"Client Started"<<endl;	
	}
	
	if(seeder==NULL)
	{
		HelperClass::TerminateApplication("No seeder specified");
	}	

	sockaddr_in destinationAddress=seeder->sockaddr;
			
	// SOCKET creation.....
 	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    seeder->sock=sock;
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
	if(this->verboseMode)
	{
		cout<<"IP address saved successfully"<<endl;
	}
	
	char *cli_id = new char[(int)ID_SIZE]; 
	HelperClass::calc_id(inet_ntoa(adr_inet.sin_addr),(unsigned)ntohs(adr_inet.sin_port),cli_id);          
	string packet="";
	char buffer[BUFSIZE]; // Buffer for echo string
	// hand shake protocol must take place here before file data is exchanged....

	if(seeder->isHandShakeDone==false)            
	{   
		if(verboseMode)
		{ 	
			cout<<"Hand shake started\n";
		}
		
		sendHandshakeReq(sock, cli_id);
		//free memory
		delete[] cli_id;
		// RECIEVING HAND SHAKE RESPONSE FROM PEER...
		int num=0;
		while (num<HAND_SHAKE_BUFSIZE)
		{
			ssize_t numBytesRcvd = recv(sock, buffer, BUFSIZE, 0);		
			if (numBytesRcvd < 0)
			{
				HelperClass::TerminateApplication("recv() failed!!");
			}
			num+=numBytesRcvd;
			packet.append(buffer,numBytesRcvd);           						
		}
		if(packet!="")
		{
		    recvHandShakeResp(packet, (char*)seeder->id); 			
		}
		else
		HelperClass::TerminateApplication("RECEIVED EMPTY BUFFER FROM PEER");  
	}
		
	requestPiece(seeder);	
	close(sock);	
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
		FileObject::CreateFileWithSize(bt_args.bt_info->length, "alpha.mp3"); //TODO --change file name here...
		thread clientThread(&Peer::startClient,this);
		clientThread.join();
	}
	isInit=true;		
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
			
			new thread(&Peer::handleConnectionRequest,this,clntSock,&clntAddr);		
		}
		else
		{
			HelperClass::TerminateApplication("\nUnable to determine Client Address");
		}
	 }
}


void Peer::readBtMsg(bt_msg_t& val,FILE* instream)
{	
	val.bt_type=(int)BT_HAVE; //init with this..
	
	while(val.bt_type == (int)BT_HAVE) //this loop prevents making sense of "have" messages... 
	{
		if (fread(&val, sizeof(bt_msg_t), 1, instream) != 1) 
		{
			cout<<"Receiving failed in bt_msg"<<endl;
			throw; //throwing an exception..
		}
	}
}

//this method recieves requests and send the files...
void Peer::handleRequest(co_peer_t* leecher)
{
	FILE *instream = fdopen(leecher->sock, "r");

	//send the unchoked 
	bt_msg_t unchoked;
	unchoked.bt_type=(int)BT_UNCHOKE;
	cout<<"Unchoke message sent is "<<unchoked.bt_type<<endl;
	unchoked.bt_type=htonl(unchoked.bt_type);

	if (send(leecher->sock, &unchoked, sizeof(unchoked), 0) != sizeof(unchoked))
	{
		HelperClass::TerminateApplication("Bit Field Message send Failed");
	}	

	if(verboseMode)
	{
		cout<<"Unchoke Message Sent\n";
	}	

	//send the bit field message...
	bt_msg_t bitField;
	bitField.bt_type=htons(BT_BITFILED);	
	bitField.payload.bitfiled.size=htons(bt_args.bt_info->num_pieces);	
	bitField.payload.bitfiled.bitfield = new char[bt_args.bt_info->num_pieces];
	for(int i=0;i<bt_args.bt_info->num_pieces;i++)
	{
		bitField.payload.bitfiled.bitfield[i]='1';
	}
	if (send(leecher->sock, &bitField, sizeof(bitField), 0) != sizeof(bitField))
	{
		delete[] bitField.payload.bitfiled.bitfield;
		HelperClass::TerminateApplication("Bit Field Message send Failed");
	}	

	delete[] bitField.payload.bitfiled.bitfield;
	if(verboseMode)
	{
		cout<<"Bit Field Message Sent\n";
	}
	
	//receive bit field message...
	bt_msg_t bitReply;
	readBtMsg(bitReply, instream);
	if(ntohs(bitReply.bt_type)!=BT_BITFILED)
	{
		cout<<"Recieved Bit type is"<<bitReply.bt_type<<endl;
		cout<<"Didnot Receive bit field message"<<endl<<"Terminating Thread!!!"<<endl;
		//TODO --exit the thread..
	}
	if(verboseMode)
	{
		cout<<"Bit Field Message Received\n";
	}	
		
	while(true)
	{
		if(this->verboseMode)
		{
			cout<<"Listening For Requests\n";
		}
		//read the request message;;;;
		//construct the request message here..
		bt_msg_t request;		
		readBtMsg(request, instream);

		{
			cout<<"message recieved\n";
		}

		request.bt_type = ntohs(request.bt_type);
		request.payload.request.index=ntohs(request.payload.request.index); //set the piece index;;
		request.payload.request.begin=ntohl(request.payload.request.begin);
		request.payload.request.length=ntohl(request.payload.request.length);			
		
		if(request.bt_type==BT_REQUEST)
		{
			//request message...have to send a packet here...
			//request is received now...process the request now...
			int offset=request.payload.request.begin;
			int numBytes=request.payload.request.length;
			string message=	FileObject::ReadPartialFile(offset, numBytes, this->bt_info->name);
			if(leecher==NULL)
			{
				HelperClass::TerminateApplication("Error in Send String. leecher doesn't exist");
			}
			bt_msg_t reply;
			reply.bt_type=htons(BT_PIECE);
			int messageLen = message.length(); // determining the length of the string....			
			memcpy(reply.payload.piece.data, message.data(), messageLen); 
			
			// set up parameters...
			reply.payload.piece.index=htonl(request.payload.request.index);
			reply.payload.piece.begin=htonl(request.payload.request.begin);
			reply.payload.piece.length=htonl(numBytes);
			//sending the request message...
			if (send(leecher->sock, &reply, sizeof(reply), 0) != sizeof(reply))
			{
				HelperClass::TerminateApplication("Bit Field Message send Failed");
			}	
	
			if(this->verboseMode)
			{
				cout<<"Message Sent\n";
			}
		}
		else if(request.bt_type==BT_CANCEL)
		{
			if(verboseMode)
			{
				cout<<"Closing Connection with Client\n";
			}
			//it means that the peer has the entire file now.. 
			//removing the peer from connectedPeers;
			mutexConnectedPeers.lock();
			for(int i=0;i<MAX_CONNECTIONS;i++)
			{
				if(bt_args.connectedPeers[i]==leecher)
				{
					bt_args.connectedPeers[i]=NULL;
				}
			}
			mutexConnectedPeers.unlock();
			return;
		}
		else
		{
			HelperClass::TerminateApplication("Un-supported bt type");
		}
	}
	return;
}

void Peer:: handleConnectionRequest(int clntSocket,struct sockaddr_in *clntAddr) 
{
	//create a new coPeer for this leecher..
	co_peer_t * leecher;
	leecher=(co_peer_t *) malloc(sizeof(co_peer_t));
	leecher->sockaddr=(*clntAddr);
	leecher->sock=clntSocket;
	//add it to the list of peers for server...

	addToConnectedPeers(leecher);
	
	char buffer[BUFSIZE]; // Buffer for echo string
	// Receive message from client
    string packet="";
	int num=0;


	while (num<HAND_SHAKE_BUFSIZE)
	{
		ssize_t numBytesRcvd = recv(leecher->sock, buffer, BUFSIZE, 0);		
		if(numBytesRcvd<0)
		{
			HelperClass::TerminateApplication("recv() failed!!!!!");
		}
		packet.append(buffer,numBytesRcvd);           
		num+=numBytesRcvd;
	}
    
    if(packet!="")
	{ 	
		if(this->verboseMode)
		{					 
			cout<<"...Handshake in process..."<<endl;
		}
		   	
		char * id = new char[ID_SIZE+1];
		char * id1 = inet_ntoa(leecher->sockaddr.sin_addr);	   
		unsigned short portNumber=(unsigned)ntohs(leecher->sockaddr.sin_port);
		HelperClass::calc_id(id1,portNumber,id);
	
		recvHandShakeResp(packet, id);

		char *cli_id1 = new char[(int)ID_SIZE]; // calculating the ip and port of the leecher....
		HelperClass::calc_id((string("127.0.0.1")).c_str(),(unsigned)ntohs(localAddress.sin_port),cli_id1);
		
		if(verboseMode)
		{
			cout<<"init sending hand shake request\n";
		}
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
	
	//recieves all the requests made by the leecher...
	handleRequest(leecher);	

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
		requestedPieces=new bool[bt_args.bt_info->num_pieces];
		for(int i=0;i<bt_args.bt_info->num_pieces;i++)
		{
			requestedPieces[i]=false;
			hasPieces[i]=false;
		}
		
		for(int i=0; i<bt_args.n_peers;i++)
		{
			bt_args.connectedPeers[i]->rThread = new thread(&Peer::SendConnectionRequests,this,bt_args.connectedPeers[i]);	
		}
		for(int i=0;i<MAX_CONNECTIONS;i++)
		{
			if(bt_args.connectedPeers[i]!=NULL)
			{
				if(bt_args.connectedPeers[i]->rThread!=NULL)
				bt_args.connectedPeers[i]->rThread->join();
				delete bt_args.connectedPeers[i]->rThread; // works ??
			}
		}			
		//while(!hasFile()); //loop till it has the file...
    }
}

void Peer::recvHandShakeResp(string packet,char* id)
{
	int i;
	if(packet[0]!=19)
	{
	   HelperClass::TerminateApplication("1st offset value did not match");
	}
	else if(this->verboseMode)
	{
		cout<<"Handshake  stage cleared"<<endl;
	}

	for(i=0;i<reserved_offset-1;i++)
	{
		if(packet[i+1]!=BitTorrent_protocol[i])
		{
			 HelperClass::TerminateApplication("Handshake terminated because strings did not match!!!");
		}		
	}
	if(this->verboseMode)
	{		
		cout<<"Handshake 1st stage cleared on peer side"<<endl;
	}  
	for(i=reserved_offset;i<info_hash_offset;i++)
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
		if(packet[i+info_hash_offset]!=bt_info->infoHash[i])
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
	   if(id[i]!=packet[peer_id_offset+i])
	   {
		  //free memory of id.   		
		  cout<<"\nPeer ids not matched\n";		  			 	 
		  HelperClass::TerminateApplication("PeerID'S not matched");
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
		delete[] requestedPieces;
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

int Peer::getNumConnectedPeers()
{
	mutexConnectedPeers.lock();
	int n=0;
	for(int i=0;i<MAX_CONNECTIONS;i++)
	{
		if(bt_args.connectedPeers[i]!=NULL)
		{
			n++;
		}	
	}	
	mutexConnectedPeers.unlock();
	return n;
}

int Peer::addToConnectedPeers(co_peer_t* peer)
{
	mutexConnectedPeers.lock();
	int n=-1;
	for(int i=0;i<MAX_CONNECTIONS;i++)
	{
		if(bt_args.connectedPeers[i]==NULL)
		{
			bt_args.connectedPeers[i]=peer;
			n=i;
		}	
	}	
	mutexConnectedPeers.unlock();
	if(n==-1)
	{
		HelperClass::TerminateApplication("Max connections reached!!");
	}
	return n;
}

