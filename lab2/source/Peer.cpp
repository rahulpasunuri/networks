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

/**
 * __parse_peer(Peer * peer, char peer_st) -> void
 *
 * parse a peer string, peer_st and store the parsed result in peer
 *
 * ERRORS: Will exit on various errors
 **/
/* TODO
void __parse_peer(Peer * peer, char * peer_st)
{
  char * parse_str;
  char * word;
  unsigned short port;
  char sep[] = ":";
  int i;

  //need to copy becaus strtok mangels things
  parse_str = (char *) malloc(strlen(peer_st)+1);
  strncpy(parse_str, peer_st, strlen(peer_st)+1);

  //only can have 2 tokens max, but may have less
  for(word = strtok(parse_str, sep), i=0; (word && i < 3); word = strtok(NULL,sep), i++)
  {
	printf("%d:%s\n",i,word);
	switch(i)
	{
		case 0://id
		  ip = word;
		  break;
		case 1://ip
		  port = atoi(word);
		default:
		  break;
	}
  }

  if(i < 2)
  {
    fprintf(stderr,"ERROR: Parsing Peer: Not enough values in '%s'\n",peer_st);
    HelperClass::Usage(stderr);
    exit(1);
  }

  if(word)
  {
    fprintf(stderr, "ERROR: Parsing Peer: Too many values in '%s'\n",peer_st);
    HelperClass::Usage(stderr);
    exit(1);
  }


//TODO

  //calculate the id, value placed in id
//  calc_id(ip,port,id);

//TODO
  //build the object we need
 // init_peer(peer, id, ip, port);
  
  //free extra memory
  free(parse_str);

  return;
}
*/

void Peer::Print()
{
	printf("macha");
}


//constructor for the peer class...
//pass the arguments to client and server accordingly here...
Peer:: Peer(bt_args_t args) : Server(args) //, Client(args) TODO
{
	this->sockaddr=args.destaddr;
	thread serverThread(&Peer::startServer,this);
	serverThread.join();
}

void Peer::calc_id(char * ip, unsigned short port, char *id)
{
  char data[256];
  int len;
  
  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 
  
  return;
}



/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int Peer::init_peer(Peer *peer, char * id, char * ip, unsigned short port)
{
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  memcpy(peer->id, id, ID_SIZE);
  
  //TODO
  //peer->port = port;
    
  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL)
  {
		perror("gethostbyname failure, no such host?");
		herror("gethostbyname");
		exit(1);
  }
  
  //zero out the sock address
  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
      
  //set the family to AF_INET, i.e., Iternet Addressing
  peer->sockaddr.sin_family = AF_INET;
    
  //copy the address to the right place
  bcopy((char *) (hostinfo->h_addr), 
        (char *) &(peer->sockaddr.sin_addr.s_addr),
        hostinfo->h_length);
    
  //encode the port
  peer->sockaddr.sin_port = htons(port);
  
  return 0;

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

	printf("peer: %s:%u ", inet_ntoa(this->sockaddr.sin_addr), this->getPortNumber());
	printf("id: ");
	for(i=0;i<ID_SIZE;i++)
	{
		printf("%02x",this->id[i]);
	}
	printf("\n");	  
}



