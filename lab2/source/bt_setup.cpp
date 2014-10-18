#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "../include/bt_setup.h"
#include <openssl/sha.h> //hashing pieces
#include<string>
#include<thread>
#include<iostream>
#include "../include/HelperClass.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

using namespace std;

Peer currentPeer;
void my_handler(int s)
{
   printf("De allocating resources.. %d\n",s);
   close(currentPeer.sock);   
   exit(1); 
}

void initSigHandler()
{
   struct sigaction sigIntHandler;
   sigIntHandler.sa_handler = my_handler;
   sigemptyset(&sigIntHandler.sa_mask);
   sigIntHandler.sa_flags = 0;
   sigaction(SIGINT, &sigIntHandler, NULL);
}

/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the co_peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(co_peer_t *peer, char * id, char * ip, unsigned short port)
{
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  memcpy(peer->id, id, ID_SIZE);
    
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
 * __parse_peer(Peer * peer, char peer_st) -> void
 *
 * parse a peer string, peer_st and store the parsed result in peer
 *
 * ERRORS: Will exit on various errors
 **/

void __parse_peer(co_peer_t *peer, char * peer_st)
{
  char * parse_str;
  char * word;
  unsigned short port;
  char sep[] = ":";
  int i;
  char* ip;
  //need to copy becaus strtok mangels things
  parse_str = (char *) malloc(strlen(peer_st)+1);
  strncpy(parse_str, peer_st, strlen(peer_st)+1);
  parse_str[strlen(peer_st)]='\0';
  
  //only can have 2 tokens max, but may have less
  for(word = strtok(parse_str, sep), i=0; (word && i < 3); word = strtok(NULL,sep), i++)
  {
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
  char* id = new char[ID_SIZE+1];
  //calculate the id, value placed in id
  HelperClass::calc_id(ip,port,id);

  //build the object we need
  if(init_peer(peer, id, ip, port)<0)
  {
  	HelperClass::TerminateApplication("InitPeer() failed");
  }
  
  //free extra memory
  delete[] id;
  free(parse_str);

  return;
}



/**
 * parse the command line arguments to bt_client using getopt and
 * store the result in bt_args.
 **/
void parse_args(bt_args_t * bt_args, int argc,  char * argv[])
{
  int ch; //ch for each flag
  bt_args->n_peers = 0;

  /* set the default args */
  bt_args->verboseMode=false; //no verbosity
  bt_args->isSeeder= false;
  
  //null save_file, log_file and torrent_file
  memset(bt_args->save_file,0x00,FILE_NAME_MAX);
  memset(bt_args->torrent_file,0x00,FILE_NAME_MAX);
  bt_args->save_file[0]='\0'; //will be used to know whether it is set or not...
  //null out file pointers
  bt_args->f_save = NULL;
  bt_args->port=INIT_PORT;
  //null bt_info pointer, should be set once torrent file is read
  bt_args->bt_info = NULL;


  //initialize the connected peers array
  for(int i=0;i<MAX_CONNECTIONS;i++)
  {
    bt_args->connectedPeers[i] = NULL; //initially NULL
  }
 
  bt_args->id = 0;
  
  while ((ch = getopt(argc, argv, "hp:s:l:fvI:b:")) != -1) 
  {
    switch (ch) 
    {
		case 'h': //help
		  HelperClass::Usage(stdout);
		  exit(0);
		  break;
		case 'v': //verbose
		  bt_args->verboseMode = true;
		  break;
		case 's': //save file
		  strncpy(bt_args->save_file,optarg,FILE_NAME_MAX);
		  break;
		case 'f':// seeder or leecher
		  bt_args->isSeeder = true;
		 
		  break;
		case 'l': //log file
		  if(strlen(optarg)>FILE_NAME_MAX)
		  {
		  	HelperClass::TerminateApplication("file name limit exceeded");
		  }
		  HelperClass::logFileName=optarg;
		  break;
		case 'p': //peer
		  //check if we are going to overflow
		  if(bt_args->n_peers > MAX_CONNECTIONS)
		  {
  		    HelperClass::Usage(stderr);
		    HelperClass::TerminateApplication(" ERROR: Cannot support this many number of peers");
		  }
	          
		  bt_args->connectedPeers[bt_args->n_peers] = (co_peer_t *) malloc(sizeof(co_peer_t));
		  bt_args->connectedPeers[bt_args->n_peers]->isHandShakeDone=false;
		  //parse peers
		  __parse_peer(bt_args->connectedPeers[bt_args->n_peers], optarg);
  		  bt_args->n_peers++; 
		  break;
		case 'I':
		  bt_args->id = atoi(optarg);
		  break;
		case 'b':
		  bt_args->ipAddress=string(optarg);
		  //if ip address is not specified in server.. we will default it to local host.
		  memset(&(bt_args->destaddr), 0, sizeof(bt_args->destaddr)); 	
		  if(inet_pton(AF_INET, bt_args->ipAddress.c_str(), &((bt_args->destaddr).sin_addr.s_addr))<0)
		  {
			HelperClass::Usage(stderr);
			HelperClass::TerminateApplication("Invalid IP address");
		  }	  
		  bt_args->destaddr.sin_family = AF_INET;
		  bt_args->destaddr.sin_port=htons(bt_args->port);		  
		  break;

		default:
		  HelperClass::Usage(stdout);
		  HelperClass::TerminateApplication("ERROR: Unknown option");
    }
  }

  argc -= optind;
  argv += optind;

  if(argc == 0)
  {
    HelperClass::Usage(stderr);
  	HelperClass::TerminateApplication("ERROR: Require torrent file");
  }

  //copy torrent file over
  strncpy(bt_args->torrent_file,argv[0],FILE_NAME_MAX);  
  //decode bencoding...
  Bencode bnc;
  bt_info_t bti=bnc.ParseTorrentFile(bt_args->torrent_file);
  bt_args->bt_info = new bt_info_t;
  mempcpy(bt_args->bt_info, &bti, sizeof(bt_info_t));
  return;
}

int main(int argc, char * argv[])
{
	try
	{	
		//start the timer for the log file...
		HelperClass::startTime = clock();

		//use a seed for the random function..
		srand (time(NULL));
		//this is the main entry point to the code....
		bt_args_t args;
		parse_args(&args, argc, argv);
			
		 initSigHandler();
		//command line arguments are saved in bt_args now..
		//lets create a peer and send this arguments to the peer.		
		currentPeer.init(args);		
	}
	catch(...)
	{
		//cout<<"Exception is "<<i<<endl;
		HelperClass::TerminateApplication("Some error occurred in the application");
	}
	return 0;
}
