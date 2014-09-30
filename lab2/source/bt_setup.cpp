#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "../include/bt_setup.h"
#include<string>



/**
 * parse the command line arguments to bt_client using getopt and
 * store the result in bt_args.
 **/
void parse_args(bt_args_t * bt_args, int argc,  char * argv[])
{
  int ch; //ch for each flag
  int n_peers = 0;

  /* set the default args */
  bt_args->verboseMode=false; //no verbosity
  
  //null save_file, log_file and torrent_file
  memset(bt_args->save_file,0x00,FILE_NAME_MAX);
  memset(bt_args->torrent_file,0x00,FILE_NAME_MAX);
  memset(bt_args->log_file,0x00,FILE_NAME_MAX);
  
  //null out file pointers
  bt_args->f_save = NULL;

  //null bt_info pointer, should be set once torrent file is read
  bt_args->bt_info = NULL;

  //default log file
  strncpy(bt_args->log_file,DEFAULTLOGFILE,FILE_NAME_MAX);
  
  
  //TODO
  /*
  for(i=0;i<MAX_CONNECTIONS;i++)
  {
    bt_args->peers[i] = NULL; //initially NULL
  }
  */
  
  bt_args->id = 0;
  
  while ((ch = getopt(argc, argv, "hp:s:l:vI:")) != -1) 
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
		case 'l': //log file
		  strncpy(bt_args->log_file,optarg,FILE_NAME_MAX);
		  break;
		case 'p': //peer
		  n_peers++;
		  //check if we are going to overflow
		  if(n_peers > MAX_CONNECTIONS)
		  {
  		    HelperClass::Usage(stderr);
		  	HelperClass::TerminateApplication(" ERROR: Cannot support this many number of peers");
		  }

		  //have to worry about this.
		  //bt_args->peers[n_peers] = (Peer *) malloc(sizeof(Peer));

		  //parse peers
		  //__parse_peer(bt_args->peers[n_peers], optarg);
		  break;
		case 'I':
		  bt_args->id = atoi(optarg);
		  break;
		case 'b':
		  bt_args->ipAddress=string(optarg);
		  //if ip address is not specified in server.. we will default it to local host.
		
		  if(inet_pton(AF_INET, bt_args->ipAddress.c_str(), &((bt_args->destaddr).sin_addr.s_addr))<0)
		  {
			HelperClass::Usage(stderr);
			HelperClass::TerminateApplication("Invalid IP address");
		  }	  		
		  memset(&(bt_args->destaddr), 0, sizeof(bt_args->destaddr)); 		  
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

  return ;
}


int main(int argc, char * argv[])
{
	try
	{
		//this is the main entry point to the code....
		bt_args_t args;
		parse_args(&args, argc, argv);
		
		//command line arguments are saved in bt_args now..
		//lets create a peer and send this arguments to the peer.
		Peer p(args);		
	}
	catch(...)
	{
		HelperClass::TerminateApplication("Some error occurred in the application");
	}
	return 0;
}
