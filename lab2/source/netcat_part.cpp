#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <exception>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include<iostream>
#include<string>
using namespace std;

//custom headers
#include "../include/Server.h"
#include "../include/Client.h"

void usage(FILE * file)
{
  fprintf(file,
         "netcat_part [OPTIONS]  dest_ip [file] \n"
         "\t -h           \t\t Print this help screen\n"
         "\t -v           \t\t Verbose output\n"
	 "\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
	 "                \t\t Warning: if you specify this option, you do not specify a file. \n"
         "\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
         "\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
         "\t -o offset    \t\t Offset into file to start sending\n"
         "\t -l           \t\t Listen on port instead of connecting and write output to file\n"
         "                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
         );
}

/**
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 **/
void parse_args(nc_args_t * nc_args, int argc, char * argv[])
{
  int ch;
  //set defaults
  nc_args->n_bytes = 0;
  nc_args->offset = 0;
  nc_args->listen = false;
  nc_args->port = 6767; //default port address...
  nc_args->verbose = false;
  nc_args->message_mode = false;
 
  while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) 
  {
    switch (ch) 
    {
	    case 'h': //help
	      usage(stdout);
	      exit(0);
	      break;
	    case 'l': //listen
	      nc_args->listen = true;
	      break;
	    case 'p': //port
	      nc_args->port = atoi(optarg);
	      break;
	    case 'o'://offset
	      nc_args->offset = atoi(optarg);
	      break;
	    case 'n'://bytes
	      nc_args->n_bytes = atoi(optarg);
	      break;
	    case 'v':
	      nc_args->verbose = true;
	      break;
	    case 'm':
	      nc_args->message_mode = true;
	      nc_args->message = (char *)malloc(strlen(optarg)+1);
	      strncpy(nc_args->message, optarg, strlen(optarg)+1);
	      break;
	    default:
	      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
	      usage(stdout);
	      exit(1);
    }
  }
    
  argc -= optind;
  argv += optind;
    
  if (argc < 1 && nc_args->listen == false)
  {
    fprintf(stderr, "ERROR: Require destination ip address\n");
    usage(stderr);
    exit(1);
  }
  
  if (argc < 2 && nc_args->listen == false && nc_args->message_mode==false)
  {
    fprintf(stderr, "ERROR: Require both destination ip address followed by file name\n");
    usage(stderr);
    exit(1);
  }  
  
  if (argc != 1 && nc_args->message_mode == 1 && nc_args->message_mode==false) 
  {
    fprintf(stderr, "ERROR: Require ip send/recv from when in message mode\n");
    usage(stderr);
    exit(1);
  }
  string ipAddress;
  //if ip address is not specified in server.. we will default it to local host.
  if (argc == 0 && nc_args->listen == true) 
  {
      int rtnVal = inet_pton(AF_INET, "127.0.0.1", &((nc_args->destaddr).sin_addr.s_addr));
      if(rtnVal<0)
      {
        fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
        usage(stderr);
        exit(1);
      }
  }
  else
  {
      int rtnVal = inet_pton(AF_INET, argv[0], &((nc_args->destaddr).sin_addr.s_addr));
      if(rtnVal<0)
      {
        fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
        usage(stderr);
        exit(1);
      }
  }
  
  memset(&(nc_args->destaddr), 0, sizeof(nc_args->destaddr)); 

  
  nc_args->destaddr.sin_family = AF_INET;
  nc_args->destaddr.sin_port=htons(nc_args->port);

  /* Save file name if not in message mode */
  if (nc_args->message_mode == 0 && nc_args->listen==false) 
  {
    nc_args->filename = (char*)malloc(strlen(argv[1])+1);
    strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);   
  }
  return;
}


int main(int argc, char * argv[])
{
	try
	{
		nc_args_t nc_args;
		//initializes the arguments struct for your use
		parse_args(&nc_args, argc, argv);
		if(nc_args.verbose)
		{
			cout<<"Parsing Arguments done!!"<<endl;
		}
		if(nc_args.listen==false)
		{			
			if(nc_args.verbose)
			{
				cout<<"Starting Client!!"<<endl;
			}
			if(!nc_args.message_mode)
			{
				if(nc_args.verbose)
				{
					cout<<"Checking if File Exists!!"<<endl;
				}
				//check if file exists...
				if(!HelperClass::CheckIfFileExists(nc_args.filename))
				{
					HelperClass::TerminateApplication("File doesn't exist!!");
				}
			}
			//address variable is destination address here....
			//this is a client...
			Client* cl=new Client(nc_args);			
		}		
		else
		{
			if(nc_args.verbose)
			{
				cout<<"Starting Server!!"<<endl;
			}
			//address is local address here...
			//this is a server..
			Server* s = new Server(nc_args);
		}
		
		/**
		* FILL ME IN
		**/
	}
	catch (int param)
	{
		//always exit gracefully
		fprintf(stderr, "\n***Exception occurred in the Application. Terminating the Application***\n");
		//release all resources before returning...
		
		return -1;
	}
	return 0;
}
