#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include<string>
using namespace std;

#define BUFSIZE 1024


//tags used in packets..
const string STARTPACKETTAG="<packet>";
const string ENDPACKETTAG="</packet>";

const string STARTBODYTAG="<body>";
const string ENDBODYTAG="</body>";


const string STARTFILENAMETAG="<fileName>";
const string ENDFILENAMETAG="</fileName>";

const string STARTDIGESTTAG="<digest>";
const string ENDDIGESTTAG="</digest>";


#define BUFFERSIZE 124
/**
 * Structure to hold all relevant state
 **/
struct nc_args_t
{
  struct sockaddr_in destaddr; //destination/server address
  unsigned short port; //destination/listen port
  bool listen; //listen flag
  long int n_bytes ; //number of bytes to send
  long int offset ; //file offset
  bool verbose; //verbose output info //saving verbose as a bool, instead if an int.
  bool message_mode; // retrieve input to send via command line
  char* message; // if message_mode is activated, this will store the message
  char* filename; //input/output file
};


class HelperClass
{
	public:
		static bool IsValidPortNumber(short portNum);
		static void TerminateApplication(string);
		static bool CheckIfFileExists(const char*);
		static const char * GetDigest(string H);
};
