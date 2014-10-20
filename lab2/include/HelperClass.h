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
#include<mutex>
#include<time.h>
#include "bt_lib.h"

using namespace std;
#define BUFSIZE 1024
#define DEFAULTLOGFILE "bt-client.log"


enum LOG_TYPES 
{
	HANDSHAKE_INIT, 
	HANDSHAKE_SUCCESS, 
	MESSAGE_REQUEST_FROM, 
	MESSAGE_PIECE_TO,
	MISC	
};


class HelperClass
{	
	public:
		static void TerminateApplication(string);
		static void Usage(FILE*);
		static void calc_id(const char * ip, unsigned short port, char *id);
		static string logFileName;
		static void Log(const char* message, co_peer_t* peer=NULL, LOG_TYPES=MISC);	
		static mutex mutexLog;
		static clock_t startTime;
		static bool CheckIfFileExists(const char* fileName);
		
};
