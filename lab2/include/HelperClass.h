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
#include <chrono>
using namespace std;

#define BUFSIZE 1024
#define DEFAULTLOGFILE "bt-client.log"


enum LOG_TYPES 
{
	HANDSHAKE_INIT=1, 
	HANDSHAKE_SUCCESS=2, 
	MESSAGE_REQUEST_FROM=3, 
	MESSAGE_PIECE_TO=4,
	MISC=5	
};


class HelperClass
{	
	public:
		static bool IsValidPortNumber(short portNum);
		static void TerminateApplication(string);
		static bool CheckIfFileExists(const char*);
		static const char * GetDigest(string H);
		static void Usage(FILE*);
		static void calc_id(const char * ip, unsigned short port, char *id);
		static string logFileName;
		static void Log(const char* message);	
		static mutex mutexLog;
		static chrono::steady_clock::time_point startTime;
};
