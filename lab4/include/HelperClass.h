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
#include<time.h>
#include<vector>

using namespace std;

#define MAX_RETRANSMISSIONS 3

enum scanTypes_t
{
	TCP_SYN,
	TCP_NULL,
	TCP_FIN,
	TCP_XMAS,
	TCP_ACK,
	UDP
};

enum portState
{
	OPEN,
	CLOSED,
	FILTERED,
	UNFILTERED,
	OPEN_OR_FILTERED		
}

struct args_t
{
       vector<int> portNumbers;
       vector<string> ipAddresses;
       bool verboseMode;
       int numThreads;
       vector<scanTypes_t> scanTypes;
};


class HelperClass
{	
	public:
		static void TerminateApplication(string);
		static bool CheckIfFileExists(const char* fileName);
		static bool isValidPortNumber(int portNum);
		static bool isValidIpAddress(string ip);
		static bool isNumber(string s);
		static const char* getScanTypeName(scanTypes_t inp);
		static scanTypes_t getScanTypeId(string s);
};
