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
#define SHA_DIGEST_LENGTH 20
class HelperClass
{
	public:
		static bool IsValidPortNumber(short portNum);
		static void TerminateApplication(string);
		static bool CheckIfFileExists(const char*);
		static void Usage(FILE*);
		static void calc_id(const char * ip, unsigned short port, char *id);
};
