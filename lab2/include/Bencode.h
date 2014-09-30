#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include<stdlib.h>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include "HelperClass.h"
#include "bt_lib.h"

using namespace std;
#define MAX_MATCHES 100 //The maximum number of matches allowed in a single string

class Bencode
{
	public:
	static int pieceLength; 
	static int sm; 
	static char * buffer; 
	static bool isString;
	static regex_t exp;
	static bool isInit;
		
	static void initVariables();
	static char* nextToken(regex_t *pexp, char* &sz, int *size,bt_info_t &result);
	static void token(char * text,regex_t *exp,bt_info_t &result);
	
	
	~Bencode();
	static bt_info_t ParseTorrentFile(const char* fileName);
	

};
