#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include<stdlib.h>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include "../include/HelperClass.h"

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
	static char* nextToken(regex_t *pexp, char* &sz, int *size);
	static void token(char * text,regex_t *exp);
	
	
	~Bencode();
	static void ParseTorrentFile(const char* fileName);
	

};
