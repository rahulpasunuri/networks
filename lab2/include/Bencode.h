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
	private:
	int pieceLength; 
	int sm; 
	char * buffer; 
	bool isString;
	regex_t exp;
	bool isInit;
	bool isFileName;
	void initVariables();
	char* nextToken(regex_t *pexp, char* &sz, int *size,bt_info_t &result);
	void token(char * text,regex_t *exp,bt_info_t &result);		
	bool isLength;
	bool isPieceLength;
	bool isPieces;
	public:
	Bencode();
	~Bencode();
	bt_info_t ParseTorrentFile(const char* fileName);
};
