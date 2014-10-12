#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include "HelperClass.h"


class FileObject
{
	private:
		const char*  fileName;
		ofstream* fp; //this is the file pointer
		short offSet;
		short numBytes;	
		bool readOnlyMode;
	public:
		~FileObject();	
		FileObject(const char*fileName, short offSet=0, short numBytes=0,bool readOnlyMode=true);
		static void CreateFileWithSize(const int , const char* );
		static void WritePartialFile(const int ,const int , const char*, const char* );
		static string ReadPartialFile(const int ,int& , const char* );
		void Append(string text); //returns whether the append was succesfull or not..		
};
