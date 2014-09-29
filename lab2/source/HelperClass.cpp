#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include <string>
#include<iostream>
#include<fstream>
#include<string>
#include "../include/HelperClass.h"
using namespace std;

//define helper class methods..
bool HelperClass::IsValidPortNumber(short portNum)
{
	if(portNum<1024 || portNum>65535)
	{
		//dont allow this range of port numbers..
		HelperClass::TerminateApplication("Port Number Out of Bounds!!. Terminating Application");		
		return false; //writing this return to make the compiler happy..
	}
	else return true;
}

void HelperClass::TerminateApplication(string text)
{
	cout<<text<<endl<<"Terminating Application!!"<<endl;
	exit(1);
	return;
}

bool HelperClass::CheckIfFileExists(const char* fileName)
{
	ifstream f(fileName);
	if (f.good()) 
	{
		//file exists...
		f.close();
		return true;
	} 
	else 
	{
		//file doesnt exist...
		f.close();
		return false;
	}
}

const char* key_signed="This is key"; 

const char* HelperClass::GetDigest(string message)
{
    try
    {        

        const char* key_signed="this is key";
        int keyLength=strlen(key_signed);
        unsigned char *key=(unsigned char *)malloc(sizeof(unsigned char )*keyLength);    
        for(int k=0;k<keyLength;k++)
        {
            key[k]=(unsigned char)key_signed[k];
        }



        //const unsigned char *data=(const unsigned char *)data_signed;
        int messageLen=message.length();
        unsigned char *data=(unsigned char *)malloc(sizeof(unsigned char)*messageLen);
        
        for(int j=0;j<messageLen;j++)
        {
            data[j]=(unsigned char)message[j];
        }
        
        unsigned char *hash = (unsigned char *) malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE);
        //return "test";
        unsigned int *hashlen= (unsigned int *)malloc(sizeof(unsigned int));
        HMAC(EVP_sha1(), key, keyLength,data, message.length(), hash, hashlen);                         
        char* rethash=new char[(*hashlen)+1];        
        rethash[*hashlen]='\0';
        for(unsigned int i=0;i<*hashlen;i++)
        {
           rethash[i]=(char)hash[i];
        }
        delete[] hash;
        delete hashlen;
        return (const char *) rethash;    
   
     }
     catch(...)
     {  
        HelperClass::TerminateApplication("Digest computation failed");
     }
     return NULL;
}
   

void HelperClass::Usage(FILE * file)
{
  if(file == NULL)
  {
    file = stdout;
  }

  fprintf(file,
          "bt-client [OPTIONS] file.torrent\n"
          "  -h            \t Print this help screen\n"
          "  -b ip         \t Bind to this ip for incoming connections, ports\n"
          "                \t are selected automatically\n"
          "  -s save_file  \t Save the torrent in directory save_dir (dflt: .)\n"
          "  -l log_file   \t Save logs to log_filw (dflt: bt-client.log)\n"
          "  -p ip:port    \t Instead of contacing the tracker for a peer list,\n"
          "                \t use this peer instead, ip:port (ip or hostname)\n"
          "                \t (include multiple -p for more than 1 peer)\n"
          "  -I id         \t Set the node identifier to id (dflt: random)\n"
          "  -v            \t verbose, print additional verbose info\n");
}

