#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/sha.h>// need to add -lssl to compile
#include <string>
#include<iostream>
#include<fstream>
#include<string>
#include "../include/HelperClass.h"
using namespace std;

void HelperClass::TerminateApplication(string text)
{
	cout<<text<<endl<<"Terminating Application!!"<<endl;
	exit(1);
	return;
}

void HelperClass::calc_id(const char * ip,const unsigned short port, char *id)
{
  char data[256];
  int len;
  
  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 
  return;
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


string HelperClass::logFileName="bt-client.log";
clock_t HelperClass::startTime = clock();
mutex HelperClass::mutexLog;
void HelperClass::Log(const char* message, co_peer_t* peer, LOG_TYPES logType)
{
	//logs the messages into a log file...	
	mutexLog.lock();
	//mutex is required here... as multiple threads will be accessing this part...
	try
	{				
		fstream f;
		try
		{
			// open the file in an append mode...
			f.open(HelperClass::logFileName.c_str(),ios::app | ios::out);
		}
		catch(...)
		{
			HelperClass::TerminateApplication("Error opening the log file");
		}
		f<<'['<< ((clock()-HelperClass::startTime)*1000/CLOCKS_PER_SEC) <<']'; //add the time stamp...
		
		if(logType==HANDSHAKE_INIT)
		{
			f<<" HANDSHAKE INIT";
		}		
 		else if(logType==HANDSHAKE_SUCCESS)
		{
			f<<" HANDSHAKE SUCCESS";
		}		
		else if(logType==MESSAGE_REQUEST_FROM)
		{
			f<<" MESSAGE REQUEST FROM";
		}		
		else if(logType==MESSAGE_PIECE_TO)
		{
			f<<" MESSAGE_PIECE_TO";
		}					
		else
		{
			f<<" MISC";
		}		
		f<<" "<<message;
		if(peer!=NULL)
		{								
			f<<" ip: "<<inet_ntoa(peer->sockaddr.sin_addr);		
			f<<" port: "<<ntohs(peer->sockaddr.sin_port);				
		}
		f<<endl;
		f.flush();
		f.close();		
	}
	catch(...)
	{
		mutexLog.unlock();	
		TerminateApplication("Error in logging messages");
	}
	mutexLog.unlock();	
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
