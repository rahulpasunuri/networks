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
chrono::steady_clock::time_point HelperClass::startTime = std::chrono::steady_clock::now();
mutex HelperClass::mutexLog;
void HelperClass::Log(const char* message)
{
	//logs the messages into a log file...	
	mutexLog.lock();
	//mutex is required here... as multiple threads will be accessing this part...
	try
	{
		// the operation to time (for elapsed time)

		std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now() ;

		typedef std::chrono::duration<int,std::milli> millisecs_t ;
		millisecs_t duration( std::chrono::duration_cast<millisecs_t>(end-HelperClass::startTime) ) ;
		std::cout << duration.count() << " milliseconds.\n" ;
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
		f<<'['<<duration.count()<<']'; //add the time stamp...
		//TODO .. shld add the message type as well...
		f<<" "<<message;
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

