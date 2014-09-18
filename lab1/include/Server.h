#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include "HelperClass.h"
#include "FileObject.h"

static const int MAXPENDING = 5; // Maximum outstanding connection requests

class Server
{	
	private:
		bool verboseMode;
		double computeDigest();		
		sockaddr_in localAddress;		 
		int sock;
		void handleTCPClient(int);
		void parsePacket(string, string&, string&,string&);
		void handlePacket(string);
	public:
		Server(nc_args_t input);
};
