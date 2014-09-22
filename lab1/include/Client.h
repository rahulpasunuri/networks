#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include <string.h>

//custom headers..
#include "HelperClass.h"
#include "FileObject.h"


class Client
{
	private:
		bool verboseMode;
		//data properties of Client....
		short serverPortNumber;
		sockaddr_in destinationAddress;
		int sock;
		int offSet, lsize;
		char * file,* buffer;
		int numBytes;		
		int result, msgDesc;		
		FileObject *fp;
		void sendString(string, const char *, string);
		
	public:
		//constructor of Client()
		Client(nc_args_t clnt_arg);								
};
