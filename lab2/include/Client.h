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
#include "bt_lib.h"


class Client
{
	private:
		bool verboseMode;
		//data properties of Client....
		void sendString(co_peer_t*, int ,string, const char *, string);
		void sendPacket(co_peer_t* leecher);
		
	public:
		//constructor of Client()
		Client(bt_args_t args);					
};
