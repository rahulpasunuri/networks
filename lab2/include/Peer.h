#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile

#include "HelperClass.h"
#include "FileObject.h"
#include "Server.h"
#include "Client.h"
#include "bt_lib.h"

class Peer : public Server
{
	private:
	unsigned char id[ID_SIZE]; //the peer id
	unsigned int idInt; //this bt_clients id
	struct sockaddr_in sockaddr; //sockaddr for peer
	int choked; //peer choked?
	int interested; //peer interested?	
	
	bt_args_t bt_args; //holds the bt arguments.

	/* set once torrent is parsed */
	bt_info_t * bt_info; //the parsed info for this torrent	
	
	/*choose a random id for this node*/
	unsigned int select_id();

	/*calc the peer id based on the string representation of the ip and
	  port*/
	void calc_id(char * ip, unsigned short port, char * id);

	/*propogate a Peer struct and add it */
	int add_peer(Peer *peer, char * hostname, unsigned short port);

	/*drop an unresponsive or failed peer*/
	int drop_peer(Peer *peer);

	/* initialize connection with peers */
	int init_peer(Peer *peer, char * id, char * ip, unsigned short port);

	/* print info about this peer */
	void print_peer();

	/* check status on peers, maybe they went offline? */
	int check_peer(Peer *peer);

	/*check if peers want to send me something*/
	int poll_peers();

	/*send a msg to a peer*/
	int send_to_peer(Peer * peer, bt_msg_t * msg);

	/*read a msg from a peer and store it in msg*/
	int read_from_peer(Peer * peer, bt_msg_t *msg);	
	
	public:
	Peer(bt_args_t args);
	void Print();
	
};

