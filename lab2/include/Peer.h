#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include<fstream>
#include "HelperClass.h"
#include "FileObject.h"
#include "bt_lib.h"
#include<thread>
#include <mutex>

#define MAXPENDING 5
#define HAND_SHAKE_BUFSIZE 68
class Peer
{
	private:	
	mutex mutexConnectedPeers;
	bool verboseMode;
	bool isHandShakeDone;
	sockaddr_in localAddress;		 
	int sock;
	int portNumber;		
	unsigned char id[ID_SIZE]; //the peer id
	unsigned int idInt; //this bt_clients id
	int choked; //peer choked?
	int interested; //peer interested?	
	
	bt_args_t bt_args; //holds the bt arguments.
	bt_info_t * bt_info; //the parsed info for this torrent	
	
	void sendHandshakeReq(int sock, char* cli_id);
	void recvHandShakeResp(string packet,char* id);
	void handleTCPClient(int, struct sockaddr_in*);
	void parsePacket(string, string&, string&,string&);
	void handlePacket(string);
	void bindToAPort();
	/*choose a random id for this node*/
	unsigned int select_id();
	double computeDigest();		
	

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
	

	void sendString(co_peer_t*, int ,string, const char *, string);
	void sendPacket(co_peer_t* leecher);

	public:
	const int protocol_name_offset = 1;
	const int reserved_offset = protocol_name_offset + 19; //20
	const int info_hash_offset = reserved_offset + 8; //28
	const int peer_id_offset = info_hash_offset + 20; //48

	const char prefix = 19;
	const string BitTorrent_protocol = "BitTorrent protocol";
	void init(bt_args_t args);
	Peer();
	int getPortNumber();
	void startServer();	
	void startClient();

	~Peer();
};

