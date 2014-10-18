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
	bool isInit;
	
	//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
	mutex readMutex;
	mutex writeMutex;
	mutex mutexConnectedPeers;
	mutex mutexHasPieces;
	mutex mutexRequestPieces;
	mutex mutexStatus;
	//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
	
	//download status
	long uploaded;
	long downloaded;
	///
	
	bool verboseMode;
	bool isHandShakeDone;
	sockaddr_in localAddress;		 
	int portNumber;		
	unsigned char id[ID_SIZE]; //the peer id
	unsigned int idInt; //this bt_clients id
	
	bt_args_t bt_args; //holds the bt arguments.
	bt_info_t * bt_info; //the parsed info for this torrent		
	
	//leecher properties...
	bool* hasPieces;
	bool* requestedPieces;
	void setHasPiece(int index);
	void unSetRequestedPieces(int index);
	/*drop an unresponsive or failed peer*/
	int drop_peer(Peer *peer);
	string fileNameWithPath;
	/* initialize connection with peers */
	int init_peer(Peer *peer, char * id, char * ip, unsigned short port);

	/* check status on peers, maybe they went offline? */
	int check_peer(Peer *peer);

	/*read a msg from a peer and store it in msg*/
	int read_from_peer(Peer * peer, bt_msg_t *msg);	
	
	
	//*********************common functionalities********************
	void sendHandshakeReq(int sock, char* cli_id);
	void recvHandShakeResp(string packet,char* id);
	int addToConnectedPeers(co_peer_t* peer);
	int getNumConnectedPeers();
	int readBtMsg(bt_msg_t& var, FILE* instream); //return -1 on error.
	void deleteFromConnectedPeers(co_peer_t* peer);
	void updateFileStatus(bool isServer, int bytes);
	
	//*****************seeder functionalities*************************
	void handleRequest(co_peer_t* leecher);
	void bindToAPort();
	void handleConnectionRequest(int, struct sockaddr_in*);
	
	//********************leecher functionalities*********************
	bool hasFile();
	int requestPieceIndex();
	void requestPiece(co_peer_t* seeder);
	void handlePacket(string);	
	void parsePacket(string, string&, string&,string&);
	double computeDigest();		
	void SendConnectionRequests(co_peer_t* seeder);

	public:		
	void init(bt_args_t args);
	Peer();
	void startServer();	
	void startClient();
	int sock;
	~Peer();
};

