#ifndef _BT_LIB_H
#define _BT_LIB_H

//standard stuff
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include<string>
#include <poll.h>

//networking stuff
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

/*Maximum file name size, to make things easy*/
#define FILE_NAME_MAX 1024

/*Maxium number of connections*/
#define MAX_CONNECTIONS 5

/*initial port to try and open a listen socket on*/
#define INIT_PORT 6667 

/*max port to try and open a listen socket on*/
#define MAX_PORT 6699

/*Different BitTorrent Message Types*/
#define BT_CHOKE 0
#define BT_UNCHOKE 1
#define BT_INTERSTED 2
#define BT_NOT_INTERESTED 3
#define BT_HAVE 4
#define BT_BITFILED 5
#define BT_REQUEST 6
#define BT_PIECE 7
#define BT_CANCEL 8

#define DEFAULTLOGFILE "bt-client.log"

/*size (in bytes) of id field for peers*/
#define ID_SIZE 20


//holds information about a peer
typedef struct peer
{
  unsigned char id[ID_SIZE]; //the peer id
  unsigned short port; //the port to connect n
  struct sockaddr_in sockaddr; //sockaddr for peer
  int choked; //peer choked?
  int interested; //peer interested?
}co_peer_t;

//holds information about a torrent file
typedef struct 
{
  char name[FILE_NAME_MAX]; //name of file
  int piece_length; //number of bytes in each piece
  int length; //length of the file in bytes
  int num_pieces; //number of pieces, computed based on above two values
  char ** piece_hashes; //pointer to 20 byte data buffers containing the sha1sum of each of the pieces
} bt_info_t;


//holds all the agurments and state for a running the bt client
typedef struct 
{
  bool verboseMode; //verbose level
  char save_file[FILE_NAME_MAX];//the filename to save to
  FILE * f_save;
  char log_file[FILE_NAME_MAX];//the log file
  char torrent_file[FILE_NAME_MAX];// *.torrent file
  co_peer_t * connectedPeers[MAX_CONNECTIONS]; // array of peer_t pointers
  unsigned int id; //this bt_clients id
  int sockets[MAX_CONNECTIONS]; //Array of possible sockets
  struct pollfd poll_sockets[MAX_CONNECTIONS]; //Array of pollfd for polling for input
  std::string ipAddress;
  struct sockaddr_in destaddr; //local address
  unsigned short port; //listen port
  /* set once torrent is parsed */
  bt_info_t * bt_info; //the parsed info for this torrent
  

} bt_args_t;


/**
 * Message structures
 **/

typedef struct 
{
  char * bitfield; //bitfield where each bit represents a piece that
                   //the peer has or doesn't have
  size_t size;//size of the bitfiled
} bt_bitfield_t;

typedef struct
{
  int index; //which piece index
  int begin; //offset within piece
  int length; //amount wanted, within a power of two
} bt_request_t;

typedef struct
{
  int index; //which piece index
  int begin; //offset within piece
  char piece[0]; //pointer to start of the data for a piece
} bt_piece_t;



typedef struct bt_msg
{
  int length; //length of remaining message, 
              //0 length message is a keep-alive message
  unsigned int bt_type;//type of bt_mesage

  //payload can be any of these
  union { 
    bt_bitfield_t bitfiled;//send a bitfield
    int have; //what piece you have
    bt_piece_t piece; //a peice message
    bt_request_t request; //request messge
    bt_request_t cancel; //cancel message, same type as request
    char data[0];//pointer to start of payload, just incase
  }payload;

} bt_msg_t;

#endif
