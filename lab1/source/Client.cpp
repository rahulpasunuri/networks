#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include<fstream>
#include <string>
#include <openssl/hmac.h>
//include custom header files...
#include "../include/Client.h"
#include "../include/FileObject.h"
using namespace std;

Client::Client(nc_args_t clnt_arg)
{
	//intitialize the destination Address..		
	//Zero out structure
	memset(&destinationAddress, 0, sizeof(destinationAddress));		
	verboseMode=clnt_arg.verbose;
    memset(&destinationAddress, 0, sizeof(destinationAddress)); // Zero out structure
	destinationAddress = clnt_arg.destaddr;		
	offSet = 0;  numBytes = 0;      
	// SOCKET creation.....
 	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock < 0)
	{
		HelperClass::TerminateApplication("Socket Creation Failed!!");
	}

	if(verboseMode)
	{
		cout<<"Socket Creation Successfull!!"<<endl;
	}
	
	// connecting socket to the server    
	if (connect(sock, (struct sockaddr *) &destinationAddress, sizeof(destinationAddress)) < 0)
	{      
		HelperClass::TerminateApplication("connect() failed");
	}
	    
	if(verboseMode)
	{
		cout<<"Connection established successfully"<<endl;
	}
    
	// sending a string of message if in message mode.
	if(clnt_arg.message_mode)            
	{
		sendString(clnt_arg.message, HelperClass::GetDigest(clnt_arg.message),"");
	}	
	else	
	{
	        
    	FileObject clnt_File(clnt_arg.filename, clnt_arg.offset, clnt_arg.n_bytes);   // initialising file object
    	offSet = clnt_File.GetoffSet();	    
    	numBytes = clnt_File.GetNumBytes();       
        cout<<numBytes;
	
		FILE* fp = fopen(clnt_File.GetFileName(), "rb");	
		if (fp==NULL) {fputs ("File error",stderr); exit (1);}		
	
        if(offSet == 0)
		{
	    	fseek(fp, 0, SEEK_END);
	    	lsize = ftell(fp);		
        	rewind(fp);
		}
		else
		{
		    fseek(fp, offSet, SEEK_END); 
		    lsize = ftell(fp);  
		    rewind(fp);               
	    	fseek(fp, offSet, SEEK_SET);
     	}
        //numBytes is less than zero, we will send, every byte from offset till EOF.        
        if(numBytes != 0)
        {  
	         if(numBytes <= lsize)		     
	         {
                 	lsize = numBytes;                      
	         }
	         else
	         {                       
            	 	HelperClass::TerminateApplication("numBytes exceeding limit");
	         }
        }		    		  								     								
		
      ifstream file (clnt_arg.filename,ios::in|ios::ate);
      string s="";
      if (file.is_open())
      {
        int size = file.tellg();
        cout<<"Printing file size"<<size<<"\n";
        char* memblock = new char [size+1];
        file.seekg (0, ios::beg);
        file.read (memblock, size);
        memblock[size]='\0';

        s.append(memblock,size);
        cout<<"length of string s is "<<s.length()<<"\n";               
        file.close();        
        cout << "the entire file content is in memory"<<endl;

        delete[] memblock;
      }
      else cout << "Unable to open file";
        
       cout<<"before sending"<<endl;
        //string message="";
        //message.append(buffer,lsize);
        sendString(s, HelperClass::GetDigest(s), clnt_arg.filename);	       // sending loaded buffer with file name into the string...
        close(sock);	
	}
}

void Client::sendString(string message,const char * digest, string fileName="")
{         
        string d(digest);       
        string MSG="";     
        if(fileName!="")
        {            
            MSG.append(STARTPACKETTAG);
            MSG.append(STARTFILENAMETAG);
            MSG.append(fileName);            
            MSG.append(ENDFILENAMETAG);
            MSG.append(STARTBODYTAG);
            MSG.append(message);
            MSG.append(ENDBODYTAG);
            MSG.append(STARTDIGESTTAG);
            MSG.append(d);
            MSG.append(ENDDIGESTTAG);
            MSG.append(ENDPACKETTAG);
        }
        else
        {
            MSG = STARTPACKETTAG+STARTBODYTAG+message+ENDBODYTAG+STARTDIGESTTAG+d+ENDDIGESTTAG+ENDPACKETTAG;  
        }
        if(verboseMode)
        {
            //cout<<"Packet to be sent is:\n"<<MSG<<endl;
        }    
        int messageLen = MSG.length(); // determining the length of the string....
        cout<<"Length of the packet is "<<MSG.length();
        ssize_t msgDesc = send(sock, MSG.data(), messageLen, 0);

        if(msgDesc < 1)
        {
            HelperClass::TerminateApplication("send() failed");
        }
        else if(msgDesc != messageLen)
        {
            HelperClass::TerminateApplication("send() failed due to incorrect no. of bytes");
        }
	
	    if(verboseMode)
	    {
	        cout<<"message sent successfully"<<endl;
	    }	

} 
