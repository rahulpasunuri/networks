#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include<stdlib.h>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include "../include/Bencode.h"
#include <openssl/sha.h> //hashing pieces

using namespace std;

Bencode::Bencode()
{
	pieceLength=0; 
	sm=0; 
	isString=false;
	isInit=false;
	isFileName=false;
	isLength=false;
	isPieceLength=false;
	isPieces=false;
    if(isInit==false)
    {  	        	
        int rv = regcomp(&exp, "([idel])|([0-9]+):|(-?[0-9]+)", REG_EXTENDED);
        if (rv != 0) 
        {
	        HelperClass::TerminateApplication("Compilation of the regular expression failed");
        }	        
        isInit=true;
    }
    return;
}
			
char* Bencode::nextToken(regex_t *pexp, char* &sz, int *size,bt_info_t &result) 
{
	isString=false;
	regmatch_t matches[MAX_MATCHES];
	//regexec() returns 0 on match, otherwise REG_NOMATCH
	if(regexec(pexp, sz, MAX_MATCHES, matches, 0) == 0)
	{
		int endIndex=matches[0].rm_eo;										
		if(sz[endIndex-1] == ':')
		{
		    isString=true;
    	    endIndex--;	    
		    char* integer = new char[endIndex+1];
    	    for(int i=0;i<endIndex;i++)
    	    {
            	integer[i]=sz[i];
            }		
            integer[endIndex]='\0';
            int lengthOfString=atoi(integer);
            *size = lengthOfString;

            char *s=new char[lengthOfString+1];
            for(int j=0;j<lengthOfString;j++)
            {
               s[j]=sz[j+endIndex+1];
            }
            s[lengthOfString]='\0';
    
            sz+=lengthOfString;
            sz+=(endIndex); 
		    sz++; 
		    delete[] integer;              
            return s;            
		}
		else
		{          		    
    		char* var = new char[endIndex+1];
    		for(int i=0;i<endIndex;i++)
    		{
        		var[i]=sz[i];
    		}
    		var[endIndex]='\0';
       		sz+=(endIndex);
    
    		return var;            
		}        
	} 	
	return NULL;
}

void Bencode::token(char * text,regex_t *exp,bt_info_t &result)
{
	if(strcmp(text,string("i").c_str())==0)
	{   
		char *nToken=nextToken(exp, buffer,&sm,result);
		int len= atoi(nToken);
		delete[] nToken;
		//free up space...
		if(isLength)
		{
			result.length =len;
			isLength=false;
		}
		else if (isPieceLength)
		{
			result.piece_length=len;
			isPieceLength=false;
		}
		nToken = nextToken(exp, buffer,&sm,result);
		if(strcmp(nToken,string("e").c_str())!=0)
		{
			delete[] nToken;
			HelperClass::TerminateApplication("parsing error");  
		}
		delete[] nToken;					  
	}
	else if(isString==true) 
	{ 
		if(!strcmp(text,"length"))
		{
			isLength=true;
		}
		else if(!strcmp(text,"name"))
		{
			isFileName=true;
		}
		else if(!strcmp(text,"piece length"))
		{
			isPieceLength=true;
		}
		else if(!strcmp(text,"pieces"))
		{
			isPieces=true;
		}
		else if(!strcmp(text,"info"))
		{
			//save the info hash which will be matched between two peers...
			int infoLen=strlen(buffer)-2; //removing the two 'e' letters at the end
			result.infoHash=new char[ID_SIZE];
			//id is just the SHA1 of the ip and port string
			SHA1((unsigned char *) buffer, infoLen, (unsigned char *) result.infoHash); 
		}
		else if(isPieces)
		{
			isPieces=true;
			int numPieces=sm/(int)ID_SIZE;
			if(ID_SIZE*numPieces != sm)
			{
				HelperClass::TerminateApplication("Torrent File Corrupted");
			}
			result.piece_hashes = new char*[numPieces];	
			result.num_pieces=numPieces;
			for(int i=0;i<numPieces;i++)
			{
				char* h=new char[(int)ID_SIZE+1];
				for(int j=0;j<(int)ID_SIZE;j++)
				{
					h[j]=text[j];		
				}
				h[(int)ID_SIZE]='\0';
				text+=(int)ID_SIZE;
				result.piece_hashes[i]=h;
			}
			
		}
		else if(isFileName)
		{
			if(sm>FILE_NAME_MAX-1)
			{
				HelperClass::TerminateApplication("File name exceeds the limit in torrent file");
			}
			for(int i=0;i<sm;i++)
			{
				result.name[i]=text[i];
			}
			result.name[sm]='\0';
			isFileName=false;
		}
		
	}
	else  if(!(strcmp(text,string("d").c_str())||strcmp(text,string("l").c_str())))
	{					    
		char* t =nextToken(exp, buffer, &sm,result);
		while(strcmp(t,string("e").c_str())!=0)
		{	
			text = t; 
			token(t,exp,result);
		}
		if(strcmp(text,string("d").c_str())==0)
		{		
			char* tm =nextToken(exp, buffer, &sm,result);
			while(strcmp(tm,string("e").c_str())!=0)
			{
				continue;
			}	
			delete[] tm;
		} 
					   			    
	}			   
}				

Bencode::~Bencode()
{
    regfree(&exp);      
}


bt_info_t Bencode::ParseTorrentFile(const char* fileName)
{
	if(HelperClass::CheckIfFileExists(fileName))
	{ }
	else
   	HelperClass::TerminateApplication("File doesnt exist\n");
		bt_info_t result;
		char *backUp;
		if(fileName==NULL)
		{
		    HelperClass::TerminateApplication("Please pass the name of the torrent file");
		}	
		try
		{
		    fstream fp(fileName,ios::in|ios::binary);
		    fp.seekg(0,ios::end);
		    int size = fp.tellg();                 
		    fp.seekg(0,ios::beg);
		    buffer = new char[size+1];
		    backUp=buffer;
		    fp.read(buffer,size);
		    buffer[size] = '\0';
		    fp.close();
		}
		catch(...)
		{
		    HelperClass::TerminateApplication("Error reading the torrent file");
		}  
		
		//parsing the torrent file tokens        	    
		while(true)
		{    
		    string P = "";
		    char *text=nextToken(&exp,buffer, &sm,result);
		    if(text==NULL)
		    {
		       break;
		    }
		    else 
		    {
	  		   token(text,&exp,result);
			}   		
			delete[] text;                                           
	   }

	   //free buffer...
	   delete[] backUp;
	   return result;
   
                  
}			



