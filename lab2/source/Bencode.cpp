#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include<stdlib.h>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include "../include/Bencode.h"
using namespace std;


int Bencode::pieceLength=0; 
int Bencode::sm=0; 
char * Bencode::buffer; 
bool Bencode::isString=false;
regex_t Bencode::exp;
bool Bencode::isInit=false;
bool Bencode::isFileName=false;
bool Bencode::isLength=false;
bool Bencode::isPieceLength=false;
bool Bencode::isPieces=false;

void Bencode::initVariables()
{
    if(Bencode::isInit==false)
    {  	        	
        int rv = regcomp(&Bencode::exp, "([idel])|([0-9]+):|(-?[0-9]+)", REG_EXTENDED);
        if (rv != 0) 
        {
	        HelperClass::TerminateApplication("Compilation of the regular expression failed");
        }	        
        Bencode::isInit=true;
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
		    char* integer = new char[endIndex];
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
            return s;            
		}
		else
		{          		    
    		char* var = new char[endIndex];
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
		int len= atoi(nextToken(exp, buffer,&sm,result));
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
		if(strcmp(nextToken(exp, buffer,&sm,result),string("e").c_str())!=0)
		{
			cout<<"parsing error\n";                          
		}
					  
	}
	else if(isString==true) 
	{ 
		for(int i=0;i<sm;i++)
		cout<<text[i];
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
		else if(isPieces)
		{
			isPieces=true;
			int numPieces=sm/20;
			result.piece_hashes = new char*[numPieces];	
			result.num_pieces=numPieces;
			for(int i=0;i<numPieces;i++)
			{
				char* h=new char[21];
				for(int j=0;j<20;j++)
				{
					h[j]=text[j];		
				}
				h[21]='\0';
				text+=20;
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
				for(int i=0;i<sm;i++)
				cout<<tm[i];
			}	
			//delete tm;
		} 
					   			    
	}			   
}				

Bencode::~Bencode()
{
    regfree(&exp);      
}


bt_info_t Bencode::ParseTorrentFile(const char* fileName)
{
	bt_info_t result;
    initVariables();
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
   }
   cout<<"\n~~~~~~~~~~~~Printing File length: "<<endl;   
    cout<<result.num_pieces<<endl;
	for(int i=0;i<result.num_pieces;i++)
	{
		cout<<result.piece_hashes[i]<<"\n";
	}

   //free buffer...
   //delete[] buffer;
   return result;               
}			



