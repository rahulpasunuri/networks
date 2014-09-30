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
	regmatch_t matches[MAX_MATCHES]; //A list of the matches in the string (a list of 1)
	 
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
		cout<<"\n"<<atoi(nextToken(exp, buffer,&sm,result))<<"\t"<<"\n";
					
		if(strcmp(nextToken(exp, buffer,&sm,result),string("e").c_str())!=0)
		{
			cout<<"parsing error\n";                          
		}
					  
	}
	else if(isString==true) 
	{ 
		cout<<"\t"<<"\n";
		for(int i=0;i<sm;i++)
		cout<<text[i];
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
				cout<<"\n";
				for(int i=0;i<sm;i++)
				cout<<tm[i];
			}	

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
        fstream fp("test",ios::in|ios::binary);
        fp.seekg(0,ios::end);
        int size = fp.tellg();                 
        fp.seekg(0,ios::beg);
        buffer = new char[size+1];
        fp.read(buffer,size);
        buffer[size] = '\0';
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
   return result;               
}			



