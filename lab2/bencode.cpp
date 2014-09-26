#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include<stdlib.h>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
using namespace std;
#define MAX_MATCHES 100 //The maximum number of matches allowed in a single string

int pieceLength=0; int sm=0; char * buffer; bool isString=false;


char* nextToken(regex_t *pexp, char* &sz, int *size) 
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

void token(char * text,regex_t *exp)
{
		      
	if(strcmp(text,string("i").c_str())==0)
	{   
		cout<<"\n"<<atoi(nextToken(exp, buffer,&sm))<<"\t"<<"\n";
				        
		if(strcmp(nextToken(exp, buffer,&sm),string("e").c_str())!=0)
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
				            
		char* t =nextToken(exp, buffer, &sm);
		while(strcmp(t,string("e").c_str())!=0)
		{	
			text = t; 
			token(t,exp);
		}
		if(strcmp(text,string("d").c_str())==0)
		{
			char* tm =nextToken(exp, buffer, &sm);
			while(strcmp(tm,string("e").c_str())!=0)
			{
				cout<<"\n";
				for(int i=0;i<sm;i++)
				cout<<tm[i];
			}	

		} 
					   			    
	}
		   

}						
	
 
int main(int argc, char* argv[]) 
{    
    
    regex_t exp; //Our compiled expression	    
   
    if(argc<2)
    {
        cout<<"Invalid no. of arguments\n";
        exit(0);    
    }     
	    int rv;
	    
	    rv = regcomp(&exp, "([idel])|([0-9]+):|(-?[0-9]+)", REG_EXTENDED);
	    if (rv != 0) 
	    {
		    printf("regcomp failed with %d\n", rv);
	    }

       	    fstream fp(argv[1],ios::in|ios::ate|ios::binary);
            fp.seekg(0,ios::end);
            int size = fp.tellg();                 
            fp.seekg(0,ios::beg);
            buffer = new char[size+1];
            fp.read(buffer,size);
            buffer[size] = '\0';
         
	    
	    cout<<"\n\n\n..PRINTING OUT THE KEY VALUE PAIRS..\n\n";    
        while(true)
        {    
            string P = "";
            char *text=nextToken(&exp,buffer, &sm);
            if(text==NULL)
            {
  	           break;
            }
            else 
            {
  		   token(text,&exp);
	    }   
		              
                             
       }                                                     
      
       //3. Free it
       regfree(&exp);
       return 0;
}





