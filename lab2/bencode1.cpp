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

void match(regex_t *pexp, char *sz) 
{
	regmatch_t matches[MAX_MATCHES]; //A list of the matches in the string (a list of 1)
	char token; int i=0; int data;
	//regexec() returns 0 on match, otherwise REG_NOMATCH
	while(regexec(pexp, sz, MAX_MATCHES, matches, 0) == 0)
	{
        int endIndex=matches[0].rm_eo;
        //printf("\"%s\" matches characters %d - %d\n", sz, matches[0].rm_so, matches[0].rm_eo);								
		if(sz[endIndex-1] == ':')
		{
            endIndex--;	    
			char* integer = new char[endIndex];
            for(int i=0;i<endIndex;i++)
            {
                integer[i]=sz[i];
            }		
            integer[endIndex]='\0';
            int lengthOfString=atoi(integer);
            printf("Integer is: %d\n",lengthOfString);
            
            char *s=new char[lengthOfString+1];
            for(int j=0;j<lengthOfString;j++)
            {
                s[j]=sz[j+endIndex+1];
            }
            s[lengthOfString]='\0';
            printf("String is: %s\n",s);
            sz+=lengthOfString;
            sz+=(endIndex); 
    		sz++;
		}
        else
        {
            //cout<<"End Index is "<<endIndex<<endl;
			char* var = new char[endIndex];
            for(int i=0;i<endIndex;i++)
            {
                var[i]=sz[i];
            }
            var[endIndex]='\0';
            cout<<"Var is: "<<var<<"\n";
            sz+=(endIndex);
        } 

	} 	
}
bool isString=false;
char* nextToken(regex_t *pexp, char* &sz, int *size) 
{
    isString=false;
	regmatch_t matches[MAX_MATCHES]; //A list of the matches in the string (a list of 1)
	char token; int i=0; int data;
	//regexec() returns 0 on match, otherwise REG_NOMATCH
	if(regexec(pexp, sz, MAX_MATCHES, matches, 0) == 0)
	{
        int endIndex=matches[0].rm_eo;
        //printf("\"%s\" matches characters %d - %d\n", sz, matches[0].rm_so, matches[0].rm_eo);								
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
            //printf("Integer is: %d\n",lengthOfString);

            char *s=new char[lengthOfString+1];
            for(int j=0;j<lengthOfString;j++)
            {
                s[j]=sz[j+endIndex+1];
            }
            s[lengthOfString]='\0';
            //printf("String is: %s\n",s);
            sz+=lengthOfString;
            sz+=(endIndex); 
    		sz++;                        
            return s;            
		}
        else
        {          
            //cout<<"End Index is "<<endIndex<<endl;
			char* var = new char[endIndex];
            for(int i=0;i<endIndex;i++)
            {
                var[i]=sz[i];
            }
            var[endIndex]='\0';
            //cout<<"Var is: "<<var<<"\n";
            sz+=(endIndex);
            
            return var;            
        }        
	} 	
    return NULL;
}


 
int main(int argc, char* argv[]) 
{    
    
    
    int sm=0;  //    VARIABLE TO STORE THE SIZE VALUES OF LENGTH OF STRINGS...  
    if(argc<2)
    {
        cout<<"Invalid no. of arguments\n";
        exit(0);    
    }     
	    int rv;
	    regex_t exp; //Our compiled expression	
	    rv = regcomp(&exp, "([idel])|([0-9]+):|(-?[0-9]+)", REG_EXTENDED);
	    if (rv != 0) 
	    {
		    printf("regcomp failed with %d\n", rv);
	    }

       	    fstream fp(argv[1],ios::in|ios::ate|ios::binary);
            fp.seekg(0,ios::end);
            int size = fp.tellg();                 
            fp.seekg(0,ios::beg);
            char * buffer = new char[size+1];
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
                  
         here:    if(strcmp(text,string("i").c_str())==0)
                  {   
		      	   cout<<atoi(nextToken(&exp, buffer,&sm))<<"\t"<<"\n";
                        
                           if(strcmp(nextToken(&exp, buffer,&sm),string("e").c_str())!=0)
                           {
                                
                                 cout<<"parsing error\n";                            
                           }
                          
                          
                  }
                  else if(isString==true) 
                         cout<<text<<"\n";

                  else  if(!(strcmp(text,string("d").c_str())||strcmp(text,string("d").c_str())))
                  {
                            
                            char* t =nextToken(&exp, buffer, &sm);
                            while(strcmp(t,string("e").c_str())!=0)
                            {	
				text = t; 
				goto here;
				t=nextToken(&exp, buffer, &sm);
				
	                    	if(strcmp(text,string("d").c_str())==0)
		           	{
					char* tm =nextToken(&exp, buffer, &sm);
					while(strcmp(tm,string("e").c_str())!=0)
					cout<<tm;	
			    	} 
			    }			    
		  }
             }               
               
                    
        }                                                     
      
        //3. Free it
	    regfree(&exp);
	    
	    return 0;
}





