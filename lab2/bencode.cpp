#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include<stdlib.h>
#include <iostream>
#include <string>
#include <fstream>
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
 
int main() 

{
	int rv;
	regex_t exp; //Our compiled expression	
	rv = regcomp(&exp, "([idel])|([0-9]+):|(-?[0-9]+)", REG_EXTENDED);
	if (rv != 0) 
	{
		printf("regcomp failed with %d\n", rv);
	}

        FILE* fp = fopen("moby_dick.txt.torrent", "rb");
        fseek(fp,0,SEEK_END);
        int size = ftell(fp); 
        cout<<size;    
        rewind(fp);
        char * buffer = new char[size+1];
        fread(buffer,1,size,fp);
        buffer[size] = '\0';
         
	    //2. Now run some tests on it	
	    match(&exp, buffer);
	    //3. Free it
	    regfree(&exp);
	    return 0;
}





