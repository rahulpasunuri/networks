#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> // need to add -lssl to compile
#include <string>
#include<iostream>
#include<fstream>
#include<string>
#include "../include/HelperClass.h"
#include "../include/FileObject.h"
using namespace std;



//define fileobject methods...
FileObject::FileObject(const char* fileName, short offSet, short numBytes, bool readOnlyMode)
{
	this->fileName=fileName;
	this->offSet=offSet;
	this->numBytes=numBytes;
	this->readOnlyMode=readOnlyMode;
	fp=new ofstream();
	//create a file with that name in the server..
	  
	if(this->readOnlyMode)
	{ 
	   try
	   {    
	        fp->open(this->fileName, ios::in); 
       }
       catch(...)
       {
            HelperClass::TerminateApplication("Error in Opening File\n");    
       }
    }	  
	else
	{   
       try
       {    
	        fp->open(string("serverFolder/"+string(this->fileName)).c_str(), ios::out); 
            *fp<<flush;	     
       }
       catch(...)
       {
            HelperClass::TerminateApplication("Error in Opening File\n");    
       }   

    }    
}


FileObject::~FileObject()
{
    if(!readOnlyMode)
    {
        //flush the file stream
        (*fp)<<flush;
    }
    //close the previously opened file pointer...
    try
    {
        fp->close();
    }
    catch(...)
    {
        HelperClass::TerminateApplication("Error in closing file!!");
    }
}

const char * FileObject::GetFileName()
{
	return fileName;
}

 int FileObject::GetoffSet()
{
	return offSet;
}

int FileObject::GetNumBytes()
{
	return numBytes;
}


void FileObject::Append(string text)
{
    try
    {
        //the text must be null appended...else this fails..
        (*fp).write(text.data(),text.length());
        cout<<"Appending !!\n";
    }
    catch(...)
    {    
        HelperClass::TerminateApplication("Error in Appending text!!!");        
    }
}

