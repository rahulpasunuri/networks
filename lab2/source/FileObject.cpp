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

void FileObject::CreateFileWithSize(const int size, const char* outputFileName)
{
	if(size<=0)
	{
		cout<<size<<endl;
		HelperClass::TerminateApplication("Invalid file Size!!");			
	}
	fstream f;
	try
	{
		f.open(outputFileName,ios::out);
	}
	catch(...)
	{
		HelperClass::TerminateApplication("Error creating empty file.");
	}
	int s=0;
	while(s<size)
	{
		f<<'c';
		s++;
	}
	f.close();	
}


void FileObject::WritePartialFile(const int offset,const int numBytes,const char* content,const char* fileName)
{
	fstream f;
	if(numBytes<=0)
	{
		HelperClass::TerminateApplication("numBytes is <=0");
	}
	try
	{
		f.open(fileName,ios::in|ios::out);
	}
	catch(...)
	{
		HelperClass::TerminateApplication("Error opening file for write.");
	}
	
	f.seekg(0,ios::end);
    int size = f.tellg();
	if( (offset+numBytes) > size)
	{
		HelperClass::TerminateApplication("Size limits exceeding");
	}
	
	f.seekp(offset,ios::beg);
	try
	{
		f.write(content,numBytes);
	}
	catch(...)
	{
		HelperClass::TerminateApplication("File write failed!!!");
	}
	f.close();	
}


string FileObject::ReadPartialFile(const int offset,int &numBytes,const char* fileName)
{

	fstream f;
	if(numBytes<=0)
	{
		HelperClass::TerminateApplication("numBytes is <=0");
	}
	try
	{
		f.open(fileName,ios::in);
	}
	catch(...)
	{
		HelperClass::TerminateApplication("Error opening file for write.");
	}
	string s="";
	f.seekg(0,ios::end);
    int size = f.tellg();
	if( (offset+numBytes) > size)
	{
		numBytes= size-offset;
		if(numBytes==0)
		{
			f.close();
			return "";
		}
	}
	char* content=new char[numBytes+1];		
	f.seekp(offset,ios::beg);
	try
	{
		for(int i=0;i<numBytes;i++)
		{
			f.get(content[i]);
		}		
		content[numBytes]='\0';
		s.append(content,numBytes);
		delete[] content;
	}
	catch(...)
	{
		HelperClass::TerminateApplication("File write failed!!!");
	}
	f.close();		
	return s;		
}


