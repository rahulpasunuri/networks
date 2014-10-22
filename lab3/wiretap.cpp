#include<iostream>
#include <pcap.h> //header file required for pcap...
#include<string.h>
#include<stdlib.h>
using namespace std;


/*
void applyFilter()
{

}
*/

void usage()
{
	cout<<"Invoke this application as: ./wiretap [option1, ..., optionN]"<<endl;
	cout<<"Available Options are:\n";
	cout<<"-help : Prints out the help screen\n\t\tExample: ./wiretap --help"<<endl;
	cout<<"-open <capture file to open>. : Opens an offline file.\n\t\tExample: ./wiretap --open capture.pcap"<<endl;
	exit(1);
}

char* parseArguments(int argc, char* argv[])
{
	int i=1;
	if(argc==1 || argc>3)
	{
		usage();
	}
	for(int i=1;i<argc;i++)
	{
		if(strcmp(argv[i],"--help")==0)
		{
			usage();
		}
	}
	if(strcmp(argv[1],"--open")!=0)
	{
		usage();
	}
	return argv[2];
}

int numPackets=0;

void callback(u_char *, const struct pcap_pkthdr *, const u_char *)
{
	cout<<"Callback called"<<endl;
	numPackets++;
}


int main(int argc, char* argv[])
{
	char* fileName=parseArguments(argc, argv);
	cout<<"Evaluating file: "<<fileName<<endl;

	char errbuf[PCAP_ERRBUF_SIZE]; //will hold the error messages..
	
	//opening the offline tcp dump.
	pcap_t *handle=pcap_open_offline(fileName, errbuf);
	if(handle==NULL)
	{
		cout<<"Error reading the tcp dump"<<endl;
		exit(1);
	}

	//Check that the data you are provided has been captured from Ethernet
	int linkLayerHeaderType=pcap_datalink(handle);
	if(linkLayerHeaderType==PCAP_ERROR_NOT_ACTIVATED)
	{
		cout<<"Error getting the link layer header type"<<endl;
		exit(1);
	}
	if(linkLayerHeaderType!=DLT_EN10MB)	
	{
		cout<<"The data provided has not been captured from Ethernet"<<endl;
		exit(1);
	}

	//apply filter
	const char filter[]="not ip6"; //filter out the ipv6 packets...
	struct bpf_program fp;		/* The compiled filter */
	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) 
	{
		printf("Unable to parse filter %s: %s\n", filter, pcap_geterr(handle));
		exit(1);
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		printf("Unable to apply filter %s: %s\n", filter, pcap_geterr(handle));
		exit(1);
 	}	
	

	//call the loop back function...
	int returnVal = pcap_loop(handle, -1, callback, NULL); //-1 here implies all the packets...
	if(returnVal==-1)
	{
		printf("Error occurred in pcap_loop %s\n",pcap_geterr(handle));
		exit(1);
	}
	cout<<"Number of Packets processed is "<<numPackets<<endl;
	return 0;
}
