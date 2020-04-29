#include<iostream>
#include<fstream>
#include<unordered_map>
#include<list>
#include "Structures.hpp"

using namespace std;

class ParsingPcap
{
	//instance of this class
	static ParsingPcap *instance;
	//position of the pointer in the file.
	streampos position;
	
	unsigned int packetCount=0;		//counter for the number of packet.
	unsigned int tcpCount=0;		//counter for number of TCP packets.
	unsigned int udpCount=0;		//counter for number of UDP packets.
	
	//map for storing locations of output file.
	unordered_map<string,string> mapOfOutput;

	//map for storing sessions information.
	unordered_map<string,list<packetInfo>> mapOfSession;
		
	//objects of structure of headers.
	globalHeader objOfGlobalHeader={0,0,0,0,0,0,0};
	packetHeader objOfPacketHeader={0,0,0,0};
	ethernetHeader objOfethernetHeader={'\0','\0',0};
	ipv4Header objOfipv4Header={'\0','\0',0,0,0,'\0','\0',0,'\0','\0'};
	ipv6Header objOfIpv6Header={0,'\0','\0',0,0};
	tcpHeader objOftcpHeader={0,0,0,0,0,0,0,0};
	udpHeader objOfUdpHeader={0,0,0,0};
	packetInfo objOfPacketInfo;

	//constuctor of ParsingPcap 
    ParsingPcap();
	//Destructor of ParsingPcap
	~ParsingPcap();
		
	public:

		//session output file path
		char* writeSessionPath;

		//function to give the object of this class.
		static ParsingPcap* getInstance();

		//method to check if files can be opened or not.
		int checkFileAndParse(const string &readFile,const string &writeFile);

		//function to initiate the parsing of pcap file.
		bool readPcapFile(ifstream &pcapFileRead,ofstream &pcapFileWrite);

		//declaring functions for reading different headers.
		bool readGlobalHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool readPacketHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool readPacketData(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool readEthernetHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool readIpv4Header(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool readIpv6Header(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool readtcpHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool readUdpHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite);
		bool writeToCsvFile(ofstream &pcapFileWrite);
		string checkSession(const string &ipA,const string &ipB);	
		bool addSession(const string &ipA,const string &ipB);
		void displaySession(const string &file); 
		bool writeSession(unordered_map<string,list<packetInfo>> mapOfSession,const string &file);	
};