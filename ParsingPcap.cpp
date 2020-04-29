#include<iostream>
#include<fstream>
#include<cstring>
#include<arpa/inet.h>
#include<chrono>
#include "ParsingPcap.hpp"
#include "Utilities.hpp"
using namespace std;

#define LITTLEENDIAN 2712847316
#define BIGENDIAN 3569595041
#define ETHERNET 1
#define IPV4 8
#define IPV6 56710
#define TCP 6
#define UDP 17

//initializing the static instance variable
ParsingPcap* ParsingPcap::instance=0;

//Defining Constructor
ParsingPcap::ParsingPcap()
{
    //Empty constructor.
}

//Defining Destructor
ParsingPcap::~ParsingPcap()
{

}
//instance of the class
ParsingPcap* ParsingPcap::getInstance()
{
	if(!instance)
	{
		instance=new ParsingPcap;
	}
	return instance;
}

//function to check the format of the file and send it for parsing
int ParsingPcap::checkFileAndParse(const string &readFile,const string &writeFile)
{
	//object of ifstream to read pcap file and ofstream to write in a file.
	ifstream pcapFileRead;
	ofstream pcapFileWrite;

	//opening pcap file in binary mode
	pcapFileRead.open(readFile,ios::in|ios::binary);
	//creating a file and opening it to write the content of pcap file
	pcapFileWrite.open(writeFile);
	

	//Checking if the file has been opened successfully or not
	if(pcapFileRead.is_open() && pcapFileWrite.is_open())
	{
		cout<<"File "<<readFile<<" is being parsed..."<<endl;
		
		//starting time of the parsing
        auto start = chrono::system_clock::now();

		packetCount=0;
		tcpCount=0;
		udpCount=0;
		position=0;

		//Calling readPcapFile function to parse the pcap file
		if(readPcapFile(pcapFileRead,pcapFileWrite))
		{
			//storing the output file path in the map
			mapOfOutput[readFile]=writeFile;

			//writing the session to session file.
			writeSession(mapOfSession,Utilities::getNameOfFile(readFile,writeSessionPath));
			//clearing the map for the next file
			mapOfSession.clear();

			auto end = std::chrono::system_clock::now();
   			chrono::duration<double> elapsedSeconds = end-start;
    		cout<<"Parsing Duration for file "<<readFile<<" is :"<<elapsedSeconds.count()<<" seconds."<<endl;

			cout<<"Pcap File Parsed successfully."<<endl;
		}
		else
		{
			cout<<"ERROR : Error occured while parsing."<<endl;
		}
	}
	else
	{
		//file can't be opened.
		cout<<"ERROR : File "<<readFile<<" or "<<writeFile<<" can't be open."<<endl;
	}
	//closing both the objects.
	pcapFileRead.close();
	pcapFileWrite.close();
	return 0;
}

//function to read the pcapFile
bool ParsingPcap::readPcapFile(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//initialising the position variable to point to the starting of the file.
	position=pcapFileRead.tellg();
	
	//checking if the format is pcap or not by reading global header.
	if(readGlobalHeader(pcapFileRead,pcapFileWrite))
	{
		//Writing column titles in pcapinfofile.
		pcapFileWrite<<"No.,Packet Length,Source Mac Address,Destination Mac Address,Internet Protocol,Source Ip Address,";
		pcapFileWrite<<"Destination Ip Address,Transport protocol,Source Port No.,Destination Port No.\n"<<endl;
		
		while(true)
		{
			//readPacketHeader fuction return false in case of any error.
			if(readPacketHeader(pcapFileRead,pcapFileWrite))
			{
				if(!pcapFileRead.eof())
				{
					//increasing the packet counter.
					packetCount++;
					//writing one packet detail in the file.
					writeToCsvFile(pcapFileWrite);
				}
				else
				{
					return true;
				}
			}
			else
			{
				return false;
			}
		}
	}
	return true;
}

//Defining function to read the global header.
bool ParsingPcap::readGlobalHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//reading magic number
	pcapFileRead.read((char*) &objOfGlobalHeader.magicNumber,4);

	if(objOfGlobalHeader.magicNumber==LITTLEENDIAN || objOfGlobalHeader.magicNumber==BIGENDIAN)
	{
		//skiping 16 bytes to read link layer protocol.
		pcapFileRead.seekg(16,ios::cur); 

		//reading link layer protocol and checking if it's ethernet or not.
		pcapFileRead.read((char*) &objOfGlobalHeader.linkProtocol,4); 
		if(objOfGlobalHeader.linkProtocol==ETHERNET)
		{
			//storing link protocol in object of packet info
			objOfPacketInfo.link="Ethernet";

			//Initializing position to current poisition.
			position=pcapFileRead.tellg();
			return true;
		}
		else
		{
			cout<<"ERROR : Some other header detected. This program only supports pcap file with ethernet headers."<<endl;
			return false;
		}
	}
	else
	{
		// file is not in pcap format so return false.
		cout<<"ERROR : Pcap format not detected. Give file with pcap format."<<endl;
		return false;
	}
	return true;
}

//function to read the packet header.
bool ParsingPcap::readPacketHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//Setting position to point to the starting of the packet.
	pcapFileRead.seekg(position);
	//reading tsSec field and checking if it can be read successfully or not.
	if(pcapFileRead.read((char*) &objOfPacketHeader.tsSec,4))
	{
		//readinf tsUsec field
		pcapFileRead.read((char*) &objOfPacketHeader.tsUsec,4);
	
		//reading captured length of the packet
		pcapFileRead.read((char*) &objOfPacketHeader.capturedLength,4);
		//storing captured packet length in object of packet info
		objOfPacketInfo.packetLen=objOfPacketHeader.capturedLength;

		//storing original length of the packet
		pcapFileRead.read((char*) &objOfPacketHeader.orignalLength,4);
		
		//setting position to the starting of next packet. so that the pointer can directly jump to the next
		//packet if some error occurs in parsing of the current packet.
		position=(streampos)pcapFileRead.tellg()+(streampos)objOfPacketHeader.capturedLength;
	
		//calling method to read ethernet header
		return readEthernetHeader(pcapFileRead,pcapFileWrite);
	}
	else
	{
		return true;
	}
}

//function to read the ethernet header
bool ParsingPcap::readEthernetHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//reading destination mac address. 
	pcapFileRead.read((char*)&objOfethernetHeader.destMacAdd,6);
	//storing destination mac address in object of packet info
	objOfPacketInfo.desMac=objOfethernetHeader.destMacAdd;

	//reading source mac address.
	pcapFileRead.read((char*)&objOfethernetHeader.srcMacAdd,6);
	//storing source mac address in object of packet info
	objOfPacketInfo.srcMac=objOfethernetHeader.srcMacAdd;

	//reading the ethernet type.
	pcapFileRead.read((char*) &objOfethernetHeader.ethType,2);
	//checking if it's ipv4 or not.
	if(objOfethernetHeader.ethType==IPV4)
	{
		readIpv4Header(pcapFileRead,pcapFileWrite);
		//storing internet protocol in object of packet info
		objOfPacketInfo.ip="IPV4";
	}
	else if(objOfethernetHeader.ethType==IPV6)
	{
		readIpv6Header(pcapFileRead,pcapFileWrite);
		//storing internet protocol in object of packet info
		objOfPacketInfo.ip="IPV6";
	}
	else
	{
		; //Do nothing and progress towards the next process.
	}
	return true;
}

//function to read the Ipv4 header
bool ParsingPcap::readIpv4Header(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//skipping 9 bytes to directly read the protocol field.
	pcapFileRead.seekg(9,ios::cur);
	pcapFileRead.read((char*) &objOfipv4Header.protocol,1);
	
	//skipping 2 bytes to read IP address of source and destination.
	pcapFileRead.seekg(2,ios::cur);
	
	//reading source ip address
	pcapFileRead.read((char*) &objOfipv4Header.srcIpAdd,4);

	//reading destination ip address
	pcapFileRead.read((char*) &objOfipv4Header.destIpAdd,4);

	//checking if it is tcp or not.
	if((int)objOfipv4Header.protocol==TCP)
	{
		//calling method to read TCP header.
		readtcpHeader(pcapFileRead,pcapFileWrite);
		//storing transport protocol in object of packet info
		objOfPacketInfo.transProtocol="TCP";
	}
	else if((int)objOfipv4Header.protocol==UDP)
	{
		//calling function to read udp header.
		readUdpHeader(pcapFileRead,pcapFileWrite);
		//storing transport protocol in object of packet info
		objOfPacketInfo.transProtocol="UDP";
	}
	else
	{
		//storing transport protocol in object of packet info
		objOfPacketInfo.transProtocol="Unknown";
	}
	return true;
}

//function to read the Ipv6 header
bool ParsingPcap::readIpv6Header(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//skipping 4 bytes for version, priority and flow label.
	pcapFileRead.seekg(4,ios::cur);
	
	//reading payload length field
	pcapFileRead.read((char*) &objOfIpv6Header.payloadLength,2);
	
	//reading next header field
	pcapFileRead.read((char*)&objOfIpv6Header.nextHeader,1);
	
	//reading hop limit field
	pcapFileRead.read((char*)&objOfIpv6Header.hopLimit,1);
	
	//reading source ip address
	pcapFileRead.read((char*)&objOfIpv6Header.srcaddress,16);

	//reading destination ip address
	pcapFileRead.read((char*)&objOfIpv6Header.destaddress,16);
	
	//checking if the next header is equal to TCP or not
	if((int)objOfIpv6Header.nextHeader==TCP)
	{
		//calling function to read tcp header.
		readtcpHeader(pcapFileRead,pcapFileWrite);
		tcpCount++;
		//storing transport protocol in object of packet info
		objOfPacketInfo.transProtocol="TCP";
	}
	else if((int)objOfIpv6Header.nextHeader==UDP)
	{
		//calling function to read udp header.
		readUdpHeader(pcapFileRead,pcapFileWrite);
		udpCount++;
		//storing transport protocol in object of packet info
		objOfPacketInfo.transProtocol="UDP";
	}
	else
	{
		//storing transport protocol in object of packet info
		objOfPacketInfo.transProtocol="Unknown";
	}
	return true;
}

//function to read the TCP header
bool ParsingPcap::readtcpHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//reading source port number
	pcapFileRead.read((char*) &objOftcpHeader.srcPort,2);
	objOfPacketInfo.srcport=ntohs(objOftcpHeader.srcPort);
	
	//reading destination port number
	pcapFileRead.read((char*) &objOftcpHeader.destPort,2);
	objOfPacketInfo.desport=ntohs(objOftcpHeader.destPort);

	//skipping remaining bytes and moving towards the next packet.
	pcapFileRead.seekg(14,ios::cur);
	pcapFileRead.read((char*) &objOftcpHeader.urgentPointers,2);
	return true;
}

//function to read the UDP header
bool ParsingPcap::readUdpHeader(ifstream &pcapFileRead,ofstream &pcapFileWrite)
{
	//reading source port number
	pcapFileRead.read((char*) &objOfUdpHeader.srcPort,2);
	objOfPacketInfo.srcport=ntohs(objOftcpHeader.srcPort);
	
	//reading destination port number
	pcapFileRead.read((char*) &objOfUdpHeader.desPort,2);
	objOfPacketInfo.desport=ntohs(objOftcpHeader.destPort);

	//reading length
	pcapFileRead.read((char*) &objOfUdpHeader.length,2);
	
	//reading checksum
	pcapFileRead.read((char*) &objOfUdpHeader.checksum,2);
	return true;
}

//function to Write pcap file information into a CSV file.
bool ParsingPcap::writeToCsvFile(ofstream &pcapFileWrite)
{		
	string ipA="";	//to store IP address of the first machine.
	string ipB="";	//to store IP address of the second machine.

	//writing packetcount to the pcapfileinfo file
	pcapFileWrite<<packetCount<<",";

	//writing captured length to the pcapfileinfo file.
	pcapFileWrite<<objOfPacketHeader.capturedLength<<",";

	//writing destination mac address to the pcapfileinfo file.
	for(int index=0;index<5;index++)
	{
	pcapFileWrite<<(int)objOfethernetHeader.destMacAdd[index]<<":";	

	}
	pcapFileWrite<<(int)objOfethernetHeader.destMacAdd[5]<<",";
	
	//writing source mac address to the pcapfileinfo file.
	for(int index=0;index<5;index++)
	{
	pcapFileWrite<<(int)objOfethernetHeader.srcMacAdd[index]<<":";	
	}
	pcapFileWrite<<(int)objOfethernetHeader.srcMacAdd[5]<<",";

	if(objOfethernetHeader.ethType==IPV4)
	{
		//writing ipv4 protocol to the pcapinfo file.
		pcapFileWrite<<"Ipv4,";
		//writing source ip address to the pcapfileinfo file.
		for(int index=0;index<3;index++)
		{
			pcapFileWrite<<(int)objOfipv4Header.srcIpAdd[index]<<":";
			ipA.append(to_string(objOfipv4Header.srcIpAdd[index]));
			ipA.append(":");
		}
		pcapFileWrite<<(int)objOfipv4Header.srcIpAdd[3]<<",";
		ipA.append(to_string(objOfipv4Header.srcIpAdd[3]));
		
		//writing destination ip address to the pcapfileinfo file.
		for(int index=0;index<3;index++)
		{
			pcapFileWrite<<(int)objOfipv4Header.destIpAdd[index]<<":";
			ipB.append(to_string(objOfipv4Header.destIpAdd[index]));
			ipB.append(":");
		}
		pcapFileWrite<<(int)objOfipv4Header.destIpAdd[3]<<",";
		ipB.append(to_string(objOfipv4Header.destIpAdd[3]));
	}
	else if(objOfethernetHeader.ethType==IPV6)
	{
		pcapFileWrite<<"Ipv6,";

		//writing source ip address to the pcapfileinfo file.
		for(int index=0;index<7;index++)
		{
			pcapFileWrite<<hex<<ntohs(objOfIpv6Header.srcaddress[index])<<":"<<dec;
			ipA.append(to_string(objOfIpv6Header.srcaddress[index]));
			ipA.append(":");
		}
		pcapFileWrite<<std::hex<<ntohs(objOfIpv6Header.srcaddress[7])<<","<<std::dec;
		ipA.append(to_string(objOfIpv6Header.srcaddress[7]));

		//writing destination ip address to the pcapfileinfo file.
		for(int index=0;index<8;index++)
		{
			pcapFileWrite<<std::hex<<ntohs(objOfIpv6Header.destaddress[index])<<":"<<std::dec;
			ipB.append(to_string(objOfIpv6Header.destaddress[index]));
			ipB.append(":");
		}
		pcapFileWrite<<std::hex<<ntohs(objOfIpv6Header.destaddress[7])<<","<<std::dec;
		ipB.append(to_string(objOfIpv6Header.destaddress[7]));
	}
	if((int)objOfipv4Header.protocol==TCP || (int)objOfIpv6Header.nextHeader==TCP)
	{
		//writing tcp protocol in pcapfileinfo file.
		pcapFileWrite<<"TCP,";

		//writing source port number to the pcapfileinfo file.
		pcapFileWrite<<ntohs(objOftcpHeader.srcPort)<<",";
		
		//writing destination port number to the pcapfileinfo file.
		pcapFileWrite<<ntohs(objOftcpHeader.destPort)<<",";
	}
	else if((int)objOfipv4Header.protocol==UDP || (int)objOfIpv6Header.nextHeader==UDP)
	{
		//writing UPD protocol in pcapfileinfo file.
		pcapFileWrite<<"UDP,";

		//writing source port number to the pcapfileinfo file.
		pcapFileWrite<<ntohs(objOfUdpHeader.srcPort)<<",";
		
		//writing destination port number to the pcapfileinfo file.
		pcapFileWrite<<ntohs(objOfUdpHeader.desPort)<<",";
	}
	else
	{
		pcapFileWrite<<"Unknown,";
	}
	
	pcapFileWrite<<"\n";

	//adding the session in the map
	addSession(ipA,ipB);
 
 
}

//funtion to check the session between two machines and return the session key
string ParsingPcap::checkSession(const string &ipA,const string &ipB)
{
	//checking if the session is already added in the map or not
	if(mapOfSession.find(ipA+","+ipB)!=mapOfSession.end())
	{
		return ipA+","+ipB;
	}
	else if(mapOfSession.find(ipB+","+ipA)!=mapOfSession.end())
	{
		return ipA+","+ipB;
	}
	else
	{
		return "";
	}
}

//function to add the session in the map
bool ParsingPcap::addSession(const string &ipA,const string &ipB)
{
	//if session is new then store it in the map else add the packet in
	//the list of packets corresponding to the session.
	if(checkSession(ipA,ipB)=="")
	{
		list<packetInfo> listOfPac;
		listOfPac.push_back(objOfPacketInfo);
 		mapOfSession[ipA+","+ipB]=listOfPac;
	}
	else
	{
		mapOfSession[checkSession(ipA,ipB)].push_back(objOfPacketInfo);
	}
	
}

//function to get the session information between 2 machines
void ParsingPcap::displaySession(const string &file)
{
	if(mapOfOutput.find(file)==mapOfOutput.end())
	{
		checkFileAndParse(file,Utilities::getNameOfFile(file,"home/nikhil/pcap/pcapInfo/"));
	}

	auto iter=mapOfSession.begin();
	while(iter!=mapOfSession.end())
	{
		
		list<packetInfo>::iterator itrOfList;
		itrOfList=iter->second.begin();
		while(itrOfList!=iter->second.end())
		{
			//packet details.
			itrOfList++;
		}
		iter++;

	}

}

//function to write sessions to the CSV file.
bool ParsingPcap::writeSession(unordered_map<string,list<packetInfo>> mapOfSession,const string &file)
{
	ofstream pcapFileWrite;
	pcapFileWrite.open(file);
	if(pcapFileWrite.is_open())
	{
		unordered_map<string,list<packetInfo>>::iterator itrOfMap=mapOfSession.begin();
		list<packetInfo>::iterator itrOfList;
		int pckCount=0; 
		//writing column headers in the file
		pcapFileWrite<<"IP Address A"<<","<<"IP Address B"<<",";
		pcapFileWrite<<"Packet Count,Link,Packet Length,Source mac address,";
		pcapFileWrite<<"Destination mac address,Protocol,Source port,Destination port\n";
		while(itrOfMap!=mapOfSession.end())
		{
	      	//writing the first line of the session
			pcapFileWrite<<itrOfMap->first<<",";
			itrOfList=itrOfMap->second.begin();
			pckCount=1;
			while(itrOfList!=itrOfMap->second.end())
			{
				if(pckCount>1)
				{
					pcapFileWrite<<" "<<","<<" "<<",";
				}
				
				pcapFileWrite<<pckCount<<",";

				//writing link protocol
				if(itrOfList->link=="ethernet")
				{
					pcapFileWrite<<"Ethernet"<<",";
				}
				else
				{
					pcapFileWrite<<itrOfList->link<<",";
				}
				
				//writing captured length to the pcapfileinfo file.
				pcapFileWrite<<itrOfList->packetLen<<",";

				//writing source mac address to the pcapfileinfo file.
				for(int index=0;index<5;index++)
				{
				pcapFileWrite<<(int)itrOfList->srcMac[index]<<":";	
				}
				pcapFileWrite<<(int)itrOfList->srcMac[5]<<",";

				//writing destination mac address to the pcapfileinfo file.
				for(int index=0;index<5;index++)
				{
				pcapFileWrite<<(int)itrOfList->desMac[index]<<":";	

				}
				pcapFileWrite<<(int)itrOfList->desMac[5]<<",";
				

				//writing tcp protocol
				pcapFileWrite<<itrOfList->transProtocol<<",";

				//writing source and destination port numbers
				pcapFileWrite<<itrOfList->srcport<<",";
				pcapFileWrite<<itrOfList->desport;

				//changing the line
				pcapFileWrite<<"\n";
				
				pckCount++;	
				itrOfList++;
			}
			itrOfMap++;
		}
		
	}
	else
	{
		cout<<"session file can not be opened."<<endl;
	}
	pcapFileWrite.close();
}