//Structure for Global header.
struct globalHeader
{
	unsigned int magicNumber;
	unsigned short int majVersion;
	unsigned short int minVersion;
	unsigned int thisZone;
	unsigned int preCapture;
	unsigned int snapLegth;
	unsigned int linkProtocol;	
};

//Structure for Packet header.
struct packetHeader
{
	unsigned int tsSec;
	unsigned int tsUsec;
	unsigned int capturedLength;
	unsigned int orignalLength;
};

//Structure for Ethernet header.
struct ethernetHeader
{
	unsigned char destMacAdd[6];
	unsigned char srcMacAdd[6];
	unsigned short int ethType;
};

//Structure for IPV4 header
struct ipv4Header
{
	unsigned char versionAndHlength;
	unsigned char typeOfService;
	unsigned short int totalLength;
	unsigned short int identification;
	unsigned short int fragOffset;
	unsigned char timeToLive;
	unsigned char protocol;
	unsigned short int headChecksum;
	unsigned char srcIpAdd[4];
	unsigned char destIpAdd[4];
};

//Structure for IPV6 header.
struct ipv6Header
{
	unsigned short int payloadLength;
	unsigned char nextHeader;
	unsigned char hopLimit;
	unsigned short int srcaddress[8];
	unsigned short int destaddress[8];
};

//Structure for TCP header.
struct tcpHeader
{
	unsigned short int srcPort;
	unsigned short int destPort;
	unsigned int seqNumber;
	unsigned int ackNumber;
	unsigned short int hlengthAndbits;
	unsigned short int windowSize;
	unsigned short int tcpChecksum;
	unsigned short int urgentPointers;
};

//Structure for UDP header.
struct udpHeader
{
	unsigned short int srcPort;
	unsigned short int desPort;
	unsigned short int length;
	unsigned short int checksum;
};

//structure to store required information of a packet
struct packetInfo
{
	const char* link;					//link protocol.
	const char* ip;						//internet protocol
	unsigned int packetLen;				//packet length
	unsigned const char* srcMac;		//source mac add
	unsigned const char* desMac;		//dest mac add
	const char* transProtocol;			//transport protocol
	unsigned short int srcport;			//source port number
	unsigned short int desport;			//destination port number		
};