NPPpcapparser
This application takes pcapfiles and parse them on the basis of it's structure and write the ouput in a human readable CSV format.

Compile the program with the following command(if using g++ compiler) :
" g++ PcapParser.cpp ParsingPcap.cpp Watcher.cpp Utilities.cpp -lpthread "

The program contains following files :
1)Structures(.hpp)
This file contains the structure of all the headers in the pcap file.
For example, global header,ethernet header,packet header etc.

2)PcapParser(.hpp and .cpp)
This is file which contains a class "PcapParser" and "main method". The main method takes the directory path from the user and add it to the watch(making seperate thread for the wathcer). Then the list of pcap files get extracted from the directory and send to parse.
This will also create the directories where the outputs will be stored.
Details of packets will be stored in a csv file inside "PCAPINFO" directory.
Details of session will be stored in a csv file inside "PCAPSESSION" directory.

3)ParsingPcap(.hpp and .cpp)
This class is the main class for parsing the pcap file. this takes the pcap file, parse it, write the details of packets in a csv file and prepare the session for the pcap file, write it in a csv file.

4)Watcher(.hpp and .cpp)
This file keeps a watch on the directories. and if any changes happen on runtime then this file takes care of it and handles the cases.

5)Utilities(.hpp and .cpp)
This is the utility class which contains static method like checkingFilepath. checking extension of file, taking input from user etc.
This class has methods for general purpose which does not belong to any specific task/category.

