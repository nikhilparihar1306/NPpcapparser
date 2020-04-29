#include<iostream>
#include<fstream>
#include<arpa/inet.h>
#include<pthread.h>
#include<sys/stat.h>
#include<dirent.h>
#include<string>
#include<cstring>
#include "ParsingPcap.hpp"
#include "Utilities.hpp"
#include "Watcher.hpp"

using namespace std;

#define PCAPINFO 9
#define PCAPSESSION 12
#define ALL_RIGHTS 07777

class PcapParser
{
    public:
    //variable for storing path of the directory where information of pcap details will be stored.
    char* writeDetailDirPath;		
    //variable for storing path of the directory where information of pcap session will be stored.
    char* writeSessionDirPath;

    //object of ParsingPcap class.
    ParsingPcap *objOfParsingPcap=objOfParsingPcap->getInstance();

    bool getListOfFiles(const char* rootDir);
    bool sendToParse(string &filePath);
    bool createOutputDirectory(const char* rootDir);
};

//funtion to get the list of files from the directory and send them for parsing
bool PcapParser::getListOfFiles(const char* rootDir)
{
    list<string> listOfFile;
    Utilities::getList(rootDir,listOfFile,'f');

    while(!listOfFile.empty())
    {
        sendToParse(listOfFile.front());
        listOfFile.pop_front();
    }
}

//function to send a file for parsing
bool PcapParser::sendToParse(string &filePath)
{   
    //sending file to the parser.
    objOfParsingPcap->checkFileAndParse(filePath,
    Utilities::getNameOfFile(filePath,writeDetailDirPath));
}

//function to create the output directories
bool PcapParser::createOutputDirectory(const char* rootDir)
{
    //making directory paths
    writeDetailDirPath= new char[strlen(rootDir)+PCAPINFO+1];
    writeSessionDirPath=new char[strlen(rootDir)+PCAPSESSION+1];
    
    strcpy(writeDetailDirPath,rootDir);
    strcpy(writeSessionDirPath,rootDir);

    strcat(writeDetailDirPath,"/pcapInfo/");
    strcat(writeSessionDirPath,"/pcapSession/");

    //checking if the directories already exist or not
    if(!Utilities::isPathExists(writeDetailDirPath))
    {
        //creating directory
        if(mkdir(writeDetailDirPath,ALL_RIGHTS)==-1)
        {
            cout<<"Directory pcapinfo can not be created."<<endl;
            return false;
        }
    }
    if(!Utilities::isPathExists(writeSessionDirPath))
    {
        if(mkdir(writeSessionDirPath,ALL_RIGHTS)==-1)
        {
            cout<<"Directory pcapSession can not be created."<<endl;
            return false;
        }
    }
    //setting the value of session output file path.
    objOfParsingPcap->writeSessionPath=writeSessionDirPath;
    return true;
}

//Main funtion to parse the pcapfile
int main()
{
	bool keepRunning=true;		    //to keep running the user menu.
	char choice;		            //choice of user.
	
	string directory="";            //variable for storing directory path
    string readFilePath="";		    //variable for storing path of the file that needs to be read.

	Watcher objOfWatcher;           //object of watcher class
    PcapParser objOfPcapParser;     //object of pcapparser class

	//object of ParsingPcap class.
	ParsingPcap *objOfParsingPcap=objOfParsingPcap->getInstance();
    
    pthread_t watcherThread;	    //Creating thread for watcher.
	
	while(true)
	{
		//taking directory path from user.
		cout<<"Enter the path of the directory which contains pcap files "<<endl;
		getline(cin,directory);
		//checking if path is correct or not.
		if(Utilities::isPathExists(directory))
		{ 
            objOfWatcher.rootDir=directory.c_str();		
			pthread_create(&watcherThread,NULL,&Watcher::runthread,&objOfWatcher);
            cout<<"Watcher is running."<<endl;

            //creating output directories
            if(!objOfPcapParser.createOutputDirectory(directory.c_str()))
            {
                cout<<"ERROR in creating output location."<<endl;
                return 0;
            }
            //setting output dir path in watcher class
            objOfWatcher.writeDetailDirPath=objOfPcapParser.writeDetailDirPath;

            //getting the list of pcap files from the directory and parse them.
            objOfPcapParser.getListOfFiles(directory.c_str());
			break;
		}
		else
		{
			cout<<"Enter valid Path."<<endl;
            continue;
		}
	}
    do
    {
        choice=Utilities::userInput();
        switch(choice)
        {
            case '1':
                    //showing instructions.
                    Utilities::instructions();
                    break;
            
            case '2':
                    //taking directory path from user.
		            while(true)
                    {
                        cout<<"Enter Directory Path: "<<endl;
		                getline(cin,directory);
                        if(Utilities::isPathExists(directory))
                        {
                            //getting the list of pcap files from the directory and parse them.
                            objOfPcapParser.getListOfFiles(directory.c_str());
                            break;
                        }
                        else
                        {
                            cout<<"Enter Valid Input."<<endl;
                            continue;
                        }
                    }
                    break;
            case '3' :
                    while(true)
                    {
                        cout<<"Enter file Path."<<endl;
                        getline(cin,readFilePath);
                        if(Utilities::isPathExists(readFilePath))
                        {
                            objOfParsingPcap->checkFileAndParse(readFilePath,
								Utilities::getNameOfFile(readFilePath,objOfPcapParser.writeDetailDirPath));
                            
                            break;
                        }
                        else
                        {
                            cout<<"Invalid Input."<<endl;
                        }
                    }
                    break;
            case '4' :   
                    cout<<"Current functionality of displaying the session detail on console is disabled."<<endl;
                    cout<<"Check CSV file of session details in 'pcapSession' directory."<<endl;
                    break;

            case '5' :
                    objOfWatcher.terminateWatcher();
                    while(!pthread_join(watcherThread,NULL)){}
                    cout<<"Exit"<<endl;
                    keepRunning=false;
                    break;
        }
    } while(keepRunning);
	return 0;
}
