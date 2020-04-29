#include<iostream>
#include<sys/inotify.h>
#include<unistd.h>
#include<poll.h>
#include<dirent.h>
#include<queue>
#include<string>
#include<cstring>
#include "Watcher.hpp"
#include "ParsingPcap.hpp"
#include "Utilities.hpp"

using namespace std;

#define MAX_EVENT_MONITOR 2048
#define NAME_LEN 32 //file name length
#define EVENT_SIZE (sizeof(struct inotify_event)) //size of 1 event
#define BUFFER_LEN (MAX_EVENT_MONITOR*(EVENT_SIZE+NAME_LEN)) //buffer length
#define EVENTS IN_CREATE | IN_MODIFY | IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_CLOSE_WRITE

Watcher::Watcher()
{
    //intialise File Descriptor
    fileDesc=initialiseFileDesc();
    //initialise Watch descriptor
    watchDesc=0;
    //initialise keeprunning variable
    keepRunning=true;

}

void* Watcher::runthread(void* object)
{
    Watcher *objOfWatcher=reinterpret_cast<Watcher*>(object);
    objOfWatcher->watcher();
}

int Watcher::watcher()
{   
    //If File Descriptor has been successfully initialised 
    if(fileDesc>0)
    {
        //Queue to store the events 
        queue<inotify_event*> qOfEvents;

        walkDirAndSubdir(rootDir);

        unordered_map<int,string>::iterator iter=mapOfDir.begin();
        while(iter!=mapOfDir.end())
        {
            iter++;
        }

        if(noOfDir>0)
        {
            /*wait for the events and if encountered, process them 
            otherwise terminate.*/
            processEvents(qOfEvents,fileDesc);
        }
        
        //closing the inotify instance
        close(fileDesc);
        cout<<"Terminating watcher."<<endl;
    }
}

int Watcher::initialiseFileDesc()
{
    int fileDesc=0;
    //initialising the inotify instance
    fileDesc=inotify_init1(IN_NONBLOCK);

    if(fileDesc<0)
    {
        perror("Error in initialising.");
    }
    else
    {
        cout<<"Watcher is successfully initialised."<<endl;
        return fileDesc;
    }
}

//Traversing the root directory and it's subdirectories to add watch to them.
int Watcher::walkDirAndSubdir(const char* rootDir)
{
    //adding watch to the directory.
    watchDesc=addWatch(fileDesc,rootDir,EVENTS);

    //if watch descriptor is positive then inserting it into the map.
    if(watchDesc>0)
    {
        mapOfDir[watchDesc]=rootDir;
        noOfDir++;
    }
    
    //pointer for directory entry.
    struct dirent *dir;

    //opendir returns pointer of DIR type.
    DIR *direct=opendir(rootDir);
    if(direct==NULL)
    {
        cerr<<"ERROR : Can not open directory."<<endl;
    }
    else
    {
        while((dir=readdir(direct))!=NULL)
        {
            string tempdir=rootDir;
            tempdir.append("/");
            if((dir->d_type==DT_DIR))
            {
                if(!((dir->d_name)[0]=='.'))
                {   
                    tempdir.append(dir->d_name);
                    const char* newdir=tempdir.c_str();
                    walkDirAndSubdir(newdir);
                    
                }
            }
            else
            {
                if(Utilities::getExt(dir->d_name)==".pcap")
                {
                    listOfFiles.push_back(tempdir.append(dir->d_name));
                    
                }
                

            }
        }
    }
    closedir(direct);
    return 0;
}

//Adding watch to the directory
int Watcher::addWatch(int fileDesc,const char* directory,unsigned long mask)
{
    int watchDesc=0;
    //Adding watch
    watchDesc=inotify_add_watch(fileDesc,directory,mask);

    if(watchDesc<0)
    {
        cout<<"Can not add watch to "<<directory<<endl;
        perror(" ");
    }
    else
    {
        return watchDesc;
    }
}

//processing Events
int Watcher::processEvents(queue<inotify_event*> &qOfEvents,int fileDesc)
{
    while(keepRunning)
    {
        if(getEvents(fileDesc)>0)
        {
            int noOfEvents=0;
            noOfEvents=readEvents(qOfEvents,fileDesc);
            
            if(noOfEvents>0)
            {
                handleEvents(qOfEvents);
            }
        }
    }
    return 0;
}

//get Events
int Watcher::getEvents(int fileDesc)
{
    //check if any event happens otherwise return.
    struct pollfd pfd = { fileDesc, POLLIN, 0 };
    return poll(&pfd, 1, 0);
}

//read events then store them in a queque to process later and returns no of events
int Watcher::readEvents(queue<inotify_event*> &qOfEvents,int fileDesc)
{
    char *buffer=new char[BUFFER_LEN]; //buffer for storing the events
    int readLength=0;   //No. of bytes return by the read funtion
    int bufferIndex=0;  //index of buffer from where event will start
    struct inotify_event* eventPointer; //pointer to the event
    int noOfEvents=0;
    readLength=read(fileDesc,buffer,BUFFER_LEN);

    if(readLength<0)
    {
        perror("Reading error");
    }
    while(bufferIndex<readLength)
    {
        eventPointer=(struct inotify_event*) &buffer[bufferIndex];
        //adding event in the queque.
        qOfEvents.push(eventPointer);
        bufferIndex+=EVENT_SIZE+eventPointer->len;
        noOfEvents++;
    }
    delete(buffer);
    return noOfEvents;
}

//handle events
int Watcher::handleEvents(queue<inotify_event*> &qOfEvents)
{
    struct inotify_event* event;
    //getting object of ParsingPcap class
    ParsingPcap* objOfParsingPcap=objOfParsingPcap->getInstance();
    //variable for storing filename
    string fileName;
    string filePath;

    while(!qOfEvents.empty())
    {
        //taking the first event from the queque
        event=qOfEvents.front();
        //checking the type of the event
        if(event->mask & IN_CREATE)
        {
            if(event->mask & IN_ISDIR)
            {
                cout<<"DIRECTORY CREATED : "<<event->name<<endl;
            }
            else
            {
                cout<<"FILE CREATED : "<<event->name<<endl;
            }
        }
        if(event->mask & IN_MOVED_FROM)
        {
            if(event->mask & IN_ISDIR)
            {
                cout<<"DIRECTORY MOVED FROM : "<<event->name<<endl;
            }
            else
            {
                cout<<"FILE MOVED FROM : "<<event->name<<endl;
            }
        }
        if(event->mask & IN_MOVED_TO)
        {
            if(event->mask & IN_ISDIR)
            {
                cout<<"DIRECTORY MOVED TO : "<<event->name<<endl;
            }
            else
            {
                cout<<"FILE MOVED TO : "<<event->name<<endl;
                fileName=event->name;
                filePath=getFilePath(event->wd,fileName);
                if(Utilities::getExt((char*)event->name)==".pcap")
                {
                    //sending file for parsing.
                    objOfParsingPcap->checkFileAndParse(filePath,
                        Utilities::getNameOfFile(filePath,writeDetailDirPath));
                }
            }
        }
        if(event->mask & IN_DELETE)
        {
            if(event->mask & IN_ISDIR)
            {
                cout<<"DIRECTORY DELETED : "<<event->name<<endl;
            }
            else
            {
                cout<<"FILE DELETED : "<<event->name<<endl;
            }
        }
        if(event->mask & IN_CLOSE_WRITE)
        {
            cout<<"File for writing is closed : "<<event->name<<endl;
            fileName=event->name;
            filePath=getFilePath(event->wd,fileName);
            if(Utilities::getExt((char*)event->name)==".pcap")
            {
                //sending file for parsing.
                objOfParsingPcap->checkFileAndParse(filePath,
                    Utilities::getNameOfFile(filePath,writeDetailDirPath));
            }
        }
        //removing the event that has been handled.
        qOfEvents.pop();
    }
    return 0;
}

string Watcher::getFilePath(int watchDesc, string &fileName)
{
    auto iter=mapOfDir.find(watchDesc);
    return (iter->second+"/"+fileName);
}

int Watcher::terminateWatcher()
{
    keepRunning=false;
    return 0;
}
