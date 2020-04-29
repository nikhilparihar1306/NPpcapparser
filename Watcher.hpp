#include<queue>
#include<list>
#include<unordered_map>
#include<sys/inotify.h>


using namespace std;

class Watcher
{
    int fileDesc;
    int watchDesc;
    int noOfDir=0;
    unordered_map<int,string> mapOfDir;
    list<string> listOfFiles;

    
    public:
    bool keepRunning;
    char* writeDetailDirPath;

    //Constructor
    Watcher();

    const char* rootDir;
    static void* runthread(void* object);
    int watcher();
    int initialiseFileDesc();
    int walkDirAndSubdir(const char* rootDir);
    int addWatch(int fileDesc,const char* directory,unsigned long mask);
    int processEvents(queue<inotify_event*> &qOfEvents,int fileDesc);
    int getEvents(int fileDesc);
    int readEvents(queue<inotify_event*> &qOfEvents,int fileDesc);
    int handleEvents(queue<inotify_event*> &qOfEvents);
    string getFilePath(int watchDesc,string& fileName);
    int terminateWatcher();

};