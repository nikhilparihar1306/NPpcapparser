#include<iostream>
#include<string>
#include<cstring>
#include<list>
#include<sys/stat.h>
#include<dirent.h>
#include<ios>
#include<limits>
#include"Utilities.hpp"

using namespace std;

void Utilities::instructions()
{
    cout<<"---------------------------------------------------------------------------------------"<<endl;
    cout<<"1. It will tak a few moments to get the files and parse them."<<endl;
    cout<<"2. you will be given a menu from which you have to select a particular option.";
    cout<<"(Please select valid option.)"<<endl;
    cout<<"3. The information/packet detail will be generated in a csv file and it will be located ";
    cout<<"inside 'pcapInfo' directory."<<endl;
    cout<<"4. The information about sessions  will be generated in a csv file and it will be located ";
    cout<<"inside 'pcapSession' directory."<<endl;
    cout<<"---------------------------------------------------------------------------------------"<<endl;
}

char Utilities::userInput()
{
string choice="";

    while(true)
    {
        userMenu();
        getline(cin,choice);
        //checking the input length 
        if(choice.length()>1)
        {
            cout<<"Enter Valid input."<<endl;
            continue;
        }
        if(choice=="1" || choice=="2"|| choice=="3"|| choice=="4" || choice=="5" )
        {
            return choice[0];
        }
        else
        {
            cout<<"Enter valid input."<<endl;
            continue;
        }
    }
}

void Utilities::userMenu()
{
    cout<<"Press 1 for instructions."<<endl;
    cout<<"Press 2 for adding directories to watch."<<endl;
    cout<<"Press 3 for providing path to pcap File."<<endl;
    cout<<"Press 4 for sessions."<<endl;
    cout<<"Press 5 to exit."<<endl;
}

bool Utilities::isPathExists(const string &path)
{
    struct stat buffer;
    return (stat(path.c_str(),&buffer)==0);
}

string Utilities::getExt(char *fileName)
{
    string file=fileName;
    return file.substr(file.find_last_of('.'));
}

void Utilities::getList(const char* rootDir,list<string> &listOfFiles,char param)
{
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
            char* tempdir=new char[strlen(rootDir)+strlen(dir->d_name)+2];
            strcpy(tempdir,rootDir);
            strcat(tempdir,"/");
            strcat(tempdir,dir->d_name);

            if((dir->d_type==DT_DIR))
            {
                if(!((dir->d_name)[0]=='.'))
                {   
                    getList(tempdir,listOfFiles,param);
                }
            }
            else
            {
                if(Utilities::getExt(dir->d_name)==".pcap")
                {
                    listOfFiles.push_back(tempdir);   
                }
            }
            delete(tempdir);
        }
        
    }
    closedir(direct);
}

string Utilities::getNameOfFile(const string &filePath,const string &location)
{
    int start=0;
    int end=0;
    string writeFile=location;
    
    start=filePath.find_last_of('/');
    end=filePath.find_last_of('.');
    writeFile.append(filePath.substr(start+1,end-start-1));

    if(!isPathExists(writeFile+".csv"))
    {
        return writeFile+".csv";
    }
    
    int index=1;
    while(isPathExists(writeFile+"-copy("+to_string(index)+")"+".csv"))
    {
        index++;
    }
    return writeFile+"-copy("+to_string(index)+")"+".csv";
}

