#include<iostream>
#include<string>

using namespace std;

class Utilities
{
    public:
    static char userInput();
    static void userMenu();
    static void instructions();
    static void isInteger(const string &input);
    static bool isPathExists(const string &path);
    static string getExt(char *fileName);
    static void getList(const char* rootDir,list<string> &listOfFiles,char param);
    static string getNameOfFile(const string &filePath,const string &location);
};