#include <stdio.h>
#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <iostream>
#include <csignal>
#include <time.h>

#define sizeId "size"
#define lowerId "lower"
#define upperId "upper"
#define alphanumId "alphanum"
#define alphaId "alpha"
#define numId "num"
#define fileId "f"
#define ThreadsId "threads"

#define GPG_COMMAND "gpg --batch --passphrase "
#define GPG_FILE_OPTION " -d "
#define GPG_REDIRECTION  " >>/dev/null 2>>/dev/null"

#define ASCIIIni 33
#define ASCIIFi 126

int NumThreads = 1;

bool SolutionFinded=false;
std::string FilePath;
std::string Solucion;

std::vector<char> CharactersPool;

std::queue<std::string> PasswordsStringsPool;
std::queue<std::queue<std::string>> PasswordsPool;

std::condition_variable cvPasswordsPool;
std::mutex PasswordsPoolMutex;

std::atomic<int> Counter;
std::atomic<unsigned long> GlobalCounter;
int ClavesSegundoMedias;

void parseArguments(int argc,char *argv[], bool &alphaNum, bool &onlyLower, bool &onlyUpper, bool &onlyAlpha, bool &onlyNum, int &size);
void checkArguments(bool &alphaNum, bool &onlyLower, bool &onlyUpper, bool &onlyAlpha, bool &onlyNum);

void generateCharacterSet( bool &alphaNum, bool &onlyLower, bool &onlyUpper, bool &onlyAlpha, bool &onlyNum);

void generateCharacterSet(char ini,char fi);
void generateAlphaLowerCharacterSet();
void generateAlphaUpperCharacterSet();
void generateDigitCharacterSet();

void generatePool(int Size);
void checkPassword();

void signalHandler( int signum );

int main(int argc, char *argv[])
{
    clock_t t0, t1;

    CharactersPool=std::vector<char>();
    std::vector<std::thread> Threads=std::vector<std::thread>();
    PasswordsPool=std::queue<std::queue<std::string>>();
    PasswordsStringsPool=std::queue<std::string>();

    bool alphaNum=false,onlyLower=false,onlyUpper=false,onlyAlpha=false,onlyNum=false;
    int Size=-1;
    Counter=0;
    GlobalCounter=0;
    
    parseArguments(argc, argv, alphaNum, onlyLower, onlyUpper, onlyAlpha, onlyNum, Size);
    checkArguments(alphaNum,onlyLower,onlyUpper,onlyAlpha,onlyNum);

    generateCharacterSet(alphaNum,onlyLower,onlyUpper,onlyAlpha,onlyNum);

    Threads.push_back(std::thread(generatePool,Size));
    for(int i=0; i<NumThreads;i++)
    {
        Threads.push_back(std::thread(checkPassword));
    }

    signal(SIGINT, signalHandler); 

    printf("Characters Espace Pool %d\n",(int) CharactersPool.size());
    printf("Desplegando el cracker en %d hilos\n", NumThreads);

    ClavesSegundoMedias=NumThreads*256;

    while(!SolutionFinded)
    {
        ClavesSegundoMedias+=Counter;
        ClavesSegundoMedias/=2;
        Counter=0;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Comprobando "<<Counter<<" claves/s"<< std::endl;
        std::cout << "Cantidad de claves comprobadas "<<GlobalCounter<< std::endl;
        std::cout << "Cantidad de claves en la pool para comprobar "<<PasswordsPool.size()<< std::endl<< std::endl;
    }

    if(Solucion==std::string(""))
    {
        std::cout<<"La contraseña no se ha podido encontrar"<<std::endl;
        return EXIT_FAILURE;
    }
    
    for(int i=0;i<Threads.size();i++)
    {
        if(Threads.at(i).joinable())
        {
            Threads.at(i).join();
        }
    }

    std::cout <<std::endl<< "La contraseña es: " << Solucion << std::endl;
    std::string Comand("echo "+Solucion+" >> solucion");
    system(Comand.c_str());
    
    return EXIT_SUCCESS;
}

void generatePool(int Size)
{
    int i=0;

    PasswordsStringsPool.push("");
    std::string PasswordString;
    std::string Password;
    std::queue<std::string> PasswordsStringsQueue=std::queue<std::string>();

    std::mutex PasswordQueueReadyMutex;

    while(!SolutionFinded)
    {
        if(PasswordsStringsPool.size()==0)
        {
            SolutionFinded=true;
        }
        else
        {
            PasswordString=PasswordsStringsPool.front();
            PasswordsStringsPool.pop();

            for(i=0;i<CharactersPool.size();i++)
            {
                Password=std::string(PasswordString+CharactersPool[i]);

                switch(Size)
                {
                    case -1:
                    {
                        PasswordsStringsPool.push(Password);
                        PasswordsStringsQueue.push(Password);
                        break;
                    }
                    default:
                        if(Password.length()==Size)
                        {
                            PasswordsStringsQueue.push(Password);
                        }
                        else
                        {
                            PasswordsStringsPool.push(Password);
                        }
                        break;
                }
            }

            if(PasswordsStringsQueue.size()>0)
            {
                std::unique_lock<std::mutex> PasswordsPoolLock(PasswordsPoolMutex);
                PasswordsPool.push(PasswordsStringsQueue);
                PasswordsPoolLock.unlock();

                cvPasswordsPool.notify_one();

                PasswordsStringsQueue=std::queue<std::string>();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds((int) ((int)(PasswordsPool.size()*CharactersPool.size()/(ClavesSegundoMedias-(ClavesSegundoMedias/NumThreads)+1)*50))));
        }
    }
}

void checkPassword()
{
    std::string Password;
    std::mutex PasswordQueueReadyMutex;
    std::queue<std::string> PasswordsStringsQueue;

    while(!SolutionFinded)
    {
        std::unique_lock<std::mutex> PasswordQueueReadyLock(PasswordQueueReadyMutex);
		cvPasswordsPool.wait(PasswordQueueReadyLock, [] {return !PasswordsPool.empty(); });

		std::unique_lock<std::mutex> PasswordsPoolLock(PasswordsPoolMutex);
        PasswordsStringsQueue=PasswordsPool.front();
        PasswordsPool.pop();
        PasswordsPoolLock.unlock();

        while(PasswordsStringsQueue.size())
        {
            
		    Password = PasswordsStringsQueue.front();
            PasswordsStringsQueue.pop();

            std::string Command=GPG_COMMAND+std::string("\"")+Password+std::string("\"")+GPG_FILE_OPTION+FilePath+GPG_REDIRECTION;
            /*std::cout<<Command<<std::endl;*/
            if(system(Command.c_str())==0)
            {
                Solucion=Password;
                SolutionFinded=true;
            }
            Counter++;
            GlobalCounter++;
        }
    }
}
void checkArguments(bool &alphaNum, bool &onlyLower, bool &onlyUpper, bool &onlyAlpha, bool &onlyNum)
{
    if(onlyLower && onlyUpper)
    {
        onlyAlpha=true;
    }

    if(onlyAlpha)
    {
        onlyLower=false;
        onlyUpper=false;
    }

    if(onlyNum && onlyAlpha)
    {
        alphaNum=true;
        onlyNum=false;
        onlyAlpha=false;
    }

    if(alphaNum)
    {
        onlyAlpha=false;
        onlyNum=false;
        onlyLower=false;
        onlyUpper=false;
    }
}

void parseArguments(int argc,char *argv[],bool &alphaNum, bool &onlyLower, bool &onlyUpper, bool &onlyAlpha, bool &onlyNum, int &size)
{

    while(--argc>0)
    {
        if(*(++argv)[0]=='-')
        {

            if(std::string(&(*argv)[1])==std::string(sizeId))
            {
                size=atoi(*(++argv));
                argc--;
            }
            else if(std::string(&(*argv)[1])==std::string(alphanumId))
            {
                alphaNum=true;
            }
            else if(std::string(&(*argv)[1])==std::string(alphaId))
            {
                onlyAlpha=true;
            }
            else if(std::string(&(*argv)[1])==std::string(numId))
            {
                onlyNum=true;
            }
            else if(std::string(&(*argv)[1])==std::string(lowerId))
            {
                onlyLower=true;
            }
            else if(std::string(&(*argv)[1])==std::string(upperId))
            {
                onlyUpper=true;
            }
            else if(std::string(&(*argv)[1])==std::string(fileId))
            {
                FilePath=std::string(*(++argv));
                argc--;
            }
            else if(std::string(&(*argv)[1])==std::string(ThreadsId))
            {
                NumThreads=atoi(*(++argv));
                argc--;
            }
        }
    }
}

void generateAlphaLowerCharacterSet()
{
    generateCharacterSet('a','z');
}

void generateAlphaUpperCharacterSet()
{
    generateCharacterSet('A','Z');
}

void generateDigitCharacterSet()
{
    generateCharacterSet('0','9');
}

void generateCharacterSet(char ini,char fi)
{
    for(char i=ini;i<=fi;i++)
    {
        CharactersPool.push_back(i);
    }
}

void generateCharacterSet(bool &alphaNum, bool &onlyLower, bool &onlyUpper, bool &onlyAlpha, bool &onlyNum)
{
    if(alphaNum)
    {
        generateAlphaUpperCharacterSet();
        generateAlphaLowerCharacterSet();
        generateDigitCharacterSet();
    }
    else if(onlyNum)
    {
        generateDigitCharacterSet();

        if(onlyLower)
        {
            generateAlphaLowerCharacterSet();
        }

        if(onlyUpper)
        {
            generateAlphaUpperCharacterSet();
        }
    }
    else if(onlyAlpha)
    {
        generateAlphaUpperCharacterSet();
        generateAlphaLowerCharacterSet();
    }
    else if(onlyUpper)
    {
        generateAlphaUpperCharacterSet();
    }
    else if(onlyLower)
    {
        generateAlphaLowerCharacterSet();
    }
    else
    {
        generateAlphaUpperCharacterSet();
        generateAlphaLowerCharacterSet();
        generateDigitCharacterSet();
        CharactersPool.push_back('!');
        generateCharacterSet('#','&');
        generateCharacterSet('(','+');
        generateCharacterSet('-','/');
        generateCharacterSet('<','@');
        generateCharacterSet('[','_');
        generateCharacterSet('{','~');
    }
}

void signalHandler(int signum) 
{
    if(signum==SIGINT)
    {
        std::cout << "Interrupt signal (" << signum << ") received.\n";
        exit(signum); 
    }
    else
    {
        signal(SIGINT, signalHandler);
    }
    
}