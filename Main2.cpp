#include <iostream>
#include "sha2562.h"
 
using std::string;
using std::cout;
using std::endl;
 
int main(int argc, char *argv[])
{
    string output1;
    string input = "Addio e Grazie per il Pesce";

    if (argc > 1) {

        cout <<"quack" << endl;

        input = argv[1];
        output1 = sha256(input);

    } else {

        output1 = sha256(input);

    }
    
 
    cout << "sha256('"<< input << "'):" << output1 << endl;
    return 0;
}