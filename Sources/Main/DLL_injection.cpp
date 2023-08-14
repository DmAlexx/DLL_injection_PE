#include <iostream>
#include <fstream>
#include <Windows.h>
#include "File.h"
#include "conio.h"


int main(int argc, char* argv[]) {
    if (argc != 2) 
    {
        std::cout << "Usage: program_name <file_path>" << std::endl;
        std::cout << "You didn't enter a file_path" << std::endl;
        return 1;
    }

    File researchFile(argv[1]);

    _getch();
    return 0;
}