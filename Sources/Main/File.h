#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <windows.h>
#include <vector>

namespace
{
	const int ARCHITECTURE_X86 = 86;
	const int ARCHITECTURE_X64 = 64;
}

class File
{
public:
	File(const std::string& filePath);
	~File();
	

private:
	std::string m_filePath;
	std::fstream m_readTheFile;
	IMAGE_DOS_HEADER m_dosHeader;
	IMAGE_FILE_HEADER m_fileHeader;
	int m_architecture = 0;
	void checkAndOpenFile();
	bool checkPeOrNot();
	int checkArchitecture();
	void printIat();
	void injectDll();
	void patchingIat(LPCSTR dllNamePtr);

};

