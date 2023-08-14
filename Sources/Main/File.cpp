#include "File.h"

File::File(const std::string& filePath)
	: m_filePath(filePath)
{
	checkAndOpenFile();
	
}

File::~File()
{
	m_readTheFile.close();
}

void File::checkAndOpenFile()
{
	m_readTheFile.open(m_filePath, std::ios::in | std::ios::out | std::ios::binary);
	if (!m_readTheFile.is_open())
	{
		std::cout << "Error open " << m_filePath.substr(m_filePath.find_last_of("\\") + 1, std::string::npos) << " file" << std::endl;
		perror("");
        return;
	}
    else
    {
        if (checkPeOrNot())
        {
            m_architecture = checkArchitecture();
            if (m_architecture == 0)
            {
                std::cerr << "Unknown architecture." << std::endl;
                return;
            }
            else
            {
                printIat();
                injectDll();        
            }
        }
        else
        {
            return;
        }
    }
}

bool File::checkPeOrNot()
{
    // Read the DOS header
    IMAGE_DOS_HEADER dosHeader;
    m_readTheFile.seekg(0);
    m_readTheFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
    m_dosHeader = dosHeader;

    // Check if the DOS header has the "MZ" magic number
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "The file is not a valid PE file (missing DOS header)." << std::endl;
        return false;
    }

    // Seek to the PE header offset
    m_readTheFile.seekg(dosHeader.e_lfanew);

    // Read the PE signature and the COFF header
    DWORD peSignature;
    IMAGE_FILE_HEADER fileHeader;
    m_readTheFile.read(reinterpret_cast<char*>(&peSignature), sizeof(DWORD));
    m_readTheFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER));
    m_fileHeader = fileHeader;

    // Check if the PE signature is valid and if the file is an executable
    if (peSignature != IMAGE_NT_SIGNATURE || (fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
    {
        std::cout << "The file is not a valid PE file (invalid PE signature or not an executable)." << std::endl;
        return false;
    }

    // If all checks pass, the file a valid PE
    std::cout << "The file is a valid PE executable." << std::endl;
    return true;
}

int File::checkArchitecture()
{
    // Read the Magic value
    WORD magic_number;
    m_readTheFile.read(reinterpret_cast<char*>(&magic_number), sizeof(WORD));

    if (magic_number == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // 32-bit PE
    {
        return ARCHITECTURE_X86; // Return 32-bit architecture
    }
    else if (magic_number == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // 64-bit PE
    {
        return ARCHITECTURE_X64; // Return 64-bit architecture
    }

    // If unable to determine the architecture, return 0
    return 0;
}



void File::printIat()
{
    IMAGE_DATA_DIRECTORY iatDirectory;
    IMAGE_IMPORT_DESCRIPTOR importDescriptor;

    // Find the Import Directory Entry
    m_readTheFile.seekg(sizeof(IMAGE_DOS_HEADER) + m_dosHeader.e_lfanew + sizeof(DWORD) +
    sizeof(IMAGE_FILE_HEADER) + m_fileHeader.SizeOfOptionalHeader);
    m_readTheFile.read(reinterpret_cast<char*>(&iatDirectory), sizeof(IMAGE_DATA_DIRECTORY));

    // Check if the Import Directory Entry is valid
    if (iatDirectory.VirtualAddress == 0 || iatDirectory.Size == 0)
    {
        std::cerr << "No Import Directory found." << std::endl;
        return;
    }

    // Seek to the start of the Import Descriptor array
    m_readTheFile.seekg(iatDirectory.VirtualAddress);

    // Read the Import Descriptors
    while (true)
    {
        m_readTheFile.read(reinterpret_cast<char*>(&importDescriptor), sizeof(IMAGE_IMPORT_DESCRIPTOR));

        if (importDescriptor.Name == 0)
        {
            break;
        }

        // Read the DLL name
        std::string dllName;
        m_readTheFile.seekg(m_dosHeader.e_lfanew + importDescriptor.Name);
        std::getline(m_readTheFile, dllName, '\0');

        // Print DLL name and imported functions
        std::cout << "DLL Name: " << dllName << std::endl;

        // Read and print the imported functions
        IMAGE_THUNK_DATA thunkData;
        m_readTheFile.seekg(importDescriptor.FirstThunk);

        while (true)
        {
            m_readTheFile.read(reinterpret_cast<char*>(&thunkData), sizeof(IMAGE_THUNK_DATA));

            if (thunkData.u1.AddressOfData == 0)
            {
                break;
            }
                
            if (thunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Imported by ordinal
                std::cout << "   Ordinal: " << (thunkData.u1.Ordinal & 0xFFFF) << std::endl;
            }
            else
            {
                // Imported by name
                IMAGE_IMPORT_BY_NAME importByName;
                m_readTheFile.seekg(m_dosHeader.e_lfanew + thunkData.u1.AddressOfData);
                m_readTheFile.read(reinterpret_cast<char*>(&importByName), sizeof(IMAGE_IMPORT_BY_NAME));
                std::cout << "   Function: " << importByName.Name << std::endl;
            }
        }
    }
}

void File::injectDll()
{
    std::string dllName;

    if (m_architecture == ARCHITECTURE_X86)
    {
        dllName = "for_x86.dll";
    }
    else if (m_architecture == ARCHITECTURE_X64)
    {
        dllName = "for_x64.dll";
    }

    std::ifstream dllFile(dllName, std::ios::binary | std::ios::in);

    if (!dllFile.is_open())
    {
        std::cerr << "Failed to open the DLL file." << std::endl;
        return;
    }

    // Read the contents of the DLL into a vector
    std::vector<uint8_t> dllContent((std::istreambuf_iterator<char>(dllFile)), std::istreambuf_iterator<char>());

    // Append the DLL contents to the executable
    m_readTheFile.seekg(0, std::ios::end);
    std::streampos fileSize = m_readTheFile.tellg();
    m_readTheFile.seekg(0, std::ios::beg);

    std::vector<uint8_t> exeContent((std::istreambuf_iterator<char>(m_readTheFile)), std::istreambuf_iterator<char>());
    exeContent.insert(exeContent.end(), dllContent.begin(), dllContent.end());

    // Rewrite the modified content back to the executable
    m_readTheFile.close();
    std::ofstream modifiedExe(m_filePath, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!modifiedExe.is_open())
    {
        std::cerr << "Failed to write modified executable." << std::endl;
        return;
    }

    modifiedExe.write(reinterpret_cast<const char*>(exeContent.data()), exeContent.size());

    std::cout << "DLL injected successfully." << std::endl;
    patchingIat(dllName.c_str());
}


void File::patchingIat(LPCSTR dllNamePtr)
{
    IMAGE_DATA_DIRECTORY iatDirectory;
    IMAGE_IMPORT_DESCRIPTOR importDescriptor;

    // Find the Import Directory Entry
    m_readTheFile.seekg(sizeof(IMAGE_DOS_HEADER) + m_dosHeader.e_lfanew + sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) + m_fileHeader.SizeOfOptionalHeader);
    m_readTheFile.read(reinterpret_cast<char*>(&iatDirectory), sizeof(IMAGE_DATA_DIRECTORY));

    // Check if the Import Directory Entry is valid
    if (iatDirectory.VirtualAddress == 0 || iatDirectory.Size == 0)
    {
        std::cerr << "No Import Directory found." << std::endl;
        return;
    }

    // Calculate the RVA (Relative Virtual Address) of the IAT
    DWORD iatRva = iatDirectory.VirtualAddress;

    // Seek to the start of the Import Descriptor array
    m_readTheFile.seekg(iatRva);

    // Iterate through the Import Descriptors
    while (true)
    {
        m_readTheFile.read(reinterpret_cast<char*>(&importDescriptor), sizeof(IMAGE_IMPORT_DESCRIPTOR));

        if (importDescriptor.Name == 0)
        {
            break; // End of Import Descriptors
        }

        // Calculate the RVA of the Original First Thunk (IAT entries)
        DWORD iatEntryRva = importDescriptor.OriginalFirstThunk;

        // Convert RVA to file offset
        DWORD iatEntryOffset = iatEntryRva - m_dosHeader.e_lfanew;

        // Seek to the start of the IAT entries
        m_readTheFile.seekg(iatEntryOffset);

        // Iterate through the IAT entries
        IMAGE_THUNK_DATA thunkData;
        while (true)
        {
            m_readTheFile.read(reinterpret_cast<char*>(&thunkData), sizeof(IMAGE_THUNK_DATA));

            if (thunkData.u1.AddressOfData == 0)
            {
                break; // End of IAT entries for this DLL
            }

            // Calculate the RVA of the imported function
            DWORD importAddressRva = thunkData.u1.AddressOfData;

            // Convert RVA to file offset
            DWORD importAddressOffset = importAddressRva - m_dosHeader.e_lfanew;

            // Seek to the import address offset
            m_readTheFile.seekg(importAddressOffset);

            // Read and update the import address with the actual function address in the process
            DWORD actualFunctionAddress = reinterpret_cast<DWORD>(GetProcAddress(GetModuleHandleA(dllNamePtr), "DllMain"));

            // Seek to the IAT entry and update it with the actual function address
            m_readTheFile.seekg(importAddressOffset);
            m_readTheFile.write(reinterpret_cast<const char*>(&actualFunctionAddress), sizeof(DWORD));
        }
    }

    std::cout << "IAT patched successfully." << std::endl;
    HMODULE hDll = LoadLibraryA(dllNamePtr);
}
