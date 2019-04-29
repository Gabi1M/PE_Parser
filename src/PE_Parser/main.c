#include <windows.h>
#include <stdio.h>

DWORD rvaToFa(IMAGE_DOS_HEADER* dosHeader, DWORD rva)
{
    if (rva == 0)
    {
        printf("undef\n\n");
        return -1;
    }
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        if (rva >= sectionHeader[i].VirtualAddress && rva < (sectionHeader[i].Misc.VirtualSize + sectionHeader[i].VirtualAddress))
        {
            return (rva - sectionHeader[i].VirtualAddress) + sectionHeader[i].PointerToRawData;
        }
    }
    return 0;
}

int main(int argc, char** argv)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hFileMapping = NULL;

    BYTE* fileData = NULL;
    DWORD fileSize = 0;
    DWORD iByte = 0;

    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS* ntHeaders;


    if (argc != 2)
    {
        printf("Need one parameter .exe or .dll file!\n");
        system("pause");
        return -1;
    }

    hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed with error code 0x%X\n", GetLastError());
        goto cleanup;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0)
    {
        printf("GetFileSize failed with error code 0x%X\n",GetLastError());
        goto cleanup;
    }

    hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hFileMapping == NULL)
    {
        printf("CreateFileMappingA failed with error code 0x%X\n", GetLastError());
        goto cleanup;
    }

    fileData = (BYTE*)MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (fileData == NULL)
    {
        printf("MapViewOfFile failed with error code 0x%X\n", GetLastError());
        goto cleanup;
    }

    //
    //
    //

    dosHeader = (IMAGE_DOS_HEADER*)fileData;
    if (dosHeader->e_magic != 'ZM')
    {
        printf("File is not MZ!\n");
        goto cleanup;
    }

    ntHeaders = (IMAGE_NT_HEADERS*)(fileData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != 'EP')
    {
        printf("File is not PE!\n");
        goto cleanup;
    }

    //
    //
    //

    printf("File Header:\n\n");
    printf("-Machine: 0x%X\n\n",ntHeaders->FileHeader.Machine);
    printf("-NumberOfSections: 0x%X\n\n", ntHeaders->FileHeader.NumberOfSections);
    printf("-Characteristics: 0x%X\n\n", ntHeaders->FileHeader.Characteristics);
    
    printf("Optional Header:\n\n");
    printf("-AddressOfEntryPoint: 0x%X\n\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("-ImageBase: 0x%X\n\n", ntHeaders->OptionalHeader.ImageBase);
    printf("-SectionAlignment: 0x%X\n\n", ntHeaders->OptionalHeader.SectionAlignment);
    printf("-FileAlignment: 0x%X\n\n", ntHeaders->OptionalHeader.FileAlignment);
    printf("-Subsystem: 0x%X\n\n", ntHeaders->OptionalHeader.Subsystem);
    printf("-NumberOfRvaAndSizes: 0x%X\n\n", ntHeaders->OptionalHeader.NumberOfRvaAndSizes);

    printf("Sections: \n\n");

    DWORD fileAdress = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections;i++)
    {
        if (rvaToFa(dosHeader, sectionHeader[i].VirtualAddress) == -1)
        {
            printf("undef\n\n");
            system("pause");
            break;
        }
        printf("Name: %s, FileAdress: 0x%X, Size: 0x%X\n\n", sectionHeader[i].Name,rvaToFa(dosHeader,sectionHeader[i].VirtualAddress),sectionHeader[i].Misc.VirtualSize);
    }

    printf("Exports: \n\n");

    if (rvaToFa(dosHeader, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) != -1)
    {
        IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD)dosHeader + rvaToFa(dosHeader, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
        if(exportDirectory->Name)
        {
            DWORD* addressOfFunc = (DWORD*)(rvaToFa(dosHeader, exportDirectory->AddressOfFunctions) + (DWORD)dosHeader);
            DWORD* addressOfNames = (DWORD*)(rvaToFa(dosHeader, exportDirectory->AddressOfNames) + (DWORD)dosHeader);
            WORD* addressOfOrdinals = (WORD*)(rvaToFa(dosHeader, exportDirectory->AddressOfNameOrdinals) + (DWORD)dosHeader);

            //printf("Export name: %s\n\n", rvaToFa(dosHeader, exportDirectory->Name) + (DWORD)dosHeader);

            for (DWORD i = 0; i < exportDirectory->NumberOfFunctions; i++)
            {
                WORD ordinalBase = exportDirectory->Base;
                WORD ordinal = addressOfOrdinals[i];
                DWORD addressFunc = addressOfFunc[ordinal];

                if ((char*)dosHeader + rvaToFa(dosHeader, addressOfNames[i]) != NULL)
                {
                    printf("%s, 0x%X, 0x%X\n\n", (char*)dosHeader + rvaToFa(dosHeader, addressOfNames[i]), ordinalBase + ordinal , rvaToFa(dosHeader,addressFunc) + (DWORD)dosHeader);
                }
                else
                {
                    printf("0x%X, 0x%X\n\n", ordinalBase + ordinal, (DWORD)dosHeader + rvaToFa(dosHeader, addressOfFunc[i]));
                }
            }
        }
    }

    printf("Imports: \n\n");

    if (rvaToFa(dosHeader, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) != -1)
    {
        IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)dosHeader + rvaToFa(dosHeader, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
        while (importDescriptor->Name)
        {
            DWORD rvaName = importDescriptor->Name;
            DWORD rvaThunkData;
            rvaThunkData = importDescriptor->FirstThunk;
            if (rvaToFa(dosHeader, rvaThunkData) == -1)
            {
                system("pause");
                return -1;
            }
            DWORD adressThunkData = rvaToFa(dosHeader, rvaThunkData) + (DWORD)dosHeader;
            IMAGE_THUNK_DATA* thunkData = (IMAGE_THUNK_DATA*)adressThunkData;
            while (TRUE)
            {
                if (thunkData->u1.Function == NULL)
                {
                    break;
                }

                if ((DWORD)thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    DWORD ordinal = 0x00000001;
                    ordinal = (thunkData->u1.Ordinal >> (8 * 0)) & 0xff;
                    printf("%s, 0x%X\n\n", rvaToFa(dosHeader, rvaName) + (DWORD)dosHeader, ordinal);
                    thunkData += 1;
                    continue;
                }

                IMAGE_IMPORT_BY_NAME* functionImport = (IMAGE_IMPORT_BY_NAME*)((DWORD)dosHeader + rvaToFa(dosHeader, thunkData->u1.Function));
                if (rvaToFa(dosHeader, rvaName) == -1)
                {
                    system("pause");
                    return -1;
                }
                printf("%s, %s\n\n", rvaToFa(dosHeader, rvaName) + (DWORD)dosHeader, functionImport->Name);
                thunkData += 1;
            }
            importDescriptor++;
        }
    }

cleanup:
    if (fileData != NULL)
    {
        UnmapViewOfFile(fileData);
        fileData = NULL;
    }

    if (hFileMapping != NULL)
    {
        CloseHandle(hFileMapping);
        hFileMapping = NULL;
    }

    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = NULL;
    }

    system("pause");

    return 0;
}