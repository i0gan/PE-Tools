#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>
#include <memory.h>
#define QWORD __int64
#define DEBUG printf("debug\n");
#define PATH_IN "c:/cheatengine.exe"
#define SFileBuf 0
#define SImageBuf 1
#define PATH_OUT "c:/new.exe"
/////////////////////////////////////////////////////////////////////////////////////////////
//Operation of open file and load notepad.exe
FILE* Open_File();
void* Load_File(FILE* Source_File);
void  Load_Pe(void* Buf_ptr);

//Operation of file buffer and image buffer
void* Change_File_Buf_To_Image_Buf(void* File_Buf);
void* Change_Image_Buf_To_File_Buf(void* Image_Buf);
DWORD Change_FOA_To_RVA(DWORD FOA);
DWORD Change_RVA_To_FOA(DWORD RVA);

//Operation of section
void Add_Window_Code_End_Of_Section(void* File_Buf);
void* Add_Section(void* File_Buf,DWORD New_Section_Size);
DWORD File_Alignment(DWORD Length);
DWORD Section_Alignment(DWORD Length);

//Operation of each Table--------------------------------------------->
void Relocate_Function_Address(void* Image_Buf,DWORD ImageBase);
//---------
DWORD Size_Of_Export();
void Move_Export_Table(void* File_Buf,DWORD Table_Base);
DWORD Size_Of_Basereloc();
void Move_Basereloc_Table(void* File_Buf,DWORD Table_Base);
DWORD Size_Of_Import();
void Move_Import_Table(void* File_Buf,DWORD Table_Base);

//Operation of Export
void Export_Buffer(DWORD Buf_Size,void* Buf,char* Export_Buffer_Path);	//Export Buffer to disk
//Operation of Memory copy
void Memory_Copy(IN void* Cp,OUT void* To,DWORD Length);
void Memory_Dcopy(IN void* Cp,OUT void* To,DWORD Length);

//Operation of string
int Compare_String(char* str1,char* str2);
void Copy_String(IN char* str1,OUT char* str2);
DWORD String_Length(char* str);
void Modify_ESC(IN char* Str);
//Operation of print
void Print_About_This_File(void* File_Buf);
void Print_Dos_Header(void* File_Buf);
void Print_File_Header(void* File_Buf);
void Print_Optional_Header(void* File_Buf);
void Print_Pe_Sections(void* File_Buf);
void Print_Export_Table(void* File_Buf);
void Print_Basereloc_Table(void* File_Buf);
void Print_Hexe(void* Buf,DWORD Length);
void Print_BYTE_To_String(BYTE Value);
void Print_Number_Hexe(void* Num_Ptr,DWORD Length);

void Print_LYXF_Interface();
void List_Command();
void Run_Function();

int ASCII_Hex_To_Int(char hex);
/////////////////////////////////////////////////////////////////////////////////////////////
#pragma pack(4)
struct DOS_HEADER
{
	WORD* e_magic;//-----
	WORD* e_cblp;
	WORD* e_cp;
	WORD* e_crlc;
	WORD* e_cparhdr;
	WORD* e_minalloc;
	WORD* e_maxalloc;
	WORD* e_ss;
	WORD* e_sp;
	WORD* e_csum;
	WORD* e_ip;
	WORD* e_cs;
	WORD* e_lfarlc;
	WORD* e_ovno;
	WORD* e_res_4;
	WORD* e_oemid;
	WORD* e_oeminfo;
	WORD* e_res2_10;
	DWORD* e_lfanew;//-----
};
struct FILE_HEADER
{
	WORD* Machine;
	WORD* NumberOfSections;//-----
	DWORD* TimeDateStamp;
	DWORD* PointerToSymbolTable;
	DWORD* NumberOfSymbols;
	WORD* SizeOfOptionalHeader; //-----
	WORD* Characteristics;
};
/////////////////////////////////////////////////////////////////////////////////////////////

struct ENTRY_EXPORT{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_IMPORT
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_RESOURCE
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_EXCEPTION
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_SECURITY
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_BASERELOC
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_DEBUG
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_COPYRIGHT
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_GLOBALPTR
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_TLS
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_LOAD_CONFIG
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_BOUND_IMPORT
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_IAT
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_DELAY_IMPORT
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_COM_DESCRIPTOR
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
struct ENTRY_XXX
{
	DWORD* VirtualAddress;
	DWORD* Size;
};
/////////////////////////////////////////////////////////////////////////////////////////////
struct OPTIONAL_HEADER
{
	WORD* Magic;//-----
	BYTE* MajorLinkerVersion;
	BYTE* MinorLinkerVersion;
	DWORD* SizeOfCode;
	DWORD* SizeOfInitializedData;
	DWORD* SizeOfUninitializedData;
	DWORD* AddressOfEntryPoint;//-----
	DWORD* BaseOfCode;
	DWORD* BaseOfData;
	DWORD* ImageBase;//-----
	QWORD* ImageBase64;//-----64
	DWORD* SectionAlignment;//-----
	DWORD* FileAlignment;//-----
	WORD* MajorOperatingSystemVersion;
	WORD* MinorOperatingSystemVersion;
	WORD* MajorImageVersion;
	WORD* MinorImageVersion;
	WORD* MajorSubsystemVersion;
	WORD* MinorSubsystemVersion;
	DWORD* Win32VersionValue;
	DWORD* SizeOfImage;  //-----
	DWORD* SizeOfHeaders;//-----
	DWORD* CheckSum;
	WORD* Subsystem;
	WORD* DllCharacteristics;
	DWORD* SizeOfStackReserve;
	QWORD* SizeOfStackReserve64;//-----64
	DWORD* SizeOfStackCommit;
	QWORD* SizeOfStackCommit64;//-----64
	DWORD* SizeOfHeapReserve;
	QWORD* SizeOfHeapReserve64;//-----64
	DWORD* SizeOfHeapCommit;
	QWORD* SizeOfHeapCommit64;//-----64
	DWORD* LoaderFlags;
	DWORD* NumberOfRvaAndSizes;
	
	ENTRY_EXPORT	Export;
	ENTRY_IMPORT	Import;
	ENTRY_RESOURCE	Resource;
	ENTRY_EXCEPTION Exception;
	ENTRY_SECURITY	Security;
	ENTRY_BASERELOC	Basereloc;
	ENTRY_DEBUG		Debug;
	ENTRY_COPYRIGHT	Copyright;
	ENTRY_GLOBALPTR	Globalptr;
	ENTRY_TLS		Tls;
	ENTRY_LOAD_CONFIG	Load_Config;
	ENTRY_BOUND_IMPORT	Bound_Import;
	ENTRY_IAT			Iat;
	ENTRY_DELAY_IMPORT	Delay_Import;
	ENTRY_COM_DESCRIPTOR	Com_Descriptor;
	ENTRY_XXX xxx;
};
struct NT_HEADERS
{
	DWORD* Signature;
	FILE_HEADER File_Header;
	OPTIONAL_HEADER Optional_Header;
};
struct SECTIONS
{
	BYTE* Sections_Ptr;
	DWORD Section_Ptr_Offset;
    BYTE* NameOfSection;
	DWORD* Misc_VirtualSize;
	DWORD* VirtualAddress;
	DWORD* SizeOfRawData;
	DWORD* PointerToRawData;
	DWORD* PointerToRelocations;
	DWORD* PointerToLinenumbers;
	WORD*  NumberOfRelocations;
	WORD*  NumberOfLinenumbers;
	DWORD* Characteristics;
};
struct PE_HEADERS
{
	DOS_HEADER Dos_Header;
	NT_HEADERS Nt_Headers;
	SECTIONS Sections;
};
//////////////////////////////////------Tables-----//////////////////////////////////////////////////
struct EXPORT
{
	DWORD* Characteristics;
	DWORD* TimeDateStamp;
	WORD*  MajorVersion;
	WORD*  MinorVersion;
	DWORD* Name;
	DWORD* Base;
	DWORD* NumberOfFunctions;
	DWORD* NumberOfNames;
	DWORD* AddressOfFunctions;
	DWORD* AddressOfNames;
	DWORD* AddressOfNameOrdinals;
};
struct IMPORT
{
	//union {DWORD Characteristics;DWORD OriginalFirstThunk}
	DWORD* OriginalFirstThunk;	//INT import names table,a union wtih Characteristics
	DWORD* TimeDateStamp;
	DWORD* ForwarderChain;
	DWORD* Name;
	DWORD* FirstThunk;	//IAT import addresses table
	//union {LPBYTE ForwaderString; PDWORD Funciton;DWORD Ordinal;DWORD AddressOfData }
};
struct BASERELOC
{
	DWORD* VirtualAddress;
	DWORD* SizeOfBlock;
};
struct BOUND_IMPORT
{
	DWORD* TimeDateStamp;
	WORD*  OffsetModuleName;
	WORD*  NumberOfModuleForwarderRefs;
	WORD*  Reserved;
};
struct PE_TABLES
{
	EXPORT Export;
	IMPORT Import;
	BASERELOC Basereloc;
	BOUND_IMPORT Bound_Import;
};
#pragma pack()
/////////////////////////////////////////////////////////////////////////////////////////////
BYTE  File_Path[100]={0};
DWORD File_Size;			//Define a global variable and record size of source file
DWORD Buf_Size;				//Declare a size of buffer
DWORD New_Buf_Size;			//Declare a size of new buffer
void* Buf=NULL;				//Define a buffer pointer
void  (__cdecl* EIP)()=NULL;//define a fucntion pointer to run another exe
PE_HEADERS Pe_Headers;		//Define a PE struceture
PE_TABLES  Pe_Tables;
/////////////////////////////////////////////////////////////////////////////////////////////
FILE* Open_File(char* File_Path)
{
	FILE* Source_File;
	if(!(Source_File=fopen(File_Path,"rb"))) //Get source file pointer
	{
		printf("Open source file of %s fail!\n",File_Path);
		getch();
		return NULL;
	}
	fseek(Source_File,0,SEEK_END);
	File_Size=ftell(Source_File);		//Get size of source file
	fseek(Source_File,0,SEEK_SET);
	return Source_File;	
}
/////////////////////////////////////////////////////////////////////////////////////////////
void* Load_File(FILE* Source_File)
{	
	if(Source_File==NULL) return NULL;
	void* File_Buf;					//Define a file buffer pointer
	if(!(File_Buf=malloc(File_Size)))
	{
		printf("Load file fail!\n");
		return NULL;
	}
	fread(File_Buf,1,File_Size,Source_File);	//Load file from disk to memmory
	fclose(Source_File);
	return File_Buf;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Load_Pe(void* Buf_ptr)
{	//----------------------------------Initialization-------------------------------------//
	if(Buf_ptr==NULL) return;
	//Set each header pointer
	BYTE* Dos_Header_Ptr=(BYTE*)Buf_ptr;									//Dos header pointer		
	BYTE* Nt_Headers_Ptr=(BYTE*)Buf_ptr+(*(DWORD*)(Dos_Header_Ptr+0x3C));	//Nt header pointer
	BYTE* File_Header_Ptr=Nt_Headers_Ptr+0x4;								//File header pointer	
	BYTE* Optional_Header_Ptr=Nt_Headers_Ptr+0x18;							//Optional header pointer
	BYTE* All_Table_Ptr=NULL;												//Each tables entay pointer
	//--------------------------------------------------------------------------------------//
	//Initialize Export_Ptr
	BYTE* Export_Ptr=NULL;
	BYTE* Import_Ptr=NULL;
	BYTE* Basereloc_Ptr=NULL;
	BYTE* Bound_Import=NULL;
	//--------------------------------------------------------------------------------------//
	//Set each pe detail address to global structure Pe_Headers
	//----------------------------------Load dos header-------------------------------------//
	Pe_Headers.Dos_Header.e_magic=(WORD*)(Dos_Header_Ptr);
	Pe_Headers.Dos_Header.e_cblp=(WORD*)(Dos_Header_Ptr+0x02);
	Pe_Headers.Dos_Header.e_cp=(WORD*)(Dos_Header_Ptr+0x04);
	Pe_Headers.Dos_Header.e_crlc=(WORD*)(Dos_Header_Ptr+0x06);
	Pe_Headers.Dos_Header.e_cparhdr=(WORD*)(Dos_Header_Ptr+0x08);
	Pe_Headers.Dos_Header.e_minalloc=(WORD*)(Dos_Header_Ptr+0x0a);
	Pe_Headers.Dos_Header.e_maxalloc=(WORD*)(Dos_Header_Ptr+0x0c);
	Pe_Headers.Dos_Header.e_ss=(WORD*)(Dos_Header_Ptr+0x0e);
	Pe_Headers.Dos_Header.e_sp=(WORD*)(Dos_Header_Ptr+0x10);
	Pe_Headers.Dos_Header.e_csum=(WORD*)(Dos_Header_Ptr+0x12);
	Pe_Headers.Dos_Header.e_ip=(WORD*)(Dos_Header_Ptr+0x14);
	Pe_Headers.Dos_Header.e_cs=(WORD*)(Dos_Header_Ptr+0x16);
	Pe_Headers.Dos_Header.e_lfarlc=(WORD*)(Dos_Header_Ptr+0x18);
	Pe_Headers.Dos_Header.e_ovno=(WORD*)(Dos_Header_Ptr+0x1a);
	Pe_Headers.Dos_Header.e_res_4=(WORD*)(Dos_Header_Ptr+0x1c);
	Pe_Headers.Dos_Header.e_oemid=(WORD*)(Dos_Header_Ptr+0x24);
	Pe_Headers.Dos_Header.e_oeminfo=(WORD*)(Dos_Header_Ptr+0x26);
	Pe_Headers.Dos_Header.e_res2_10=(WORD*)(Dos_Header_Ptr+0x28);
	Pe_Headers.Dos_Header.e_lfanew=(DWORD*)(Dos_Header_Ptr+0x3c);
	//----------------------------------Load nt header-------------------------------------//
	Pe_Headers.Nt_Headers.Signature=(DWORD*)(Nt_Headers_Ptr);
	//----------------------------------Load file header-------------------------------------//
	Pe_Headers.Nt_Headers.File_Header.Machine=(WORD*)(File_Header_Ptr);
	Pe_Headers.Nt_Headers.File_Header.NumberOfSections=(WORD*)(File_Header_Ptr+0x02);
	Pe_Headers.Nt_Headers.File_Header.TimeDateStamp=(DWORD*)(File_Header_Ptr+0x04);
	Pe_Headers.Nt_Headers.File_Header.PointerToSymbolTable=(DWORD*)(File_Header_Ptr+0x08);
	Pe_Headers.Nt_Headers.File_Header.NumberOfSymbols=(DWORD*)(File_Header_Ptr+0x0c);
	Pe_Headers.Nt_Headers.File_Header.SizeOfOptionalHeader=(WORD*)(File_Header_Ptr+0x10);
	Pe_Headers.Nt_Headers.File_Header.Characteristics=(WORD*)(File_Header_Ptr+0x12);
	//----------------------------------Load optional header-------------------------------------//
	Pe_Headers.Nt_Headers.Optional_Header.Magic=(WORD*)(Optional_Header_Ptr);
	Pe_Headers.Nt_Headers.Optional_Header.MajorLinkerVersion=(BYTE*)(Optional_Header_Ptr+0x02);
	Pe_Headers.Nt_Headers.Optional_Header.MinorLinkerVersion=(BYTE*)(Optional_Header_Ptr+0x3);
	Pe_Headers.Nt_Headers.Optional_Header.SizeOfCode=(DWORD*)(Optional_Header_Ptr+0x04);
	Pe_Headers.Nt_Headers.Optional_Header.SizeOfInitializedData=(DWORD*)(Optional_Header_Ptr+0x08);
	Pe_Headers.Nt_Headers.Optional_Header.SizeOfUninitializedData=(DWORD*)(Optional_Header_Ptr+0x0c);
	Pe_Headers.Nt_Headers.Optional_Header.AddressOfEntryPoint=(DWORD*)(Optional_Header_Ptr+0x10);
	Pe_Headers.Nt_Headers.Optional_Header.BaseOfCode=(DWORD*)(Optional_Header_Ptr+0x14);
	if(*(Pe_Headers.Nt_Headers.Optional_Header.Magic)==0x10B)
	{
		Pe_Headers.Nt_Headers.Optional_Header.BaseOfData=(DWORD*)(Optional_Header_Ptr+0x18);
		Pe_Headers.Nt_Headers.Optional_Header.ImageBase=(DWORD*)(Optional_Header_Ptr+0x1c);
	}
	else
	{
		Pe_Headers.Nt_Headers.Optional_Header.ImageBase64=(QWORD*)(Optional_Header_Ptr+0x18);
	}
	Pe_Headers.Nt_Headers.Optional_Header.SectionAlignment=(DWORD*)(Optional_Header_Ptr+0x20);
	Pe_Headers.Nt_Headers.Optional_Header.FileAlignment=(DWORD*)(Optional_Header_Ptr+0x24);
	Pe_Headers.Nt_Headers.Optional_Header.MajorOperatingSystemVersion=(WORD*)(Optional_Header_Ptr+0x28);
	Pe_Headers.Nt_Headers.Optional_Header.MinorOperatingSystemVersion=(WORD*)(Optional_Header_Ptr+0x2a);
	Pe_Headers.Nt_Headers.Optional_Header.MajorImageVersion=(WORD*)(Optional_Header_Ptr+0x2c);
	Pe_Headers.Nt_Headers.Optional_Header.MinorImageVersion=(WORD*)(Optional_Header_Ptr+0x2e);
	Pe_Headers.Nt_Headers.Optional_Header.MajorSubsystemVersion=(WORD*)(Optional_Header_Ptr+0x30);
	Pe_Headers.Nt_Headers.Optional_Header.MinorSubsystemVersion=(WORD*)(Optional_Header_Ptr+0x32);
	Pe_Headers.Nt_Headers.Optional_Header.Win32VersionValue=(DWORD*)(Optional_Header_Ptr+0x34);
	Pe_Headers.Nt_Headers.Optional_Header.SizeOfImage=(DWORD*)(Optional_Header_Ptr+0x38);
	Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeaders=(DWORD*)(Optional_Header_Ptr+0x3c);
	Pe_Headers.Nt_Headers.Optional_Header.CheckSum=(DWORD*)(Optional_Header_Ptr+0x40);
	Pe_Headers.Nt_Headers.Optional_Header.Subsystem=(WORD*)(Optional_Header_Ptr+0x44);
	Pe_Headers.Nt_Headers.Optional_Header.DllCharacteristics=(WORD*)(Optional_Header_Ptr+0x46);
	
	if(*(Pe_Headers.Nt_Headers.Optional_Header.Magic)==0x10B)	//Distinguish between 64-bit and 34-bit
	{
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackReserve=(DWORD*)(Optional_Header_Ptr+0x48);
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackCommit=(DWORD*)(Optional_Header_Ptr+0x4c);
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapReserve=(DWORD*)(Optional_Header_Ptr+0x50);
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapCommit=(DWORD*)(Optional_Header_Ptr+0x54);
		Pe_Headers.Nt_Headers.Optional_Header.LoaderFlags=(DWORD*)(Optional_Header_Ptr+0x58);
		Pe_Headers.Nt_Headers.Optional_Header.NumberOfRvaAndSizes=(DWORD*)(Optional_Header_Ptr+0x5c);
		All_Table_Ptr=(Optional_Header_Ptr+0x60);				//Set table 32 bit table pointer
	}
	else
	{
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackReserve64=(QWORD*)(Optional_Header_Ptr+0x48);
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackCommit64=(QWORD*)(Optional_Header_Ptr+0x50);
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapReserve64=(QWORD*)(Optional_Header_Ptr+0x58);
		Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapCommit64=(QWORD*)(Optional_Header_Ptr+0x60);
		Pe_Headers.Nt_Headers.Optional_Header.LoaderFlags=(DWORD*)(Optional_Header_Ptr+0x68);
		Pe_Headers.Nt_Headers.Optional_Header.NumberOfRvaAndSizes=(DWORD*)(Optional_Header_Ptr+0x6c);
		All_Table_Ptr=(Optional_Header_Ptr+0x70);				//Set table 64 bit table pointer
	}
	//----------------------------------Load sections table pointer-----------------------------------//
	//To get pointer address of first section
	Pe_Headers.Sections.Sections_Ptr=(BYTE*)Optional_Header_Ptr+(*Pe_Headers.Nt_Headers.File_Header.SizeOfOptionalHeader);
	Pe_Headers.Sections.Section_Ptr_Offset=(DWORD)Pe_Headers.Sections.Sections_Ptr-(DWORD)Dos_Header_Ptr;

	//----------------------------------Load entry of each tables-------------------------------------//
	Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress=(DWORD*)(All_Table_Ptr+0x00);
	Pe_Headers.Nt_Headers.Optional_Header.Export.Size=(DWORD*)(All_Table_Ptr+0x04);
	Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress=(DWORD*)(All_Table_Ptr+0x08);
	Pe_Headers.Nt_Headers.Optional_Header.Import.Size=(DWORD*)(All_Table_Ptr+0x0c);
	Pe_Headers.Nt_Headers.Optional_Header.Resource.VirtualAddress=(DWORD*)(All_Table_Ptr+0x10);
	Pe_Headers.Nt_Headers.Optional_Header.Resource.Size=(DWORD*)(All_Table_Ptr+0x14);
	Pe_Headers.Nt_Headers.Optional_Header.Exception.VirtualAddress=(DWORD*)(All_Table_Ptr+0x18);
	Pe_Headers.Nt_Headers.Optional_Header.Exception.Size=(DWORD*)(All_Table_Ptr+0x1c);
	Pe_Headers.Nt_Headers.Optional_Header.Security.VirtualAddress=(DWORD*)(All_Table_Ptr+0x20);
	Pe_Headers.Nt_Headers.Optional_Header.Security.Size=(DWORD*)(All_Table_Ptr+0x24);
	Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress=(DWORD*)(All_Table_Ptr+0x28);
	Pe_Headers.Nt_Headers.Optional_Header.Basereloc.Size=(DWORD*)(All_Table_Ptr+0x2c);
	Pe_Headers.Nt_Headers.Optional_Header.Debug.VirtualAddress=(DWORD*)(All_Table_Ptr+0x30);
	Pe_Headers.Nt_Headers.Optional_Header.Debug.Size=(DWORD*)(All_Table_Ptr+0x34);
	Pe_Headers.Nt_Headers.Optional_Header.Copyright.VirtualAddress=(DWORD*)(All_Table_Ptr+0x38);
	Pe_Headers.Nt_Headers.Optional_Header.Copyright.Size=(DWORD*)(All_Table_Ptr+0x3c);
	Pe_Headers.Nt_Headers.Optional_Header.Globalptr.VirtualAddress=(DWORD*)(All_Table_Ptr+0x40);
	Pe_Headers.Nt_Headers.Optional_Header.Globalptr.Size=(DWORD*)(All_Table_Ptr+0x44);
	Pe_Headers.Nt_Headers.Optional_Header.Tls.VirtualAddress=(DWORD*)(All_Table_Ptr+0x48);
	Pe_Headers.Nt_Headers.Optional_Header.Tls.Size=(DWORD*)(All_Table_Ptr+0x4c);
	Pe_Headers.Nt_Headers.Optional_Header.Load_Config.VirtualAddress=(DWORD*)(All_Table_Ptr+0x50);
	Pe_Headers.Nt_Headers.Optional_Header.Load_Config.Size=(DWORD*)(All_Table_Ptr+0x54);
	Pe_Headers.Nt_Headers.Optional_Header.Bound_Import.VirtualAddress=(DWORD*)(All_Table_Ptr+0x58);
	Pe_Headers.Nt_Headers.Optional_Header.Bound_Import.Size=(DWORD*)(All_Table_Ptr+0x5c);
	Pe_Headers.Nt_Headers.Optional_Header.Iat.VirtualAddress=(DWORD*)(All_Table_Ptr+0x60);
	Pe_Headers.Nt_Headers.Optional_Header.Iat.Size=(DWORD*)(All_Table_Ptr+0x64);
	Pe_Headers.Nt_Headers.Optional_Header.Delay_Import.VirtualAddress=(DWORD*)(All_Table_Ptr+0x68);
	Pe_Headers.Nt_Headers.Optional_Header.Delay_Import.Size=(DWORD*)(All_Table_Ptr+0x6c);
	Pe_Headers.Nt_Headers.Optional_Header.Com_Descriptor.VirtualAddress=(DWORD*)(All_Table_Ptr+0x70);
	Pe_Headers.Nt_Headers.Optional_Header.Com_Descriptor.Size=(DWORD*)(All_Table_Ptr+0x74);
	//----------------------------------Load export table-------------------------------------//
	if(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress!=0)
	{
		//Get Address of Export table
		Export_Ptr=(BYTE*)((BYTE*)Buf_ptr+Change_RVA_To_FOA(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress));
		Pe_Tables.Export.Characteristics=(DWORD*)(Export_Ptr+0x0);
		Pe_Tables.Export.TimeDateStamp=(DWORD*)(Export_Ptr+0x4);
		Pe_Tables.Export.MajorVersion=(WORD*)(Export_Ptr+0x8);
		Pe_Tables.Export.MinorVersion=(WORD*)(Export_Ptr+0xa);
		Pe_Tables.Export.Name=(DWORD*)(Export_Ptr+0xc);
		Pe_Tables.Export.Base=(DWORD*)(Export_Ptr+0x10);
		Pe_Tables.Export.NumberOfFunctions=(DWORD*)(Export_Ptr+0x14);
		Pe_Tables.Export.NumberOfNames=(DWORD*)(Export_Ptr+0x18);
		Pe_Tables.Export.AddressOfFunctions=(DWORD*)(Export_Ptr+0x1c);
		Pe_Tables.Export.AddressOfNames=(DWORD*)(Export_Ptr+0x20);
		Pe_Tables.Export.AddressOfNameOrdinals=(DWORD*)(Export_Ptr+0x24);
	}
	//----------------------------------Load import table-------------------------------------//
	if(*Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress!=0)
	{
		//Get Address of Export table
		Import_Ptr=(BYTE*)((BYTE*)Buf_ptr+Change_RVA_To_FOA(*Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress));
		Pe_Tables.Import.OriginalFirstThunk=(DWORD*)(Import_Ptr+0x0);
		Pe_Tables.Import.TimeDateStamp=(DWORD*)(Import_Ptr+0x4);
		Pe_Tables.Import.ForwarderChain=(DWORD*)(Import_Ptr+0x8);
		Pe_Tables.Import.Name=(DWORD*)(Import_Ptr+0xc);
		Pe_Tables.Import.FirstThunk=(DWORD*)(Import_Ptr+0x10);
	}
	//----------------------------------Load base relocation table-------------------------------------//
	if(*Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress!=0)
	{
		//Get Address of base relocation table
		Bound_Import=(BYTE*)((BYTE*)Buf_ptr+Change_RVA_To_FOA(*Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress));
		Pe_Tables.Basereloc.VirtualAddress=(DWORD*)(Bound_Import+0x0);
		Pe_Tables.Basereloc.SizeOfBlock=(DWORD*)(Bound_Import+0x4);
	}
	if(*Pe_Headers.Nt_Headers.Optional_Header.Bound_Import.VirtualAddress!=0)
	{
		//Get Address of base relocation table
		Basereloc_Ptr=(BYTE*)((BYTE*)Buf_ptr+Change_RVA_To_FOA(*Pe_Headers.Nt_Headers.Optional_Header.Bound_Import.VirtualAddress));
		Pe_Tables.Bound_Import.TimeDateStamp=(DWORD*)(Basereloc_Ptr+0x0);
		Pe_Tables.Bound_Import.OffsetModuleName=(WORD*)(Basereloc_Ptr+0x4);
		Pe_Tables.Bound_Import.NumberOfModuleForwarderRefs=(WORD*)(Basereloc_Ptr+0x6);
		Pe_Tables.Bound_Import.Reserved=(WORD*)(Basereloc_Ptr+0x6);
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////---Chage Buffer---//////////////////////////////////////////////
void* Change_File_Buf_To_Image_Buf(void* File_Buf)  //To chage buffer from file buffer to image buffer
{
	void* Image_Buf=NULL;
	BYTE* Section_Ptr=Pe_Headers.Sections.Sections_Ptr;
	DWORD SizeOfImage=*Pe_Headers.Nt_Headers.Optional_Header.SizeOfImage;
	DWORD Image_Offset=0;
	DWORD File_Offset=0;
	DWORD i_1=0,i_2=0;
	DWORD SizeOfData=0;
	if(!(Image_Buf=malloc(SizeOfImage)))
	{
		printf("Malloc fali when load file buffer\n");
		return NULL;
	}
	memset(Image_Buf,0,SizeOfImage);	//To full with 0
	//Copy each header to the image buffer
	while(i_1<(*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeaders)/4))
	{
		*((DWORD*)Image_Buf+i_1)=*((DWORD*)File_Buf+i_1);
		i_1++;
	}
	i_1=0;

	//copy each sections
	while(i_1<6)	//(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections)
	{
		Image_Offset=*((DWORD*)(Section_Ptr+0xc));			//Get section offset in image buffer --VirtualAddress
		File_Offset=*((DWORD*)(Section_Ptr+0x14));
		SizeOfData=(*((DWORD*)(Section_Ptr+0x10)));
		while(i_2<(SizeOfData/4))		//Copy section data from file buffer to image buffer
		{
			*((DWORD*)((BYTE*)Image_Buf+Image_Offset)+i_2)=*((DWORD*)((BYTE*)File_Buf+File_Offset)+i_2);	
			i_2++;
		}
		Section_Ptr+=0x28;
		i_2=0;
		i_1++;
	}
	//----------------------------Change and free Buffer------------------
	free(File_Buf);			//Free old file buffer
	Load_Pe(Image_Buf); //Load new PE
	Buf_Size=SizeOfImage;		//Set a new buffer size
	//------------------------------------------------
	return Image_Buf;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void* Change_Image_Buf_To_File_Buf(void* Image_Buf)
{
	void* File_Buf=NULL;
	DWORD Size_Of_File_Buf=0;
	BYTE* Section_Ptr=Pe_Headers.Sections.Sections_Ptr;
	DWORD Image_Offset=0;
	DWORD File_Offset=0;
	DWORD i_1=0,i_2=0;
	DWORD SizeOfData=0;
	//Set the section_table pointer to the last section
	for(DWORD i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections-1);i++) Section_Ptr+=0x28;
	//Obtain size of file buffer
	Size_Of_File_Buf=File_Alignment(*((DWORD*)(Section_Ptr+0x10))+*((DWORD*)(Section_Ptr+0x14)));
	//Reset section pointer
	Section_Ptr=Pe_Headers.Sections.Sections_Ptr;
	if(!(File_Buf=malloc(Size_Of_File_Buf)))
	{
		printf("Malloc fali when load image buffer\n");
		return NULL;
	}
	memset(File_Buf,0,Size_Of_File_Buf);	//To full with 0
	//Copy each header to the image buffer
	while(i_1<(*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeaders)/4))
	{
		*((DWORD*)File_Buf+i_1)=*((DWORD*)Image_Buf+i_1);
		i_1++;
	}
	i_1=0;
	//copy each sections
	while(i_1<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections))
	{
		Image_Offset=*((DWORD*)(Section_Ptr+0xc));			//Get section offset in image buffer --VirtualAddress
		File_Offset=*((DWORD*)(Section_Ptr+0x14));
		SizeOfData=(*((DWORD*)(Section_Ptr+0x10)));
		while(i_2<(SizeOfData/4))		//Copy section data from image buffer to file buffer
		{
			*((DWORD*)((BYTE*)File_Buf+File_Offset)+i_2)=*((DWORD*)((BYTE*)Image_Buf+Image_Offset)+i_2);
			i_2++;
		}
		Section_Ptr+=0x28;
		i_2=0;
		i_1++;
	}
	//----------------------------Change and free Buffer------------------
	free(Image_Buf);			//Free old file buffer
	Load_Pe(File_Buf); //Load new PE
	Buf_Size=Size_Of_File_Buf;		//Set a new buffer size
	//------------------------------------------------
	return File_Buf;
}
/////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////FOA OR RVA Transfer///////////////////////////////////////////////
DWORD Change_FOA_To_RVA(DWORD FOA)
{
	DWORD RVA=0;
	BYTE* Sections_Ptr=Pe_Headers.Sections.Sections_Ptr;
	DWORD Num_Of_Section=1;
	if(FOA>=0&&FOA<(*Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeaders))
	{
		return FOA;
	}
	else
	{
		for(DWORD i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections);i++)
		{
			if((FOA>=(*((DWORD*)(Sections_Ptr+0x14))))&&(FOA<((*((DWORD*)(Sections_Ptr+0x14)))+File_Alignment((*((DWORD*)(Sections_Ptr+0x10)))))))
			{
				Num_Of_Section+=i;
			}
			Sections_Ptr+=0x28;
		}
		Sections_Ptr=Sections_Ptr-(0x28*(*(Pe_Headers.Nt_Headers.File_Header.NumberOfSections)-Num_Of_Section+0x1));
		RVA=(*((DWORD*)(Sections_Ptr+0xc))+(FOA-(*((DWORD*)(Sections_Ptr+0x14)))));
	}
	return RVA;
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD Change_RVA_To_FOA(DWORD RVA)
{
	DWORD FOA=0;
	BYTE* Sections_Ptr=Pe_Headers.Sections.Sections_Ptr;
	DWORD Num_Of_Section=1;
	if(RVA>=0&&RVA<(*Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeaders))
	{
		return RVA;
	}
	else
	{
		for(DWORD i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections);i++)
		{
			if((RVA>=(*((DWORD*)(Sections_Ptr+0xc))))&&(RVA<((*((DWORD*)(Sections_Ptr+0xc)))+(*((DWORD*)(Sections_Ptr+0x10))))))
			{
				Num_Of_Section+=i;
			}
			Sections_Ptr+=0x28;
		}
		Sections_Ptr=Sections_Ptr-(0x28*(*(Pe_Headers.Nt_Headers.File_Header.NumberOfSections)-Num_Of_Section+0x1));
		FOA=(*((DWORD*)(Sections_Ptr+0x14))+(RVA-(*((DWORD*)(Sections_Ptr+0xc)))));
	}
	return FOA;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Add_Window_Code_End_Of_Section(void* File_Buf)			//Show a error window 
{	
	Load_Pe(File_Buf);
	DWORD Code_Address=(DWORD)MessageBoxA;	//Get MessageBox address
	char Shell_Code[]={
		0x6a,0x03,0x6a,0x00,0x6a,0x00,0x6a,0x00,
			0xe8,0x00,0x00,0x00,0x00,0xe9,0x00,0x00,0x00,0x00
	};





	BYTE* Sections_Ptr=Pe_Headers.Sections.Sections_Ptr;
	DWORD Num_Of_Section=0,i=0;
	DWORD File_Offset=0;
	DWORD Image_Offset=0;
	DWORD Image_Code_Address=0;
	DWORD Entry_Address=*Pe_Headers.Nt_Headers.Optional_Header.AddressOfEntryPoint+(*Pe_Headers.Nt_Headers.Optional_Header.ImageBase);
	BYTE* Code_Ptr=NULL;					//A pointer to code address in file buffer
	BYTE* Shell_Code_Ptr=(BYTE*)Shell_Code;	//get char[] pointer
	printf("Number of sections: %d\n",*(Pe_Headers.Nt_Headers.File_Header.NumberOfSections));
	printf("Which section will you inject your code?\nInput section number\n");
	
	scanf("%d",&Num_Of_Section);
	
	for(i=0;i<(Num_Of_Section-1);i++) Sections_Ptr+=0x28; //Relocate File Section section pointer
	
	*((DWORD*)(Sections_Ptr+0x24))=*((DWORD*)(Sections_Ptr+0x24))|0xe0000020;			// Or Characteristics  
	
	Code_Ptr=(BYTE*)File_Buf+(*(DWORD*)(Sections_Ptr+0x14))+(*(DWORD*)(Sections_Ptr+0x8)); //Get Code_Ptr
	
	File_Offset=Code_Ptr-(BYTE*)File_Buf;				//Change FOA to RVA
	Image_Offset=Change_FOA_To_RVA(File_Offset);
	
	*(Pe_Headers.Nt_Headers.Optional_Header.AddressOfEntryPoint)=Image_Offset;		//Set address of entry point to code of injection
	Image_Code_Address=*Pe_Headers.Nt_Headers.Optional_Header.ImageBase+Image_Offset+0x8;
	
	*(DWORD*)(Shell_Code_Ptr+0x9)=Code_Address-(Image_Code_Address+0x5);
	*(DWORD*)(Shell_Code_Ptr+0xe)=Entry_Address-(Image_Code_Address+0xA);
	
	if(*((DWORD*)(Sections_Ptr+0x10))-(*((DWORD*)(Sections_Ptr+0x8)))>sizeof(Shell_Code))
	{
		for(i=0;i<sizeof(Shell_Code);i++)				//Copy data from char[] to file buffer
		{
			*(Code_Ptr+i)=Shell_Code[i];
		}
	}else
	{
		printf("Have no enough free space to inject your code\n");
		return;
	}
	printf("Success!\n");
}
//-------------------------------------------------------------------------------------------------------
int ASCII_Hex_To_Int(char hex)
{
	int num = 0;
	if(hex == 'F' || hex == 'f')
	{
		num = 0xF;
	}else if(hex == 'E' || hex == 'e')
	{
		num = 0xE;
	}else if(hex == 'D' || hex == 'd')
	{
		num = 0xD;
	}else if(hex == 'C' || hex == 'c')
	{
		num = 0xC;
	}else if(hex == 'B' || hex == 'b')
	{
		num = 0xB;
	}else if(hex == 'A' || hex == 'a')
	{
		num = 0xA;
	}else if(hex == '9')
	{
		num = 0x9;
	}else if(hex == '8')
	{
		num = 0x8;
	}else if(hex == '7')
	{
		num = 0x7;
	}else if(hex == '6')
	{
		num = 0x6;
	}else if(hex == '5')
	{
		num = 0x5;
	}else if(hex == '4')
	{
		num = 0x4;
	}else if(hex == '3')
	{
		num = 0x3;
	}else if(hex == '2')
	{
		num = 0x2;
	}else if(hex == '1')
	{
		num = 0x1;
	}else if(hex == '0')
	{
		num = 0x0;
	}
	return num;
}
void* Add_Shell_Code(void* File_Buf)			//Show a error window 
{	
	printf("NUM: %d\n", *Pe_Headers.Nt_Headers.File_Header.NumberOfSections);
	void *buf = Add_Section(File_Buf,0x1000);
	File_Buf = NULL;

	int i = 0;
	char Sh_File_Path[128] = {0};
	BYTE* Shell_Code_Section_Ptr = NULL; // The pointer of end of section data ***** 
	DWORD Shell_Code_Size = 0;
	BYTE* Sections_Ptr = Pe_Headers.Sections.Sections_Ptr;
	DWORD Shell_Code_Addr_Mem = 0;
	DWORD Number_Of_Sections = *Pe_Headers.Nt_Headers.File_Header.NumberOfSections;


	// Shell code part
	FILE* Shell_Code_File = NULL; //The pointer of shellcode file
	BYTE* Code_Ptr=NULL;
	BYTE  Code_Num_Ch1 = 0;
	BYTE  Code_Num_Ch2 = 0;
	BYTE  Code_Num = 0;
	DWORD Tem_I = 0;  //shellcode text var
	DWORD Tem_S = 0;  //shellcode section var


	//Set setcions_ptr to end seciton
	for(i=0; i<(Number_Of_Sections-1) ;i++) Sections_Ptr+=0x28;				//Relocate File Section section pointer
	Shell_Code_Section_Ptr = (BYTE*)( *((DWORD*)(Sections_Ptr+0x14)) + (DWORD)(buf)); // The pointer of end of section data *****

	*((DWORD*)(Sections_Ptr+0x24))=*((DWORD*)(Sections_Ptr+0x24))|0xe0000020;	// Or Characteristics
	

	// Set address of entry point as shell code 
	*Pe_Headers.Nt_Headers.Optional_Header.AddressOfEntryPoint = Change_FOA_To_RVA((DWORD)Shell_Code_Section_Ptr - (DWORD)buf);
	

	printf("Plz open a mfs shellcode file\n(notice: it is a text file!!!)\n");
	printf("Your shellcode file path:\n");
	scanf("%s",Sh_File_Path);
	Modify_ESC(IN Sh_File_Path);
	//Open the shell code file
	if(!(Shell_Code_File=fopen(Sh_File_Path,"r")))
	{
		printf("Open source file of %s fail!\n",Sh_File_Path);
		getch();
		return buf;
	}else 
	{
		printf("Open shellcode file success!\n");
	}
	fseek(Shell_Code_File,0,SEEK_END);
	Shell_Code_Size = ftell(Shell_Code_File);		//Get size of source file
	fseek(Shell_Code_File,0,SEEK_SET);
	Code_Ptr = (BYTE*)malloc(Shell_Code_Size);
	memset(Code_Ptr, 0, Shell_Code_Size);
	fread(Code_Ptr, 1, Shell_Code_Size, Shell_Code_File); // read data from file to memory
	fclose(Shell_Code_File); // Close the shell code text file

	//Write shellcode to file buffer...
	while(Tem_I < Shell_Code_Size)
	{
		if((Code_Ptr[Tem_I] == '\\')  &&  ((Code_Ptr[Tem_I+1] == 'x')||(Code_Ptr[Tem_I+1] == 'X')) )
		{
			Code_Num_Ch1 = ASCII_Hex_To_Int(Code_Ptr[Tem_I+2]);
			Code_Num_Ch2 = ASCII_Hex_To_Int(Code_Ptr[Tem_I+3]);
			
			Code_Num = Code_Num_Ch1 * 0x10 + Code_Num_Ch2;
			Shell_Code_Section_Ptr[Tem_S] = Code_Num;
			Tem_I += 4;
			Tem_S ++;
		}else
		{
			Tem_I += 1;
		}	
	}
	printf("Write your shellcode to new section success!\n");
	return buf;
}


void* Add_New_Section(void* File_Buf)
{
	unsigned float New_Size = 0.0;
	DWORD New_Size_INT = 0.0;
	printf("How many MB do you wannay to create? (Unit: MB)\n(For example: input 30,than program size will add 30MB)\n");
	printf("LYXF->");
	scanf("%d",&New_Size_INT);
	New_Size_INT*= 0x100000;
	return Add_Section(File_Buf,New_Size_INT);
}
void* test(void *File_Buf)
{
	//return Add_Shell_Code(File_Buf);
	return NULL;
}

//---------------------------------------------------------------------------------------------------
void* Inject_Dll(void* File_Buf)
{
	system("cls");
	printf("Only can inject debug program! \n");
	if(*Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress==0) return NULL;
	//--------------------------------------------------------------------------------------->Load your own dll
	void* Dll_Buf=NULL;
	printf("Move your dll file to the attached pe file\n");
	char Dll_Name[]="LYXF_DLL.dll";
	char Dll_PATH[]="c:/LYXF_DLL.dll";
	printf("Input your dll path(for example:  c:/your.dll )\n");
	scanf("%s",Dll_Name);
	Modify_ESC(Dll_Name);
	Dll_Buf=Load_File(Open_File(Dll_Name));
	Load_Pe(Dll_Buf);
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress==0)
	{
		printf("Your DLL No Export Table\n");
		getch();
		return NULL;
	}
	//Initiualize function address table pointer
	DWORD* Fuctnions_Ptr=(DWORD*)((BYTE*)Dll_Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfFunctions)));
	//Initiualize function ordernal address table pointer
	WORD* Name_Ordinals_Ptr=(WORD*)((BYTE*)Dll_Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNameOrdinals)));
	//Initiualize name table pointer
	DWORD* Names_Ptr=(DWORD*)((BYTE*)Dll_Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNames)));//Pointer of Names table in file buffer
	DWORD* DLL_FName=(DWORD*)((BYTE*)Dll_Buf+Change_RVA_To_FOA(*Names_Ptr));		//Function name address in file buffer
	DWORD i=0,i2=0;
	//------------------------Print function--------------------------------------//
	printf("Your own dll have functions as below:\n\n");
	for(i=0;i<(*(Pe_Tables.Export.NumberOfFunctions));i++)
	{
		if(*(Fuctnions_Ptr+i)!=0)	//To filter no function address just leave real function
		{
			for(i2=0;i2<(*(Pe_Tables.Export.NumberOfFunctions));i2++)
			{
				//To judge if have name and print
				if(i==*(Name_Ordinals_Ptr+i2))						//If have name
				{
					DLL_FName=(DWORD*)((BYTE*)Dll_Buf+Change_RVA_To_FOA(*(Names_Ptr+i2)));
					printf("Function: %s \n",DLL_FName);
					printf("Ordinal: %d\n",(*(Name_Ordinals_Ptr+i2))+*(Pe_Tables.Export.Base));
					break;
				}
				if(i2==(*(Pe_Tables.Export.NumberOfFunctions)-0x1))	//If have no name
				{
					printf("Function: No name\n");
					printf("Ordinal: %d\n",*(Pe_Tables.Export.Base)+i);
					break;
				}
			}
			printf("Enray Point: "); Print_Number_Hexe(Fuctnions_Ptr+i,0x4);	//Anyway have or no name to print entray point
			printf("\n");
		}
	}
	free(Dll_Buf);
	printf("What function name do you wanna inject,inputing your function name\n");
	char DLL_YFName[]="Print_LYXF_Interface";	//The function name of your dll 
	scanf("%s",DLL_YFName);						//Set function name of your dll from you
	//--------------------------------------------------------------------------------------->Inject your own dll
	Load_Pe(File_Buf);
	File_Buf=Add_Section(File_Buf,Size_Of_Import()+0x200);
	DWORD* Import_Table_Ptr=Pe_Tables.Import.OriginalFirstThunk;
	DWORD Size_Of_Import_Table=0;	//The size of import table
	DWORD Number_Of_Import_Table=0;
	BYTE* Sections_Table_Ptr=Pe_Headers.Sections.Sections_Ptr;
	BYTE* Section_Ptr=0;
	
	DWORD OriginalFirstThunk=0;
	DWORD TimeDateStamp=0;
	DWORD ForwarderChain=0;
	DWORD Name=0;
	DWORD FirstThunk=0;
	
	DWORD INT_Addr=0;
	DWORD IAT_Addr=0;
	i=0;	//Tmp variable
	while((*(Import_Table_Ptr+0x4)!=0)||(*(Import_Table_Ptr+0x0)!=0))	//Obtain number of import tables
	{
		Number_Of_Import_Table++;
		Import_Table_Ptr+=0x5;
	}
	Size_Of_Import_Table=0x14*Number_Of_Import_Table; //Obtain size of import tables
	//Relocate import talbe pointer to first import talbe
	Import_Table_Ptr=Pe_Tables.Import.OriginalFirstThunk;
	//Relocate File Section section pointer to the last section
	for(i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections-1);i++) Sections_Table_Ptr+=0x28;
	Section_Ptr=*((DWORD*)(Sections_Table_Ptr+0x14))+(BYTE*)File_Buf;
	//-----------------------------------------Copy Odd Table----------------------------------------//
	//Copy data from import table to the last section
	Memory_Copy(Import_Table_Ptr,Section_Ptr,Size_Of_Import_Table);
	//-----------------------------------------Add A Import Table------------------------------------//
	Section_Ptr+=Size_Of_Import_Table;
	memset(Section_Ptr,0,0x14);
	Section_Ptr+=0x28;
	//Set Import table details
	OriginalFirstThunk=Change_FOA_To_RVA((DWORD)Section_Ptr-(DWORD)File_Buf+0x0);
	TimeDateStamp=0;
	ForwarderChain=0;
	Name=Change_FOA_To_RVA((DWORD)Section_Ptr-(DWORD)File_Buf+0x8+String_Length(DLL_YFName)+0x2);
	FirstThunk=Change_FOA_To_RVA((DWORD)Section_Ptr-(DWORD)File_Buf+0x0);
	
	Copy_String(Dll_Name,(char*)(Section_Ptr+0x8+String_Length(DLL_YFName)+0x2));
	
	*(DWORD*)(Section_Ptr+0x0)=Change_FOA_To_RVA((DWORD)Section_Ptr-(DWORD)File_Buf+0x8);
	
	Copy_String(DLL_YFName,(char*)(Section_Ptr+0x8+0x2));
	
	Section_Ptr-=0x28;
	
	*(DWORD*)(Section_Ptr+0x0)=OriginalFirstThunk;
	*(DWORD*)(Section_Ptr+0x4)=TimeDateStamp;
	*(DWORD*)(Section_Ptr+0x8)=ForwarderChain;
	*(DWORD*)(Section_Ptr+0xc)=Name;
	*(DWORD*)(Section_Ptr+0x10)=FirstThunk;
	//----------------------------------------Modify Table---------------------------------------//
	*(Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress)=Change_FOA_To_RVA(*((DWORD*)(Sections_Table_Ptr+0x14)));
	*Pe_Headers.Nt_Headers.Optional_Header.Iat.VirtualAddress=0x0;
	*Pe_Headers.Nt_Headers.Optional_Header.Iat.Size=0x0;
	printf("Success to inject your own dll to this pe file!\n");
	getch();
	return File_Buf;
}
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////Add number of section to the end////////////////////////////////
void* Add_Section(void* File_Buf,DWORD New_Section_Size)	//New_Section_Size:  Size of new section
{	
	if(New_Section_Size==0)
	{
		printf("Add new section fail! \n");
		return File_Buf;
	}
	New_Section_Size=File_Alignment(New_Section_Size);
	Load_Pe(File_Buf);		
	BYTE* Sections_Ptr=Pe_Headers.Sections.Sections_Ptr;
	BYTE* Sections_Ptr_Set=Pe_Headers.Sections.Sections_Ptr;		//A pointer to begin address of section table
	DWORD Section_Offset=0;	//The start address of first section 
	DWORD Size_Of_Nt_And_Section=0;
	DWORD Size_Of_Section=0;
	//New section table
	BYTE Section_Name[8]=".LYXF";
	DWORD Misc_VirtualSize=0;
	DWORD VirtualAddress=0;
	DWORD SizeOfRawData=0;
	DWORD PointerToRawData=0;
	
	DWORD PointerToRelocations=0;
	DWORD PointerToLinenumbers=0;
	WORD  NumberOfRelocations=0;
	WORD  NumberOfLinenumbers=0;
	DWORD Characteristics=0x60000020;
	
	for(DWORD i=0;i<*Pe_Headers.Nt_Headers.File_Header.NumberOfSections;i++) Sections_Ptr+=0x28; //Relocate File Section section pointer
	
	//Calculat section address
	Misc_VirtualSize=New_Section_Size;
	VirtualAddress=Section_Alignment(*((DWORD*)(Sections_Ptr-0x28+0xc))+(*((DWORD*)(Sections_Ptr-0x28+0x10))));
	SizeOfRawData=New_Section_Size;
	PointerToRawData=File_Alignment(*((DWORD*)(Sections_Ptr-0x28+0x14))+(*((DWORD*)(Sections_Ptr-0x28+0x10))));
	
	//Modify characteristics in headers
	*Pe_Headers.Nt_Headers.File_Header.NumberOfSections+=0x1;			//Add number of section
	*Pe_Headers.Nt_Headers.Optional_Header.SizeOfImage=Section_Alignment(VirtualAddress+New_Section_Size); //Set SizeOfImage
	*Pe_Headers.Dos_Header.e_lfanew=0x40;
	//Set new section table
	for(i=0;i<8;i++) *(Sections_Ptr+i)=Section_Name[i];
	*((DWORD*)(Sections_Ptr+0x8))=Misc_VirtualSize;
	*((DWORD*)(Sections_Ptr+0xc))=VirtualAddress;
	*((DWORD*)(Sections_Ptr+0x10))=SizeOfRawData;
	*((DWORD*)(Sections_Ptr+0x14))=PointerToRawData;
	*((DWORD*)(Sections_Ptr+0x18))=PointerToRelocations;
	*((DWORD*)(Sections_Ptr+0x1c))=PointerToLinenumbers;
	*((DWORD*)(Sections_Ptr+0x20))=NumberOfRelocations;
	*((DWORD*)(Sections_Ptr+0x22))=NumberOfLinenumbers;
	*((DWORD*)(Sections_Ptr+0x24))=Characteristics;
	
	New_Buf_Size=File_Alignment(PointerToRawData+SizeOfRawData); //Get New file size
	
	void* New_File_Buf;
	if(!(New_File_Buf=malloc(New_Buf_Size)))
	{
		printf("Malloc a new file buffer fail! \n");
		return NULL;
	}
	//Calculate total size of nt headers and sections
	Size_Of_Nt_And_Section=0x18+(*Pe_Headers.Nt_Headers.File_Header.SizeOfOptionalHeader)+(0x28*(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections));
	Section_Offset=*((DWORD*)(Sections_Ptr_Set+0x14));
	Size_Of_Section=*((DWORD*)(Sections_Ptr+0x14-0x28))+(*((DWORD*)(Sections_Ptr+0x10-0x28)))-Section_Offset;
	//Initialize with 0 
	memset(New_File_Buf,0,New_Buf_Size);
	Memory_Dcopy(File_Buf,New_File_Buf,0x40);
	Memory_Dcopy((void*)(Pe_Headers.Nt_Headers.Signature),(void*)((BYTE*)New_File_Buf+0x40),Size_Of_Nt_And_Section);
	Memory_Dcopy((void*)((DWORD)File_Buf+Section_Offset),(void*)((BYTE*)New_File_Buf+Section_Offset),Size_Of_Section);
	//----------------------------Change and free Buffer------------------
	free(File_Buf);			//Free old file buffer
	Load_Pe(New_File_Buf);  //Load new PE
	Buf_Size=New_Buf_Size;	//Set a new buffer size
	//------------------------------------------------
	return New_File_Buf;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void* Enlarge_Section(void* File_Buf)
{
	Load_Pe(File_Buf);
	DWORD Enlarge_Section_Size=0x1000;			//Size of new section
	BYTE* Sections_Ptr=Pe_Headers.Sections.Sections_Ptr;
	BYTE* Sections_Ptr_Set=Pe_Headers.Sections.Sections_Ptr;		//A pointer to begin address of section table
	//Relocate File Section section pointer
	for(DWORD i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections-1);i++) Sections_Ptr+=0x28;
	//Modify detail in section table
	*((DWORD*)(Sections_Ptr+0x8))+=Enlarge_Section_Size;
	*((DWORD*)(Sections_Ptr+0x10))+=Enlarge_Section_Size;
	*((DWORD*)(Sections_Ptr+0x24))=*((DWORD*)(Sections_Ptr+0x24));//|0x60000020;
	//Modify SizeOfImage
	*Pe_Headers.Nt_Headers.Optional_Header.SizeOfImage=Section_Alignment(*((DWORD*)(Sections_Ptr+0xc))+*((DWORD*)(Sections_Ptr+0x10)));
	New_Buf_Size=File_Alignment(*((DWORD*)(Sections_Ptr+0x14))+*((DWORD*)(Sections_Ptr+0x10))); //Get New file size
	
	void* New_File_Buf;
	if(!(New_File_Buf=malloc(New_Buf_Size)))
	{
		printf("Malloc a new file buffer fail! \n");
		return NULL;
	}
	memset(New_File_Buf,0,New_Buf_Size);
	Memory_Dcopy(File_Buf,New_File_Buf,Buf_Size);
	printf("Success\n");
	//----------------------------Change and free Buffer------------------
	free(File_Buf);			//Free old file buffer
	Load_Pe(New_File_Buf); //Load new PE
	Buf_Size=New_Buf_Size;		//Set a new buffer size
	//------------------------------------------------
	return New_File_Buf;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void* Merge_All_Sections(void* File_Buf)
{	
	Load_Pe(File_Buf);
	void* Image_Buf=Change_File_Buf_To_Image_Buf(File_Buf);
	BYTE* Sections_Ptr=Pe_Headers.Sections.Sections_Ptr;	//Obtain section table pointer
	DWORD Addr_Of_FSection=*((DWORD*)(Sections_Ptr+0x14));	//The address of first section in file buffer
	DWORD Addr_Of_ISection=*((DWORD*)(Sections_Ptr+0xc));	//The address of first section in Image buffer
	DWORD All_Section_Length=0;
	DWORD Size_Of_File_Buf=0;
	DWORD Section_Characteristics=0;
	//Get the characteristics of sections and Set the section_table pointer to the last section
	for(DWORD i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections-1);i++)
	{
		Section_Characteristics=Section_Characteristics|*(DWORD*)(Sections_Ptr+0x24);
		Sections_Ptr+=0x28;
	}
	//Get the characteristics of last sections
	Section_Characteristics=Section_Characteristics|*(DWORD*)(Sections_Ptr+0x24);
	//Obtain size of file buffer
	Size_Of_File_Buf=File_Alignment(*((DWORD*)(Sections_Ptr+0x10))+*((DWORD*)(Sections_Ptr+0xc))-Addr_Of_ISection+Addr_Of_FSection);
	//Reset section pointer
	Sections_Ptr=Pe_Headers.Sections.Sections_Ptr;
	All_Section_Length=File_Alignment(Size_Of_File_Buf-Addr_Of_FSection);
	//Modify section details in headers and section table
	*Pe_Headers.Nt_Headers.File_Header.NumberOfSections=0x1;
	*(DWORD*)(Sections_Ptr+0x8)=All_Section_Length;
	*(DWORD*)(Sections_Ptr+0x10)=All_Section_Length;
	*(DWORD*)(Sections_Ptr+0x24)=Section_Characteristics;
	if(!(File_Buf=malloc(Size_Of_File_Buf)))	//Malloc new file buffer
	{
		printf("Malloc fali when load image buffer\n");
		return NULL;
	}
	memset(File_Buf,0,Size_Of_File_Buf);	//To full with 0
	//Copy each header to the file buffer
	Memory_Dcopy(Image_Buf,File_Buf,*Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeaders);
	//copy each sections
	Memory_Dcopy((void*)((BYTE*)Image_Buf+*((DWORD*)(Sections_Ptr+0xc))),(void*)((BYTE*)File_Buf+*((DWORD*)(Sections_Ptr+0x14))),All_Section_Length);
	//----------------------------Change and free Buffer------------------
	free(Image_Buf);			//Free old file buffer
	Load_Pe(File_Buf);		//Load new PE
	Buf_Size=Size_Of_File_Buf;	//Set a new buffer size
	//------------------------------------------------
	return File_Buf;
}
/////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////Add shell code to this new section////////////////////////////////
void Add_Code()
{
	
}
void Run_File_Buf()
{
	
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD Get_Function_Addr_By_Name(void* Function_Name)
{
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress==0)
	{
		printf("No export table\n");
		getch();
		return 0;
	}
	//Initiualize function address table pointer
	DWORD* Fuctnions_Ptr=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfFunctions)));
	//Initiualize function ordernal address table pointer
	WORD* Name_Ordinals_Ptr=(WORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNameOrdinals)));
	//Initiualize name table pointer
	DWORD* Names_Ptr=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNames)));//Pointer of Names table in file buffer
	DWORD* Name_In_Pe=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*Names_Ptr));		//Function name address in file buffer
	DWORD i=0;
	//--------------------------------------------------------------//
	for(i=0;i<(*Pe_Tables.Export.NumberOfNames);i++)
	{
		Name_In_Pe=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Names_Ptr+i)));
		if(Compare_String((char*)Name_In_Pe,(char*)Function_Name))	//Commpare tow strings if equal. if equal return 1,or 0.
		{
			return *(Fuctnions_Ptr+(*(Name_Ordinals_Ptr+i)));
		}
		if(i==((*Pe_Tables.Export.NumberOfNames)-0x1))
		{
			printf("Funciton is not found by name!\n");
			return 0;
		}
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD Get_Function_Addr_By_Ordinal(DWORD Function_Ordinal)
{
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress==0)
	{
		printf("No export table\n");
		getch();
		return 0;
	}
	//Initiualize function address table pointer
	DWORD* Fuctnions_Ptr=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfFunctions)));
	Function_Ordinal-=(*(Pe_Tables.Export.Base));//According to subscript index to find address 
	if(Function_Ordinal<=(*Pe_Tables.Export.AddressOfFunctions))
	{
		printf("%d \n",Function_Ordinal);
		return *(Fuctnions_Ptr+Function_Ordinal);	//return address
	}else
	{
		printf("Funciton is not found by ordinal!\n");
		return 0;
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Relocate_Function_Address(void* Image_Buf,DWORD ImageBase)
{
	Load_Pe(Image_Buf);
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress==0)
	{
		printf("No Base Reloaction table\n");
		getch();
		return;
	}

	DWORD* Basereloc_Ptr=(DWORD*)((BYTE*)Image_Buf+(*(Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress)));
	WORD* Blocks_Ptr=NULL;
	DWORD Select=0;
	DWORD Number_Of_Funciton_Addr=0;
	BYTE Condition=0;//Decalre for judging if equle 0x0011-----
	WORD Block_Real_Value=0;
	DWORD Address=0;
	DWORD Changed_Address=0;
	DWORD i=0,i_2=0;
	while(*Basereloc_Ptr)
	{
		Blocks_Ptr=(WORD*)(Basereloc_Ptr+0x2);
		Number_Of_Funciton_Addr=((*(Basereloc_Ptr+0x1))-0x8)/2;
		for(i=0;i<(Number_Of_Funciton_Addr-0x1);i++)
		{
			Condition=((BYTE)(*Blocks_Ptr))>>0x2;
			if(Condition=0x3)
			{
				Block_Real_Value=(*(Blocks_Ptr+i))<<4;
				Block_Real_Value>>=4;
				Address=(*Basereloc_Ptr)+Block_Real_Value;
				
				Changed_Address=*((DWORD*)((BYTE*)Image_Buf+Address))-(*Pe_Headers.Nt_Headers.Optional_Header.ImageBase)+ImageBase;//+ImageBase;
				*((DWORD*)((BYTE*)Image_Buf+Address))=Changed_Address;
				
				printf("Changed_Address %x\n",*((DWORD*)((BYTE*)Image_Buf+Address)));
			}
		}
		i_2++;
		if(i_2==524)
		{
			printf("%x \n",Changed_Address);//*((DWORD*)((BYTE*)Image_Buf+0x21d000)));
			getch();
		}
		Basereloc_Ptr=(DWORD*)((BYTE*)Basereloc_Ptr+(*(Basereloc_Ptr+0x1)));
	}
	*Pe_Headers.Nt_Headers.Optional_Header.ImageBase=ImageBase;
	printf("Sucsse!\n");
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD Size_Of_Export()
{
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress==0) return 0;
	//Pointer of Names table in file buffer
	DWORD* Names_Ptr=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNames)));
	DWORD* Name=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*Names_Ptr));		//Function name address in file buffer
	DWORD Size=0;
	//Calculate size of export talbe---------------------------
	Size=0x28+(0x4*(*Pe_Tables.Export.NumberOfFunctions))+(0x6*(*Pe_Tables.Export.NumberOfNames));
	for(DWORD i=0;i<(*Pe_Tables.Export.NumberOfNames);i++)	
		Size+=String_Length((char*)Buf+Change_RVA_To_FOA(*(Names_Ptr+i)));
	return Size;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Move_Export_Table(void* File_Buf,DWORD Table_Base)	//Move export table in file buffer
{											//---Table_Base is a Offset from last section's bigin address
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress==0) return;
	BYTE* Export_Ptr=(BYTE*)Pe_Tables.Export.Characteristics; //Initiualize export table pointer
	//Initiualize function address table pointer
	DWORD* Fuctnions_Ptr=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfFunctions)));
	//Initiualize function ordernal address table pointer
	WORD* Name_Ordinals_Ptr=(WORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNameOrdinals)));
	//Initiualize name table pointer
	DWORD* Names_Ptr=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNames)));//Pointer of Names table in file buffer
	DWORD* Name=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*Names_Ptr));		//Function name address in file buffer
	//--------------------------------------------------------------//
	DWORD i=0,i2=0;	//Temp variable
	BYTE* Sections_Table_Ptr=Pe_Headers.Sections.Sections_Ptr;
	BYTE* Section_Ptr=NULL;
	DWORD Virtual_Address=0;	//A Offset address in image buffer
	DWORD Section_Names_Table_Offset=0;
	DWORD Section_Names_Offset=0;
	//----------------------------Size---------------------------//
	DWORD Size_Of_Export_Table=0x28;
	DWORD Size_Of_Address_Table=(0x4*(*Pe_Tables.Export.NumberOfFunctions));
	DWORD Size_Of_Ordinals_Table=(0x2*(*Pe_Tables.Export.NumberOfNames));
	DWORD Size_Of_Names_Table=(0x4*(*Pe_Tables.Export.NumberOfNames));
	//Relocate File Section section pointer to the last section
	for(i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections-1);i++) Sections_Table_Ptr+=0x28;
	Section_Ptr=*((DWORD*)(Sections_Table_Ptr+0x14))+(BYTE*)File_Buf+Table_Base;
	//-------------------------------------Copy Table---------------------------------------------//
	//Copy export table to the last section
	Memory_Dcopy(Export_Ptr,Section_Ptr,Size_Of_Export_Table);
	Section_Ptr+=Size_Of_Export_Table;											//Relocate section pointer to the end of useful data
	//Copy export function address table to the last section
	Memory_Dcopy(Fuctnions_Ptr,Section_Ptr,Size_Of_Address_Table);
	Section_Ptr+=Size_Of_Address_Table;	//Relocate section pointer to the end of useful data
	
	//Copy export function ordinals table to the last section
	Memory_Copy(Name_Ordinals_Ptr,Section_Ptr,Size_Of_Ordinals_Table);
	Section_Ptr+=Size_Of_Ordinals_Table;	//Relocate section pointer to the end of useful data
	//Copy export function names table to the last section 
	Memory_Copy(Names_Ptr,Section_Ptr,Size_Of_Names_Table);
	Section_Ptr+=Size_Of_Names_Table;	//Relocate section pointer to the end of useful data
	for(i=0;i<(*Pe_Tables.Export.NumberOfNames);i++)
	{
		//Copy export function names to the last section 
		Name=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Names_Ptr+i)));	//Next name address
		Memory_Copy(Name,Section_Ptr,String_Length((char*)Name));
		Section_Ptr+=String_Length((char*)Name);	//Relocate section pointer to the end of useful data
	}
	//----------------------------------------Modify Table---------------------------------------//
	Section_Ptr=*((DWORD*)(Sections_Table_Ptr+0x14))+(BYTE*)File_Buf+Table_Base; //Relocate section pointer to the begin of table 
	//Modify AddressOfFunctions in export table
	Virtual_Address=Change_FOA_To_RVA((DWORD)(Section_Ptr+Size_Of_Export_Table)-(DWORD)File_Buf);
	*((DWORD*)(Section_Ptr+0x1c))=Virtual_Address;
	//Modify AddressOfOrdinals in export table
	Virtual_Address=Change_FOA_To_RVA(((DWORD)Section_Ptr-(DWORD)File_Buf)+Size_Of_Export_Table+Size_Of_Address_Table);
	*((DWORD*)(Section_Ptr+0x24))=Virtual_Address;
	//Modify AddressOfNames in export table
	Virtual_Address=Change_FOA_To_RVA((DWORD)Section_Ptr-(DWORD)File_Buf+Size_Of_Export_Table+Size_Of_Address_Table+Size_Of_Ordinals_Table);
	*((DWORD*)(Section_Ptr+0x20))=Virtual_Address;
	//Modify Name in export names table
	Section_Names_Table_Offset=(Size_Of_Export_Table+Size_Of_Address_Table+Size_Of_Ordinals_Table);
	Section_Names_Offset=(Size_Of_Export_Table+Size_Of_Address_Table+Size_Of_Ordinals_Table+Size_Of_Names_Table);
	for(i=0;i<(*Pe_Tables.Export.NumberOfNames);i++)
	{
		Virtual_Address=Change_FOA_To_RVA(((DWORD)Section_Ptr-(DWORD)File_Buf)+Section_Names_Offset);
		*((DWORD*)(Section_Ptr+Section_Names_Table_Offset+i*0x4))=Virtual_Address;
		Name=(DWORD*)((BYTE*)Buf+Change_RVA_To_FOA(*(Names_Ptr+i)));
		Section_Names_Offset+=String_Length((char*)Name);
	}
	//Modify entry address of export table
	*(Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress)=Change_FOA_To_RVA(*((DWORD*)(Sections_Table_Ptr+0x14))+Table_Base);
}
/////////////////////////////////////////////////////////////////////////////////////////////---------------->Import
DWORD Size_Of_Import()
{
	// If no base relocation table will return 0
	if(*Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress==0) return 0;
	DWORD Size_Of_Import_Table=0;	//The size of import table
	DWORD* Import_Table_Ptr=Pe_Tables.Import.OriginalFirstThunk;
	DWORD Number_Of_Import_Table=0;
	while((*(Import_Table_Ptr+0x4)!=0)||(*(Import_Table_Ptr+0x0)!=0))	//Obtain number of import tables
	{
		Number_Of_Import_Table++;
		Import_Table_Ptr+=0x5;
	}
	Size_Of_Import_Table=0x14*Number_Of_Import_Table;
	return Size_Of_Import_Table;
}
/////////////////////////////////////////////////////////////////////////////////////////////----->
void Move_Import_Table(void* File_Buf,DWORD Table_Base)
{
	// If no base relocation table will terminate
	if(*Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress==0) return;
	DWORD* Import_Table_Ptr=Pe_Tables.Import.OriginalFirstThunk;
	DWORD Size_Of_Import_Table=0;	//The size of import table
	DWORD Number_Of_Import_Table=0;
	BYTE* Sections_Table_Ptr=Pe_Headers.Sections.Sections_Ptr;
	BYTE* Section_Ptr=0;
	DWORD i=0;	//Tmp variable
	while((*(Import_Table_Ptr+0x4)!=0)||(*(Import_Table_Ptr+0x0)!=0))	//Obtain number of import tables
	{
		Number_Of_Import_Table++;
		Import_Table_Ptr+=0x5;
	}
	Size_Of_Import_Table=0x14*Number_Of_Import_Table; //Obtain size of import tables
	//Relocate import talbe pointer to first import talbe
	Import_Table_Ptr=Pe_Tables.Import.OriginalFirstThunk;
	//Relocate File Section section pointer to the last section
	for(i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections-1);i++) Sections_Table_Ptr+=0x28;
	Section_Ptr=*((DWORD*)(Sections_Table_Ptr+0x14))+(BYTE*)File_Buf+Table_Base;
	//-----------------------------------------Copy Table----------------------------------------//
	//Copy data from import table to the last section
	Memory_Copy(Import_Table_Ptr,Section_Ptr,Size_Of_Import_Table);
	//----------------------------------------Modify Table---------------------------------------//
	*(Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress)=Change_FOA_To_RVA(*((DWORD*)(Sections_Table_Ptr+0x14))+Table_Base);
}
/////////////////////////////////////////////////////////////////////////////////////////////---------------->Basereloc
DWORD Size_Of_Basereloc()	//Obtail size of Total Base Relocation table 
{
	// If no base relocation table will return 0
	if(*Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress==0) return 0;
	DWORD Size_Of_Baseraloc_Table=0;	//The size of base relocation table
	DWORD* Basereloc_Ptr=Pe_Tables.Basereloc.VirtualAddress;
	while(*Basereloc_Ptr)	//Obtail size of all blocks and Base Relocation table 
	{
		Size_Of_Baseraloc_Table+=(*(Basereloc_Ptr+0x1));
		Basereloc_Ptr=(DWORD*)((BYTE*)Basereloc_Ptr+(*(Basereloc_Ptr+0x1)));
	}
	
	return Size_Of_Baseraloc_Table;
}
/////////////////////////////////////////////////////////////////////////////////////////////----->
void Move_Basereloc_Table(void* File_Buf,DWORD Table_Base)	//Move Base Relocation table to the last section in file buffer
{
	// If no base relocation table will terminate
	if(*Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress==0) return;
	DWORD Size_Of_Baseraloc_Table=0;
	DWORD* Basereloc_Ptr=Pe_Tables.Basereloc.VirtualAddress;
	BYTE* Sections_Table_Ptr=Pe_Headers.Sections.Sections_Ptr;
	BYTE* Section_Ptr=0;
	DWORD i=0;
	//Relocate File Section section pointer to the last section
	for(i=0;i<(*Pe_Headers.Nt_Headers.File_Header.NumberOfSections-1);i++) Sections_Table_Ptr+=0x28;
	Section_Ptr=*((DWORD*)(Sections_Table_Ptr+0x14))+(BYTE*)File_Buf+Table_Base;
	while(*Basereloc_Ptr)	//Copy data from basereloc table to the last section
	{
		Memory_Copy(Basereloc_Ptr,Section_Ptr,(*(Basereloc_Ptr+0x1)));
		Section_Ptr+=(*(Basereloc_Ptr+0x1));	//Plus size of current block itself
		Basereloc_Ptr=(DWORD*)((BYTE*)Basereloc_Ptr+(*(Basereloc_Ptr+0x1)));
	}
	//Modify entry address of basereloc table
	*Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress=Change_FOA_To_RVA(*((DWORD*)(Sections_Table_Ptr+0x14))+Table_Base);
}
/////////////////////////////////////////////////////////////////////////////////////////////---------------->
void Move_All_Tables(void* File_Buf)
{
	Load_Pe(File_Buf);
	DWORD Size_Of_Tables=0;
	DWORD Section_Base=0;
	Size_Of_Tables+=Size_Of_Export()+Size_Of_Basereloc()+Size_Of_Import();
	Buf=Add_Section(File_Buf,Size_Of_Tables);
	
	Move_Export_Table(Buf,Section_Base);
	Section_Base+=Size_Of_Export();
	
	Move_Basereloc_Table(Buf,Section_Base);
	Section_Base+=Size_Of_Basereloc();
	
	Move_Import_Table(Buf,Section_Base);
	Section_Base+=Size_Of_Import();
	
	printf("Success!\n");
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD File_Alignment(DWORD Length)
{
	DWORD File_Alignment=*Pe_Headers.Nt_Headers.Optional_Header.FileAlignment;
	DWORD Align_Data=0;
	if(Length%File_Alignment==0)
	{
		Align_Data=Length;
	}else
	{
		Align_Data=((Length/File_Alignment)+1)*File_Alignment;
	}
	return Align_Data;
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD Section_Alignment(DWORD Length)
{
	DWORD Section_Alignment=*Pe_Headers.Nt_Headers.Optional_Header.SectionAlignment;
	DWORD Align_Data=0;
	if(Length%Section_Alignment==0)
	{
		Align_Data=Length;
	}else
	{
		Align_Data=((Length/Section_Alignment)+1)*Section_Alignment;
	}
	return Align_Data;
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD Dword_Alignment(DWORD Length)
{
	DWORD Dword_Alignment=4;
	DWORD Align_Data=0;
	if(Length%Align_Data==0)
	{
		Align_Data=Length;
	}else
	{
		Align_Data=((Length/Dword_Alignment)+1)*Dword_Alignment;
	}
	return Align_Data;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Export_Buffer(DWORD Buf_Size,void* Buf,char* Export_Buffer_Path)	//Export Buffer to disk
{
	FILE* Exported_File;
	if(!(Exported_File=fopen(Export_Buffer_Path,"wb")))
	{
		printf("Writing fail!\n");
		free(Buf);
		return;
	}
	fwrite(Buf,1,Buf_Size,Exported_File);
	fclose(Exported_File);
	printf("Writing successful\n");
	getch();
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Memory_Copy(IN void* Cp,OUT void* To,DWORD Length)		//Copy data from a memory to another memory whit byte
{
	for(DWORD i=0;i<Length;i++)	*((BYTE*)To+i)=*((BYTE*)Cp+i);
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Memory_Dcopy(IN void* Cp,OUT void* To,DWORD Length)	//Copy data from a memory to another memory whit dword
{
	for(DWORD i=0;i<(Length/4);i++)	*((DWORD*)To+i)=*((DWORD*)Cp+i);
}
/////////////////////////////////////////////////////////////////////////////////////////////
int Compare_String(char* str1,char* str2)	//Commpare tow strings if equal. if equal return 1,or 0.
{
	DWORD str1_lenth=0,i=0;
	while(*(str1+str1_lenth)) str1_lenth++;
	while(i<(str1_lenth+1))
	{
		if(*(str1+i)!=*(str2+i)) return 0;
		i++;
	}
	return 1;
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Copy_String(IN char* str1,OUT char* str2)
{
	DWORD str1_lenth=0,i=0;
	while(*(str1+str1_lenth)) str1_lenth++;
	while(i<(str1_lenth+1))
	{
		*(str2+i)=*(str1+i);
		i++;
	}
}
void Add_Name_To_Path(IN char* Name,OUT char* Path)
{
	DWORD i=0;
	DWORD Path_ESC=0;
	DWORD Current_Path_ESC=0;
	DWORD Path_lenth=0;
	while(*(Path+Path_lenth))
	{
		if(*Path=='\\')
		{
			Path_ESC++;
		}
		Path_lenth++;
	}
	Path_lenth=0;
	while(*(Path+Path_lenth))
	{
		if(*Path=='\\')
		{
			Current_Path_ESC++;
		}
		if(Current_Path_ESC==Path_ESC)
		{
			Copy_String(Name,(Path+Path_lenth));
		}
		Path_lenth++;
	}
}

void Cut_Name_From_Path(char* Path)
{
	
}
/////////////////////////////////////////////////////////////////////////////////////////////
DWORD String_Length(char* str)
{
	DWORD str_lenth=0;
	while(*(str+str_lenth)) str_lenth++;
	str_lenth++;//Include 0
	return str_lenth;
}
void Modify_ESC(IN char* Str)
{
	DWORD i=0;
	while(*(Str+i)) 
	{
		if(*(Str+i)=='/')
		{
			*(Str+i)='\\';
		}
		i++;
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////Print PE Header Functions////////////////////////////////////////////
void Print_About_This_File(void* File_Buf)
{	
	Load_Pe(File_Buf);
	printf("File path:                  %s\n",File_Path);
	printf("The size of this file:      %d bytes %f MB\n",File_Size,((float)File_Size/1024/1024));
	if(*(Pe_Headers.Nt_Headers.Optional_Header.Magic)==0x10B)	//To judge this PE file is 32 bit pe file or 64 bit pe file
	{
		printf("Operation platform:         32 bit\n");
		printf("Imagebase:                  %08X h\n",*(Pe_Headers.Nt_Headers.Optional_Header.ImageBase));
	}
	else
	{
		printf("Operation platform:         64 bit\n");
		printf("ImageBase:                  "); Print_Number_Hexe((void*)Pe_Headers.Nt_Headers.Optional_Header.ImageBase64,8);
	}
	printf("SizeOfOptionalHeader:       %X h\n",*(Pe_Headers.Nt_Headers.File_Header.SizeOfOptionalHeader));
	printf("NumberOfSections:           %d\n",*(Pe_Headers.Nt_Headers.File_Header.NumberOfSections));
	
	printf("AddressOfEntryPoint:        %08X h\n",*(Pe_Headers.Nt_Headers.Optional_Header.AddressOfEntryPoint));
	printf("SectionAlignment:           %X h\n",*(Pe_Headers.Nt_Headers.Optional_Header.SectionAlignment));
	printf("FileAlignment:              %X h\n",*(Pe_Headers.Nt_Headers.Optional_Header.FileAlignment));
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Dos_Header(void* File_Buf)
{
	Load_Pe(File_Buf);
	printf(" Dos_Header\n");
	printf(" 2bytes    e_magic:          %04X\n",*(Pe_Headers.Dos_Header.e_magic));
	printf(" 2bytes    e_cblp:           %04X\n",*(Pe_Headers.Dos_Header.e_cblp));
	printf(" 2bytes    e_cp:             %04X\n",*(Pe_Headers.Dos_Header.e_cp));
	printf(" 2bytes    e_crlc:           %04X\n",*(Pe_Headers.Dos_Header.e_crlc));
	printf(" 2bytes    e_cparhdr:        %04X\n",*(Pe_Headers.Dos_Header.e_cparhdr));
	printf(" 2bytes    e_minalloc:       %04X\n",*(Pe_Headers.Dos_Header.e_minalloc));
	printf(" 2bytes    e_maxalloc:       %04X\n",*(Pe_Headers.Dos_Header.e_maxalloc));
	printf(" 2bytes    e_ss:             %04X\n",*(Pe_Headers.Dos_Header.e_ss));
	printf(" 2bytes    e_sp:             %04X\n",*(Pe_Headers.Dos_Header.e_sp));
	printf(" 2bytes    e_csum:           %04X\n",*(Pe_Headers.Dos_Header.e_csum));
	printf(" 2bytes    e_ip:             %04X\n",*(Pe_Headers.Dos_Header.e_ip));
	printf(" 2bytes    e_cs:             %04X\n",*(Pe_Headers.Dos_Header.e_cs));
	printf(" 2bytes    e_lfarlc:         %04X\n",*(Pe_Headers.Dos_Header.e_lfarlc));
	printf(" 2bytes    e_ovno:           %04X\n",*(Pe_Headers.Dos_Header.e_ovno));
	////////////------------------------------------------------------------------
	printf(" 8bytes    e_res[4]:         ");
	for(int i=0;i<4;i++) printf("%04X",*(Pe_Headers.Dos_Header.e_res_4+i));
	printf("\n");
	////////////------------------------------------------------------------------
	printf(" 2bytes    e_oemid:          %04X\n",*(Pe_Headers.Dos_Header.e_oemid));
	printf(" 2bytes    e_oeminfo:        %04X\n",*(Pe_Headers.Dos_Header.e_oeminfo));
	////////////------------------------------------------------------------------
	printf(" 20bytes   e_res2[10]:       ");
	for(i=0;i<10;i++) printf("%04X",*(Pe_Headers.Dos_Header.e_res2_10+i));
	printf("\n");
	////////////------------------------------------------------------------------
	printf(" 4bytes    e_lfanew:         %08X\n",*(Pe_Headers.Dos_Header.e_lfanew));
	
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_File_Header(void* File_Buf)
{
	Load_Pe(File_Buf);
	printf(" File Header:\n");
	printf(" 2bytes    Machine:                 %04X\n",*(Pe_Headers.Nt_Headers.File_Header.Machine));
	printf(" 2bytes    NumberOfSections:        %04X\n",*(Pe_Headers.Nt_Headers.File_Header.NumberOfSections));
	printf(" 4bytes    TimeDateStamp:           %08X\n",*(Pe_Headers.Nt_Headers.File_Header.TimeDateStamp));
	printf(" 4bytes    PointerToSymbolTable:    %08X\n",*(Pe_Headers.Nt_Headers.File_Header.PointerToSymbolTable));
	printf(" 4bytes    NumberOfSymbols:         %08X\n",*(Pe_Headers.Nt_Headers.File_Header.NumberOfSymbols));
	printf(" 2bytes    SizeOfOptionalHeader:    %04X\n",*(Pe_Headers.Nt_Headers.File_Header.SizeOfOptionalHeader));
	printf(" 2bytes    Characteristics:         %04X\n",*(Pe_Headers.Nt_Headers.File_Header.Characteristics));
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Optional_Header(void* File_Buf)
{
	Load_Pe(File_Buf);
	printf(" Optional Header:\n");
	printf(" 2bytes    Magic:                         %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Magic));
	printf(" 1bytes    MajorLinkerVersion:            %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MajorLinkerVersion));
	printf(" 1bytes    MinorLinkerVersion:            %02X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MinorLinkerVersion));
	printf(" 4bytes    SizeOfCode:                    %02X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfCode));
	printf(" 4bytes    SizeOfInitializedData:         %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfInitializedData));
	printf(" 4bytes    SizeOfUninitializedData:       %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfUninitializedData));
	printf(" 4bytes    AddressOfEntryPoint:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.AddressOfEntryPoint));
	printf(" 4bytes    BaseOfCode:                    %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.BaseOfCode));
	
	if(*(Pe_Headers.Nt_Headers.Optional_Header.Magic)==0x10B)
	{
		printf(" 4bytes    BaseOfData:                    %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.BaseOfData));
		printf(" 4bytes    ImageBase:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.ImageBase));
	}
	else
	{
		printf(" 0bytes    BaseOfData:                    None\n");
		printf(" 8bytes    ImageBase:                     "); Print_Number_Hexe((void*)Pe_Headers.Nt_Headers.Optional_Header.ImageBase64,8);
	}
	
	printf(" 4bytes    SectionAlignment:              %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SectionAlignment));
	printf(" 4bytes    FileAlignment:                 %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.FileAlignment));
	printf(" 2bytes    MajorOperatingSystemVersion:   %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MajorOperatingSystemVersion));
	printf(" 2bytes    MinorOperatingSystemVersion:   %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MinorOperatingSystemVersion));
	printf(" 2bytes    MajorImageVersion:             %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MajorImageVersion));
	printf(" 2bytes    MinorImageVersion:             %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MinorImageVersion));
	printf(" 2bytes    MajorSubsystemVersion:         %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MajorSubsystemVersion));
	printf(" 2bytes    MinorSubsystemVersion:         %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.MinorSubsystemVersion));
	printf(" 4bytes    Win32VersionValue:             %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Win32VersionValue));
	printf(" 4bytes    SizeOfImage:                   %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfImage));
	printf(" 4bytes    SizeOfHeaders:                 %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeaders));
	printf(" 4bytes    CheckSum:                      %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.CheckSum));	
	printf(" 2bytes    Subsystem:                     %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Subsystem));
	printf(" 2bytes    SubDllCharacteristicssystem:   %04X\n",*(Pe_Headers.Nt_Headers.Optional_Header.DllCharacteristics));
	
	if(*(Pe_Headers.Nt_Headers.Optional_Header.Magic)==0x10B)
	{
		printf(" 4bytes    SizeOfStackReserve:            %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackReserve));
		printf(" 4bytes    SizeOfStackCommit:             %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackCommit));
		printf(" 4bytes    SizeOfHeapReserve:             %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapReserve));
		printf(" 4bytes    SizeOfHeapCommit:              %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapCommit));
	}
	else
	{
		printf(" 8bytes    SizeOfStackReserve:            "); Print_Number_Hexe((void*)Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackReserve64,8);
		printf(" 8bytes    SizeOfStackCommit:             "); Print_Number_Hexe((void*)Pe_Headers.Nt_Headers.Optional_Header.SizeOfStackCommit64,8);
		printf(" 8bytes    SizeOfHeapReserve:             "); Print_Number_Hexe((void*)Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapReserve64,8);
		printf(" 8bytes    SizeOfHeapCommit:              "); Print_Number_Hexe((void*)Pe_Headers.Nt_Headers.Optional_Header.SizeOfHeapCommit64,8);
	}
	printf(" 4bytes    LoaderFlags:                   %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.LoaderFlags));
	printf(" 4bytes    NumberOfRvaAndSizes:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.NumberOfRvaAndSizes));
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Entry_Of_Each_Table(void* File_Buf)	//Print each entry of table
{
	Load_Pe(File_Buf);
	printf("\n EXPORT ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Export.Size));
	printf("\n IMPORT ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Import.Size));
	printf("\n RESOURCE ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Resource.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Resource.Size));
	printf("\n EXCEPTION ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Exception.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Exception.Size));
	printf("\n SECURITY ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Security.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Security.Size));
	printf("\n BASERELOC ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Basereloc.Size));
	printf("\n DEBUG ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Debug.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Debug.Size));
	printf("\n COPYRIGHT ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Copyright.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Copyright.Size));
	printf("\n GLOBALPT ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Globalptr.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Globalptr.Size));
	printf("\n TLS ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Tls.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Tls.Size));
	printf("\n LOAD_CONFIG ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Load_Config.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Load_Config.Size));
	printf("\n BOUND_IMPORT ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Bound_Import.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Bound_Import.Size));
	printf("\n IAT ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Iat.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Iat.Size));
	printf("\n DELAY_IMPORT ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Delay_Import.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Delay_Import.Size));
	printf("\n COM_DESCRIPTOR ENTRY:\n");
	printf(" 4bytes    VirtualAddress:           %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Com_Descriptor.VirtualAddress));
	printf(" 4bytes    Size:                     %08X\n",*(Pe_Headers.Nt_Headers.Optional_Header.Com_Descriptor.Size));
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Export_Table(void* File_Buf)
{
	Load_Pe(File_Buf);
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Export.VirtualAddress==0)
	{
		printf("No export table\n");
		getch();
		return;
	}
	//Initiualize function address table pointer
	DWORD* Fuctnions_Ptr=(DWORD*)((BYTE*)File_Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfFunctions)));
	printf("%x \n",*Fuctnions_Ptr);
	//Initiualize function ordernal address table pointer
	WORD* Name_Ordinals_Ptr=(WORD*)((BYTE*)File_Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNameOrdinals)));
	//Initiualize name table pointer
	DWORD* Names_Ptr=(DWORD*)((BYTE*)File_Buf+Change_RVA_To_FOA(*(Pe_Tables.Export.AddressOfNames)));//Pointer of Names table in file buffer
	DWORD* Name=(DWORD*)((BYTE*)File_Buf+Change_RVA_To_FOA(*Names_Ptr));		//Function name address in file buffer
	//--------------------------------------------------------------//
	DWORD i=0,i2=0;
	char Select=0;
	while(true)
	{	
		system("cls");
		Print_LYXF_Interface();
		printf("t-----Print Export main table\n");	//To select function
		printf("f-----Print Export function table\n");
		printf("q-----Quit\n");
		Select=getch();
		//-----------------------Print Export table---------------------------------------//
		if(Select=='t')
		{
			system("cls");
			Print_LYXF_Interface();
			printf(" 4bytes    Characteristics:          %08X\n",*(Pe_Tables.Export.Characteristics));
			printf(" 4bytes    TimeDateStamp:            %08X\n",*(Pe_Tables.Export.TimeDateStamp));
			printf(" 2bytes    MajorVersion:             %04X\n",*(Pe_Tables.Export.MajorVersion));
			printf(" 2bytes    MinorVersion:             %04X\n",*(Pe_Tables.Export.MinorVersion));
			printf(" 4bytes    Name:                     %08X\n",*(Pe_Tables.Export.Name));
			printf(" 4bytes    Base:                     %08X\n",*(Pe_Tables.Export.Base));
			printf(" 4bytes    NumberOfFunctions:        %08X\n",*(Pe_Tables.Export.NumberOfFunctions));
			printf(" 4bytes    NumberOfNames:            %08X\n",*(Pe_Tables.Export.NumberOfNames));
			printf(" 4bytes    AddressOfFunctions:       %08X\n",*(Pe_Tables.Export.AddressOfFunctions));
			printf(" 4bytes    AddressOfNames:           %08X\n",*(Pe_Tables.Export.AddressOfNames));
			printf(" 4bytes    AddressOfNameOrdinals:    %08X\n",*(Pe_Tables.Export.AddressOfNameOrdinals));
			printf("Press any key to back");
			getch();
		}
		//------------------------Print function--------------------------------------//
		if(Select=='f')
		{
			system("cls");
			Print_LYXF_Interface();
			for(i=0;i<(*(Pe_Tables.Export.NumberOfFunctions));i++)
			{
				
				if(*(Fuctnions_Ptr+i)!=0)	//To filter no function address just leave real function
				{
					
					for(i2=0;i2<(*(Pe_Tables.Export.NumberOfFunctions));i2++)
					{
						//To judge if have name and print
						if(i==*(Name_Ordinals_Ptr+i2))						//If have name
						{
							Name=(DWORD*)((BYTE*)File_Buf+Change_RVA_To_FOA(*(Names_Ptr+i2)));
							printf("Function: %s \n",Name);
							printf("Ordinal: %d\n",(*(Name_Ordinals_Ptr+i2))+*(Pe_Tables.Export.Base));
							break;
						}
						if(i2==(*(Pe_Tables.Export.NumberOfFunctions)-0x1))	//If have no name
						{
							printf("Function: No name\n");
							printf("Ordinal: %d\n",*(Pe_Tables.Export.Base)+i);
							break;
						}
					}
					printf("Enray Point: "); Print_Number_Hexe(Fuctnions_Ptr+i,0x4);	//Anyway have or no name to print entray point
					printf("\n");
				}
			}
			printf("----------------------------------------->Press any key to back!");
			getch();
		}
		//--------------------------------------------------------------//
		if(Select=='q')
		{
			break;
		}
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Import_Table(void* File_Buf)
{
	Load_Pe(File_Buf);
	if(*Pe_Headers.Nt_Headers.Optional_Header.Import.VirtualAddress==0)
	{
		printf("No Import table\n");
		getch();
		return;
	}
	DWORD  Platform=0;	//Platform in 32 bit system or 64 bit system
	DWORD* Import_Table_Ptr=Pe_Tables.Import.OriginalFirstThunk;
	DWORD Select=0;
	DWORD Select_In_IANT=0;
	DWORD Number_Of_Import_Table=0;
	DWORD Order_Of_Import_Table=1;
	DWORD* IANT=0;		//A pointer of import addresses table or import names table in 32 bit platform	
	QWORD* IANT_64=0;	//A pointer of import addresses table or import names table in 64 bit platform
	DWORD* IANT_Name_Addr=0;
	DWORD  IANT_IF=0;
	DWORD  IANT_Value=0;
	DWORD Number_Of_IANT=0;
	DWORD i=0;	//Tmp variable
	//To judge this PE file is 32 bit pe file or 64 bit pe file
	if(*(Pe_Headers.Nt_Headers.Optional_Header.Magic)==0x10B)	Platform=32;
	else Platform=64;
	
	while((*(Import_Table_Ptr+0x4)!=0)||(*(Import_Table_Ptr+0x0)!=0))	//Obtain number of import tables
	{
		Number_Of_Import_Table++;
		Import_Table_Ptr+=0x5;
	}
	Import_Table_Ptr=Pe_Tables.Import.OriginalFirstThunk;	//Relocate Import table pointer
	while(true)
	{
		system("cls");
		Print_LYXF_Interface();
		printf("Commands: 'j'--->next table 'k'--->last table\n          'f'--->show functions in this table 'q'--->quit\n");
		printf("Tatal Tables: %d   Current Table: %d\n",Number_Of_Import_Table,Order_Of_Import_Table);
		printf("OriginalFirstThunk:    %08X      INT\n",*(Import_Table_Ptr+0x0));
		if(*(Import_Table_Ptr+0x1)==0xffffffff)
			printf("TimeDateStamp:         %08X      IAT had changed\n",*(Import_Table_Ptr+0x1));
		else printf("TimeDateStamp:         %08X\n",*(Import_Table_Ptr+0x1));
		printf("ForwarderChain:        %08X\n",*(Import_Table_Ptr+0x2));
		printf("Name:                  %08X      %s\n",*(Import_Table_Ptr+0x3),((BYTE*)File_Buf+Change_RVA_To_FOA(*(Import_Table_Ptr+0x3))));
		printf("FirstThunk:            %08X        IAT\n",*(Import_Table_Ptr+0x4));
		Select=getch();
		if(Select=='j'&&Order_Of_Import_Table<Number_Of_Import_Table)	//If press 'j' to print next import table
		{
			Order_Of_Import_Table++;
			Import_Table_Ptr+=0x5;
		}
		if(Select=='k'&&Order_Of_Import_Table>1)	//If press 'k' to print last import table
		{
			Order_Of_Import_Table--;
			Import_Table_Ptr-=0x5;
		}
		if(Select=='f')
		{
			system("cls");
			Print_LYXF_Interface();
			Number_Of_IANT=0;
			//--------------------------------------------------------------->
			//If this pe file is Plaatform 32
			if(Platform==32)
			{
				if(*(Import_Table_Ptr))//If entry address of INA is 0 will replace IANT pointer with IAT pointer 
				{
					IANT=(DWORD*)((DWORD)File_Buf+Change_RVA_To_FOA(*(Import_Table_Ptr)));
				}else
				{
					IANT=(DWORD*)((DWORD)File_Buf+Change_RVA_To_FOA(*(Import_Table_Ptr+0x4)));
				}
				for(i=0;*(IANT+i);i++) Number_Of_IANT++;	//Obtain number of INT or IAT
				printf("\nTotal Functions: %d\n",Number_Of_IANT);
				for(i=0;i<Number_Of_IANT;i++)
				{
					IANT_IF=(*(IANT+i)>>31);				//Obtain highest positon bit
					IANT_Value=(*(IANT+i)<<1);				//Obtain low 63 positon bit value
					IANT_Value>>=1;
					if((i+1)<10)        printf("NO.%d   ",i+1);			//Allgnment print
					if(10<=(i+1)&&(i+1)<100)   printf("NO.%d  ",i+1);	//Allgnment print
					if(100<=(i+1)&&(i+1)<1000) printf("NO.%d ",i+1);	//Allgnment print
					if(IANT_IF)	//If highest positon bit is 1 means this function is invoked by ordinal
					{
						printf("F Ordinals: %d\n",IANT_Value);
					}else		//If highest positon bit is 0 means this function is invoked by name
					{	//Obtain address of function name
						IANT_Name_Addr=(DWORD*)((DWORD)File_Buf+Change_RVA_To_FOA(IANT_Value)+0x2);
						printf("F Name: %s\n",IANT_Name_Addr);
					}
					if(i>8)	//Print whthin 10 lines imformation
					{
						printf("Press 'q' to stop\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
						Select_In_IANT=getch();
						if(Select_In_IANT=='q') break;
					}
				}
			}
			//--------------------------------------------------------------->
			//If this pe file is Plaatform 64
			if(Platform==64)
			{
				if(*(Import_Table_Ptr))		//If entry address of INA is 0 will replace IANT pointer with IAT pointer 
				{
					IANT_64=(QWORD*)((DWORD)File_Buf+Change_RVA_To_FOA(*(Import_Table_Ptr)));
				}else
				{
					IANT_64=(QWORD*)((DWORD)File_Buf+Change_RVA_To_FOA(*(Import_Table_Ptr+0x4)));
				}
				for(i=0;*(IANT_64+i);i++) Number_Of_IANT++; //Obtain number of INT or IAT
				printf("\nTotal Functions: %d\n",Number_Of_IANT);
				for(i=0;i<Number_Of_IANT;i++)
				{
					IANT_IF=(*(IANT_64+i)>>63);				//Obtain highest positon bit
					IANT_Value=(*(IANT_64+i)<<1);			//Obtain low 63 positon bit value
					IANT_Value>>=1;
					if((i+1)<10)        printf("NO.%d   ",i+1); //Allgnment print
					if(10<=(i+1)&&(i+1)<100)   printf("NO.%d  ",i+1);//Allgnment print
					if(100<=(i+1)&&(i+1)<1000) printf("NO.%d ",i+1);//Allgnment print
					if(IANT_IF)	//If highest positon bit is 1 means this function is invoked by ordinal
					{
						printf("F Ordinals: %d\n",IANT_Value);
					}else		//If highest positon bit is 0 means this function is invoked by name
					{
						IANT_Name_Addr=(DWORD*)((DWORD)File_Buf+Change_RVA_To_FOA(IANT_Value)+0x2);	//Obtain address of function name
						printf("F Name: %s\n",IANT_Name_Addr);
					}
					if(i>8)	//Print whthin 10 lines imformation
					{
						printf("Press 'q' to stop\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
						Select_In_IANT=getch();
						if(Select_In_IANT=='q') break;
					}
				}
			}
			//--------------------------------------------------------------->
			printf("----------------------------------------->Press any key to back!");
			getch();
		}
		if(Select=='q')
		{
			break;
		}
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Basereloc_Table(void* File_Buf)
{
	Load_Pe(File_Buf);
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Basereloc.VirtualAddress==0)
	{
		printf("No Base Reloaction table\n");
		getch();
		return;
	}
	DWORD* Basereloc_Ptr=Pe_Tables.Basereloc.VirtualAddress;
	DWORD Select=0;
	DWORD Number_Of_Block=0;
	DWORD Order_Of_Block=1;
	while(*Basereloc_Ptr)
	{
		Number_Of_Block++;
		Basereloc_Ptr=(DWORD*)((BYTE*)Basereloc_Ptr+(*(Basereloc_Ptr+0x1)));
	}
	Basereloc_Ptr=Pe_Tables.Basereloc.VirtualAddress;
	while(true)
	{
		system("cls");
		Print_LYXF_Interface();
		printf("Total blocks: %d Current block: %d\n",Number_Of_Block,Order_Of_Block);
		printf(" 'j'---next block 'v' view content 'q'---quit\n\n");
		
		printf("Virtual Address:  ");	Print_Number_Hexe((void*)Basereloc_Ptr,0x4);
		printf("Size Of Block:    ");	Print_Number_Hexe((void*)(Basereloc_Ptr+0x1),0x4);
		printf("LYXF->");
		Select=getch();
		
		if(Select=='j')	//Next block
		{
			if(Order_Of_Block<Number_Of_Block)
			{
				Order_Of_Block++;
				Basereloc_Ptr=(DWORD*)((BYTE*)Basereloc_Ptr+(*(Basereloc_Ptr+0x1)));
			}
		}
		if(Select=='v')	//View content
		{
			Print_Hexe(Basereloc_Ptr,*(Basereloc_Ptr+0x1));
		}
		if(Select=='q')
		{
			break;
		}
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Bound_Import_Table(void* File_Buf)
{
	//To judge if have export table,if not have will return
	if(*Pe_Headers.Nt_Headers.Optional_Header.Bound_Import.VirtualAddress==0)
	{
		printf("No Bound Import Table\n");
		getch();
		return;
	}
	BYTE* BIT_Ptr=(BYTE*)Pe_Tables.Bound_Import.TimeDateStamp;//A pointer of Bound import table
	BYTE* Name=(BYTE*)Pe_Tables.Bound_Import.TimeDateStamp+*(WORD*)(BIT_Ptr+0x4);
	DWORD Select=0;
	DWORD Number_Of_BIT=0;	//Total of bound import table
	WORD  Number_Of_MFR=0;	//Number Of Module Forwarder Refs
	DWORD Order_Of_BIT=1;	//Current order of bound import table
	DWORD i=0;				//Tmp Variable
	for(i=0;*(DWORD*)(BIT_Ptr+(i*8));i++) 
	{	
		if(*(WORD*)(BIT_Ptr+0x6+(i*8))!=0)
		{
			Number_Of_MFR++;
		}
		Number_Of_BIT++;
	}
	Number_Of_BIT-=Number_Of_MFR;
	Number_Of_MFR-=0;
	while(true)
	{
		system("cls");
		
		printf("Number of Bound import table : %d  Current: %d\n",Number_Of_BIT,Order_Of_BIT);
		Number_Of_MFR=*(WORD*)(BIT_Ptr+0x6);
		for(i=0;i<(Number_Of_MFR+1);i++)
		{
			BYTE* Name=(BYTE*)Pe_Tables.Bound_Import.TimeDateStamp+(*(WORD*)(BIT_Ptr+0x4+i*8));
			if(i==0)
				printf("\nDescriptor:%d\n",Order_Of_BIT);
			else
				printf("\nModule Forwarder %d\n",i);
			printf("TimeDateStamp:                  %x\n",*(DWORD*)(BIT_Ptr+0x0+i*8));
			printf("OffsetModuleName:               %x     %s\n",*(WORD*)(BIT_Ptr+0x4+i*8),Name);
			printf("NumberOfModuleForwarderRefs:    %x\n",*(WORD*)(BIT_Ptr+0x6+i*8));
		}
		Select=getch();
		if((Select=='j')&&(Order_Of_BIT<Number_Of_BIT))
		{
			Order_Of_BIT++;
			BIT_Ptr+=((Number_Of_MFR+1)*8);
		}
		if(Select=='q')
		{
			break;
		}
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Pe_Sections(void* File_Buf)		// To print each sections
{
	Load_Pe(File_Buf);
	char* Sections_Ptr=NULL;	//To get address of first section
	char Sections_Name[9]={0};	//The name of each section
	DWORD i_1;					//Define temporature variables
	DWORD i_2;
	DWORD Current_Section = 1;
	char Function_Select=0;
	char Section_Select = 0;
	Sections_Ptr=(char*)Pe_Headers.Sections.Sections_Ptr;
	while(true)
	{
		system("cls");
		printf("Press 'c' to show Characteristics discription\n");
		printf("Press 'q' to back\n");
		printf("Press 'j' to print next seciton,'k' to print last section\n\n");
		printf("Current section: %d Total:%d \n",Current_Section,*(Pe_Headers.Nt_Headers.File_Header.NumberOfSections));
			
			for(i_2=0;i_2<8;i_2++)
			{
				Sections_Name[i_2]=*(Sections_Ptr+i_2);
			}
			printf("---------------------------------------------->\n");
			printf("8bytes    NameOfSection:              %s\n",Sections_Name);
			printf("4bytes    Misc-VirtualSize:           %08X\n",*((DWORD*)(Sections_Ptr+0x08)));
			printf("4bytes    VirtualAddress:             %08X\n",*((DWORD*)(Sections_Ptr+0x0c)));
			printf("4bytes    SizeOfRawData:              %08X\n",*((DWORD*)(Sections_Ptr+0x10)));
			printf("4bytes    PointerToRawData:           %08X\n",*((DWORD*)(Sections_Ptr+0x14)));
			printf("4bytes    PointerToRelocations:       %08X\n",*((DWORD*)(Sections_Ptr+0x18)));
			printf("4bytes    PointerToLinenumbers:       %08X\n",*((DWORD*)(Sections_Ptr+0x1c)));
			printf("2bytes    NumberOfRelocations:        %04X\n",*((WORD*)(Sections_Ptr+0x20)));
			printf("2bytes    NumberOfLinenumbers:        %04X\n",*((WORD*)(Sections_Ptr+0x22)));
			printf("4bytes    Characteristics:            %08X\n",*((DWORD*)(Sections_Ptr+0x24)));
			printf("---------------------------------------------->\n");

			Section_Select = getch();
			
			
			if((Section_Select == 'j') && (Current_Section < (*(Pe_Headers.Nt_Headers.File_Header.NumberOfSections))))
			{
				Sections_Ptr+=0x28;
				Current_Section ++;
			}
			if((Section_Select == 'k') && (Current_Section > 1))
			{
				Sections_Ptr-=0x28;
				Current_Section --;
			}
			if(Section_Select == 'q')
			{
				break;
			}
			
			if(Section_Select == 'c')
			{	
				system("cls");
				printf("---------------------------------------------->\n");
				printf("Characteristics discription:\n");
				printf("value:00000020       Section contains code\n");
				printf("value:00000040       Section contains initialized data\n");
				printf("value:00000080       Section contains uninitialized data\n");
				printf("value:00000200       Section contains comments or some other type of\n                     information\n");
				printf("value:00000800       Section contents will not become part of image\n");
				printf("value:00001000       Section contents comdat\n");
				printf("value:00004000       Reset speculative exceptions handling bits in the\n                     TLB entries for this section\n");
				printf("value:00008000       Section content can be accessed relative to GP\n");
				printf("value:00500000       Default alignment if no others are specifie\n");
				printf("value:01000000       Section contains extended relocations\n");
				printf("value:02000000       Section can be discarded\n");
				printf("value:04000000       Section is not cachable\n");
				printf("value:08000000       Section is not pageable\n");
				printf("value:10000000       Section is shareable\n");
				printf("value:20000000       Section is executable\n");
				printf("value:40000000       Section is readable\n");
				printf("value:80000000       Section is writeable\n");
				printf("---------------------------------------------->Press any key to back!");
				getch();
			}
			
	}	
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Hexe(void* Buf,DWORD Length)
{
	BYTE* Buf_Ptr=(BYTE*)Buf;
	DWORD Function=0;
	signed int Set=0x0;		//Address of start of position
	signed int End=0x160;	//Address of end of position
	DWORD i=1;				//A variable to control order 
	DWORD Address=0;		//Address of start of position for print
	DWORD Address_Offset=0;	//Address offset for print
	DWORD Tmp_Length=Length%0x10;
	while(true)
	{
		
		system("cls");		//Clear screen
		
		if(Function=='j'&&(End<Length))	//Function control
		{
			Set=Set+0x10;
			End=End+0x10;
			Address+=0x10;
		}
		if(Function=='k'&&(Set>0))
		{
			Set-=0x10;
			End-=0x10;
			Address-=0x10;
		}
		if(Function=='q')
		{
			break;
		}
		Address_Offset=0;
		if((End-Set)>Length)	//if Length < a page length(0x160),the page length will be buffet length
		{
			for(i=1;i<(Length+0x1);i++)
			{
				if((i%0x10==0))
				{
					printf("-> %08X --- ",(Address+Address_Offset)-0xf);	//Print address
				}
				printf(" ");
				printf("%02X",*(Buf_Ptr+Set+i-1));
				if((i%4==0))    printf("  ");
					if((i%0x10==0))
					{
						printf("-> %08X --- ",(Address+Address_Offset)-0xf);	//Print address
						printf("\n");
					}
					Address_Offset++;
			}
		}
		else			//if Length >=a page length(0x160)
		{
			Address_Offset=0;
			if(End<=(Length-Tmp_Length))	//if length is a multiple of 0x10, will output with a page
			{
				for(i=1;i<(End-Set+1);i++)
				{
					printf(" ");
					printf("%02X",*(Buf_Ptr+Set+i-1));
					if((i%4==0))    printf("  ");
						if((i%0x10==0))
						{
							printf("-> %08X --- ",(Address+Address_Offset)-0xf);	//Print address
							printf("\n");
						}
						Address_Offset++;
				}
			}
			else				//if length is not a multiple of 0x10,the last line will output with remainder of length/0x10 bytes
			{
				for(i=1;i<(End-Set-0x10+Tmp_Length+0x1);i++)
				{
					
					printf(" ");
					printf("%02X",*(Buf_Ptr+Set+i-1));
					if((i%4==0))    printf("  ");
					if((i%0x10==0))
					{
						printf("-> %08X --- ",(Address+Address_Offset)-0xf);	//Print address
						printf("\n");
					}
					Address_Offset++;
				}
			}
		}
		printf("\n");
		printf("Set: %x End: %x      'j'->Next line 'k'->Last line 'q'->Quit\n",Set,End);
		Function=getch();		//Get key to run function
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_BYTE_To_String(BYTE Value)
{
	BYTE Str[3]={0};
	if(Value>=0x10)
	{
		if((Value/0x10)>=0xA)
		{
			Str[0]=Value/0x10+0x37;
		}
		else
		{
			Str[0]=Value/0x10+0x30;
		}
		
		if((Value%0x10)>=0xA) 
		{
			Str[1]=Value%0x10+0x37;
		}
		else
		{
			Str[1]=Value%0x10+0x30;
		}
	}else
	{
		Str[0]=0x30;
		if((Value%0x10)>=0xA)
		{
			Str[1]=Value%0x10+0x37;
		}
		else
		{
			Str[1]=Value%0x10+0x30;
		}
	}
	printf("%s",Str);
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_Number_Hexe(void* Num_Ptr,DWORD Length)
{
	Num_Ptr=(void*)((BYTE*)Num_Ptr+Length-1);
	for(DWORD i=0;i<Length;i++)
	{
		Print_BYTE_To_String(*((BYTE*)Num_Ptr-i));
	}
	printf("\n");
}
/////////////////////////////////////////////////////////////////////////////////////////////
void About_Me()
{
	printf("This software is completely free\n");
	printf("Mainly to learn the PE structure of Windows\n");
	printf("Easy for learners to use this tool\n");
	printf("Author Name:Xu Lvguo(Logan) QQ:418894113\n");
	printf("For more information, please join QQ Group 729054809\n");
	printf("Version: 2.0\n");
	printf("Update date: 2019.12.30\n");
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Open_File_System()
{
	char Function[256]={0};  //The name of command
	system("cls");
	printf("Dos System\nPress 'q' to quit\n");
	while(true)
	{
		fflush(stdin);	//Clear stdin buffer
		gets(Function);
		if(Compare_String("q",(char*)Function))
		{
			break;
		}
		if(!Compare_String("",(char*)Function))
		{
			system(Function);
		}
	}
	printf("----------------------------------------->Press any key to back!");
	getch();
	DEBUG
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Print_LYXF_Interface()
{
	printf("\t    *__________________________________________________________________________*\n");
	printf("\t    |              __   _          __  _         __          .___________.     |\n");
	printf("\t    |             /  > < >        <  >< >       <  >         <  _ _ _ _ _>     |\n");
	printf("\t    |           /  /    \\ \\     /  /   \\ \\     /  /         /  /               |\n");
	printf("\t    |         /  /        \\ \\_/  /       \\ \\_/  /         /  /-------->        |\n");
	printf("\t    |       /  /           ~/  /        /  /\\  \\        /  /---------~         |\n");
	printf("\t    |     /  /_ _ _ _ _   /  /        /  /   \\  \\     /  /                     |\n");
	printf("\t    |   /____________/  /__/        /__/       \\__\\ /__/                       |\n");
	printf("\t    |*________________________________________________________________________*|\n");
	printf("\t    <<<<__*_((((((((---^---Welcome to use LYXF_Tools_2.0---^---)))))))))__*_>>>>\n");
	printf("\t    /__________________________________________________________________________\\\n");
}
/////////////////////////////////////////////////////////////////////////////////////////////
void List_Command()
{
	int Select=0;
	int Order=0;
	while(1)
	{
		system("cls");
		printf("\t\t\t\tCommands:\n\n");
		if(Select=='q')
		{
			break;
		}else if(Select=='j'&&Order<1)
		{
			Order++;
		}else if(Select=='k'&&Order>0)
		{
			Order--;
		}
		if(Order==0)
		{
			printf("\tBasic commands:\n");
			printf("\t[01]  a-------------About me\n");
			printf("\t[02]  ls------------To list commands\n");
			printf("\t[03]  o-------------Open a new file\n");
			printf("\t[04]  c-------------Close this file\n");
			printf("\t[05]  w-------------Write to disk\n");
			printf("\t[06]  q-------------Quit\n");
			printf("\t[07]  cmd-----------Open dos system\n");
			printf("\t[08]  note----------Open notepad program\n");
			printf("\t[09]  calc----------Open calculator program\n");
			printf("\t[10]  sysinfo-------Show system information\n");
			printf("\t[11]  ps------------Print program process in memmory\n");
			printf("\t[12]  psw-----------Open task manager program\n");
			printf("\t[13]  ip------------Print system ip infomation\n");
			printf("\t[14]  <F7>----------Show history of commands\n");
		}else if(Order==1)
		{
			
			printf("\tPE file commands:\n");
			printf("\t[15]  ijd-----------Inject your own dll\n");
			printf("\t[16]  adsc----------Add your shellcode to this program\n");
			printf("\t[16]  adw-----------Add a window to this program\n");
			printf("\t[17]  ph------------Print buffer with Hexe\n");
			printf("\t[18]  pa------------Print breaf detials about this file\n");
			printf("\t[19]  pd------------Print Dos Header\n");
			printf("\t[20]  pf------------Print File Header\n");
			printf("\t[21]  po------------Print Optional Header\n");
			printf("\t[22]  pes-----------Print each section tables\n");
			printf("\t[23]  pe------------Print entry of each table  \n");
			printf("\t[24]  pet-----------Print Export table\n");
			printf("\t[25]  pit-----------Print Import table\n");
			printf("\t[26]  prt-----------Print Base Reloacetion table\n");
			printf("\t[27]  pbit----------Print Bound import table\n");
			printf("\t[28]  ads-----------Add number of section\n");
			printf("\t[29]  elgs----------Enlarge section of end\n");
			printf("\t[30]  mgas----------Merge all sections\n");
			printf("\t[31]  mvt-----------Move all useful tables to last section\n");
			printf("\t[32]  fti-----------Change file buffer to image buffer\n");
			printf("\t[33]  itf-----------Change image buffer to file buffer\n");
		}
		printf("---------------->  Press 'q' to quit! 'j' next cmds! 'k' last cmds!");
		Select=getch();
		
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void Run_Function()
{
	//_____________UI_________________//
	Print_LYXF_Interface();	//UI interface	
	printf("\t\t\t\tLoading");
	for(int i=0;i<20;i++)
	{
		printf("-");
		Sleep(10);
	}
	printf(">  ");
	for(i=0;i<5;i++)
	{
		printf("\b/");
		Sleep(50);
		printf("\b-");
		Sleep(50);
		printf("\b\\");
		Sleep(50);
		printf("\b|");
		Sleep(50);
	}
	//_____________UI_________________//
	//Initualize----------------------------------
	FILE* Source_File=NULL;
	char Source_File_Path[100]={0}; //The path of source pe file
	char Export_File_Path[100]={0}; //The path of export pe file
	BYTE Function[16]={0};  //The name of command
	DWORD Contorl=0;		//A judge in start commands
	DWORD Contorl_If_Open_File=false;
	DWORD IF=0;				//To use if is file buffer of image buffer,0 represent file buffer,1 represent image buffer
	//--------------------------------------------
	while(true)
	{
		system("cls");
		Print_LYXF_Interface();
		if(Contorl<5)
		{
			printf("\t\t\tInput 'ls' to list commands in this tools\n");
			Contorl++;
		}
		if(Contorl_If_Open_File==true)
		{
			printf("\t\t\tYour file is: %s\n",Source_File_Path);
		}else
		{
			printf("\t\t\tInput 'o' command to open your pe file!\n");
		}
		printf("LYXF->");
		scanf("%s",&Function);			//Get command from user
		
		if(Compare_String("o",(char*)Function))
		{
			if(Contorl_If_Open_File==false)
			{
				printf("Input your pe file path  (for example:c:/full_pe_file_name)\n->");
				//Copy_String(PATH_IN,Source_File_Path); //The name of source pe file
				
				scanf("%s",&Source_File_Path);
				
				Modify_ESC(Source_File_Path);				//Mocify escape characters
				Copy_String((char*)Source_File_Path,(char*)File_Path); //Copy name of source file to the global file path
				
				Source_File=Open_File(Source_File_Path);
				if(Source_File==NULL)
				{
					printf("---------->Open %s fail!\n",Source_File_Path);
					Contorl_If_Open_File=false;
				}else
				{
					Buf=Load_File(Source_File);	//Load file from disk to memmory
					Buf_Size=File_Size;
					Load_Pe(Buf);//Load Pe
					printf("---------->Open %s successfully!\n",Source_File_Path);
					Contorl_If_Open_File=true;
				}
			}
			else
			{
				printf("\n                   You have opened a pe file,if you wanna\n                   open a new file you must colse it!\n");
			}
			printf("----------------------------------------->Press any key to back!");
			getch();
		}
		
		if(Compare_String("c",(char*)Function))
		{
			if(Contorl_If_Open_File==true)
			{
				free(Buf);
				Buf=NULL;
				Contorl_If_Open_File=false;
				printf("You close %s successfully!\n",Source_File_Path);
			}else
			{
				printf("You have not open a pe file\n");
				
			}
			printf("----------------------------------------->Press any key to back!");
			getch();
		}
		
		if(Compare_String("a",(char*)Function))
		{	
			About_Me();
			printf("----------------------------------------->Press any key to back!");
			getch();
		}
		if(Compare_String("ls",(char*)Function))
		{
			system("cls");
			List_Command();
		}
		
		if(Compare_String("cmd",(char*)Function))
		{
			Open_File_System();
			
		}
		if(Compare_String("note",(char*)Function))
		{
			system("notepad");
			
		}
		if(Compare_String("calc",(char*)Function))
		{
			system("calc");
			
		}
		if(Compare_String("sysinfo",(char*)Function))
		{
			system("winver");
		}
		if(Compare_String("ps",(char*)Function))
		{
			system("tasklist");
			printf("----------------------------------------->Press any key to back!");
			getch();	
		}
		if(Compare_String("psw",(char*)Function))
		{
			system("taskmgr");
		}
		if(Compare_String("ip",(char*)Function))
		{
			system("ipconfig");
			printf("----------------------------------------->Press any key to back!");
			getch();
			
		}
		if(Compare_String("q",(char*)Function))
		{
			free(Buf);
			break;
		}
		//---------------------------------PE Function------------------------------------->
		
		if(Contorl_If_Open_File==true)
		{
			if(Compare_String("ijd",(char*)Function)) //Test program
			{	
				Buf=Inject_Dll(Buf);
			}
			if(Compare_String("adw",(char*)Function)) //Test program
			{	
				Add_Window_Code_End_Of_Section(Buf);
				printf("----------------------------------------->Press any key to back!");
				getch();
			}
			if(Compare_String("adsc",(char*)Function)) //Test program
			{	
				Buf = Add_Shell_Code(Buf);
				printf("----------------------------------------->Press any key to back!");
				getch();
			}
			if(Compare_String("pd",(char*)Function))
			{
				Print_Dos_Header(Buf);
				printf("----------------------------------------->Press any key to back!");
				getch();
			}
			if(Compare_String("po",(char*)Function))
			{
				Print_Optional_Header(Buf);
				printf("----------------------------------------->Press any key to back!");
				getch();
			}
			if(Compare_String("pf",(char*)Function))
			{
				Print_File_Header(Buf);
				printf("----------------------------------------->Press any key to back!");
				getch();
			}
			if(Compare_String("pa",(char*)Function))
			{
				Print_About_This_File(Buf);
				printf("----------------------------------------->Press any key to back!");
				getch();
			}
			if(Compare_String("pes",(char*)Function))
			{
				Print_Pe_Sections(Buf);
			}
			if(Compare_String("pe",(char*)Function))
			{
				Print_Entry_Of_Each_Table(Buf);
				printf("----------------------------------------->Press any key to back!");
				getch();
			}
			if(Compare_String("pet",(char*)Function))
			{
				Print_Export_Table(Buf);
			}
			if(Compare_String("pit",(char*)Function))	
			{
				Print_Import_Table(Buf);
			}
			if(Compare_String("prt",(char*)Function))
			{
				Print_Basereloc_Table(Buf);
			}
			if(Compare_String("pbit",(char*)Function))
			{
				Print_Bound_Import_Table(Buf);
			}
			if(Compare_String("ads",(char*)Function))
			{
				Buf=Add_New_Section(Buf);
				printf("Success!");
				getch();
			}
			if(Compare_String("elgs",(char*)Function))
			{
				Buf=Enlarge_Section(Buf);
				getch();
			}
			if(Compare_String("mgas",(char*)Function))
			{
				Buf=Merge_All_Sections(Buf);
				getch();
			}
			if(Compare_String("mvt",(char*)Function))
			{
				Move_All_Tables(Buf);
				getch();
			}
			if(Compare_String("ph",(char*)Function))
			{
				Print_Hexe(Buf,Buf_Size);	
			}
			if(Compare_String("fti",(char*)Function))
			{
				if(IF==SFileBuf)
				{
					Buf=Change_File_Buf_To_Image_Buf(Buf);
					printf("Success!\n");
				}else
				{
					printf("Your buffer is not file buffer\n");
				}	
				getch();
			}
			if(Compare_String("itf",(char*)Function))
			{
				if(IF==SImageBuf)
				{
					Buf=Change_Image_Buf_To_File_Buf(Buf);
					printf("Success!\n");
				}else
				{
					printf("Your buffer is not image buffer\n");
				}
				getch();
			}
			if(Compare_String("w",(char*)Function))
			{
				printf("Input export path(for example:c:/export_file_name)\n");
				Copy_String(PATH_OUT,Export_File_Path); //The name of source pe file
				scanf("%s",Export_File_Path);
				Modify_ESC(Export_File_Path);				//Mocify escape characters
				Export_Buffer(Buf_Size,Buf,Export_File_Path);
			}
			if(Compare_String("t",(char*)Function))
			{
				Buf = test(Buf);

				getch();
			}
		}
		//---------------------------------PE Function------------------------------------->
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////
void __stdcall Entrance()
{
	//
	system("mode con cols=100 lines=30");	//Ajust size of Dos window
	system("color A");						//Set color
	Run_Function();
}