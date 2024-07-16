#include<iostream>
#include<Windows.h>
//#include<Winternl.h>

using namespace std;
using PrototypeMessageBox = int (WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType); /*
																										Here WINAPI* is used to specify the calling convention used by the windows ie. __stdcall
																										And the parameters inside it are the parameters passed in MessageBoxA function.
																									*/ 

PrototypeMessageBox originalMessage = MessageBoxA;													// gonna store the original address of MessageBoxA

int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

int main() {

	MessageBoxA(NULL, "Hello Before Hooking", "Hello Before Hooking", 0);
	LPVOID imageBase = GetModuleHandleA(NULL);													//get the handle 
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;									
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;											//NULL because we gonna provide the address later

	IMAGE_DATA_DIRECTORY importDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // IMAGE_DIRECTORY_ENTRY_IMPORT -> Import Directory.

	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importDirectory.VirtualAddress + (DWORD_PTR)imageBase);

	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functName = NULL;

	while(importDescriptor->Name) {
			
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;					//get the name of the import library
		library = LoadLibraryA(libraryName);													// Loading the library

		//iterating over the library to find the function
		if (library) {					
			PIMAGE_THUNK_DATA originalFirstThunk = NULL, FirstThunk = NULL;						//originalFirstThunk ->  Names of functions that exported by the dll
																								//FirstThunk ->	point to IAT.

			originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			FirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			//Will iterate over all the functions of teh library till we found the desired one
			while (originalFirstThunk->u1.AddressOfData != NULL) {

				functName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData); //To get the current function  
				if (strcmp(functName->Name, "MessageBoxA") == 0) {
					SIZE_T bytesWritten = 0;
					DWORD oldProtect = 0;

					// Swap MessageBoxA with the address of HookedMessageBox
					VirtualProtect((LPVOID)(&FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &oldProtect);
					FirstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;		// accessing the IAT as FirstThunk points to IAT
				}
				++originalFirstThunk;
				++FirstThunk;
			}
		}
		++importDescriptor;
	}

	MessageBoxA(NULL, "Hooked", "Hooked", 0);

}

int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	MessageBoxW(NULL, L"Hooked from Aish", L"Hooked", 0);
	//execute the original MessageBoxA
	return originalMessage(hWnd, lpText, lpCaption, uType);
}