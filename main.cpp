#include <iostream>
#include "MemReader.h"

int main()
{
	MemReader* memReader = new MemReader(L"UltimMC.exe");
	memReader->Open();
	


	system("PAUSE");
}