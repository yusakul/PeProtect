// Pack.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "string"
#include "PE.h"
#include "..\\Stub\\Stub.h"
using namespace std;

//加壳
extern "C" _declspec(dllexport)
bool Pack(PCHAR pPath)
{
	bool ret = false;
	//1 把stub.dll载入到内存
	HMODULE hStub = LoadLibrary(L"..\\Debug\\Stub.dll");
	//3 在内存中找到和stub.dll通讯的 g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress(hStub , "g_PackInfo");
	CPe obj;
	ret = obj.ReadTargetFile(pPath, pPackInfo);
	if (!ret)
	{
		return ret;
	}

	//获取TLS信息
	BOOL bTlsUseful = obj.ModifyTlsTable(pPackInfo);

	// 对代码段进行加密
	obj.Encryption();

	//压缩区段
	obj.EnCompression(pPackInfo);

	//2 获取stub.dll的内存大小和节区头(也就是要拷贝的头部)
	PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)hStub;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + (PCHAR)hStub);
	DWORD dwImageSize = pNt->OptionalHeader.SizeOfImage;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);//stub.dll使用Release编译，第一个区段为.text 如Debug编译：.textbss

	
	//4. 设置加壳信息======

	// 获取目标程序OEP
	pPackInfo->TargetOepRva = obj.GetOepRva();
	// 获取目标程序加载基址Iamgebase
	pPackInfo->ImageBase = obj.GetImageBase();
	// 获取目标程序重定位表rva和导入表的rva
	pPackInfo->ImportTableRva = obj.GetImportTableRva();
	pPackInfo->RelocRva = obj.GetRelocRva();

	//5 获得Stub.dll模块中Start函数的相对虚拟地址：VA-Stub.dll基址
	DWORD dwStartRva = (DWORD)pPackInfo->StartAddress - (DWORD)hStub;
	// ---在修改完所有通讯结构体的内容之后再对dll进行内存拷贝---
	//6 由于直接在本进程中修改会影响进程,所以将dll拷贝一份到pStubBuf
	PCHAR pStubBuf = new CHAR[dwImageSize];
	memcpy_s(pStubBuf , dwImageSize , (PCHAR)hStub , dwImageSize);

	//7 修复dll文件重定位,这里第二个参数应该传入Stub.dll模块基址hStub,因为这是dll加载时重定位的依据
	obj.FixDllRloc(pStubBuf, (PCHAR)hStub);

	//8 把stub.dll的代码段.text添加为目标程序的新区段
	DWORD NewSectionRva = obj.AddSection(
		".15PB" ,									//区段名
		pSection->VirtualAddress + pStubBuf,		//区段地址
		pSection->SizeOfRawData,					//区段大小
		pSection->Characteristics					//区段属性
	);
	
	obj.SetTls(NewSectionRva, (PCHAR)hStub, pPackInfo);
	
	//=================重定位相关====================
	// 可以选择去掉重定位
	//obj.CancleRandomBase();
	// 或者将stub的重定位区段粘到最后面,将重定位项指向之,但是这之前也必须FixDllRloc,使其适应新的PE文件
	obj.ChangeReloc(pStubBuf);
	
	//9 把目标程序的OEP设置为stub中的start函数

	DWORD dwChazhi = (dwStartRva - pSection->VirtualAddress);
	DWORD dwNewOep = (dwChazhi + NewSectionRva);
	obj.SetNewOep(dwNewOep);
	
	// 设置每个区段可写
	obj.SetMemWritable();

	// 对IAT进行加密
	obj.ChangeImportTable();

	FreeLibrary(hStub);
	//10 保存成文件
	string savePath = pPath;
	savePath = savePath + "_pack.exe";
	obj.SaveNewFile((char*)savePath.c_str());

	return ret;
}
