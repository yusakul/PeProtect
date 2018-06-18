#pragma once
#include <Windows.h>
#include <string.h>
#include "stdlib.h"
#include "..\\Stub\\Stub.h"
class CPe
{
public:
	CPe();
	~CPe();
public:
	//获取OEP
	DWORD GetOepRva();
	//读取文件到内存
	bool ReadTargetFile(char* pPath, PPACKINFO&  pPackInfo);
	//添加新区段
	DWORD AddSection(
		PCHAR szName ,        //新区段的名字
		PCHAR pSectionBuf ,   //新区段的内容
		DWORD dwSectionSize , //新区段的大小
		DWORD dwAttribute    //新区段的属性
	);

	//修复加载的dll重定位
	void FixDllRloc(PCHAR pBuf,PCHAR pOri);
	//加密
	void Encryption();
	//去除随机基址
	void CancleRandomBase();
	//获取导入表地址
	DWORD GetImportTableRva();
	//获取重定位表地址
	DWORD GetRelocRva();
	//导入表项清0
	void ChangeImportTable();
	//获取加载基址
	DWORD GetImageBase();
	//设置所有区段为可写
	void SetMemWritable();
	//将目标程序重定位指针指向为dll重定位表
	void ChangeReloc(PCHAR pBuf);
	//获取新区段地址
	DWORD GetNewSectionRva();
	//获取最后区段地址
	DWORD GetLastSectionRva();
	//获取文件偏移
	DWORD RvaToOffset(DWORD Rva);

	//压缩
	void EnCompression(PPACKINFO& pPackInfo);

	//调用压缩库
	PCHAR Compress(PVOID pSource, IN long InLength, OUT long &OutLength);

	//获取新区段（第一个）的地址
	DWORD GetFirstNewSectionRva();
	//获取新的OEP
	void SetNewOep(DWORD dwNewOep);
	//保存文件
	void SaveNewFile(char* pPath);

	//计算对齐大小
	DWORD  CalcAlignment(DWORD dwSize , DWORD dwAlignment);

	//修改Tls表
	BOOL ModifyTlsTable(PPACKINFO & pPackInfo);

	void SetTls(DWORD NewSectionRva, PCHAR pStubBuf, PPACKINFO pPackInfo);

	BOOL DealwithTLS(PPACKINFO & pPackInfo);

private:
	// 目标程序区段数量
	DWORD m_SectionNumber;
	// 代码段所在区段
	DWORD m_codeIndex;


	DWORD m_pResRva;				//资源表地址
	DWORD m_pResSectionRva;			//资源段地址
	DWORD m_ResSectionIndex;		//资源段在区段中的序号
	DWORD m_ResPointerToRawData ;	// 资源段在文件中的偏移
	DWORD m_ResSizeOfRawData ;		//	资源段大小


	DWORD m_pTlsDataRva;			// 存储tls数据的区段,也就是.tls区段
	DWORD m_pTlsSectionRva;			//Tls段地址
	DWORD m_TlsSectionIndex;
	DWORD m_TlsPointerToRawData;
	DWORD m_TlsSizeOfRawData;


private:
	//TLS表中的信息
	DWORD m_StartOfDataAddress;		//TLS区段开始地址
	DWORD m_EndOfDataAddress;		//TLS区段结束地址
	DWORD m_CallBackFuncAddress;	//TLS回调函数数组地址
	
private:
	//原目标程序内存
	PCHAR m_pBuf;			//文件数据
	DWORD m_FileSize;
private:
	//新开辟空间复制的目标程序
	PCHAR m_pNewBuf;		//文件数据
	DWORD m_dwNewFileSize;

	PIMAGE_DOS_HEADER m_pDos;
	PIMAGE_NT_HEADERS m_pNt;
	PIMAGE_SECTION_HEADER m_pSection;

};

