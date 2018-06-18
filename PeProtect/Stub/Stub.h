#pragma once
typedef struct _PACKINFO
{
	DWORD StartAddress;			//存储起始函数地址
	DWORD temp1[20];
	
	DWORD TargetOepRva;			//用来存储目标程序的OEP的
	DWORD ImageBase;			//加载基址

	
	BOOL bIsTlsUserful;			//是否存在TLS表
	
	DWORD  TlsCallbackFuncRva;// tls回调函数指针数组
	DWORD TlsIndex;				//TLS索引序号
	

	DWORD ImportTableRva;		//IAT的rva
	DWORD RelocRva;				//重定位表rva
 

	DWORD PackSectionNumber;	// 压缩区段数量
	DWORD packSectionRva;		// 压缩区段的rva
	DWORD packSectionSize;		//压缩区段的大小
	// 压缩区段中每个区段的index和大小	
	// 下标1表示压缩节区的数量 下标二[0]=压缩区段序号 下标二[1]=压缩文件大小 
	DWORD PackInfomation[50][2];


	
}PACKINFO , *PPACKINFO;

