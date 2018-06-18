#include "stdafx.h"
#include "PE.h"


CPe::CPe()
{
}


CPe::~CPe()
{
}



//获取目标程序的入口点Rva
DWORD CPe::GetOepRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.AddressOfEntryPoint;
}

//读取要加密文件到内存
#pragma comment(lib, "User32.lib")	//messageboxa
bool CPe::ReadTargetFile(char* pPath, PPACKINFO& pPackInfo)
{
	DWORD dwRealSize = 0;
	//1 打开文件
	HANDLE hFile = CreateFileA(
		pPath , 0x0001 , FILE_SHARE_READ ,
		NULL ,
		OPEN_EXISTING ,
		FILE_ATTRIBUTE_NORMAL , NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "读取文件失败...", "Tip", NULL);
		return FALSE;
	}


	//2 获取文件大小
	m_FileSize = GetFileSize(hFile , NULL);
	m_dwNewFileSize = m_FileSize;
	//3 申请新空间用来存放目标文件
	m_pBuf = new CHAR[m_FileSize];
	m_pNewBuf = m_pBuf;
	memset(m_pBuf , 0 , m_FileSize);

	//4 把文件内容读取到申请出的空间中
	ReadFile(hFile , m_pBuf , m_FileSize , &dwRealSize , NULL);

	//获取目标文件的PE信息
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(m_pNt);
	// 保存原始节区数
	m_SectionNumber = m_pNt->FileHeader.NumberOfSections;

	// 获取OEP
	DWORD dwOEP = m_pNt->OptionalHeader.AddressOfEntryPoint;

	// 获得资源段的信息
	m_pResRva = m_pNt->OptionalHeader.DataDirectory[2].VirtualAddress;

	//初始化资源段信息
	m_pResSectionRva = 0;		//资源段地址
	m_ResSectionIndex = -1;		//资源段在现有区段中的序号
	m_ResPointerToRawData = 0;	//资源段在文件中的偏移
	m_ResSizeOfRawData = 0;		//资源段在文件中的大小

	//获取tls区段信息，初始化
	m_pTlsSectionRva = 0;		//Tls段地址
	m_TlsSectionIndex = -1;		//Tls段 在现有区段中的序号
	m_TlsPointerToRawData = 0;	//Tls段在文件中的偏移
	m_TlsSizeOfRawData = 0;		//Tls段在文件中大小
	if (m_pNt->OptionalHeader.DataDirectory[9].VirtualAddress)	//如果目标文件中存在Tls段
	{
		//获取Tls表指针
		PIMAGE_TLS_DIRECTORY32 g_lpTlsDir = (PIMAGE_TLS_DIRECTORY32)
			(RvaToOffset(m_pNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);
		//获取Tls数据起始RVA
		m_pTlsDataRva = g_lpTlsDir->StartAddressOfRawData + m_pNt->OptionalHeader.ImageBase;
	}

	//获取代码段.text和资源段所在的区段序号（从0开始）
	for(int i = 0; i < m_pNt->FileHeader.NumberOfSections; i++)
	{
		// 如果oep在这个区段,就判断这个区段是代码段
		if(dwOEP >= pSection->VirtualAddress &&
		   dwOEP <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			// 获取代码段所在区段序号[通过oep判断]
			m_codeIndex = i;
		}

		// 获取rsrc段的信息
		if(m_pResRva >= pSection->VirtualAddress &&
		   m_pResRva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			m_pResSectionRva = pSection->VirtualAddress;
			m_ResPointerToRawData = pSection->PointerToRawData;
			m_ResSizeOfRawData = pSection->SizeOfRawData;
			m_ResSectionIndex = i;
		}
		
		//获取Tls信息
		if (m_pNt->OptionalHeader.DataDirectory[9].VirtualAddress)	//如果存在TLs
		{
			if (m_pTlsDataRva >= pSection->VirtualAddress&&
				m_pTlsDataRva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
			{
				m_pTlsSectionRva = pSection->VirtualAddress;
				m_TlsSectionIndex = i;
				m_TlsPointerToRawData = pSection->PointerToRawData;
				m_TlsSizeOfRawData = pSection->SizeOfRawData;
			}
		}
		pSection = pSection + 1;
	}

	//5 关闭文件
	CloseHandle(hFile);
	return TRUE;
}


// 用于将PE文件的rva转为文件偏移
DWORD CPe::RvaToOffset(DWORD Rva)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	for (int i= 0; i<pNt->FileHeader.NumberOfSections; i++)
	{
		if(Rva >= pSection->VirtualAddress&&
		   Rva <= pSection->VirtualAddress+pSection->Misc.VirtualSize)
		{
			// 如果文件地址为0,将无法在文件中找到对应的内容
			if (pSection->PointerToRawData == 0)
			{
				return -1;
			}
			return Rva - pSection->VirtualAddress + pSection->PointerToRawData;
		}
		pSection = pSection + 1;
	}
}




//添加区段
DWORD CPe::AddSection(
	PCHAR szName ,        //新区段的名字
	PCHAR pSectionBuf ,   //新区段的内容
	DWORD dwSectionSize , //新区段的大小
	DWORD dwAttribute    //新区段的属性
)
{
	//1 根据刚才读取的exe文件的内容，得到添加完区段后，新的exe文件的大小
	m_dwNewFileSize = m_FileSize + CalcAlignment(dwSectionSize , 0x200);
	//2 申请空间
	m_pNewBuf = new CHAR[ m_dwNewFileSize ];
	memset(m_pNewBuf , 0 , m_dwNewFileSize);
	//3 把原来的PE内容拷贝到新申请的空间中
	memcpy(m_pNewBuf , m_pBuf , m_FileSize);
	//4 把新区段拷贝到PE文件的后面
	memcpy(m_pNewBuf + m_FileSize , pSectionBuf , dwSectionSize);
	//5 修改区段表
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pSection = IMAGE_FIRST_SECTION(m_pNt);
	//得到区段表的最后一项
	PIMAGE_SECTION_HEADER pLastSection =
		m_pSection + m_pNt->FileHeader.NumberOfSections - 1;
	//得到区段表的最后一项的后面
	PIMAGE_SECTION_HEADER pNewSection = pLastSection + 1;
	pNewSection->Characteristics = dwAttribute;    //属性
	strcpy_s((char *)pNewSection->Name , 32 , szName);//区段名--->此处有问题,如果你不重新为之申请空间,当你添加节区头时可能会越界.

	// 设置内存偏移和内存大小
	pNewSection->Misc.VirtualSize = dwSectionSize; //内存中的大小（不需要对齐）
	pNewSection->VirtualAddress = pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize , 0x1000);
	pNewSection->SizeOfRawData = CalcAlignment(dwSectionSize , 0x200);

	// 设置文件偏移和文件大小
	while (TRUE)
	{
		if (pLastSection->PointerToRawData)
		{
			// 找到前一个非0的区段
			pNewSection->PointerToRawData = pLastSection->PointerToRawData +
				pLastSection->SizeOfRawData;
			break;
		}
		pLastSection = pLastSection - 1;
	}

	//6 修改区段数量和镜像大小
	m_pNt->FileHeader.NumberOfSections++;
	m_pNt->OptionalHeader.SizeOfImage = pNewSection->VirtualAddress + dwSectionSize;



	// 保存一份当前的大小
	m_FileSize = m_dwNewFileSize;

	// 释放之前的内存,并更新目标文件占用内存大小
	delete[] m_pBuf;
	m_pBuf = m_pNewBuf;

	// 返回新添加区段的rva
	return pNewSection->VirtualAddress;
}

//获取第一个新区段的rva
DWORD CPe::GetFirstNewSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + m_SectionNumber - 1;

	return pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize , 0x1000);
}

//设置新的程序入口点
void CPe::SetNewOep(DWORD dwNewOep)
{
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pNt->OptionalHeader.AddressOfEntryPoint = dwNewOep;
}

//保存文件
void CPe::SaveNewFile(char* pPath)
{
	//1 打开文件
	DWORD dwRealSize = 0;
	HANDLE hFile = CreateFileA(
		pPath , GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ ,
		NULL ,
		OPEN_ALWAYS ,
		FILE_ATTRIBUTE_NORMAL , NULL
	);
	//2 把内存中的数据写入到文件中
	WriteFile(hFile ,
			  m_pNewBuf , m_dwNewFileSize , &dwRealSize , NULL);
	//3 关闭文件句柄。
	CloseHandle(hFile);
}


//获取对齐后的大小
DWORD  CPe::CalcAlignment(DWORD dwSize , DWORD dwAlignment)
{
	if(dwSize%dwAlignment == 0)
	{
		return dwSize;
	}
	else
	{
		return (dwSize / dwAlignment + 1)*dwAlignment;
	}
}
	
//************************************
// 函数名:	FixRloc
// 描述:	根据新区段的地址修复dll的重定位[dll是加载到内存的,这里根据默认加载基址,新添加的节区的rva以及和原节区开始的差值来重新设置.text的重定位]
// 返回值:	void
// 参数:	PCHAR pStubBuf, 传入stubdll的内存首地址
// 参数:    PCHAR pStub(用于确定dll加载时重定位)
//************************************
void CPe::FixDllRloc(PCHAR pStubBuf, PCHAR pStub)
{
	// 定义重定位信息结构体
	typedef struct _TYPE
	{
		unsigned short offset : 12;
		unsigned short type : 4;
	}TYPE , *PTYPE;
	
	//定位到第一个重定位块
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pStubBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pStubBuf);
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + 5);
	PIMAGE_BASE_RELOCATION pReloc =
		(PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress + pStubBuf);

	// 开始修复重定位
	while(pReloc->SizeOfBlock != 0)
	{
		// 重定位项开始的项
		DWORD BeginLoc = (DWORD)(pReloc->VirtualAddress + pStubBuf);
		// 重定位项的个数
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		// 重定位类型
		PTYPE pType = (PTYPE)(pReloc + 1);
		// 修复每一个重定位项
		for(size_t i = 0; i < dwCount; i++)
		{
			// 如果类型是3
			if(pType->type == 3)
			{
				// 获取重定位地址
				PDWORD pReloction = (PDWORD)(pReloc->VirtualAddress + pType->offset + pStubBuf);
				// 获取该重定位地址处重定位项与节区头的偏移: 重定位地址rva - 模块rva - 区段rva
				DWORD Chazhi = *pReloction - (DWORD)pStub - 0x1000;		
				// 将偏移加上新节区的rva获得该重定位项的rva,在加上当前默认加载基址即可修复重定位
				*pReloction = Chazhi + GetNewSectionRva() + GetImageBase();
			}
			//定位到下一个重定位项
			pType++;
		}
		// 定位到下一个重定位块
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}
}


//对代码段进行加密
void CPe::Encryption()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	// 根据保存的代码段序号，定位到代码段,并将代码段加密
	pSection = pSection + m_codeIndex;
	PCHAR pStart = pSection->PointerToRawData + m_pNewBuf;
	for(int i = 0; i < (pSection->Misc.VirtualSize); i++)
	{
		pStart[i] ^= 0x15;
	}

}

//去除重定位
void CPe::CancleRandomBase()
{
	m_pNt->OptionalHeader.DllCharacteristics &=
		~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

//获取导入表的rva
DWORD CPe::GetImportTableRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.DataDirectory[ 1 ].VirtualAddress;
}

//获取重定位表的rva
DWORD CPe::GetRelocRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.DataDirectory[5].VirtualAddress;
}

//对导入表进行更改
void CPe::ChangeImportTable()
{
	// 3.将目录表的导入表项清0
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	pNt->OptionalHeader.DataDirectory[ 1 ].VirtualAddress = 0;
	pNt->OptionalHeader.DataDirectory[ 1 ].Size = 0;

	pNt->OptionalHeader.DataDirectory[ 12 ].VirtualAddress = 0;
	pNt->OptionalHeader.DataDirectory[ 12 ].Size = 0;

}

//获取目标程序加载基址
DWORD CPe::GetImageBase()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.ImageBase;
}

//设置每个区段为可写状态
void CPe::SetMemWritable()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	DWORD SectionNumber = pNt->FileHeader.NumberOfSections;

	for (int i = 0; i < SectionNumber; i++)
	{
		pSection[ i ].Characteristics |= 0x80000000;
	}
}

//重定位思路：FixDllRloc修复加载到内存的stub.dll重定位，ChangeReloc将系统PE重定位指向stub.dll重定位，stub.dll函数FixExeReloc修复目标文件重定位
//************************************
// 函数名:	ChangeReloc
// 描述:	对于动态加载基址,需要将stub的重定位区段(.reloc)修改后保存,将PE重定位信息指针指向该地址（新区段）
// 返回值:	void
// 参数:	PCHAR pBuf 传入stubdll的内存首地址
//************************************
void CPe::ChangeReloc(PCHAR pBuf)
{
	// 定位到第一个重定位块
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + 5);
	PIMAGE_BASE_RELOCATION pReloc =
		(PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress + pBuf);

	// 开始更改重定位
	while(pReloc->SizeOfBlock != 0)
	{
		// 重定位项开始的项,将其定位到在此之前添加15pb段  
		pReloc->VirtualAddress = (DWORD)(pReloc->VirtualAddress - 0x1000 + GetLastSectionRva());
		// 定位到下一个重定位块
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}

	DWORD dwRelocRva = 0;
	DWORD dwRelocSize = 0;
	DWORD dwSectionAttribute = 0;
	while(TRUE)
	{
		if(!strcmp((char*)pSection->Name , ".reloc"))
		{
			dwRelocRva = pSection->VirtualAddress;
			dwRelocSize = pSection->SizeOfRawData;
			dwSectionAttribute = pSection->Characteristics;
			break;
		}
		pSection = pSection + 1;
	}

	// 将stubdll的.reloc添加到PE文件的最后,命名为.nreloc,返回该区段的Rva
	DWORD RelocRva = AddSection(".nreloc" , dwRelocRva + pBuf , dwRelocSize , dwSectionAttribute);

	// 将重定位信息指向新添加的区段
	PIMAGE_DOS_HEADER pExeDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pExeNt = (PIMAGE_NT_HEADERS)(pExeDos->e_lfanew + m_pNewBuf);
	pExeNt->OptionalHeader.DataDirectory[5].VirtualAddress = RelocRva;
	pExeNt->OptionalHeader.DataDirectory[5].Size = dwRelocSize;



}

//如果要添加一个新区段,获得这个新区段的rva
DWORD CPe::GetNewSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize , 0x1000);
}


//获取最后一个段的rva
DWORD CPe::GetLastSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return (DWORD)pLastSection;
}



#include "../aplib/aplib.h"
#pragma comment(lib,"..//aplib//aplib.lib")
//压缩区段 压缩在加密区段之后
void CPe::EnCompression(PPACKINFO & pPackInfo)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	//用于记录压缩区段的个数
	pPackInfo->PackSectionNumber = 0;

	//1. 获取文件头的大小，并获取除资源段.rsrc和线程本地存储.tls之外的区段的文件总大小
	DWORD SecSizeWithOutResAndTls = 0;
	PIMAGE_SECTION_HEADER pSectionTmp_1 = pSection;	//临时区段头地址
	BOOL flag = TRUE;		//次数
	DWORD dwHeaderSize = 0;	//文件头大小

	for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		//获取第一个非空区段的文件偏移，即文件头大小
		if (flag && pSectionTmp_1->SizeOfRawData != 0)
		{
			dwHeaderSize = pSectionTmp_1->PointerToRawData;
			flag = FALSE;
		}
		//获取非 rsrc/tls端的总大小
		if (pSectionTmp_1->VirtualAddress != m_pResSectionRva &&
			pSectionTmp_1->VirtualAddress != m_pTlsSectionRva)
		{
			SecSizeWithOutResAndTls += pSectionTmp_1->SizeOfRawData;
		}
		pSectionTmp_1++;
	}


	//2. 读取要压缩的段到内存

	//申请内存
	PCHAR memWorked = new CHAR[SecSizeWithOutResAndTls];

	//已经拷贝的内存大小
	DWORD dwCopySize = 0;

	//保存这些区段到内存
	PIMAGE_SECTION_HEADER pSectionTmp_2 = pSection;

	//复制要压缩区段到新空间
	for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if (pSectionTmp_2->VirtualAddress != m_pResSectionRva &&
			pSectionTmp_2->VirtualAddress != m_pTlsSectionRva)
		{
			memcpy_s(memWorked + dwCopySize,
				pSectionTmp_2->SizeOfRawData,
				m_pNewBuf + pSectionTmp_2->PointerToRawData,
				pSectionTmp_2->SizeOfRawData);
			dwCopySize += pSectionTmp_2->SizeOfRawData;
		}
		pSectionTmp_2++;
	}

	//3. 压缩
	long CompressedSize;
	PCHAR CompressData = Compress(memWorked, SecSizeWithOutResAndTls, CompressedSize);

	//4. 保存.rsrc .tls段到内存空间
	PCHAR resBuffer = new CHAR[m_ResSizeOfRawData];
	PCHAR tlsBuffer = new CHAR[m_TlsSizeOfRawData];
	memcpy_s(resBuffer, m_ResSizeOfRawData, m_ResPointerToRawData+m_pNewBuf,m_ResSizeOfRawData);
	memcpy_s(tlsBuffer, m_TlsSizeOfRawData, m_TlsPointerToRawData + m_pNewBuf, m_TlsSizeOfRawData);

	//5. 设置压缩信息到信息结构体
	
	//原目标文件PE信息
	PIMAGE_DOS_HEADER pOriDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pOriNt = (PIMAGE_NT_HEADERS)(pOriDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pOriSection = IMAGE_FIRST_SECTION(pOriNt);

	for (int i = 0; i < pOriNt->FileHeader.NumberOfSections; i++)
	{
		if (pOriSection->VirtualAddress != m_pResSectionRva &&
			pOriSection->VirtualAddress != m_pTlsSectionRva)
		{
			//用于获取压缩节区的数量
			pPackInfo->PackSectionNumber++;
			//设置压缩节区index
			pPackInfo->PackInfomation[pPackInfo->PackSectionNumber][0] = i;
			//设置压缩节区的文件大小
			pPackInfo->PackInfomation[pPackInfo->PackSectionNumber][1] = pOriSection->SizeOfRawData;
			//设置原来的节区的文件中的偏移和大小为0
			pOriSection->SizeOfRawData = 0;
			pOriSection->PointerToRawData = 0;
		}
		pOriSection++;
	}

	//6. 申请新空间，使m_pNewBuf指向它，将m_pBuf文件头拷贝
	m_FileSize = dwHeaderSize + m_ResSizeOfRawData + m_TlsSizeOfRawData;//文件头大小 + res大小 + Tls大小
	//将m_pNewBuf指向它
	m_pNewBuf = new CHAR[m_FileSize];
	//修改res段的区段头
	pOriSection = IMAGE_FIRST_SECTION(pOriNt);	//定位到区段头
	if (m_ResSectionIndex < m_TlsSectionIndex)	//资源段在Tls段前面
	{
		//将原资源段文件偏移设置为文件头结尾，即为第一个区段
		pOriSection[m_ResSectionIndex].PointerToRawData = dwHeaderSize;
		//将原TLs段文件偏移设置到上面的资源到后面
		pOriSection[m_TlsSectionIndex].PointerToRawData = dwHeaderSize + m_ResSizeOfRawData;

		//先复制原文件内容到新空间
		memcpy_s(m_pNewBuf, dwHeaderSize, m_pBuf, dwHeaderSize);
		//复制资源段内容到区段头位置，资源段成为第一个区段
		memcpy_s(m_pNewBuf + dwHeaderSize, m_ResSizeOfRawData, resBuffer, m_ResSizeOfRawData);
		//复制TLS段，第二个区段
		memcpy_s(m_pNewBuf + dwHeaderSize + m_ResSizeOfRawData, m_TlsSizeOfRawData,
			tlsBuffer, m_TlsSizeOfRawData);
	}
	else if (m_ResSectionIndex > m_TlsSectionIndex)	//资源段顺序在TLS段后面
	{
		pOriSection[m_TlsSectionIndex].PointerToRawData = dwHeaderSize;
		pOriSection[m_ResSectionIndex].PointerToRawData = dwHeaderSize + m_TlsSizeOfRawData;
		memcpy_s(m_pNewBuf, dwHeaderSize, m_pBuf, dwHeaderSize);
		memcpy_s(m_pNewBuf + dwHeaderSize, m_TlsSizeOfRawData, tlsBuffer, m_TlsSizeOfRawData);
		memcpy_s(m_pNewBuf + dwHeaderSize + m_TlsSizeOfRawData
			, m_ResSizeOfRawData, resBuffer, m_ResSizeOfRawData);
	}
	else
	{
		//没有资源段和TLS 只需复制原有文件到新空间
		memcpy_s(m_pNewBuf, dwHeaderSize, m_pBuf, dwHeaderSize);
	}

	delete[] m_pBuf;
	m_pBuf = m_pNewBuf;

	//添加区段
	pPackInfo->packSectionRva = AddSection(".compres", CompressData, CompressedSize, 0xC0000040);
	pPackInfo->packSectionSize = CalcAlignment(CompressedSize, 0x200);

	//7. 添加.compres段
	delete[] memWorked;
	free(CompressData);
	delete[] resBuffer;
}


 
 //调用压缩库
 PCHAR CPe::Compress(PVOID pSource, IN long InLength, OUT long & OutLength)
 {
 	PCHAR CompressData=NULL;		//保存压缩数据的空间
 	PCHAR workmem= NULL;			//为完成压缩需要使用的空间
 
	if ((CompressData = (PCHAR)malloc(aP_max_packed_size(InLength))) == NULL ||		//存放压缩文件的空间大小
		(workmem = (PCHAR)malloc(aP_workmem_size(InLength))) == NULL)			//工作空间大小
	{
		return NULL;
	}

	//调用aPsafe_pack压缩函数,返回压缩后的空间大小
	OutLength = aPsafe_pack(pSource, CompressData, InLength, workmem, NULL, NULL);
	if (OutLength == APLIB_ERROR) return NULL;

	free(workmem);
	workmem = NULL;

 	return CompressData;
 }
 


 //修改Tls表
 BOOL CPe::ModifyTlsTable(PPACKINFO & pPackInfo)
 {
	 PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	 PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);


	 if (pNt->OptionalHeader.DataDirectory[9].VirtualAddress == 0)	//如果不存在TLS表
	 {
		 pPackInfo->bIsTlsUserful = FALSE;
		 return FALSE;
	 }
	 else
	 {
		 pPackInfo->bIsTlsUserful = TRUE;

		 //获取Tls在内存中的地址 RVA + 在内存中的起始地址
		 PIMAGE_TLS_DIRECTORY32 g_lpTlsDir = (PIMAGE_TLS_DIRECTORY32)
			 (RvaToOffset(pNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);
		 //获取TLS索引的RVA  AddressOfIndex（VA） - 加载基址
		 DWORD TlsIndexRVA = g_lpTlsDir->AddressOfIndex - pNt->OptionalHeader.ImageBase;
		 //获取TLS索引的文件偏移
		 DWORD TlsIndexOffset = RvaToOffset(TlsIndexRVA);
		 //设置Tls索引的值
		 pPackInfo->TlsIndex = 0;
		 if (TlsIndexOffset != -1)
		 {
			 //TLS索引 = 偏移 + 文件地址
			 pPackInfo->TlsIndex = *(DWORD*)(TlsIndexOffset + m_pNewBuf);
		 }
		 //保存目标程序TLS表信息
		 m_StartOfDataAddress = g_lpTlsDir->StartAddressOfRawData;	//源数据的起始地址  （VA)
		 m_EndOfDataAddress = g_lpTlsDir->EndAddressOfRawData;		//源数据的终止地址	（VA)
		 m_CallBackFuncAddress = g_lpTlsDir->AddressOfCallBacks;		//保存TLS索引的位置 （VA)

																		//将TLS回调函数RVA设置到共享信息结构体
		 pPackInfo->TlsCallbackFuncRva = m_CallBackFuncAddress;
		 return TRUE;
	 }
 }



 //************************************
 // 函数名:	SetTls
 // 描述:	
 // 返回值:	void
 // 参数:	DWORD NewSectionRva  新添加的15pb区段的rva
 // 参数:	PCHAR pStubBuf       stubdll在内存的指针
 // 参数:	DWORD pPackInfo		 共享信息结构体的首地址,PackInfo中保存了tlsRva
 //************************************
 void CPe::SetTls(DWORD NewSectionRva, PCHAR pStubBuf, PPACKINFO pPackInfo)
 {
	 PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)pStubBuf;
	 PIMAGE_NT_HEADERS pStubNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + pStubBuf);

	 PIMAGE_DOS_HEADER pPeDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	 PIMAGE_NT_HEADERS pPeNt = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + m_pNewBuf);

	 //0 将pe目录表9指向stub的tls表
	 pPeNt->OptionalHeader.DataDirectory[9].VirtualAddress =
		 (pStubNt->OptionalHeader.DataDirectory[9].VirtualAddress - 0x1000) + NewSectionRva;
	 pPeNt->OptionalHeader.DataDirectory[9].Size =
		 pStubNt->OptionalHeader.DataDirectory[9].Size;

	 PIMAGE_TLS_DIRECTORY32  pITD =
		 (PIMAGE_TLS_DIRECTORY32)(RvaToOffset(pPeNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);
	 // 获取公共结构体中tlsIndex的rva
	 DWORD indexRva = ((DWORD)pPackInfo - (DWORD)pStubBuf + 4) - 0x1000 + NewSectionRva + pPeNt->OptionalHeader.ImageBase;
	 pITD->AddressOfIndex = indexRva;
	 pITD->StartAddressOfRawData = m_StartOfDataAddress;
	 pITD->EndAddressOfRawData = m_EndOfDataAddress;

	 // 这里先取消tls的回调函数,向共享信息结构体中传入tls回调函数指针,在stub解壳的过程中手动调用tls,并将tls回调函数指针设置回去
	 pITD->AddressOfCallBacks = 0;

	 m_pBuf = m_pNewBuf;
 }
