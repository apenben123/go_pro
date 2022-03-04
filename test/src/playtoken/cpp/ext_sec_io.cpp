//-------------------------------------------------------------*-C++-*---------
//	版本号 1.0
//-----------------------------------------------------------------------------
//	文件名: ext_sec_io.cpp
//-----------------------------------------------------------------------------
//	版权所有 (C) 2004-2010，雪天公司。
//	保留所有版权，未经授权，任何单位和个人不得擅自复制、使用本成果。
//-----------------------------------------------------------------------------
//	雪天公司: 
//	
//	修改人员		修改日期		修改内容
//
//	成学文		2009.02.21		初步设计
//	成学文		2012.06.14		移植到homed
//-----------------------------------------------------------------------------
// XteSecIO.cpp: implementation of the XteSecIO class.
//
//////////////////////////////////////////////////////////////////////

#include "ext_sec_io.h"
//#include "mod_ext/xt/XtGlobal.h"

#ifdef LINUX
#include   <sys/types.h>      
#include   <sys/socket.h>      
#include   <sys/ioctl.h>      
#include   <netinet/in.h>      
#include   <net/if.h>      
#include   <net/if_arp.h>      
#include   <arpa/inet.h>      
#include   <errno.h>      
#endif

#ifdef DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//!	需要加解码的最大长度
#define XTE_MAX_BUF_LENGTH		8192

//!	一个字节a循环右移b位
#define XTRCMBYTE(a,b)	(a) = ((a) >> (b) | (a) <<  (8 - (b)))
//!	一个字节a循环左移b位
#define XTLCMBYTE(a,b)	(a) = ((a) << (b) | (a) >>  (8 - (b)))

//!	ENCRY SEED
char g_szEncrySeed[]		= "没￥FG*.24$9，；@$%^&‘$@#)错(^&%$^%&&&^ZC×FTI位YU有RYF无JHj％……※×";
int  g_nEncrySeedLength		= (int)::strlen(g_szEncrySeed);
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

//=======new begin===========================================================================================

static void BeginFunction4AllBase(){}
//==============基本算法begin========================================================================================
/*******************************************************************************/
//begin: 算法代码,包括MD5码计算,AES加密,自定义加密等,这些代码是通用的,可能需要拷贝到各个模块中去
/*******************************************************************************/

//----取服务器信息算法begin--------------------------------------------------------------------------
static void BeginFunction4GetSrvInfo(){}
/**
将获取uuid和mac的功能函数组合到一个源代码文件，通过get_server_info()函数来同时调用。
注意:只支持linux系统	
*/
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <string>
#include <sstream>
#include <vector>

using namespace std;

#ifdef LINUX
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

/** 用到的主要函数 */
extern int inituuid(char *uuid);
extern int get_first_ether_mac(char* mac, char delimiter);
extern void * md5_buffer(const char *buffer, size_t len, void *resblock);

extern "C"{
    void md5( const unsigned char *input, size_t ilen, unsigned char output[16] );
}

#define MD5_DIGEST_SIZE 16

/*
功能:
      获取服务器的身份标识信息。
返回值:
      返回字符串长度为0表示失败，否则返回指向标识信息的字符串。
*/
static string get_server_info(void)
{
    char mac[32] = { 0 };
    char uuid[96] = { 0 };
    char *id_info = NULL;

    int ret1 = 0;
    int ret2 = 0;


    ret1 = inituuid(uuid);
    ret2 = get_first_ether_mac(mac,':');

    if (ret1 && ret2)
    {
        return string("");
    }

	ostringstream oss;
	oss << uuid << '+' << mac;
	return oss.str(); 
}


/************************************************************
 *  获取UUID和序列号相关的代码 
 ************************************************************/



//#define MAXINTERFACES   16
#ifdef __ia64__
#define USE_EFI
#endif /* __ia64__ */

/* Default memory device file */
#ifdef __BEOS__
#define DEFAULT_MEM_DEV "/dev/misc/mem"
#else
#define DEFAULT_MEM_DEV "/dev/mem"
#endif

/* Use mmap or not */
#ifndef __BEOS__
#define USE_MMAP
#endif


//#define VERSION "2.8"

#ifndef TYPES_H
#define TYPES_H

typedef signed short i16;


/*
 * These macros help us solve problems on systems that don't support
 * non-aligned memory access. This isn't a big issue IMHO, since the tools
 * in this package are intended mainly for Intel and compatible systems,
 * which are little-endian and support non-aligned memory access. Anyway,
 * you may use the following defines to control the way it works:
 * - Define BIGENDIAN on big-endian systems.
 * - Define ALIGNMENT_WORKAROUND if your system doesn't support
 *   non-aligned memory access. In this case, we use a slower, but safer,
 *   memory access method.
 * You most probably will have to define none or the two of them.
 */

#ifdef BIGENDIAN
typedef struct {
	unsigned  int h;
	unsigned  int l;
} su64;
#else
typedef struct {
	unsigned  int l;
	unsigned  int h;
} su64;
#endif

#ifdef ALIGNMENT_WORKAROUND
static su64 U64(unsigned  int low, unsigned  int high)
{
	su64 self;
	
	self.l=low;
	self.h=high;
	
	return self;
}
#endif

#ifdef ALIGNMENT_WORKAROUND
#	ifdef BIGENDIAN
#	define WORD(x) (unsigned  short)((x)[1]+((x)[0]<<8))
#	define DWORD(x) (unsigned  int)((x)[3]+((x)[2]<<8)+((x)[1]<<16)+((x)[0]<<24))
#	define QWORD(x) (U64(DWORD(x+4), DWORD(x)))
#	else /* BIGENDIAN */
#	define WORD(x) (unsigned  short)((x)[0]+((x)[1]<<8))
#	define DWORD(x) (unsigned  int)((x)[0]+((x)[1]<<8)+((x)[2]<<16)+((x)[3]<<24))
#	define QWORD(x) (U64(DWORD(x), DWORD(x+4)))
#	endif /* BIGENDIAN */
#else /* ALIGNMENT_WORKAROUND */
#define WORD(x) (unsigned  short)(*(const unsigned  short *)(x))
#define DWORD(x) (unsigned  int)(*(const unsigned  int *)(x))
#define QWORD(x) (*(const su64 *)(x))
#endif /* ALIGNMENT_WORKAROUND */

#endif


struct string_keyword
{
	const char *keyword;
	unsigned char type;
	unsigned char offset;
	const char *(*lookup)(unsigned char);
	void (*print)(unsigned char *);
};

struct soption
{
	const char* devmem;
	unsigned int flags;
	unsigned char *type;
	const struct string_keyword *string;
};

struct soption opt;  // 在源代码基础上修改类型，使得类型名不与变量名相同

#define FLAG_VERSION            (1<<0)
#define FLAG_HELP               (1<<1)
#define FLAG_DUMP               (1<<2)
#define FLAG_QUIET              (1<<3)


struct dmi_header
{
	unsigned char type;
	unsigned char length;
	unsigned short handle;
};



unsigned char g_uuidbuf[16] = {0};
unsigned char g_serial_no[20] = {0};




/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
static void *mem_chunk(size_t base, size_t len, const char *devmem)
{
	void *p;
	int fd;
#ifdef USE_MMAP
	size_t mmoffset;
	void *mmp;
#endif
	
	if((fd=open(devmem, O_RDONLY))==-1)
	{
		perror(devmem);
		return NULL;
	}
	
	if((p=malloc(len))==NULL)
	{
		perror("malloc");
		return NULL;
	}
	
#ifdef USE_MMAP
#ifdef _SC_PAGESIZE
	mmoffset=base%sysconf(_SC_PAGESIZE);
#else
	mmoffset=base%getpagesize();
#endif /* _SC_PAGESIZE */
	/*
	 * Please note that we don't use mmap() for performance reasons here,
	 * but to workaround problems many people encountered when trying
	 * to read from /dev/mem using regular read() calls.
	 */
	mmp=mmap(0, mmoffset+len, PROT_READ, MAP_SHARED, fd, base-mmoffset);
	if(mmp==MAP_FAILED)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("mmap");
		free(p);
		return NULL;
	}
	
	memcpy(p, (unsigned char *)mmp+mmoffset, len);
	
	if(munmap(mmp, mmoffset+len)==-1)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("munmap");
	}
#else /* USE_MMAP */
	if(lseek(fd, base, SEEK_SET)==-1)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("lseek");
		free(p);
		return NULL;
	}
	
	if(myread(fd, p, len, devmem)==-1)
	{
		free(p);
		return NULL;
	}
#endif /* USE_MMAP */
	
	if(close(fd)==-1)
		perror(devmem);
	
	return p;
}


static int checksum(const unsigned char *buf, size_t len)
{
	unsigned char sum=0;
	size_t a;
	
	for(a=0; a<len; a++)
		sum+=buf[a];
	return (sum==0);
}

#if 0
static void dmi_system_uuid(unsigned char *p)		//获得uuid 的函数
{
	int only0xFF=1, only0x00=1;
	int i;
	for(i=0; i<16 && (only0x00 || only0xFF); i++)
	{
		if(p[i]!=0x00) only0x00=0;
		if(p[i]!=0xFF) only0xFF=0;
	}
	
	if(only0xFF)
	{
		//printf("Not Present");
		return;
	}
	if(only0x00)
	{
		//printf("Not Settable");
		return;
	}

	memcpy(&g_uuidbuf,p,16);
}
#endif



/*
 * 7.2 System Information (Type 1)
 */

static void dmi_system_uuid(const unsigned char *p, unsigned short ver)
{
	int only0xFF = 1, only0x00 = 1;
	int i;

	for (i = 0; i < 16 && (only0x00 || only0xFF); i++)
	{
		if (p[i] != 0x00) only0x00 = 0;
		if (p[i] != 0xFF) only0xFF = 0;
	}

	if (only0xFF)
	{
		//printf("Not Present");
		return;
	}
	if (only0x00)
	{
		//printf("Not Settable");
		return;
	}

	/*
	 * As of version 2.6 of the SMBIOS specification, the first 3
	 * fields of the UUID are supposed to be encoded on little-endian.
	 * The specification says that this is the defacto standard,
	 * however I've seen systems following RFC 4122 instead and use
	 * network byte order, so I am reluctant to apply the byte-swapping
	 * for older versions.
	 */
    if (ver >= 0x0206)
    {
        g_uuidbuf[0] = p[3]; g_uuidbuf[1] = p[2];
        g_uuidbuf[2] = p[1]; g_uuidbuf[3] = p[0];

        g_uuidbuf[4] = p[5]; g_uuidbuf[5] = p[4];

        g_uuidbuf[6] = p[7]; g_uuidbuf[7] = p[6];

        for(int i=0;i<8;i++) g_uuidbuf[i] = p[i];
    }

		//printf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		//	p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
		//	p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    else
    {
        for(int i=0;i<16;i++) g_uuidbuf[i] = p[i];
    }
		//printf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		//	p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		//	p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}


#define DMI_SYSINFO_SN_SIZE 32
char g_sn[DMI_SYSINFO_SN_SIZE] = { 0 };
/*
功能: 将序列号存放到对应全局变量g_sn中。
说明:
      该函数是从dmidecode源码的dmi_string()函数转变过来的，主要修改了返回值类型和用途，
      以及写入到g_sn的操作。原函数返回的是一个指向序列号的字符串，修改后的函数返回整型值，
      表示成功与否，序列号存入g_sn中。
*/
//const char *dmi_string_sn(const struct dmi_header *dm, u8 s)
static int dmi_string_sn(unsigned char *data, unsigned char s)
{
	//char *bp = (char *)dm->data;
    char *bp = (char *)data;
	size_t i, len;

	if (s == 0)
        //return "Not Specified";
		return -1;

    //bp += dm->length;
	bp += data[1]; // data[1] is the very length of the header
	while (s > 1 && *bp)
	{
		bp += strlen(bp);
		bp++;
		s--;
	}

    if (!*bp)
        //return bad_index;
        return -1;

	if (!(opt.flags & FLAG_DUMP))
	{
		/* ASCII filtering */
		len = strlen(bp);
		for (i = 0; i < len; i++)
			if (bp[i] < 32 || bp[i] == 127)
				bp[i] = '.';
	}

    snprintf(g_sn, DMI_SYSINFO_SN_SIZE, "%s", bp);

	//return bp;
    return 0;
}

/*
说明:
    本函数来源于dmidecode程序源码。对该函数进行了修改，只使用类型1的信息，即
    System Information，具体只取其中的Serial Number和UUID两项信息。取到的信息
    分别存放到全局变量之中。分别在具体调用函数中进行写全局变量操作。序列号放到
    g_sn中，在dmi_string_sn()函数中进行写操作；UUID放到g_uuidbuf中，在
    dmi_system_uuid()函数中进行操作。

 */

static void dmi_decode(unsigned char *data, unsigned short ver)
{
	struct dmi_header *h=(struct dmi_header *)data;

	switch(h->type)
	{

	case 1: 
        if (h->length < 0x08) break;
        
        dmi_string_sn(data, data[0x07]);

		if(h->length<0x19) break;

		dmi_system_uuid(data+0x08, ver);	//在这里求出 uuid  参数data + 0x08
		//printf("\n");
		return;
	default:
		break;
	}
}
		
static void dmi_table(unsigned int base, unsigned short len, unsigned short num, unsigned short ver, const char *devmem)//使用了dmi_decode 调//////dmi_system_uuid用
{
	unsigned char *buf;
	unsigned char *data;
	int i=0;
	
	if((buf=(unsigned char *)mem_chunk(base, len, devmem))==NULL)
	{
#ifndef USE_MMAP
		printf("Table is unreachable, sorry. Try compiling dmidecode with -DUSE_MMAP.\n");
#endif
		return;
	}
	
	data=buf;
	while(i<num && data+sizeof(struct dmi_header)<=buf+len)//循环调用dmi_decode
	{
		unsigned char *next;
		struct dmi_header *h=(struct dmi_header *)data;
		int display=((opt.type==NULL || opt.type[h->type])
			&& !((opt.flags & FLAG_QUIET) && h->type>39)
			&& !opt.string);

		if((opt.flags & FLAG_QUIET) && h->type==127)
			break;
			
		/* look for the next handle */
		next=data+h->length;
		while(next-buf+1<len && (next[0]!=0 || next[1]!=0))
			next++;
		next+=2;
		if(display)
		{
			if(next-buf<=len)
			{
				if(opt.flags & FLAG_DUMP)
					;
				else
					dmi_decode(data, ver);  //调用dmi_decode 参数 data ver
			}

		}
		data=next;
		i++;
	}
	free(buf);
}

static int smbios_decode(unsigned char *buf, const char *devmem)//dmi_table ...dmi_system_uuid
{
	if(checksum(buf, buf[0x05])
	 && memcmp(buf+0x10, "_DMI_", 5)==0
	 && checksum(buf+0x10, 0x0F))
	{
		dmi_table(DWORD(buf+0x18), WORD(buf+0x16), WORD(buf+0x1C),// 这里
			(buf[0x06]<<8)+buf[0x07], devmem);
		return 1;
	}
	
	return 0;
}


#ifndef USE_EFI
static int legacy_decode(unsigned char *buf, const char *devmem)
{
	if(checksum(buf, 0x0F))
	{
		if(!(opt.flags & FLAG_QUIET))
			printf("Legacy DMI %u.%u present.\n",
				buf[0x0E]>>4, buf[0x0E]&0x0F);
		dmi_table(DWORD(buf+0x08), WORD(buf+0x06), WORD(buf+0x0C),// 这里
			((buf[0x0E]&0xF0)<<4)+(buf[0x0E]&0x0F), devmem);
		return 1;
	}
	
	return 0;
}
#endif /* USE_EFI */
//返回0 正确  返回1错误

static int check_uuid(unsigned char* uuid)
{
	int i;
	for(i=0;i<16;i++)
	{
		if(uuid[i] != 0)
			return 0;
	}
	return 1;//说明uuid 都为0  即是空串
}


//返回0成功 返回1失败
static int getuuid(char* uuid)
{
	int ret=0;                  /* Returned value */
	int found=0;
	size_t fp;     //重要参数
#ifdef USE_EFI
	FILE *efi_systab;
	const char *filename;
	char linebuf[64];
#endif /* USE_EFI */

	unsigned char *buf; //定义参数buf
	opt.devmem=DEFAULT_MEM_DEV; //给参数opt.devmem赋值  DEFAULT_MEM_DEV =="/dev/misc/mem" or "/dev/mem"
	opt.flags=0;

#ifdef USE_EFI
	/*
	 * Linux up to 2.6.6-rc2: /proc/efi/systab
	 * Linux 2.6.6-rc3 and up: /sys/firmware/efi/systab
	 */
	if((efi_systab=fopen(filename="/proc/efi/systab", "r"))==NULL
	&& (efi_systab=fopen(filename="/sys/firmware/efi/systab", "r"))==NULL)
	{
		perror(filename);
		ret=1;
		printf("1");
		goto exit_free;
	}
	fp=0;
	while((fgets(linebuf, sizeof(linebuf)-1, efi_systab))!=NULL)//char linebuf[64];
	{
		char* addr=memchr(linebuf, '=', strlen(linebuf));//求参数
		*(addr++)='\0';
		if(strcmp(linebuf, "SMBIOS")==0)
		{
			fp=strtoul(addr, NULL, 0);//将字符串转换成无符号长整型数 给参数赋值  
		}
	}

	if(fclose(efi_systab)!=0)
		perror(filename);

	if(fp==0)
	{
		ret=1;
		printf("2");
		goto exit_free;
	}

	if((buf=(unsigned char *)mem_chunk(fp, 0x20, opt.devmem))==NULL)// 求参数 buf   fp, 0x20, opt.devmem
	{
		ret=1;
		printf("3");
		goto exit_free;
	}
	
	if(smbios_decode(buf, opt.devmem))//从这里到uuid 参数 buf  opt.devmem
		found++;
	
	free(buf);


#else /* USE_EFI */

	//if((buf=(unsigned char *)mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL)
    if((buf=(unsigned char *)mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL)
	{
		ret=1;
		goto exit_free;
	}
	
	for(fp=0; fp<=0xFFF0; fp+=16)
	{
		if(memcmp(buf+fp, "_SM_", 4)==0 && fp<=0xFFE0)
		{
			if(smbios_decode(buf+fp, opt.devmem))//从这里到uuid 参数 buf  opt.devmem
				found++;
			fp+=16;
		}
		else if(memcmp(buf+fp, "_DMI_", 5)==0)
		{
			if (legacy_decode(buf+fp, opt.devmem))
				found++;
		}
	}
 
#endif /* USE_EFI */

    // 检查一下
    ret = check_uuid(g_uuidbuf) || check_uuid((unsigned char*)g_sn); // check_uuid()返回真表示uuid是空串

    if (!ret)  // ret为0，表示成功获取；将相关信息转成字符串到uuid（实际上加上序列号之后叫machine_info更妥当。
    {
        unsigned char *p = (unsigned char *)g_uuidbuf;

		sprintf(uuid,"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X+%s",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],g_sn);
    }

	//if( (ret = choose_SN(uuid))== 0)//为了有返回值
	//	putSN(uuid);

exit_free:
	free(opt.type);

	return ret;
}

/*
功能: 
      返回UUID+序列号信息。用字符串表示，格式是“<UUID>+<SN>”，比如“44454C4C-4E00-1038-8058-B4C04F443258+4N8XD2X”。
参数:
      uuid: 存放输出字符串的缓冲区；大小以64字节为宜。
返回值:
      返回0成功，否则失败    
*/
int inituuid(char *uuid)
{
	return getuuid(uuid);
}



/***********************************************************
 *     获取第一个网卡的MAC地址的代码                         
 ***********************************************************/

#define MAXINTERFACES   16

/*
功能:
      获取第一个以太网卡的MAC地址。
参数:
      mac:       存放输出的MAC地址（以字符串表示）的缓冲区，大小以32字节为宜；
      delimiter: MAC地址转成字符串时，各字节之间分隔符，建议使用':'；
返回值:
      成功返回0，否则表示失败。
*/
int get_first_ether_mac(char* mac, char delimiter)
{
    int fd;
    int intrface;
    int ret = 0;
    struct ifreq buf[MAXINTERFACES];
    struct ifconf ifc;

    if (delimiter == '\0')
        delimiter = ':';

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = (caddr_t)buf;

        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
        {
            //获取接口信息
            intrface = ifc.ifc_len / sizeof(struct ifreq);

            int selected_index = -1;
            for (int i = 0; i < intrface; i++)
            {
                /* 选取第一个以太网接口的原则：
                   各接口的先后顺序是它们对应在ifreq数组元素的顺序（从第一个元素开始）；
                   如果有e开头的以太网接口名字，那么返回它们之中的第一个；
                   如果没有e开头的，则选取除lo以外的其他的接口的第一个（可能是虚拟网卡）；
                   如果没有接口或者只有lo，然会错误；

                   实现方法：初始索引置为-1；按顺序扫描ifreq数组，若有e开头的，那么终止循环，
                   返回该索引；如果是lo跳过；如果是其他则记录第一个值并继续；
                   */
                if (!(buf[i].ifr_name[0] == 'l' && buf[i].ifr_name[1] == 'o'))  // not 'lo'
                {
                    if (buf[i].ifr_name[0] == 'e')  // 名字是'e'开头的接口
                    {
                        selected_index = i;
                        break;
                    }
                    else  // 其他接口(虚拟网桥或网卡）
                    {
                        if (selected_index < 0)
                        {
                            selected_index = i;  // 记录首次碰到的索引
                        }
                    }
                }
            }

            if (selected_index < 0)
            {
                ret = -1;
            }
            else
            {
                int iif = selected_index;  // 当前选中接口的索引，iif名字精简
                int ci = 0; // 用作索引游标


                // 显示MAC地址
                if (!(ioctl(fd, SIOCGIFHWADDR, (char *)&buf[iif])))
                {
                    for (int i = 0; i < 6; i++)
                    {
                        ci += snprintf(mac+ci, 4, "%02x%c",(unsigned char)buf[iif].ifr_hwaddr.sa_data[i],delimiter);
                    }
                    mac[ci-1] = '\0';
                }
                else
                {
                    ret = -1;
                }
            }
        }
        else
        {
            ret = -1;
        } 
    }
    else
        ret = -1;

    close(fd);
    return ret;
}
#else//#ifdef LINUX

static string get_server_info(void){return string("");}

static void EndFunction4GetSrvInfo(){}
#endif//#ifdef LINUX
//----取服务器信息算法end--------------------------------------------------------------------------


//----基础函数begin-----------------------------------------------------------------------------------
static void BeginFunction4Base(){}

//!	将字节串转换为字符串
static int XtBytesToString(const void * pSrcBuf,int nSrcBufByteLength,char * szDestString,bool bLowerChar)
{
	static unsigned char achNum2LowerS[256][2] = 
	{
		{'0','0'},{'0','1'},{'0','2'},{'0','3'},{'0','4'},{'0','5'},{'0','6'},{'0','7'},{'0','8'},{'0','9'},{'0','a'},{'0','b'},{'0','c'},{'0','d'},{'0','e'},{'0','f'},
		{'1','0'},{'1','1'},{'1','2'},{'1','3'},{'1','4'},{'1','5'},{'1','6'},{'1','7'},{'1','8'},{'1','9'},{'1','a'},{'1','b'},{'1','c'},{'1','d'},{'1','e'},{'1','f'},
		{'2','0'},{'2','1'},{'2','2'},{'2','3'},{'2','4'},{'2','5'},{'2','6'},{'2','7'},{'2','8'},{'2','9'},{'2','a'},{'2','b'},{'2','c'},{'2','d'},{'2','e'},{'2','f'},
		{'3','0'},{'3','1'},{'3','2'},{'3','3'},{'3','4'},{'3','5'},{'3','6'},{'3','7'},{'3','8'},{'3','9'},{'3','a'},{'3','b'},{'3','c'},{'3','d'},{'3','e'},{'3','f'},
		{'4','0'},{'4','1'},{'4','2'},{'4','3'},{'4','4'},{'4','5'},{'4','6'},{'4','7'},{'4','8'},{'4','9'},{'4','a'},{'4','b'},{'4','c'},{'4','d'},{'4','e'},{'4','f'},
		{'5','0'},{'5','1'},{'5','2'},{'5','3'},{'5','4'},{'5','5'},{'5','6'},{'5','7'},{'5','8'},{'5','9'},{'5','a'},{'5','b'},{'5','c'},{'5','d'},{'5','e'},{'5','f'},
		{'6','0'},{'6','1'},{'6','2'},{'6','3'},{'6','4'},{'6','5'},{'6','6'},{'6','7'},{'6','8'},{'6','9'},{'6','a'},{'6','b'},{'6','c'},{'6','d'},{'6','e'},{'6','f'},
		{'7','0'},{'7','1'},{'7','2'},{'7','3'},{'7','4'},{'7','5'},{'7','6'},{'7','7'},{'7','8'},{'7','9'},{'7','a'},{'7','b'},{'7','c'},{'7','d'},{'7','e'},{'7','f'},
		{'8','0'},{'8','1'},{'8','2'},{'8','3'},{'8','4'},{'8','5'},{'8','6'},{'8','7'},{'8','8'},{'8','9'},{'8','a'},{'8','b'},{'8','c'},{'8','d'},{'8','e'},{'8','f'},
		{'9','0'},{'9','1'},{'9','2'},{'9','3'},{'9','4'},{'9','5'},{'9','6'},{'9','7'},{'9','8'},{'9','9'},{'9','a'},{'9','b'},{'9','c'},{'9','d'},{'9','e'},{'9','f'},
		{'a','0'},{'a','1'},{'a','2'},{'a','3'},{'a','4'},{'a','5'},{'a','6'},{'a','7'},{'a','8'},{'a','9'},{'a','a'},{'a','b'},{'a','c'},{'a','d'},{'a','e'},{'a','f'},
		{'b','0'},{'b','1'},{'b','2'},{'b','3'},{'b','4'},{'b','5'},{'b','6'},{'b','7'},{'b','8'},{'b','9'},{'b','a'},{'b','b'},{'b','c'},{'b','d'},{'b','e'},{'b','f'},
		{'c','0'},{'c','1'},{'c','2'},{'c','3'},{'c','4'},{'c','5'},{'c','6'},{'c','7'},{'c','8'},{'c','9'},{'c','a'},{'c','b'},{'c','c'},{'c','d'},{'c','e'},{'c','f'},
		{'d','0'},{'d','1'},{'d','2'},{'d','3'},{'d','4'},{'d','5'},{'d','6'},{'d','7'},{'d','8'},{'d','9'},{'d','a'},{'d','b'},{'d','c'},{'d','d'},{'d','e'},{'d','f'},
		{'e','0'},{'e','1'},{'e','2'},{'e','3'},{'e','4'},{'e','5'},{'e','6'},{'e','7'},{'e','8'},{'e','9'},{'e','a'},{'e','b'},{'e','c'},{'e','d'},{'e','e'},{'e','f'},
		{'f','0'},{'f','1'},{'f','2'},{'f','3'},{'f','4'},{'f','5'},{'f','6'},{'f','7'},{'f','8'},{'f','9'},{'f','a'},{'f','b'},{'f','c'},{'f','d'},{'f','e'},{'f','f'},
	};
	static unsigned char achNum2UpperS[256][2] = 
	{
		{'0','0'},{'0','1'},{'0','2'},{'0','3'},{'0','4'},{'0','5'},{'0','6'},{'0','7'},{'0','8'},{'0','9'},{'0','A'},{'0','B'},{'0','C'},{'0','D'},{'0','E'},{'0','F'},
		{'1','0'},{'1','1'},{'1','2'},{'1','3'},{'1','4'},{'1','5'},{'1','6'},{'1','7'},{'1','8'},{'1','9'},{'1','A'},{'1','B'},{'1','C'},{'1','D'},{'1','E'},{'1','F'},
		{'2','0'},{'2','1'},{'2','2'},{'2','3'},{'2','4'},{'2','5'},{'2','6'},{'2','7'},{'2','8'},{'2','9'},{'2','A'},{'2','B'},{'2','C'},{'2','D'},{'2','E'},{'2','F'},
		{'3','0'},{'3','1'},{'3','2'},{'3','3'},{'3','4'},{'3','5'},{'3','6'},{'3','7'},{'3','8'},{'3','9'},{'3','A'},{'3','B'},{'3','C'},{'3','D'},{'3','E'},{'3','F'},
		{'4','0'},{'4','1'},{'4','2'},{'4','3'},{'4','4'},{'4','5'},{'4','6'},{'4','7'},{'4','8'},{'4','9'},{'4','A'},{'4','B'},{'4','C'},{'4','D'},{'4','E'},{'4','F'},
		{'5','0'},{'5','1'},{'5','2'},{'5','3'},{'5','4'},{'5','5'},{'5','6'},{'5','7'},{'5','8'},{'5','9'},{'5','A'},{'5','B'},{'5','C'},{'5','D'},{'5','E'},{'5','F'},
		{'6','0'},{'6','1'},{'6','2'},{'6','3'},{'6','4'},{'6','5'},{'6','6'},{'6','7'},{'6','8'},{'6','9'},{'6','A'},{'6','B'},{'6','C'},{'6','D'},{'6','E'},{'6','F'},
		{'7','0'},{'7','1'},{'7','2'},{'7','3'},{'7','4'},{'7','5'},{'7','6'},{'7','7'},{'7','8'},{'7','9'},{'7','A'},{'7','B'},{'7','C'},{'7','D'},{'7','E'},{'7','F'},
		{'8','0'},{'8','1'},{'8','2'},{'8','3'},{'8','4'},{'8','5'},{'8','6'},{'8','7'},{'8','8'},{'8','9'},{'8','A'},{'8','B'},{'8','C'},{'8','D'},{'8','E'},{'8','F'},
		{'9','0'},{'9','1'},{'9','2'},{'9','3'},{'9','4'},{'9','5'},{'9','6'},{'9','7'},{'9','8'},{'9','9'},{'9','A'},{'9','B'},{'9','C'},{'9','D'},{'9','E'},{'9','F'},
		{'A','0'},{'A','1'},{'A','2'},{'A','3'},{'A','4'},{'A','5'},{'A','6'},{'A','7'},{'A','8'},{'A','9'},{'A','A'},{'A','B'},{'A','C'},{'A','D'},{'A','E'},{'A','F'},
		{'B','0'},{'B','1'},{'B','2'},{'B','3'},{'B','4'},{'B','5'},{'B','6'},{'B','7'},{'B','8'},{'B','9'},{'B','A'},{'B','B'},{'B','C'},{'B','D'},{'B','E'},{'B','F'},
		{'C','0'},{'C','1'},{'C','2'},{'C','3'},{'C','4'},{'C','5'},{'C','6'},{'C','7'},{'C','8'},{'C','9'},{'C','A'},{'C','B'},{'C','C'},{'C','D'},{'C','E'},{'C','F'},
		{'D','0'},{'D','1'},{'D','2'},{'D','3'},{'D','4'},{'D','5'},{'D','6'},{'D','7'},{'D','8'},{'D','9'},{'D','A'},{'D','B'},{'D','C'},{'D','D'},{'D','E'},{'D','F'},
		{'E','0'},{'E','1'},{'E','2'},{'E','3'},{'E','4'},{'E','5'},{'E','6'},{'E','7'},{'E','8'},{'E','9'},{'E','A'},{'E','B'},{'E','C'},{'E','D'},{'E','E'},{'E','F'},
		{'F','0'},{'F','1'},{'F','2'},{'F','3'},{'F','4'},{'F','5'},{'F','6'},{'F','7'},{'F','8'},{'F','9'},{'F','A'},{'F','B'},{'F','C'},{'F','D'},{'F','E'},{'F','F'},
	};

	const unsigned char * pSrc	= (const unsigned char *)pSrcBuf;
	unsigned char * pDest		= (unsigned char *)szDestString;
	if(bLowerChar)
	{
		int i = 0;
		for(; i < nSrcBufByteLength; ++i)
		{
			*pDest++ = achNum2LowerS[*pSrc][0];
			*pDest++ = achNum2LowerS[*pSrc][1];
			pSrc++;
		}//fori
	}
	else
	{
		int i = 0;
		for(; i < nSrcBufByteLength; ++i)
		{
			*pDest++ = achNum2UpperS[*pSrc][0];
			*pDest++ = achNum2UpperS[*pSrc][1];
			pSrc++;
		}//fori
	}
	szDestString[nSrcBufByteLength*2] = 0;

	return nSrcBufByteLength*2;

	//--------------------------------------------------------------------------
	//以下是老方法,效率较低
#if 0
	const unsigned char * pBuf	= (const unsigned char *)pSrcBuf;
	if(bLowerChar)
	{
		int i = 0;
		for(; i < nSrcBufByteLength; ++i)
		{
			sprintf(szDestString+i*2,"%02x",pBuf[i]);
		}//fori
	}
	else
	{
		int i = 0;
		for(; i < nSrcBufByteLength; ++i)
		{
			sprintf(szDestString+i*2,"%02X",pBuf[i]);
		}//fori
	}
	szDestString[nSrcBufByteLength*2] = 0;

	return nSrcBufByteLength*2;
#endif

}
//!	将字符串转换为字节串
static int XtStringToBytes(const char * szSrcString,void * pDestBuf)
{
	int nStrLength = (int)strlen(szSrcString);
	int nBufLength = nStrLength/2;
	unsigned char * pBuf = (unsigned char *)pDestBuf;

	int i = 0;
	for(; i < nBufLength; ++i)
	{
		pBuf[i] = 0;
		char ch1 = szSrcString[2*i];
		char ch2 = szSrcString[2*i+1];
		int j = 0;
		for(; j < 2; ++j)
		{
			char ch = j == 0?ch1:ch2;
			if(ch >= '0' && ch <= '9')
			{
				pBuf[i]	+= ch - '0';
			}//if
			else if(ch >= 'a' && ch <= 'f')
			{
				pBuf[i]	+= ch - 'a' + 10;
			}//if
			else if(ch >= 'A' && ch <= 'F')
			{
				pBuf[i]	+= ch - 'A' + 10;
			}//if
			if(j == 0)
			{
				pBuf[i] <<= 4;
			}//if
		}//forj
	}//fori

	return nBufLength;
}

static void EndFunction4Base(){}
//----基础函数end-----------------------------------------------------------------------------------

//----md5 begin-------------------------------------------------------------------------
//begin: MD5
//typedef struct {
//
//    unsigned int state[4];      
//
//    unsigned int count[2];      
//
//    unsigned char buffer[64];      
//
//} MD5Context;
//
// 
//
//void MD5_Init(MD5Context * context);
//
//void MD5_Update(MD5Context * context, unsigned char * buf, int len);
//
//void MD5_Final(MD5Context * context, unsigned char digest[16]);
//
//#define S11 7
//
//#define S12 12
//
//#define S13 17
//
//#define S14 22
//
//#define S21 5
//
//#define S22 9
//
//#define S23 14
//
//#define S24 20
//
//#define S31 4
//
//#define S32 11
//
//#define S33 16
//
//#define S34 23
//
//#define S41 6
//
//#define S42 10
//
//#define S43 15
//
//#define S44 21
//
// 
//
//static unsigned char PADDING[64] =
//
//{
//
//    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//
//    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//
//    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
//
//};
//
//#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
//
//#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
//
//#define H(x, y, z) ((x) ^ (y) ^ (z))
//
//#define I(x, y, z) ((y) ^ ((x) | (~z)))
//
// 
//
//#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
//
// 
//
//#define FF(a, b, c, d, x, s, ac)          \
//    {                       \
//    (a) += F((b), (c), (d)) + (x) + (unsigned int)(ac);  \
//    (a) = ROTATE_LEFT((a), (s));           \
//    (a) += (b);                 \
//    }
//
// 
//
//#define GG(a, b, c, d, x, s, ac)          \
//    {                       \
//    (a) += G((b), (c), (d)) + (x) + (unsigned int)(ac);  \
//    (a) = ROTATE_LEFT((a), (s));           \
//    (a) += (b);                 \
//    }
//
// 
//
//#define HH(a, b, c, d, x, s, ac)          \
//    {                       \
//    (a) += H((b), (c), (d)) + (x) + (unsigned int)(ac);  \
//    (a) = ROTATE_LEFT((a), (s));           \
//    (a) += (b);                 \
//    }
//
// 
//
//#define II(a, b, c, d, x, s, ac)          \
//    {                       \
//    (a) += I((b), (c), (d)) + (x) + (unsigned int)(ac);  \
//    (a) = ROTATE_LEFT((a), (s));           \
//    (a) += (b);                 \
//    }
//
//static void MD5_Encode(unsigned char * output, unsigned int * input, int len)
//
//{
//
//    unsigned int i, j;
//
// 
//
//    for (i = 0, j = 0; j < len; i++, j += 4) 
//
//    {
//
//       output[j] = (unsigned char) (input[i] & 0xff);
//
//       output[j + 1] = (unsigned char) ((input[i] >> 8) & 0xff);
//
//       output[j + 2] = (unsigned char) ((input[i] >> 16) & 0xff);
//
//       output[j + 3] = (unsigned char) ((input[i] >> 24) & 0xff);
//
//    }
//
//}
//
// 
//
//static void MD5_Decode(unsigned int * output, unsigned char * input, int len)
//
//{
//
//    unsigned int i, j;
//
// 
//
//    for (i = 0, j = 0; j < len; i++, j += 4)
//
//    {
//
//       output[i] = ((unsigned int) input[j]) |
//
//           (((unsigned int) input[j + 1]) << 8) |
//
//           (((unsigned int) input[j + 2]) << 16) |
//
//           (((unsigned int) input[j + 3]) << 24);
//
//    }
//
//}
//
// 
//
//static void MD5_Transform(unsigned int state[4], unsigned char block[64])
//
//{
//
//    unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];
//
// 
//
//    MD5_Decode(x, block, 64);
//
// 
//
//    /* Round 1 */
//
//    FF(a, b, c, d, x[0], S11, 0xd76aa478);    /* 1 */
//
//    FF(d, a, b, c, x[1], S12, 0xe8c7b756);    /* 2 */
//
//    FF(c, d, a, b, x[2], S13, 0x242070db);    /* 3 */
//
//    FF(b, c, d, a, x[3], S14, 0xc1bdceee);    /* 4 */
//
//    FF(a, b, c, d, x[4], S11, 0xf57c0faf);    /* 5 */
//
//    FF(d, a, b, c, x[5], S12, 0x4787c62a);    /* 6 */
//
//    FF(c, d, a, b, x[6], S13, 0xa8304613);    /* 7 */
//
//    FF(b, c, d, a, x[7], S14, 0xfd469501);    /* 8 */
//
//    FF(a, b, c, d, x[8], S11, 0x698098d8);    /* 9 */
//
//    FF(d, a, b, c, x[9], S12, 0x8b44f7af);    /* 10 */
//
//    FF(c, d, a, b, x[10], S13, 0xffff5bb1);   /* 11 */
//
//    FF(b, c, d, a, x[11], S14, 0x895cd7be);   /* 12 */
//
//    FF(a, b, c, d, x[12], S11, 0x6b901122);   /* 13 */
//
//    FF(d, a, b, c, x[13], S12, 0xfd987193);   /* 14 */
//
//    FF(c, d, a, b, x[14], S13, 0xa679438e);   /* 15 */
//
//    FF(b, c, d, a, x[15], S14, 0x49b40821);   /* 16 */
//
// 
//
//    /* Round 2 */
//
//    GG(a, b, c, d, x[1], S21, 0xf61e2562);    /* 17 */
//
//    GG(d, a, b, c, x[6], S22, 0xc040b340);    /* 18 */
//
//    GG(c, d, a, b, x[11], S23, 0x265e5a51);   /* 19 */
//
//    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);    /* 20 */
//
//    GG(a, b, c, d, x[5], S21, 0xd62f105d);    /* 21 */
//
//    GG(d, a, b, c, x[10], S22, 0x2441453);    /* 22 */
//
//    GG(c, d, a, b, x[15], S23, 0xd8a1e681);   /* 23 */
//
//    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);    /* 24 */
//
//    GG(a, b, c, d, x[9], S21, 0x21e1cde6);    /* 25 */
//
//    GG(d, a, b, c, x[14], S22, 0xc33707d6);   /* 26 */
//
//    GG(c, d, a, b, x[3], S23, 0xf4d50d87);    /* 27 */
//
//    GG(b, c, d, a, x[8], S24, 0x455a14ed);    /* 28 */
//
//    GG(a, b, c, d, x[13], S21, 0xa9e3e905);   /* 29 */
//
//    GG(d, a, b, c, x[2], S22, 0xfcefa3f8);    /* 30 */
//
//    GG(c, d, a, b, x[7], S23, 0x676f02d9);    /* 31 */
//
//    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);   /* 32 */
//
// 
//
//    /* Round 3 */
//
//    HH(a, b, c, d, x[5], S31, 0xfffa3942);    /* 33 */
//
//    HH(d, a, b, c, x[8], S32, 0x8771f681);    /* 34 */
//
//    HH(c, d, a, b, x[11], S33, 0x6d9d6122);   /* 35 */
//
//    HH(b, c, d, a, x[14], S34, 0xfde5380c);   /* 36 */
//
//    HH(a, b, c, d, x[1], S31, 0xa4beea44);    /* 37 */
//
//    HH(d, a, b, c, x[4], S32, 0x4bdecfa9);    /* 38 */
//
//    HH(c, d, a, b, x[7], S33, 0xf6bb4b60);    /* 39 */
//
//    HH(b, c, d, a, x[10], S34, 0xbebfbc70);   /* 40 */
//
//    HH(a, b, c, d, x[13], S31, 0x289b7ec6);   /* 41 */
//
//    HH(d, a, b, c, x[0], S32, 0xeaa127fa);    /* 42 */
//
//    HH(c, d, a, b, x[3], S33, 0xd4ef3085);    /* 43 */
//
//    HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
//
//    HH(a, b, c, d, x[9], S31, 0xd9d4d039);    /* 45 */
//
//    HH(d, a, b, c, x[12], S32, 0xe6db99e5);   /* 46 */
//
//    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);   /* 47 */
//
//    HH(b, c, d, a, x[2], S34, 0xc4ac5665);    /* 48 */
//
// 
//
//    /* Round 4 */
//
//    II(a, b, c, d, x[0], S41, 0xf4292244);    /* 49 */
//
//    II(d, a, b, c, x[7], S42, 0x432aff97);    /* 50 */
//
//    II(c, d, a, b, x[14], S43, 0xab9423a7);   /* 51 */
//
//    II(b, c, d, a, x[5], S44, 0xfc93a039);    /* 52 */
//
//    II(a, b, c, d, x[12], S41, 0x655b59c3);   /* 53 */
//
//    II(d, a, b, c, x[3], S42, 0x8f0ccc92);    /* 54 */
//
//    II(c, d, a, b, x[10], S43, 0xffeff47d);   /* 55 */
//
//    II(b, c, d, a, x[1], S44, 0x85845dd1);    /* 56 */
//
//    II(a, b, c, d, x[8], S41, 0x6fa87e4f);    /* 57 */
//
//    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);   /* 58 */
//
//    II(c, d, a, b, x[6], S43, 0xa3014314);    /* 59 */
//
//    II(b, c, d, a, x[13], S44, 0x4e0811a1);   /* 60 */
//
//    II(a, b, c, d, x[4], S41, 0xf7537e82);    /* 61 */
//
//    II(d, a, b, c, x[11], S42, 0xbd3af235);   /* 62 */
//
//    II(c, d, a, b, x[2], S43, 0x2ad7d2bb);    /* 63 */
//
//    II(b, c, d, a, x[9], S44, 0xeb86d391);    /* 64 */
//
// 
//
//    state[0] += a;
//
//    state[1] += b;
//
//    state[2] += c;
//
//    state[3] += d;
//
// 
//
//    memset((char *) x, 0, sizeof(x));
//
//}
//
// 
//
//void MD5_Init(MD5Context * context)
//
//{
//
//    context->count[0] = context->count[1] = 0;
//
// 
//
//    context->state[0] = 0x67452301;
//
//    context->state[1] = 0xefcdab89;
//
//    context->state[2] = 0x98badcfe;
//
//    context->state[3] = 0x10325476;
//
//}
//
// 
//
//void MD5_Update(MD5Context * context, unsigned char * buf, int len)
//
//{
//
//    unsigned int i, index, partLen;
//
// 
//
//    index = (unsigned int) ((context->count[0] >> 3) & 0x3F);
//
// 
//
//    if ((context->count[0] += ((unsigned int) len << 3)) < ((unsigned int) len << 3))
//
//    context->count[1]++;
//
//    context->count[1] += ((unsigned int) len >> 29);
//
// 
//
//    partLen = 64 - index;
//
// 
//
//    if (len >= partLen) 
//
//    {
//
//       memcpy((char *) &context->buffer[index], (char *) buf, partLen);
//
//       MD5_Transform(context->state, context->buffer);
//
// 
//
//       for (i = partLen; i + 63 < len; i += 64)
//
//           MD5_Transform(context->state, &buf[i]);
//
// 
//
//       index = 0;
//
//    } 
//
//    else 
//
//    {
//
//        i = 0;
//
//    }
//
// 
//
//    memcpy((char *) &context->buffer[index], (char *) &buf[i], len - i);
//
//}
//
// 
//
//void MD5_Final(MD5Context * context, unsigned char digest[16])
//
//{
//
//    unsigned char bits[8];
//
//    unsigned int index, padLen;
//
// 
//
//    MD5_Encode(bits, context->count, 8);
//
// 
//
//    index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
//
//    padLen = (index < 56) ? (56 - index) : (120 - index);
//
//    MD5_Update(context, PADDING, padLen);
//
// 
//
//    MD5_Update(context, bits, 8);
//
// 
//
//    MD5_Encode(digest, context->state, 16);
//
// 
//
//    memset((char *) context, 0, sizeof(*context));
//
//}
//
//void MD5_File (char * filename)
//
//{
//
//    FILE *file;
//
//    MD5Context context;
//
//    unsigned char buff[16];
//
//    int i,len;
//
//    unsigned char buffer[0x0400];
//
// 
//
//    if (!(file = fopen (filename, "rb")))
//
//       printf ("%s can't be opened\n", filename);
//
//    else 
//
//    {
//
//       MD5_Init (&context);
//
//       while (len = fread (buffer, 1, 1024, file))
//
//           MD5_Update (&context, buffer, len);
//
//       MD5_Final(&context,buff);
//
//       fclose (file);
//
//       for(i=0;i<16;i++)
//
//       {
//
//           printf("%x",(buff[i] & 0xF0)>>4);
//
//           printf("%x",buff[i] & 0x0F);
//
//       }
//
//       printf("\n");
//
//    }
//
//}

//int main()
//
//{
//    int i =0,j,len;
//
//    MD5Context context;
//
//    unsigned char buff[16];
//
//    char str[7][100] = 
//
//    {
//
//       "",
//
//       "a",
//
//       "abc",
//
//       "message digest",
//
//       "abcdefghijklmnopqrstuvwxyz",
//
//       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
//
//       "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
//
//    };
//
//    for(i=0;i<6;i++)
//
//    {
//
//       len = strlen(str[i]);
//
//       MD5_Init(&context);
//
//       MD5_Update(&context,(unsigned char *)str[i], len);
//
//       MD5_Final(&context,buff);
//
//       printf("MD5(\"%s\") = \n",str[i]);
//
//       for(j=0;j<16;j++)
//
//       {
//
//           printf("%x",(buff[j] & 0xF0)>>4);
//
//           printf("%x",buff[j] & 0x0F);
//
//       }
//
//       printf("\n***********************************************************\n");
//
//    }
//
//    printf("Wating...\n");
//
//    MD5_File("00.dat");
//
//    system("pause");
//
//    return 0;
//}

//Test suite
//
//The MD5 test suite (driver soption "-x") should print the following
//results:
//
//MD5 test suite:
//MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
//MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
//MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
//MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
//MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
//MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
//d174ab98d277d9f5a5611c2c9f419d9f
//MD5 ("123456789012345678901234567890123456789012345678901234567890123456
//	 78901234567890") = 57edf4a22be3c955ac49da2e2107b67a



//-----------------------------------------------------------------------------
static void BeginFunction4MD5(){}
//RFC 1321标准MD5算法
//A.1 global.h

/* GLOBAL.H - RSAREF types and constants
 */

/* PROTOTYPES should be set to one if and only if the compiler supports
  function argument prototyping.
The following makes PROTOTYPES default to 0 if it has not already

  been defined with C compiler flags.
 */
#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short UINT2;

/* UINT4 defines a four byte word */
typedef unsigned int UINT4;


/*MD TYPDE DEFINE*/
#define MD2		2
#define MD3		3
#define MD4		4
#define MD5		5

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

//A.2 md5.h

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

static void MD5Init PROTO_LIST ((MD5_CTX *));
static void MD5Update PROTO_LIST
  ((MD5_CTX *, unsigned char *, unsigned int));
static void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));

//A.3 md5c.c

/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

//#include "global.h"
//#include "md5.h"

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform PROTO_LIST ((UINT4 [4], unsigned char [64]));
static void Encode PROTO_LIST  ((unsigned char *, UINT4 *, unsigned int));
static void Decode PROTO_LIST  ((UINT4 *, unsigned char *, unsigned int));
static void MD5_memcpy PROTO_LIST ((POINTER, POINTER, unsigned int));
static void MD5_memset PROTO_LIST ((POINTER, int, unsigned int));

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void MD5Init (MD5_CTX *context)
{
  context->count[0] = context->count[1] = 0;
  /* Load magic initialization constants.
*/
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
static void MD5Update (MD5_CTX *context, unsigned char *input, unsigned int inputLen)
//context;                                        /* context */
//input;                                /* input block */
//inputLen;                     /* length of input block */
{
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))
	context->count[1]++;
  context->count[1] += ((UINT4)inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible.
*/
  if (inputLen >= partLen) 
  {
	MD5_memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
	MD5Transform (context->state, context->buffer);

	for (i = partLen; i + 63 < inputLen; i += 64)
		MD5Transform (context->state, &input[i]);

	index = 0;
  }
  else
	i = 0;

  /* Buffer remaining input */
  MD5_memcpy((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
static void MD5Final (unsigned char digest[16], MD5_CTX *context)
//unsigned char digest[16];                         /* message digest */
//MD5_CTX *context;                                       /* context */
{
  unsigned char bits[8];
  unsigned int index, padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.
*/
  index = (unsigned int)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  /* Store state in digest */
  Encode (digest, context->state, 16);

  /* Zeroize sensitive information.
*/
  MD5_memset ((POINTER)context, 0, sizeof (*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform (UINT4 state[4], unsigned char block[64])
//UINT4 state[4];
//unsigned char block[64];
{
  UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode (x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */

  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information.

*/
  MD5_memset ((POINTER)x, 0, sizeof (x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void Encode (unsigned char *output, UINT4 *input, unsigned int len)
//unsigned char *output;
//UINT4 *input;
//unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
 output[j] = (unsigned char)(input[i] & 0xff);
 output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
 output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
 output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4.
 */
static void Decode (UINT4 *output, unsigned char *input, unsigned int len)
//UINT4 *output;
//unsigned char *input;
//unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
 output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
   (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */

static void MD5_memcpy (POINTER output, POINTER input, unsigned int len)
//POINTER output;
//POINTER input;
//unsigned int len;
{
  unsigned int i;

  for (i = 0; i < len; i++)

 output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void MD5_memset (POINTER output, int value, unsigned int len)
//POINTER output;
//int value;
//unsigned int len;
{
  unsigned int i;

  for (i = 0; i < len; i++)
 ((char *)output)[i] = (char)value;
}

//A.4 mddriver.c

/* MDDRIVER.C - test driver for MD2, MD4 and MD5
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
rights reserved.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* The following makes MD default to MD5 if it has not already been
  defined with C compiler flags.
 */
#ifndef MD
#define MD MD5
#endif

//#include <stdio.h>
//#include <time.h>
//#include <string.h>
//#include "global.h"

//#if MD == 2
//#include "md2.h"
//#endif
//#if MD == 4
//
//#include "md4.h"
//#endif
//#if MD == 5
//#include "md5.h"
//#endif


/* Length of test block, number of test blocks.
 */
#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 1000

static void MDString PROTO_LIST ((char *));
static void MDTimeTrial PROTO_LIST ((void));
static void MDTestSuite PROTO_LIST ((void));
static void MDFile PROTO_LIST ((char *));
static void MDFilter PROTO_LIST ((void));
static void MDPrint PROTO_LIST ((unsigned char [16]));

#if MD == MD2
#define MD_CTX MD2_CTX
#define MDInit MD2Init
#define MDUpdate MD2Update
#define MDFinal MD2Final
#endif
#if MD == MD4
#define MD_CTX MD4_CTX
#define MDInit MD4Init
#define MDUpdate MD4Update
#define MDFinal MD4Final
#endif
#if MD == MD5
#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final
#endif

/* Main driver.

Arguments (may be any combination):
  -sstring - digests string
  -t       - runs time trial
  -x       - runs test script
  filename - digests file
  (none)   - digests standard input
 */
//int main (argc, argv)
//int argc;
//
//char *argv[];
//{
//  int i;
//
//  if (argc > 1)
// for (i = 1; i < argc; i++)
//   if (argv[i][0] == '-' && argv[i][1] == 's')
//     MDString (argv[i] + 2);
//   else if (strcmp (argv[i], "-t") == 0)
//     MDTimeTrial ();
//   else if (strcmp (argv[i], "-x") == 0)
//     MDTestSuite ();
//   else
//     MDFile (argv[i]);
//  else
// MDFilter ();
//
//  return (0);


/* Digests a string and prints the result.
 */
//static void MDString (string)
//char *string;
//{
//  MD_CTX context;
//  unsigned char digest[16];
//  unsigned int len = strlen (string);
//
//  MDInit (&context);
//  MDUpdate (&context, string, len);
//  MDFinal (digest, &context);
//
//  printf ("MD%d (\"%s\") = ", MD, string);
//  MDPrint (digest);
//  printf ("\n");


/* Measures the time to digest TEST_BLOCK_COUNT TEST_BLOCK_LEN-byte
  blocks.
 */
//static void MDTimeTrial ()
//{
//  MD_CTX context;
//  time_t endTime, startTime;
//  unsigned char block[TEST_BLOCK_LEN], digest[16];
//  unsigned int i;
//
//  printf
// ("MD%d time trial. Digesting %d %d-byte blocks ...", MD,
//  TEST_BLOCK_LEN, TEST_BLOCK_COUNT);
//
//  /* Initialize block */
//  for (i = 0; i < TEST_BLOCK_LEN; i++)
// block[i] = (unsigned char)(i & 0xff);
//
//  /* Start timer */
//  time (&startTime);
//
//  /* Digest blocks */
//  MDInit (&context);
//  for (i = 0; i < TEST_BLOCK_COUNT; i++)
// MDUpdate (&context, block, TEST_BLOCK_LEN);
//  MDFinal (digest, &context);
//
//  /* Stop timer */
//  time (&endTime);
//
//  printf (" done\n");
//  printf ("Digest = ");
//  MDPrint (digest);
//  printf ("\nTime = %ld seconds\n", (long)(endTime-startTime));
//  printf
// ("Speed = %ld bytes/second\n",
//  (long)TEST_BLOCK_LEN * (long)TEST_BLOCK_COUNT/(endTime-startTime));


/* Digests a reference suite of strings and prints the results.
 */
//static void MDTestSuite ()
//{
//  printf ("MD%d test suite:\n", MD);
//
//  MDString ("");
//  MDString ("a");
//  MDString ("abc");
//  MDString ("message digest");
//  MDString ("abcdefghijklmnopqrstuvwxyz");
//  MDString
// ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
//  MDString
// ("1234567890123456789012345678901234567890\
//1234567890123456789012345678901234567890");
//}

/* Digests a file and prints the result.

 */ 
static bool MDFile (const char *filename,unsigned char digest[16])
{
	FILE *file;
	MD_CTX context;
	int len;
	unsigned char buffer[1024];

	if ((file = fopen (filename, "rb")) == NULL)
	{
		return false;
	}

	else 
	{
		MDInit (&context);
		while (len = (int)fread (buffer, 1, 1024, file))
		{
			MDUpdate (&context, buffer, len);
		}
		MDFinal (digest, &context);

		fclose (file);
		return true;
	}
}

/* Digests the standard input and prints the result.
 */
//static void MDFilter ()
//{
//  MD_CTX context;
//  int len;
//  unsigned char buffer[16], digest[16];
//
//  MDInit (&context);
//  while (len = fread (buffer, 1, 16, stdin))
// MDUpdate (&context, buffer, len);
//  MDFinal (digest, &context);
//
//  MDPrint (digest);
//  printf ("\n");
//}

/* Prints a message digest in hexadecimal.
 */
//static void MDPrint (digest)
//unsigned char digest[16];
//{
//
//  unsigned int i;
//
//  for (i = 0; i < 16; i++)
// printf ("%02x", digest[i]);
//}

//A.5 Test suite
//
//   The MD5 test suite (driver soption "-x") should print the following
//   results:
//
//MD5 test suite:
//MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
//MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
//MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
//MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
//MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
//MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
//d174ab98d277d9f5a5611c2c9f419d9f
//MD5 ("123456789012345678901234567890123456789012345678901234567890123456
//78901234567890") = 57edf4a22be3c955ac49da2e2107b67a

//-----------------------------------------------------------------------------
//Xuetian defined MD5 functions
//!	MD5加密(16位)
static unsigned char* XtMD5Encode16(const void * pPlainBuf,int nPlainLength,unsigned char pEncryBuf[16])
{
	MD5_CTX context;
	MD5Init(&context);
	MD5Update(&context,(unsigned char *)pPlainBuf,nPlainLength);
	MD5Final(pEncryBuf,&context);
	return pEncryBuf;
}
static char* XtMD5EncodeToString32(const void * pPlainBuf,int nPlainLength,char szEncryBuf[32],bool bLowerChar)
{
	unsigned char pEncryBuf[16];
	XtMD5Encode16(pPlainBuf,nPlainLength,pEncryBuf);
	if(bLowerChar)
	{
		sprintf(szEncryBuf,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);
	}//if
	else
	{
		sprintf(szEncryBuf,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);

	}
	return szEncryBuf;
}
static char* XtMD5EncodeToString33(const void * pPlainBuf,int nPlainLength,char szEncryBuf[33],bool bLowerChar)
{
	XtMD5EncodeToString32(pPlainBuf,nPlainLength,szEncryBuf,bLowerChar);
	szEncryBuf[32] = '\0';
	return szEncryBuf;
}

static bool		XtMD5File16(const char * filename,unsigned char pEncryBuf[16])
{
	if(!MDFile(filename,pEncryBuf))
	{
		return false;
	}//if

	return true;
}
static bool		XtMD5FileToString32(const char * filename,char szEncryBuf[32],bool bLowerChar)
{
	unsigned char pEncryBuf[16];
	if(!MDFile(filename,pEncryBuf))
	{
		return false;
	}

	if(bLowerChar)
	{
		sprintf(szEncryBuf,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);
	}//if
	else
	{
		sprintf(szEncryBuf,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);

	}
	return true;
}
static bool		XtMD5FileToString33(const char * filename,char szEncryBuf[33],bool bLowerChar)
{
	if(!XtMD5FileToString32(filename,szEncryBuf,bLowerChar))
	{
		return false;
	}//if
	szEncryBuf[32] = '\0';
	return true;
}
//-----------------------------------------------------------------------------
static void EndFunction4MD5(){}
//end: MD5
//----md5 end-------------------------------------------------------------------------

//----aes begin-------------------------------------------------------------------------
//begin: AES
static void BeginFunction4AES(){}
//------------------------------------------------------------------------------
//Added by chengxuewen, 1999:9:28
//AES 加密算法, 这是AES最初的候选算法, 可以根据实际应用需要再做一些改进
//------------------------------------------------------------------------------
// This is an independent implementation of the encryption algorithm:       
//                                                                          
//         RIJNDAEL by Joan Daemen and Vincent Rijmen                       
//                                                                          
// which is a candidate algorithm in the Advanced Encryption Standard       
// programme of the US National Institute of Standards and Technology.      
//                                                                          
// Copyright in this implementation is held by Dr B R Gladman but I         
// hereby give permission for its free direct or derivative use subject     
// to acknowledgment of its origin and compliance with any conditions       
// that the originators of the algorithm place on its exploitation.         
//                                                                          
// Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999         

//  AES-Algorithm rijndael-rijndael.cpp 
//  128 bit key:    
//  Key Setup:    223/1416 cycles (aes_encrypt/aes_decrypt)    
//  Encrypt:       362 cycles =    70.7 mbits/sec    
//  Decrypt:       367 cycles =    69.8 mbits/sec    
//  Mean:          365 cycles =    70.2 mbits/sec    
//  192 bit key:    
//  Key Setup:    214/1660 cycles (aes_encrypt/aes_decrypt)    
//  Encrypt:       442 cycles =    57.9 mbits/sec    
//  Decrypt:       432 cycles =    59.3 mbits/sec    
//  Mean:          437 cycles =    58.6 mbits/sec    
//  256 bit key:    
//  Key Setup:    287/1994 cycles (aes_encrypt/aes_decrypt)    
//  Encrypt:       502 cycles =    51.0 mbits/sec    
//  Decrypt:       506 cycles =    50.6 mbits/sec    
//  Mean:          504 cycles =    50.8 mbits/sec    

//------------------------------------------------------------------------------

//This AES code is follow MD5 code, So, It can be support MD5 convert
#define	AES_SUPPORT_MD5

//AES-Algorithm rijndael-std_defs2.h  
/* 1. Standard types for AES cryptography source code               */ 

typedef unsigned char   aes_u1byte; /* an 8 bit unsigned character type */ 
typedef unsigned short  aes_u2byte; /* a 16 bit unsigned integer type   */ 
typedef unsigned int	aes_u4byte; /* a 32 bit unsigned integer type   */ 

typedef signed char     aes_s1byte; /* an 8 bit signed character type   */ 
typedef signed short    aes_s2byte; /* a 16 bit signed integer type     */ 
typedef signed int		aes_s4byte; /* a 32 bit signed integer type     */ 

/* 2. Standard interface for AES cryptographic routines             */ 

/* These are all based on 32 bit unsigned values and may require    */ 
/* endian conversion for big-endian architectures                   */ 

//BYTE ORDER DEFINE: LITTLE ENDIAN(e.g Windows/Linux/FreeBSD) OR BIG ENDIAN(e.g Mac OS)
#define	AES_LITTLE_ENDIAN 

//C API define
#define AES_API	extern "C"

//AES context
struct AES_CONTEXT
{
	//aes key length: 4*4bytes(128bits) or 6*4bytes(192bits) or 8*4bytes(256bits)
	aes_u4byte  aes_key_4bytes_len;
	//aes encrypt key
	aes_u4byte  aes_e_key[64];
	//aes decrypt key
	aes_u4byte  aes_d_key[64];
};

//get aes aes_name
static const char *aes_name(const AES_CONTEXT * pAES); 
//set aes key, must be 4*4bytes(128bits) or 6*4bytes(192bits) or 8*4bytes(256bits), must aes_set_key() before call aes_encrypt() and aes_decrypt()
static void aes_set_key(AES_CONTEXT * pAES,const aes_u1byte key[], const aes_u4byte key_bit_len);
//encrypt 16bytes plaintext to 16bytes ciphertext
static void aes_encrypt(const AES_CONTEXT * pAES,const aes_u1byte in_blk[16], aes_u1byte out_blk[16]);
//decrypt 16bytes  ciphertext to 16bytesplaintext
static void aes_decrypt(const AES_CONTEXT * pAES,const aes_u1byte in_blk[16], aes_u1byte out_blk[16]);


/* 3. Basic macros for speeding up generic operations               */ 

/* Circular rotate of 32 bit values                                 */ 
#define aes_rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n)))) 
#define aes_rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n)))) 

/* Invert aes_byte order in a 32 bit variable                           */ 

#define aes_bswap(x)    (aes_rotl(x, 8) & 0x00ff00ff | aes_rotr(x, 8) & 0xff00ff00) 

/* Extract aes_byte from a 32 bit quantity (little endian notation)     */  

#define aes_byte(x,n)   ((aes_u1byte)((x) >> (8 * n))) 

/* Input or output a 32 bit word in machine order					*/ 

#ifdef	AES_LITTLE_ENDIAN 

#define	aes_u4byte_in(x)		(*(aes_u4byte*)(x)) 
#define	aes_u4byte_out(x, v)	(*(aes_u4byte*)(x) = (v))  

#else 

#define	aes_u4byte_in(x)		aes_bswap(*(aes_u4byte)(x)) 
#define	aes_u4byte_out(x, v)	(*(aes_u4byte*)(x) = aes_bswap(v))  

#endif //#ifdef	AES_LITTLE_ENDIAN

/* one byte data a cycle rigth shift b bits	*/
#define aes_rcmbyte(a,b)	(a) = ((a) >> (b) | (a) <<  (8 - (b)))
/* one byte data a cycle left shift b bits	*/
#define aes_lcmbyte(a,b)	(a) = ((a) << (b) | (a) >>  (8 - (b)))

//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
//AES-Algorithm rijndael-rijndael.h
//aes key length: 4*4bytes(128bits) or 6*4bytes(192bits) or 8*4bytes(256bits)
//static aes_u4byte  pAES->aes_key_4bytes_len		= 4; 
//aes encrypt key
//static aes_u4byte  pAES->aes_e_key[64]			= {0}; 
//aes decrypt key
//static aes_u4byte  pAES->aes_d_key[64]			= {0}; 

//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
//AES-Algorithm rijndael-rijndael.cpp

//#define   _UNICODE       
#define AES_LARGE_TABLES    

namespace   
{   
	aes_u1byte  aes_pow_tab[256];   
	aes_u1byte  aes_log_tab[256];   
	aes_u1byte  aes_sbx_tab[256];   
	aes_u1byte  aes_isb_tab[256];   
	aes_u4byte  aes_rco_tab[ 10];   
	aes_u4byte  aes_ft_tab[4][256];   
	aes_u4byte  aes_it_tab[4][256];   

#ifdef  AES_LARGE_TABLES    
	aes_u4byte  aes_fl_tab[4][256];   
	aes_u4byte  aes_il_tab[4][256];   
#endif    

	aes_u4byte  aes_tab_gen = 0;   

#define aes_ff_mult(a,b)    (a && b ? aes_pow_tab[(aes_log_tab[a] + aes_log_tab[b]) % 255] : 0)    

#define aes_f_rn(bo, bi, n, k)                          \
	bo[n] =  aes_ft_tab[0][aes_byte(bi[n],0)] ^     \
	aes_ft_tab[1][aes_byte(bi[(n + 1) & 3],1)] ^	\
	aes_ft_tab[2][aes_byte(bi[(n + 2) & 3],2)] ^	\
	aes_ft_tab[3][aes_byte(bi[(n + 3) & 3],3)] ^ *(k + n)  

#define aes_i_rn(bo, bi, n, k)								\
	bo[n] =  aes_it_tab[0][aes_byte(bi[n],0)] ^     \
	aes_it_tab[1][aes_byte(bi[(n + 3) & 3],1)] ^	\
	aes_it_tab[2][aes_byte(bi[(n + 2) & 3],2)] ^	\
	aes_it_tab[3][aes_byte(bi[(n + 1) & 3],3)] ^ *(k + n)   

#ifdef AES_LARGE_TABLES    

#define aes_ls_box(x)                \
	( aes_fl_tab[0][aes_byte(x, 0)] ^    \
	aes_fl_tab[1][aes_byte(x, 1)] ^    \
	aes_fl_tab[2][aes_byte(x, 2)] ^    \
	aes_fl_tab[3][aes_byte(x, 3)] )   

#define aes_f_rl(bo, bi, n, k)                          \
	bo[n] =  aes_fl_tab[0][aes_byte(bi[n],0)] ^     \
	aes_fl_tab[1][aes_byte(bi[(n + 1) & 3],1)] ^   \
	aes_fl_tab[2][aes_byte(bi[(n + 2) & 3],2)] ^   \
	aes_fl_tab[3][aes_byte(bi[(n + 3) & 3],3)] ^ *(k + n)   

#define aes_i_rl(bo, bi, n, k)                          \
	bo[n] =  aes_il_tab[0][aes_byte(bi[n],0)] ^             \
	aes_il_tab[1][aes_byte(bi[(n + 3) & 3],1)] ^   \
	aes_il_tab[2][aes_byte(bi[(n + 2) & 3],2)] ^   \
	aes_il_tab[3][aes_byte(bi[(n + 1) & 3],3)] ^ *(k + n)   

#else    

#define aes_ls_box(x)                            \
	((aes_u4byte)aes_sbx_tab[aes_byte(x, 0)] <<  0) ^    \
		((aes_u4byte)aes_sbx_tab[aes_byte(x, 1)] <<  8) ^    \
		((aes_u4byte)aes_sbx_tab[aes_byte(x, 2)] << 16) ^    \
		((aes_u4byte)aes_sbx_tab[aes_byte(x, 3)] << 24)   

#define aes_f_rl(bo, bi, n, k)                                      \
		bo[n] = (aes_u4byte)aes_sbx_tab[aes_byte(bi[n],0)] ^                    \
		aes_rotl(((aes_u4byte)aes_sbx_tab[aes_byte(bi[(n + 1) & 3],1)]),  8) ^  \
		aes_rotl(((aes_u4byte)aes_sbx_tab[aes_byte(bi[(n + 2) & 3],2)]), 16) ^  \
		aes_rotl(((aes_u4byte)aes_sbx_tab[aes_byte(bi[(n + 3) & 3],3)]), 24) ^ *(k + n)   

#define aes_i_rl(bo, bi, n, k)                                      \
		bo[n] = (aes_u4byte)aes_isb_tab[aes_byte(bi[n],0)] ^                    \
		aes_rotl(((aes_u4byte)aes_isb_tab[aes_byte(bi[(n + 3) & 3],1)]),  8) ^  \
		aes_rotl(((aes_u4byte)aes_isb_tab[aes_byte(bi[(n + 2) & 3],2)]), 16) ^  \
		aes_rotl(((aes_u4byte)aes_isb_tab[aes_byte(bi[(n + 1) & 3],3)]), 24) ^ *(k + n)   

#endif    

		//generate tables: you can define tables' values directly
		static void aes_gen_tabs(void)   
	{   
		aes_u4byte  i, t;   
		aes_u1byte  p, q;   

		// log and power tables for GF(2**8) finite field with      
		// 0x011b as modular polynomial - the simplest prmitive     
		// root is 0x03, used here to generate the tables           

		for(i = 0,p = 1; i < 256; ++i)   
		{   
			aes_pow_tab[i] = (aes_u1byte)p; aes_log_tab[p] = (aes_u1byte)i;   

			p = p ^ (p << 1) ^ (p & 0x80 ? 0x01b : 0);   
		}   

		aes_log_tab[1] = 0; p = 1;   

		for(i = 0; i < 10; ++i)   
		{   
			aes_rco_tab[i] = p;    

			p = (p << 1) ^ (p & 0x80 ? 0x1b : 0);   
		}   

		for(i = 0; i < 256; ++i)   
		{      
			p = (i ? aes_pow_tab[255 - aes_log_tab[i]] : 0); q = p;    
			q = (q >> 7) | (q << 1); p ^= q;    
			q = (q >> 7) | (q << 1); p ^= q;    
			q = (q >> 7) | (q << 1); p ^= q;    
			q = (q >> 7) | (q << 1); p ^= q ^ 0x63;    
			aes_sbx_tab[i] = p; aes_isb_tab[p] = (aes_u1byte)i;   
		}   

		for(i = 0; i < 256; ++i)   
		{   
			p = aes_sbx_tab[i];    

#ifdef  AES_LARGE_TABLES            

			t = p; aes_fl_tab[0][i] = t;   
			aes_fl_tab[1][i] = aes_rotl(t,  8);   
			aes_fl_tab[2][i] = aes_rotl(t, 16);   
			aes_fl_tab[3][i] = aes_rotl(t, 24);   
#endif    
			t = ((aes_u4byte)aes_ff_mult(2, p)) |   
				((aes_u4byte)p <<  8) |   
				((aes_u4byte)p << 16) |   
				((aes_u4byte)aes_ff_mult(3, p) << 24);   

			aes_ft_tab[0][i] = t;   
			aes_ft_tab[1][i] = aes_rotl(t,  8);   
			aes_ft_tab[2][i] = aes_rotl(t, 16);   
			aes_ft_tab[3][i] = aes_rotl(t, 24);   

			p = aes_isb_tab[i];    

#ifdef  AES_LARGE_TABLES            

			t = p; aes_il_tab[0][i] = t;    
			aes_il_tab[1][i] = aes_rotl(t,  8);    
			aes_il_tab[2][i] = aes_rotl(t, 16);    
			aes_il_tab[3][i] = aes_rotl(t, 24);   
#endif     
			t = ((aes_u4byte)aes_ff_mult(14, p)) |   
				((aes_u4byte)aes_ff_mult( 9, p) <<  8) |   
				((aes_u4byte)aes_ff_mult(13, p) << 16) |   
				((aes_u4byte)aes_ff_mult(11, p) << 24);   

			aes_it_tab[0][i] = t;    
			aes_it_tab[1][i] = aes_rotl(t,  8);    
			aes_it_tab[2][i] = aes_rotl(t, 16);    
			aes_it_tab[3][i] = aes_rotl(t, 24);    
		}   

		aes_tab_gen = 1;   
	}   

#define aes_star_x(x) (((x) & 0x7f7f7f7f) << 1) ^ ((((x) & 0x80808080) >> 7) * 0x1b)    

#define aes_imix_col(y,x)       \
	u   = aes_star_x(x);        \
	v   = aes_star_x(u);        \
	w   = aes_star_x(v);        \
	t   = w ^ (x);          \
	(y)  = u ^ v ^ w;        \
	(y) ^= aes_rotr(u ^ t,  8) ^ \
	aes_rotr(v ^ t, 16) ^ \
	aes_rotr(t,24)   

}   // end of anonymous namespace    

//get aes aes_name
static const char * aes_name(const AES_CONTEXT * pAES)   
{   
	return "rijndael";   
}   

// initialise the key schedule from the user supplied key       

#define aes_loop4(i)                                    \
{\
	t = aes_ls_box(aes_rotr(t,  8)) ^ aes_rco_tab[i];           \
	t ^= pAES->aes_e_key[4 * i];     pAES->aes_e_key[4 * i + 4] = t;    \
	t ^= pAES->aes_e_key[4 * i + 1]; pAES->aes_e_key[4 * i + 5] = t;    \
	t ^= pAES->aes_e_key[4 * i + 2]; pAES->aes_e_key[4 * i + 6] = t;    \
	t ^= pAES->aes_e_key[4 * i + 3]; pAES->aes_e_key[4 * i + 7] = t;    \
}   

#define aes_loop6(i)                                    \
{\
	t = aes_ls_box(aes_rotr(t,  8)) ^ aes_rco_tab[i];           \
	t ^= pAES->aes_e_key[6 * i];     pAES->aes_e_key[6 * i + 6] = t;    \
	t ^= pAES->aes_e_key[6 * i + 1]; pAES->aes_e_key[6 * i + 7] = t;    \
	t ^= pAES->aes_e_key[6 * i + 2]; pAES->aes_e_key[6 * i + 8] = t;    \
	t ^= pAES->aes_e_key[6 * i + 3]; pAES->aes_e_key[6 * i + 9] = t;    \
	t ^= pAES->aes_e_key[6 * i + 4]; pAES->aes_e_key[6 * i + 10] = t;   \
	t ^= pAES->aes_e_key[6 * i + 5]; pAES->aes_e_key[6 * i + 11] = t;   \
}   

#define aes_loop8(i)                                    \
{\
	t = aes_ls_box(aes_rotr(t,  8)) ^ aes_rco_tab[i];           \
	t ^= pAES->aes_e_key[8 * i];     pAES->aes_e_key[8 * i + 8] = t;    \
	t ^= pAES->aes_e_key[8 * i + 1]; pAES->aes_e_key[8 * i + 9] = t;    \
	t ^= pAES->aes_e_key[8 * i + 2]; pAES->aes_e_key[8 * i + 10] = t;   \
	t ^= pAES->aes_e_key[8 * i + 3]; pAES->aes_e_key[8 * i + 11] = t;   \
	t  = pAES->aes_e_key[8 * i + 4] ^ aes_ls_box(t);              \
	pAES->aes_e_key[8 * i + 12] = t;                          \
	t ^= pAES->aes_e_key[8 * i + 5]; pAES->aes_e_key[8 * i + 13] = t;   \
	t ^= pAES->aes_e_key[8 * i + 6]; pAES->aes_e_key[8 * i + 14] = t;   \
	t ^= pAES->aes_e_key[8 * i + 7]; pAES->aes_e_key[8 * i + 15] = t;   \
}   

//set aes key, must be 4*4bytes(128bits) or 6*4bytes(192bits) or 8*4bytes(256bits), must aes_set_key() before call aes_encrypt() and aes_decrypt()
static void aes_set_key(AES_CONTEXT * pAES,const aes_u1byte in_key[], const aes_u4byte key_bit_len)   
{   
	aes_u4byte  i, t, u, v, w;   

	if(!aes_tab_gen) 
	{
		aes_gen_tabs(); 
	}


	pAES->aes_key_4bytes_len = (key_bit_len + 31) / 32;   

	pAES->aes_e_key[0] = aes_u4byte_in(in_key     );    
	pAES->aes_e_key[1] = aes_u4byte_in(in_key +  4);   
	pAES->aes_e_key[2] = aes_u4byte_in(in_key +  8);    
	pAES->aes_e_key[3] = aes_u4byte_in(in_key + 12);   

	switch(pAES->aes_key_4bytes_len)   
	{   
	case 4: 
		t = pAES->aes_e_key[3];   
		for(i = 0; i < 10; ++i)    
			aes_loop4(i);   
		break;   

	case 6: 
		pAES->aes_e_key[4] = aes_u4byte_in(in_key + 16); 
		t = pAES->aes_e_key[5] = aes_u4byte_in(in_key + 20);   
		for(i = 0; i < 8; ++i)    
			aes_loop6(i);   
		break;   

	case 8: 
		pAES->aes_e_key[4] = aes_u4byte_in(in_key + 16); 
		pAES->aes_e_key[5] = aes_u4byte_in(in_key + 20);   
		pAES->aes_e_key[6] = aes_u4byte_in(in_key + 24); 
		t = pAES->aes_e_key[7] = aes_u4byte_in(in_key + 28);   
		for(i = 0; i < 7; ++i)    
			aes_loop8(i);   
		break;   
	}   

	pAES->aes_d_key[0] = pAES->aes_e_key[0]; pAES->aes_d_key[1] = pAES->aes_e_key[1];   
	pAES->aes_d_key[2] = pAES->aes_e_key[2]; pAES->aes_d_key[3] = pAES->aes_e_key[3];   

	for(i = 4; i < 4 * pAES->aes_key_4bytes_len + 24; ++i)   
	{   
		aes_imix_col(pAES->aes_d_key[i], pAES->aes_e_key[i]);   
	}   

	return;   
}   

// aes_encrypt a block of text      

#define aes_f_nround(bo, bi, k) \
	aes_f_rn(bo, bi, 0, k);     \
	aes_f_rn(bo, bi, 1, k);     \
	aes_f_rn(bo, bi, 2, k);     \
	aes_f_rn(bo, bi, 3, k);     \
	k += 4   

#define aes_f_lround(bo, bi, k) \
	aes_f_rl(bo, bi, 0, k);     \
	aes_f_rl(bo, bi, 1, k);     \
	aes_f_rl(bo, bi, 2, k);     \
	aes_f_rl(bo, bi, 3, k)   

//encrypt 16bytes plaintext to 16bytes ciphertext
static void aes_encrypt(const AES_CONTEXT * pAES,const aes_u1byte in_blk[16], aes_u1byte out_blk[16])   
{   
	aes_u4byte  b0[4], b1[4], *kp;   

	b0[0] = aes_u4byte_in(in_blk    ) ^ pAES->aes_e_key[0]; b0[1] = aes_u4byte_in(in_blk +  4) ^ pAES->aes_e_key[1];   
	b0[2] = aes_u4byte_in(in_blk + 8) ^ pAES->aes_e_key[2]; b0[3] = aes_u4byte_in(in_blk + 12) ^ pAES->aes_e_key[3];   

	kp = (aes_u4byte*)(pAES->aes_e_key + 4);   

	if(pAES->aes_key_4bytes_len > 6)   
	{   
		aes_f_nround(b1, b0, kp); aes_f_nround(b0, b1, kp);   
	}   

	if(pAES->aes_key_4bytes_len > 4)   
	{   
		aes_f_nround(b1, b0, kp); aes_f_nround(b0, b1, kp);   
	}   

	aes_f_nround(b1, b0, kp); aes_f_nround(b0, b1, kp);   
	aes_f_nround(b1, b0, kp); aes_f_nround(b0, b1, kp);   
	aes_f_nround(b1, b0, kp); aes_f_nround(b0, b1, kp);   
	aes_f_nround(b1, b0, kp); aes_f_nround(b0, b1, kp);   
	aes_f_nround(b1, b0, kp); aes_f_lround(b0, b1, kp);   

	aes_u4byte_out(out_blk,      b0[0]); aes_u4byte_out(out_blk +  4, b0[1]);   
	aes_u4byte_out(out_blk +  8, b0[2]); aes_u4byte_out(out_blk + 12, b0[3]);   
}   

// aes_decrypt a block of text      

#define aes_i_nround(bo, bi, k) \
	aes_i_rn(bo, bi, 0, k);     \
	aes_i_rn(bo, bi, 1, k);     \
	aes_i_rn(bo, bi, 2, k);     \
	aes_i_rn(bo, bi, 3, k);     \
	k -= 4   

#define aes_i_lround(bo, bi, k) \
	aes_i_rl(bo, bi, 0, k);     \
	aes_i_rl(bo, bi, 1, k);     \
	aes_i_rl(bo, bi, 2, k);     \
	aes_i_rl(bo, bi, 3, k)   


//decrypt 16bytes  ciphertext to 16bytesplaintext
static void aes_decrypt(const AES_CONTEXT * pAES,const aes_u1byte in_blk[16], aes_u1byte out_blk[16])   
{   
	aes_u4byte  b0[4], b1[4], *kp;   

	b0[0] = aes_u4byte_in(in_blk     ) ^ pAES->aes_e_key[4 * pAES->aes_key_4bytes_len + 24];    
	b0[1] = aes_u4byte_in(in_blk +  4) ^ pAES->aes_e_key[4 * pAES->aes_key_4bytes_len + 25];   
	b0[2] = aes_u4byte_in(in_blk +  8) ^ pAES->aes_e_key[4 * pAES->aes_key_4bytes_len + 26];    
	b0[3] = aes_u4byte_in(in_blk + 12) ^ pAES->aes_e_key[4 * pAES->aes_key_4bytes_len + 27];   

	kp = (aes_u4byte*)(pAES->aes_d_key + 4 * (pAES->aes_key_4bytes_len + 5));   

	if(pAES->aes_key_4bytes_len > 6)   
	{   
		aes_i_nround(b1, b0, kp); aes_i_nround(b0, b1, kp);   
	}   

	if(pAES->aes_key_4bytes_len > 4)   
	{   
		aes_i_nround(b1, b0, kp); aes_i_nround(b0, b1, kp);   
	}   

	aes_i_nround(b1, b0, kp); aes_i_nround(b0, b1, kp);   
	aes_i_nround(b1, b0, kp); aes_i_nround(b0, b1, kp);   
	aes_i_nround(b1, b0, kp); aes_i_nround(b0, b1, kp);   
	aes_i_nround(b1, b0, kp); aes_i_nround(b0, b1, kp);   
	aes_i_nround(b1, b0, kp); aes_i_lround(b0, b1, kp);   

	aes_u4byte_out(out_blk,     b0[0]); aes_u4byte_out(out_blk +  4, b0[1]);   
	aes_u4byte_out(out_blk + 8, b0[2]); aes_u4byte_out(out_blk + 12, b0[3]);   
}   

//--------------------------------------------------------------------------
//Xuetian defined AES functions
//!set aes key
static int XtAesSetKey(AES_CONTEXT * pAES,const void* pKey, int nKeyBitsLength,bool bConvertToMD5Key)
{
#ifdef AES_SUPPORT_MD5
	//convert all key to md5 format
	if(bConvertToMD5Key)
	{
		aes_u1byte abyMD5Key[16];
		MD5_CTX context;
		MD5Init(&context);
		MD5Update(&context,(unsigned char *)pKey,(nKeyBitsLength+7)/8);
		MD5Final(abyMD5Key,&context);

		nKeyBitsLength = 128;
		aes_set_key(pAES,(const aes_u1byte*)abyMD5Key,nKeyBitsLength);
	}//if
	//keep key
	else
#endif//#ifdef AES_SUPPORT_MD5
	{
		if(nKeyBitsLength == 128 || nKeyBitsLength == 192 || nKeyBitsLength == 256)
		{
			aes_set_key(pAES,(const aes_u1byte*)pKey,nKeyBitsLength);
		}//if
		else
		{
			int nGetOldKeyBytes		= (nKeyBitsLength+7)/8;
			if(nGetOldKeyBytes > 8*4)
			{
				nGetOldKeyBytes		= 8*4;
			}//if

			aes_u1byte* pOldKey		= (aes_u1byte*)pKey;
			aes_u1byte* pRealKey	= 0;
			if(nKeyBitsLength <= 128)
			{
				pRealKey = (aes_u1byte*)::malloc(4*4);
				::memset(pRealKey,0,4*4);
				int i = 0;
				for(; i < nGetOldKeyBytes; ++i)
				{
					pRealKey[i] = pOldKey[i];
				}//fori
				nKeyBitsLength = 4*4*8;
			}//if
			else if(nKeyBitsLength <= 192)
			{
				pRealKey = (aes_u1byte*)::malloc(6*4);
				::memset(pRealKey,0,4*6);
				int i = 0;
				for(; i < nGetOldKeyBytes; ++i)
				{
					pRealKey[i] = pOldKey[i];
				}//fori
				nKeyBitsLength = 6*4*8;
			}//if
			else//
			{
				pRealKey = (aes_u1byte*)::malloc(8*4);
				::memset(pRealKey,0,8*4);
				int i = 0;
				for(; i < nGetOldKeyBytes; ++i)
				{
					pRealKey[i] = pOldKey[i];
				}//fori
				nKeyBitsLength = 8*4*8;
			}//if
			aes_set_key(pAES,(const aes_u1byte*)pRealKey,nKeyBitsLength);
			::free(pRealKey);
		}
	}
	return nKeyBitsLength;
}
static int XtAesSetKeyByString(AES_CONTEXT * pAES,const char* pszKey,bool bConvertToMD5Key)
{
	return XtAesSetKey(pAES,(const void*)pszKey,(int)strlen(pszKey)*8,bConvertToMD5Key);
}

//!encrypt plaintext to ciphertext
static void XtAesEncrypt(const AES_CONTEXT * pAES,const void* pPlainTextBuf, int nPlainTextLength,void* pCipherTextBuf)
{
	//AES ecrypt only for 128bits blocks
	int nC = nPlainTextLength / 16;
	int i = 0;
	for(; i < nC; ++i)
	{
		aes_encrypt(pAES,((const aes_u1byte*)pPlainTextBuf)+i*16,((aes_u1byte*)pCipherTextBuf)+i*16);
	}//fori

	//left bytes will be bytes rotation
	int nLeftBytes = nPlainTextLength - nC * 16;

	if(nLeftBytes > 0)
	{
		const aes_u1byte* pInStart	= ((const aes_u1byte*)pPlainTextBuf) + nC * 16;
		aes_u1byte* pOutStart		= ((aes_u1byte*)pCipherTextBuf) + nC * 16;

		int i = 0;
		int n = 0;
		for(; i < nLeftBytes; ++i)
		{
			pOutStart[i]			= pInStart[i];
			n = (i+3)%7;
			aes_rcmbyte(pOutStart[i],n);
		}//fori
	}//if
}
static int XtAesEncryptString(const AES_CONTEXT * pAES,const char* pszPlainTextBuf, char* pszCipherTextBuf)
{
	int nSL = (int)strlen(pszPlainTextBuf);
	XtAesEncrypt(pAES,(const void*)pszPlainTextBuf,nSL,(void*)pszCipherTextBuf);
	pszCipherTextBuf[nSL] = 0;
	return nSL;
}
//!encrypt plaintext to ciphertext
static void XtAesDecrypt(const AES_CONTEXT * pAES,const void* pCipherTextBuf, int nCipherTextLength,void* pPlainTextBuf)
{
	//AES decrypt only for 128bits blocks
	int nC = nCipherTextLength / 16;
	int i = 0;
	for(; i < nC; ++i)
	{
		aes_decrypt(pAES,((const aes_u1byte*)pCipherTextBuf)+i*16,((aes_u1byte*)pPlainTextBuf)+i*16);
	}//fori

	//left bytes will be bytes rotation
	int nLeftBytes = nCipherTextLength - nC * 16;

	if(nLeftBytes > 0)
	{
		const aes_u1byte* pInStart	= ((const aes_u1byte*)pCipherTextBuf) + nC * 16;
		aes_u1byte* pOutStart		= ((aes_u1byte*)pPlainTextBuf) + nC * 16;

		int i = 0;
		int n = 0;
		for(; i < nLeftBytes; ++i)
		{
			pOutStart[i]			= pInStart[i];
			n = (i+3)%7;
			aes_lcmbyte(pOutStart[i],n);
		}//fori
	}//if
}
static int XtAesDecryptString(const AES_CONTEXT * pAES,const char* pszCipherTextBuf, char* pszPlainTextBuf,int nCipherTextBufLength = 0)
{
	int nSL = nCipherTextBufLength == 0?(int)strlen(pszCipherTextBuf):nCipherTextBufLength;
	XtAesDecrypt(pAES,(const void*)pszCipherTextBuf,nSL,(void*)pszPlainTextBuf);
	pszPlainTextBuf[nSL] = 0;
	return nSL;
}

/*
//AES test case:
void main()
{
	srand((int)time(NULL));

	printf("This is a test case for AES agorithm\r\n");
	
	AES_CONTEXT aes;

	int j = 0;
	for(; j < 6; ++j)
	{
		//set key
		if(j == 0)
		{
			char szKey[]		= "ThisIsKey";
			int nRealKeyBitsLen = XtAesSetKeyByString(&aes,szKey,false);			
			printf("XtAesSetKeyString()=%d: string key: %s\r\n",nRealKeyBitsLen,szKey);
		}
		else if(j == 1)
		{
			char szKey[]		= "ThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKeyThisIsLongLongKey";
			int nRealKeyBitsLen = XtAesSetKeyByString(&aes,szKey,false);
			printf("XtAesSetKeyString()=%d: string key: %s\r\n",nRealKeyBitsLen,szKey);
		}
		else if(j == 2)
		{
#define AES_T_KEY_4B_LEN_4 4
			aes_u1byte abyKey[AES_T_KEY_4B_LEN_4*4];
			int i = 0;
			for(; i < AES_T_KEY_4B_LEN_4*4; ++i)
			{
				abyKey[i] = rand()%256;
			}//fori
			int nRealKeyBitsLen = XtAesSetKey(&aes,abyKey,AES_T_KEY_4B_LEN_4*4*8,false);
			printf("XtAesSetKey(%d)=%d: bytes key: ",AES_T_KEY_4B_LEN_4*4*8,nRealKeyBitsLen);
			i = 0;
			for(; i < AES_T_KEY_4B_LEN_4*4; ++i)
			{
				printf("%02x",abyKey[i]);
			}//fori
			printf("\r\n");
		}
		else if(j == 3)
		{
#define AES_T_KEY_4B_LEN_6 6
			aes_u1byte abyKey[AES_T_KEY_4B_LEN_6*4];
			int i = 0;
			for(; i < AES_T_KEY_4B_LEN_6*4; ++i)
			{
				abyKey[i] = rand()%256;
			}//fori
			int nRealKeyBitsLen = XtAesSetKey(&aes,abyKey,AES_T_KEY_4B_LEN_6*4*8,false);
			printf("XtAesSetKey(%d)=%d: bytes key: ",AES_T_KEY_4B_LEN_6*4*8,nRealKeyBitsLen);
			i = 0;
			for(; i < AES_T_KEY_4B_LEN_6*4; ++i)
			{
				printf("%02x",abyKey[i]);
			}//fori
			printf("\r\n");
		}
		else if(j == 4)
		{
#define AES_T_KEY_4B_LEN_8 8
			aes_u1byte abyKey[AES_T_KEY_4B_LEN_8*4];
			int i = 0;
			for(; i < AES_T_KEY_4B_LEN_8*4; ++i)
			{
				abyKey[i] = rand()%256;
			}//fori
			int nRealKeyBitsLen = XtAesSetKey(&aes,abyKey,AES_T_KEY_4B_LEN_8*4*8,false);
			printf("XtAesSetKey(%d)=%d: bytes key: ",AES_T_KEY_4B_LEN_8*4*8,nRealKeyBitsLen);
			i = 0;
			for(; i < AES_T_KEY_4B_LEN_8*4; ++i)
			{
				printf("%02x",abyKey[i]);
			}//fori
			printf("\r\n");
		}
		else// if(j == 5)
		{
#define AES_T_KEY_4B_LEN_LONG 11
			aes_u1byte abyKey[AES_T_KEY_4B_LEN_LONG*4];
			int i = 0;
			for(; i < AES_T_KEY_4B_LEN_LONG*4; ++i)
			{
				abyKey[i] = rand()%256;
			}//fori
			int nRealKeyBitsLen = XtAesSetKey(&aes,abyKey,AES_T_KEY_4B_LEN_LONG*4*8,false);
			printf("XtAesSetKey(%d)=%d: bytes key: ",AES_T_KEY_4B_LEN_LONG*4*8,nRealKeyBitsLen);
			i = 0;
			for(; i < AES_T_KEY_4B_LEN_LONG*4; ++i)
			{
				printf("%02x",abyKey[i]);
			}//fori
			printf("\r\n");
		}

		//--------------------------------------------------------------------------
		//encrypt/decrypt string data
		printf("---------begin: encrypt/decrypt string data---------------------\r\n");

		char szIn[]		= "This is plaintext data. 这是明文数据";
		char * pszOut1	= (char *)::malloc(strlen(szIn)+1);
		char * pszOut2	= (char *)::malloc(strlen(szIn)+1);

		printf("XtAesEncryptString: String IN data: %s\r\n",szIn);
		int nCipherTextLength = XtAesEncryptString(&aes,szIn,pszOut1);
		printf("XtAesEncryptString: String OUT data: %s\r\n",pszOut1);

		printf("XtAesDecryptString: String IN data: %s\r\n",pszOut1);
		int nPlainTextLength = XtAesDecryptString(&aes,pszOut1,pszOut2,nCipherTextLength);
		printf("XtAesDecryptString: String OUT data: %s\r\n",pszOut2);

		printf("XtAesEncryptString/XtAesDecryptString: %s\r\n",strcmp(pszOut2,szIn) == 0?"OK":"ERROR");

		printf("---------end: encrypt/decrypt string data---------------------\r\n");
		::free(pszOut1);
		::free(pszOut2);
		//--------------------------------------------------------------------------

		//--------------------------------------------------------------------------
		//encrypt/decrypt byte data
		printf("---------begin: encrypt/decrypt byte data---------------------\r\n");
#define AES_T_B_LEN 35
		aes_u1byte abyIn[AES_T_B_LEN];
		aes_u1byte abyOut1[AES_T_B_LEN];
		aes_u1byte abyOut2[AES_T_B_LEN];
		int i = 0;
		for(; i < AES_T_B_LEN; ++i)
		{
			abyIn[i] = rand()%256;
		}//fori

		printf("XtAesEncrypt: bytes IN data:");
		i = 0;
		for(; i < AES_T_B_LEN; ++i)
		{
			printf("%02x",abyIn[i]);
		}//fori
		printf("\r\n");

		XtAesEncrypt(&aes,abyIn,AES_T_B_LEN,abyOut1);

		printf("XtAesEncrypt: bytes OUT data:");
		i = 0;
		for(; i < AES_T_B_LEN; ++i)
		{
			printf("%02x",abyOut1[i]);
		}//fori
		printf("\r\n");



		printf("XtAesDecrypt: bytes IN data:");
		i = 0;
		for(; i < AES_T_B_LEN; ++i)
		{
			printf("%02x",abyOut1[i]);
		}//fori
		printf("\r\n");

		XtAesDecrypt(&aes,abyOut1,AES_T_B_LEN,abyOut2);

		printf("XtAesDecrypt: bytes OUT data:");
		i = 0;
		for(; i < AES_T_B_LEN; ++i)
		{
			printf("%02x",abyOut2[i]);
		}//fori
		printf("\r\n");

		bool bOK = true;
		i = 0;
		for(; i < AES_T_B_LEN; ++i)
		{
			if(abyOut2[i] != abyIn[i])
			{
				bOK = false;
				break;
			}
		}//fori
		printf("XtAesEncrypt/XtAesDecrypt: %s\r\n",bOK?"OK":"ERROR");

		printf("---------end: encrypt/decrypt byte data---------------------\r\n");
		//--------------------------------------------------------------------------
	}//forj

	printf("press any key to quit\r\n");
	getchar();
}
*/
static void EndFunction4AES(){}
//end: AES
//-----aes end------------------------------------------------------------------------

//----rsa begin-------------------------------------------------------------------------
//begin: RSA
static void BeginFunction4RSA(){}

//!	我们自己定义rsa的密钥基准(大整数)长度固定为1024bit
#define RSA_KEY_BASE_BIT_SIZE			1024
//!	rsa的密钥字节长度
#define RSA_KEY_BASE_SIZE				(RSA_KEY_BASE_BIT_SIZE/8)
//!	rsa的密钥字符串长度(不含字符串结束符)
#define RSA_STRING_KEY_BASE_SIZE		(RSA_KEY_BASE_SIZE*2)
//!	rsa的密钥字符串长度(含字符串结束符)
#define RSA_STRING_KEY_BASE_SIZE1		(RSA_STRING_KEY_BASE_SIZE+1)

//!	私钥长度
#define RSA_SKEY_SIZE					(RSA_KEY_BASE_SIZE*8)
//!	公钥长度
#define RSA_PKEY_SIZE					(RSA_KEY_BASE_SIZE*2)
//!	私钥字符串长度(不含字符串结束符)
#define RSA_STRING_SKEY_SIZE			(RSA_SKEY_SIZE*2)
//!	公钥字符串长度(不含字符串结束符)
#define RSA_STRING_PKEY_SIZE			(RSA_PKEY_SIZE*2)
//!	私钥字符串长度(含字符串结束符)
#define RSA_STRING_SKEY_SIZE1			(RSA_STRING_SKEY_SIZE+1)
//!	公钥字符串长度(含字符串结束符)
#define RSA_STRING_PKEY_SIZE1			(RSA_STRING_PKEY_SIZE+1)
/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This set of compile-time options may be used to enable
 * or disable features selectively, and reduce the global
 * memory footprint.
 */
#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

/**
 * \name SECTION: System support
 *
 * This section sets system specific settings.
 * \{
 */

/**
 * \def POLARSSL_HAVE_INT8
 *
 * The system uses 8-bit wide native integers.
 *
 * Uncomment if native integers are 8-bit wide.
 */
//#define POLARSSL_HAVE_INT8

/**
 * \def POLARSSL_HAVE_INT16
 *
 * The system uses 16-bit wide native integers.
 *
 * Uncomment if native integers are 16-bit wide.
 */
//#define POLARSSL_HAVE_INT16

/**
 * \def POLARSSL_HAVE_LONGLONG
 *
 * The compiler supports the 'long long' type.
 * (Only used on 32-bit platforms)
 */
#define POLARSSL_HAVE_LONGLONG

/**
 * \def POLARSSL_HAVE_ASM
 *
 * The compiler has support for asm().
 *
 * Requires support for asm() in compiler.
 *
 * Used in:
 *      library/timing.c
 *      library/padlock.c
 *      include/polarssl/bn_mul.h
 *
 * Comment to disable the use of assembly code.
 */
#define POLARSSL_HAVE_ASM

/**
 * \def POLARSSL_HAVE_SSE2
 *
 * CPU supports SSE2 instruction set.
 *
 * Uncomment if the CPU supports SSE2 (IA-32 specific).
 */
//#define POLARSSL_HAVE_SSE2

/**
 * \def POLARSSL_HAVE_TIME
 *
 * System has time.h and time() / localtime()  / gettimeofday().
 *
 * Comment if your system does not support time functions
 */
#define POLARSSL_HAVE_TIME

/**
 * \def POLARSSL_HAVE_IPV6
 *
 * System supports the basic socket interface for IPv6 (RFC 3493),
 * specifically getaddrinfo(), freeaddrinfo() and struct sockaddr_storage.
 *
 * Note: on Windows/MingW, XP or higher is required.
 *
 * Comment if your system does not support the IPv6 socket interface
 */
#define POLARSSL_HAVE_IPV6

/**
 * \def POLARSSL_PLATFORM_MEMORY
 *
 * Enable the memory allocation layer.
 *
 * By default PolarSSL uses the system-provided malloc() and free().
 * This allows different allocators (self-implemented or provided) to be
 * provided to the platform abstraction layer.
 *
 * Enabling POLARSSL_PLATFORM_MEMORY will provide "platform_set_malloc_free()"
 * to allow you to set an alternative malloc() and free() function pointer.
 *
 * Requires: POLARSSL_PLATFORM_C
 *
 * Enable this layer to allow use of alternative memory allocators.
 */
//#define POLARSSL_PLATFORM_MEMORY

/**
 * \def POLARSSL_PLATFORM_NO_STD_FUNCTIONS
 *
 * Do not assign standard functions in the platform layer (e.g. malloc() to
 * POLARSSL_PLATFORM_STD_MALLOC and printf() to POLARSSL_PLATFORM_STD_PRINTF)
 *
 * This makes sure there are no linking errors on platforms that do not support
 * these functions. You will HAVE to provide alternatives, either at runtime
 * via the platform_set_xxx() functions or at compile time by setting
 * the POLARSSL_PLATFORM_STD_XXX defines.
 *
 * Requires: POLARSSL_PLATFORM_C
 *
 * Uncomment to prevent default assignment of standard functions in the
 * platform layer.
 */
//#define POLARSSL_PLATFORM_NO_STD_FUNCTIONS

/**
 * \def POLARSSL_PLATFORM_XXX_ALT
 *
 * Uncomment a macro to let PolarSSL support the function in the platform
 * abstraction layer.
 *
 * Example: In case you uncomment POLARSSL_PLATFORM_PRINTF_ALT, PolarSSL will
 * provide a function "platform_set_printf()" that allows you to set an
 * alternative printf function pointer.
 *
 * All these define require POLARSSL_PLATFORM_C to be defined!
 *
 * Uncomment a macro to enable alternate implementation of specific base
 * platform function
 */
//#define POLARSSL_PLATFORM_PRINTF_ALT
//#define POLARSSL_PLATFORM_FPRINTF_ALT
/* \} name SECTION: System support */

/**
 * \name SECTION: PolarSSL feature support
 *
 * This section sets support for features that are or are not needed
 * within the modules that are enabled.
 * \{
 */

/**
 * \def POLARSSL_TIMING_ALT
 *
 * Uncomment to provide your own alternate implementation for hardclock(),
 * get_timer(), set_alarm() and m_sleep().
 *
 * Only works if you have POLARSSL_TIMING_C enabled.
 *
 * You will need to provide a header "timing_alt.h" and an implementation at
 * compile time.
 */
//#define POLARSSL_TIMING_ALT

/**
 * \def POLARSSL_XXX_ALT
 *
 * Uncomment a macro to let PolarSSL use your alternate core implementation of
 * a symmetric or hash algorithm (e.g. platform specific assembly optimized
 * implementations). Keep in mind that the function prototypes should remain
 * the same.
 *
 * Example: In case you uncomment POLARSSL_AES_ALT, PolarSSL will no longer
 * provide the "struct aes_context" definition and omit the base function
 * declarations and implementations. "aes_alt.h" will be included from
 * "aes.h" to include the new function definitions.
 *
 * Uncomment a macro to enable alternate implementation for core algorithm
 * functions
 */
//#define POLARSSL_AES_ALT
//#define POLARSSL_ARC4_ALT
//#define POLARSSL_BLOWFISH_ALT
//#define POLARSSL_CAMELLIA_ALT
//#define POLARSSL_DES_ALT
//#define POLARSSL_XTEA_ALT
//#define POLARSSL_MD2_ALT
//#define POLARSSL_MD4_ALT
//#define POLARSSL_MD5_ALT
//#define POLARSSL_RIPEMD160_ALT
//#define POLARSSL_SHA1_ALT
//#define POLARSSL_SHA256_ALT
//#define POLARSSL_SHA512_ALT

/**
 * \def POLARSSL_AES_ROM_TABLES
 *
 * Store the AES tables in ROM.
 *
 * Uncomment this macro to store the AES tables in ROM.
 *
 */
//#define POLARSSL_AES_ROM_TABLES

/**
 * \def POLARSSL_CIPHER_MODE_CBC
 *
 * Enable Cipher Block Chaining mode (CBC) for symmetric ciphers.
 */
#define POLARSSL_CIPHER_MODE_CBC

/**
 * \def POLARSSL_CIPHER_MODE_CFB
 *
 * Enable Cipher Feedback mode (CFB) for symmetric ciphers.
 */
#define POLARSSL_CIPHER_MODE_CFB

/**
 * \def POLARSSL_CIPHER_MODE_CTR
 *
 * Enable Counter Block Cipher mode (CTR) for symmetric ciphers.
 */
#define POLARSSL_CIPHER_MODE_CTR

/**
 * \def POLARSSL_CIPHER_NULL_CIPHER
 *
 * Enable NULL cipher.
 * Warning: Only do so when you know what you are doing. This allows for
 * encryption or channels without any security!
 *
 * Requires POLARSSL_ENABLE_WEAK_CIPHERSUITES as well to enable
 * the following ciphersuites:
 *      TLS_ECDH_ECDSA_WITH_NULL_SHA
 *      TLS_ECDH_RSA_WITH_NULL_SHA
 *      TLS_ECDHE_ECDSA_WITH_NULL_SHA
 *      TLS_ECDHE_RSA_WITH_NULL_SHA
 *      TLS_ECDHE_PSK_WITH_NULL_SHA384
 *      TLS_ECDHE_PSK_WITH_NULL_SHA256
 *      TLS_ECDHE_PSK_WITH_NULL_SHA
 *      TLS_DHE_PSK_WITH_NULL_SHA384
 *      TLS_DHE_PSK_WITH_NULL_SHA256
 *      TLS_DHE_PSK_WITH_NULL_SHA
 *      TLS_RSA_WITH_NULL_SHA256
 *      TLS_RSA_WITH_NULL_SHA
 *      TLS_RSA_WITH_NULL_MD5
 *      TLS_RSA_PSK_WITH_NULL_SHA384
 *      TLS_RSA_PSK_WITH_NULL_SHA256
 *      TLS_RSA_PSK_WITH_NULL_SHA
 *      TLS_PSK_WITH_NULL_SHA384
 *      TLS_PSK_WITH_NULL_SHA256
 *      TLS_PSK_WITH_NULL_SHA
 *
 * Uncomment this macro to enable the NULL cipher and ciphersuites
 */
//#define POLARSSL_CIPHER_NULL_CIPHER

/**
 * \def POLARSSL_CIPHER_PADDING_XXX
 *
 * Uncomment or comment macros to add support for specific padding modes
 * in the cipher layer with cipher modes that support padding (e.g. CBC)
 *
 * If you disable all padding modes, only full blocks can be used with CBC.
 *
 * Enable padding modes in the cipher layer.
 */
#define POLARSSL_CIPHER_PADDING_PKCS7
#define POLARSSL_CIPHER_PADDING_ONE_AND_ZEROS
#define POLARSSL_CIPHER_PADDING_ZEROS_AND_LEN
#define POLARSSL_CIPHER_PADDING_ZEROS

/**
 * \def POLARSSL_ENABLE_WEAK_CIPHERSUITES
 *
 * Enable weak ciphersuites in SSL / TLS.
 * Warning: Only do so when you know what you are doing. This allows for
 * channels with virtually no security at all!
 *
 * This enables the following ciphersuites:
 *      TLS_RSA_WITH_DES_CBC_SHA
 *      TLS_DHE_RSA_WITH_DES_CBC_SHA
 *
 * Uncomment this macro to enable weak ciphersuites
 */
//#define POLARSSL_ENABLE_WEAK_CIPHERSUITES

/**
 * \def POLARSSL_REMOVE_ARC4_CIPHERSUITES
 *
 * Remove RC4 ciphersuites by default in SSL / TLS.
 * This flag removes the ciphersuites based on RC4 from the default list as
 * returned by ssl_list_ciphersuites(). However, it is still possible to
 * enable (some of) them with ssl_set_ciphersuites() by including them
 * explicitly.
 *
 * Uncomment this macro to remove RC4 ciphersuites by default.
 */
//#define POLARSSL_REMOVE_ARC4_CIPHERSUITES

/**
 * \def POLARSSL_ECP_XXXX_ENABLED
 *
 * Enables specific curves within the Elliptic Curve module.
 * By default all supported curves are enabled.
 *
 * Comment macros to disable the curve and functions for it
 */
//#define POLARSSL_ECP_DP_SECP192R1_ENABLED
//#define POLARSSL_ECP_DP_SECP224R1_ENABLED
//#define POLARSSL_ECP_DP_SECP256R1_ENABLED
//#define POLARSSL_ECP_DP_SECP384R1_ENABLED
//#define POLARSSL_ECP_DP_SECP521R1_ENABLED
//#define POLARSSL_ECP_DP_SECP192K1_ENABLED
//#define POLARSSL_ECP_DP_SECP224K1_ENABLED
//#define POLARSSL_ECP_DP_SECP256K1_ENABLED
//#define POLARSSL_ECP_DP_BP256R1_ENABLED
//#define POLARSSL_ECP_DP_BP384R1_ENABLED
//#define POLARSSL_ECP_DP_BP512R1_ENABLED
//#define POLARSSL_ECP_DP_M221_ENABLED  // Not implemented yet!
//#define POLARSSL_ECP_DP_M255_ENABLED
//#define POLARSSL_ECP_DP_M383_ENABLED  // Not implemented yet!
//#define POLARSSL_ECP_DP_M511_ENABLED  // Not implemented yet!

/**
 * \def POLARSSL_ECP_NIST_OPTIM
 *
 * Enable specific 'modulo p' routines for each NIST prime.
 * Depending on the prime and architecture, makes operations 4 to 8 times
 * faster on the corresponding curve.
 *
 * Comment this macro to disable NIST curves optimisation.
 */
//#define POLARSSL_ECP_NIST_OPTIM

/**
 * \def POLARSSL_ECDSA_DETERMINISTIC
 *
 * Enable deterministic ECDSA (RFC 6979).
 * Standard ECDSA is "fragile" in the sense that lack of entropy when signing
 * may result in a compromise of the long-term signing key. This is avoided by
 * the deterministic variant.
 *
 * Requires: POLARSSL_HMAC_DRBG_C
 *
 * Comment this macro to disable deterministic ECDSA.
 */
//#define POLARSSL_ECDSA_DETERMINISTIC

/**
 * \def POLARSSL_KEY_EXCHANGE_PSK_ENABLED
 *
 * Enable the PSK based ciphersuite modes in SSL / TLS.
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_PSK_WITH_AES_256_GCM_SHA384
 *      TLS_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_PSK_WITH_AES_256_CBC_SHA
 *      TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_PSK_WITH_AES_128_GCM_SHA256
 *      TLS_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_PSK_WITH_AES_128_CBC_SHA
 *      TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_PSK_WITH_3DES_EDE_CBC_SHA
 *      TLS_PSK_WITH_RC4_128_SHA
 */
#define POLARSSL_KEY_EXCHANGE_PSK_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED
 *
 * Enable the DHE-PSK based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_DHM_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
 *      TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_DHE_PSK_WITH_AES_256_CBC_SHA
 *      TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
 *      TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_DHE_PSK_WITH_AES_128_CBC_SHA
 *      TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
 *      TLS_DHE_PSK_WITH_RC4_128_SHA
 */
//#define POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED
 *
 * Enable the ECDHE-PSK based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_ECDH_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
 *      TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
 *      TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDHE_PSK_WITH_RC4_128_SHA
 */
//#define POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED
 *
 * Enable the RSA-PSK based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_RSA_C, POLARSSL_PKCS1_V15,
 *           POLARSSL_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
 *      TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_RSA_PSK_WITH_AES_256_CBC_SHA
 *      TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
 *      TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_RSA_PSK_WITH_AES_128_CBC_SHA
 *      TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
 *      TLS_RSA_PSK_WITH_RC4_128_SHA
 */
#define POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_RSA_ENABLED
 *
 * Enable the RSA-only based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_RSA_C, POLARSSL_PKCS1_V15,
 *           POLARSSL_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_RSA_WITH_AES_256_CBC_SHA256
 *      TLS_RSA_WITH_AES_256_CBC_SHA
 *      TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      TLS_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_RSA_WITH_AES_128_CBC_SHA
 *      TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      TLS_RSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_RSA_WITH_RC4_128_SHA
 *      TLS_RSA_WITH_RC4_128_MD5
 */
#define POLARSSL_KEY_EXCHANGE_RSA_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED
 *
 * Enable the DHE-RSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_DHM_C, POLARSSL_RSA_C, POLARSSL_PKCS1_V15,
 *           POLARSSL_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 *      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 *      TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
 *      TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
 */
//#define POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED
 *
 * Enable the ECDHE-RSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_ECDH_C, POLARSSL_RSA_C, POLARSSL_PKCS1_V15,
 *           POLARSSL_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 *      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDHE_RSA_WITH_RC4_128_SHA
 */
//#define POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
 *
 * Enable the ECDHE-ECDSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_ECDH_C, POLARSSL_ECDSA_C, POLARSSL_X509_CRT_PARSE_C,
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 *      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
 */
//#define POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
 *
 * Enable the ECDH-ECDSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_ECDH_C, POLARSSL_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDH_ECDSA_WITH_RC4_128_SHA
 *      TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
 *      TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
 *      TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 */
//#define POLARSSL_KEY_EXCHANGE_ECDH_ECDSA_ENABLED

/**
 * \def POLARSSL_KEY_EXCHANGE_ECDH_RSA_ENABLED
 *
 * Enable the ECDH-RSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: POLARSSL_ECDH_C, POLARSSL_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDH_RSA_WITH_RC4_128_SHA
 *      TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
 *      TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
 *      TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
 */
//#define POLARSSL_KEY_EXCHANGE_ECDH_RSA_ENABLED

/**
 * \def POLARSSL_PK_PARSE_EC_EXTENDED
 *
 * Enhance support for reading EC keys using variants of SEC1 not allowed by
 * RFC 5915 and RFC 5480.
 *
 * Currently this means parsing the SpecifiedECDomain choice of EC
 * parameters (only known groups are supported, not arbitrary domains, to
 * avoid validation issues).
 *
 * Disable if you only need to support RFC 5915 + 5480 key formats.
 */
//#define POLARSSL_PK_PARSE_EC_EXTENDED

/**
 * \def POLARSSL_ERROR_STRERROR_BC
 *
 * Make available the backward compatible error_strerror() next to the
 * current polarssl_strerror().
 *
 * For new code, it is recommended to use polarssl_strerror() instead and
 * disable this.
 *
 * Disable if you run into name conflicts and want to really remove the
 * error_strerror()
 */
#define POLARSSL_ERROR_STRERROR_BC

/**
 * \def POLARSSL_ERROR_STRERROR_DUMMY
 *
 * Enable a dummy error function to make use of polarssl_strerror() in
 * third party libraries easier when POLARSSL_ERROR_C is disabled
 * (no effect when POLARSSL_ERROR_C is enabled).
 *
 * You can safely disable this if POLARSSL_ERROR_C is enabled, or if you're
 * not using polarssl_strerror() or error_strerror() in your application.
 *
 * Disable if you run into name conflicts and want to really remove the
 * polarssl_strerror()
 */
#define POLARSSL_ERROR_STRERROR_DUMMY

/**
 * \def POLARSSL_GENPRIME
 *
 * Enable the prime-number generation code.
 *
 * Requires: POLARSSL_BIGNUM_C
 */
#define POLARSSL_GENPRIME

/**
 * \def POLARSSL_FS_IO
 *
 * Enable functions that use the filesystem.
 */
#define POLARSSL_FS_IO

/**
 * \def POLARSSL_NO_DEFAULT_ENTROPY_SOURCES
 *
 * Do not add default entropy sources. These are the platform specific,
 * hardclock and HAVEGE based poll functions.
 *
 * This is useful to have more control over the added entropy sources in an
 * application.
 *
 * Uncomment this macro to prevent loading of default entropy functions.
 */
//#define POLARSSL_NO_DEFAULT_ENTROPY_SOURCES

/**
 * \def POLARSSL_NO_PLATFORM_ENTROPY
 *
 * Do not use built-in platform entropy functions.
 * This is useful if your platform does not support
 * standards like the /dev/urandom or Windows CryptoAPI.
 *
 * Uncomment this macro to disable the built-in platform entropy functions.
 */
//#define POLARSSL_NO_PLATFORM_ENTROPY

/**
 * \def POLARSSL_ENTROPY_FORCE_SHA256
 *
 * Force the entropy accumulator to use a SHA-256 accumulator instead of the
 * default SHA-512 based one (if both are available).
 *
 * Requires: POLARSSL_SHA256_C
 *
 * On 32-bit systems SHA-256 can be much faster than SHA-512. Use this soption
 * if you have performance concerns.
 *
 * This soption is only useful if both POLARSSL_SHA256_C and
 * POLARSSL_SHA512_C are defined. Otherwise the available hash module is used.
 */
//#define POLARSSL_ENTROPY_FORCE_SHA256

/**
 * \def POLARSSL_MEMORY_DEBUG
 *
 * Enable debugging of buffer allocator memory issues. Automatically prints
 * (to stderr) all (fatal) messages on memory allocation issues. Enables
 * function for 'debug output' of allocated memory.
 *
 * Requires: POLARSSL_MEMORY_BUFFER_ALLOC_C
 *
 * Uncomment this macro to let the buffer allocator print out error messages.
 */
//#define POLARSSL_MEMORY_DEBUG

/**
 * \def POLARSSL_MEMORY_BACKTRACE
 *
 * Include backtrace information with each allocated block.
 *
 * Requires: POLARSSL_MEMORY_BUFFER_ALLOC_C
 *           GLIBC-compatible backtrace() an backtrace_symbols() support
 *
 * Uncomment this macro to include backtrace information
 */
//#define POLARSSL_MEMORY_BACKTRACE

/**
 * \def POLARSSL_PKCS1_V15
 *
 * Enable support for PKCS#1 v1.5 encoding.
 *
 * Requires: POLARSSL_RSA_C
 *
 * This enables support for PKCS#1 v1.5 operations.
 */
#define POLARSSL_PKCS1_V15


/**
 * \def POLARSSL_PKCS1_V21
 *
 * Enable support for PKCS#1 v2.1 encoding.
 *
 * Requires: POLARSSL_MD_C, POLARSSL_RSA_C
 *
 * This enables support for RSAES-OAEP and RSASSA-PSS operations.
 */
#define POLARSSL_PKCS1_V21

/**
 * \def POLARSSL_RSA_NO_CRT
 *
 * Do not use the Chinese Remainder Theorem for the RSA private operation.
 *
 * Uncomment this macro to disable the use of CRT in RSA.
 *
 */
//#define POLARSSL_RSA_NO_CRT

/**
 * \def POLARSSL_SELF_TEST
 *
 * Enable the checkup functions (*_self_test).
 */
#define POLARSSL_SELF_TEST

/**
 * \def POLARSSL_SSL_ALL_ALERT_MESSAGES
 *
 * Enable sending of alert messages in case of encountered errors as per RFC.
 * If you choose not to send the alert messages, PolarSSL can still communicate
 * with other servers, only debugging of failures is harder.
 *
 * The advantage of not sending alert messages, is that no information is given
 * about reasons for failures thus preventing adversaries of gaining intel.
 *
 * Enable sending of all alert messages
 */
#define POLARSSL_SSL_ALERT_MESSAGES

/**
 * \def POLARSSL_SSL_DEBUG_ALL
 *
 * Enable the debug messages in SSL module for all issues.
 * Debug messages have been disabled in some places to prevent timing
 * attacks due to (unbalanced) debugging function calls.
 *
 * If you need all error reporting you should enable this during debugging,
 * but remove this for production servers that should log as well.
 *
 * Uncomment this macro to report all debug messages on errors introducing
 * a timing side-channel.
 *
 */
//#define POLARSSL_SSL_DEBUG_ALL

/**
 * \def POLARSSL_SSL_HW_RECORD_ACCEL
 *
 * Enable hooking functions in SSL module for hardware acceleration of
 * individual records.
 *
 * Uncomment this macro to enable hooking functions.
 */
//#define POLARSSL_SSL_HW_RECORD_ACCEL

/**
 * \def POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO
 *
 * Enable support for receiving and parsing SSLv2 Client Hello messages for the
 * SSL Server module (POLARSSL_SSL_SRV_C).
 *
 * Comment this macro to disable support for SSLv2 Client Hello messages.
 */
#define POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO

/**
 * \def POLARSSL_SSL_SRV_RESPECT_CLIENT_PREFERENCE
 *
 * Pick the ciphersuite according to the client's preferences rather than ours
 * in the SSL Server module (POLARSSL_SSL_SRV_C).
 *
 * Uncomment this macro to respect client's ciphersuite order
 */
//#define POLARSSL_SSL_SRV_RESPECT_CLIENT_PREFERENCE

/**
 * \def POLARSSL_SSL_MAX_FRAGMENT_LENGTH
 *
 * Enable support for RFC 6066 max_fragment_length extension in SSL.
 *
 * Comment this macro to disable support for the max_fragment_length extension
 */
#define POLARSSL_SSL_MAX_FRAGMENT_LENGTH

/**
 * \def POLARSSL_SSL_PROTO_SSL3
 *
 * Enable support for SSL 3.0.
 *
 * Requires: POLARSSL_MD5_C
 *           POLARSSL_SHA1_C
 *
 * Comment this macro to disable support for SSL 3.0
 */
#define POLARSSL_SSL_PROTO_SSL3

/**
 * \def POLARSSL_SSL_PROTO_TLS1
 *
 * Enable support for TLS 1.0.
 *
 * Requires: POLARSSL_MD5_C
 *           POLARSSL_SHA1_C
 *
 * Comment this macro to disable support for TLS 1.0
 */
#define POLARSSL_SSL_PROTO_TLS1

/**
 * \def POLARSSL_SSL_PROTO_TLS1_1
 *
 * Enable support for TLS 1.1.
 *
 * Requires: POLARSSL_MD5_C
 *           POLARSSL_SHA1_C
 *
 * Comment this macro to disable support for TLS 1.1
 */
#define POLARSSL_SSL_PROTO_TLS1_1

/**
 * \def POLARSSL_SSL_PROTO_TLS1_2
 *
 * Enable support for TLS 1.2.
 *
 * Requires: POLARSSL_SHA1_C or POLARSSL_SHA256_C or POLARSSL_SHA512_C
 *           (Depends on ciphersuites)
 *
 * Comment this macro to disable support for TLS 1.2
 */
#define POLARSSL_SSL_PROTO_TLS1_2

/**
 * \def POLARSSL_SSL_ALPN
 *
 * Enable support for Application Layer Protocol Negotiation.
 * draft-ietf-tls-applayerprotoneg-05
 *
 * Comment this macro to disable support for ALPN.
 */
#define POLARSSL_SSL_ALPN

/**
 * \def POLARSSL_SSL_SESSION_TICKETS
 *
 * Enable support for RFC 5077 session tickets in SSL.
 *
 * Requires: POLARSSL_AES_C
 *           POLARSSL_SHA256_C
 *           POLARSSL_CIPHER_MODE_CBC
 *
 * Comment this macro to disable support for SSL session tickets
 */
#define POLARSSL_SSL_SESSION_TICKETS

/**
 * \def POLARSSL_SSL_SERVER_NAME_INDICATION
 *
 * Enable support for RFC 6066 server name indication (SNI) in SSL.
 *
 * Comment this macro to disable support for server name indication in SSL
 */
#define POLARSSL_SSL_SERVER_NAME_INDICATION

/**
 * \def POLARSSL_SSL_TRUNCATED_HMAC
 *
 * Enable support for RFC 6066 truncated HMAC in SSL.
 *
 * Comment this macro to disable support for truncated HMAC in SSL
 */
#define POLARSSL_SSL_TRUNCATED_HMAC

/**
 * \def POLARSSL_SSL_SET_CURVES
 *
 * Enable ssl_set_curves().
 *
 * This is disabled by default since it breaks binary compatibility with the
 * 1.3.x line. If you choose to enable it, you will need to rebuild your
 * application against the new header files, relinking will not be enough.
 * It will be enabled by default, or no longer an soption, in the 1.4 branch.
 *
 * Uncomment to make ssl_set_curves() available.
 */
//#define POLARSSL_SSL_SET_CURVES

/**
 * \def POLARSSL_THREADING_ALT
 *
 * Provide your own alternate threading implementation.
 *
 * Requires: POLARSSL_THREADING_C
 *
 * Uncomment this to allow your own alternate threading implementation.
 */
//#define POLARSSL_THREADING_ALT

/**
 * \def POLARSSL_THREADING_PTHREAD
 *
 * Enable the pthread wrapper layer for the threading layer.
 *
 * Requires: POLARSSL_THREADING_C
 *
 * Uncomment this to enable pthread mutexes.
 */
//#define POLARSSL_THREADING_PTHREAD

/**
 * \def POLARSSL_VERSION_FEATURES
 *
 * Allow run-time checking of compile-time enabled features. Thus allowing users
 * to check at run-time if the library is for instance compiled with threading
 * support via version_check_feature().
 *
 * Requires: POLARSSL_VERSION_C
 *
 * Comment this to disable run-time checking and save ROM space
 */
#define POLARSSL_VERSION_FEATURES

/**
 * \def POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3
 *
 * If set, the X509 parser will not break-off when parsing an X509 certificate
 * and encountering an extension in a v1 or v2 certificate.
 *
 * Uncomment to prevent an error.
 */
//#define POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3

/**
 * \def POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
 *
 * If set, the X509 parser will not break-off when parsing an X509 certificate
 * and encountering an unknown critical extension.
 *
 * Uncomment to prevent an error.
 */
//#define POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION

/**
 * \def POLARSSL_X509_CHECK_KEY_USAGE
 *
 * Enable verification of the keyUsage extension (CA and leaf certificates).
 *
 * Disabling this avoids problems with mis-issued and/or misused
 * (intermediate) CA and leaf certificates.
 *
 * \warning Depending on your PKI use, disabling this can be a security risk!
 *
 * Comment to skip keyUsage checking for both CA and leaf certificates.
 */
#define POLARSSL_X509_CHECK_KEY_USAGE

/**
 * \def POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE
 *
 * Enable verification of the extendedKeyUsage extension (leaf certificates).
 *
 * Disabling this avoids problems with mis-issued and/or misused certificates.
 *
 * \warning Depending on your PKI use, disabling this can be a security risk!
 *
 * Comment to skip extendedKeyUsage checking for certificates.
 */
#define POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE

/**
 * \def POLARSSL_X509_RSASSA_PSS_SUPPORT
 *
 * Enable parsing and verification of X.509 certificates, CRLs and CSRS
 * signed with RSASSA-PSS (aka PKCS#1 v2.1).
 *
 * Comment this macro to disallow using RSASSA-PSS in certificates.
 */
#define POLARSSL_X509_RSASSA_PSS_SUPPORT

/**
 * \def POLARSSL_ZLIB_SUPPORT
 *
 * If set, the SSL/TLS module uses ZLIB to support compression and
 * decompression of packet data.
 *
 * \warning TLS-level compression MAY REDUCE SECURITY! See for example the
 * CRIME attack. Before enabling this soption, you should examine with care if
 * CRIME or similar exploits may be a applicable to your use case.
 *
 * Used in: library/ssl_tls.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * This feature requires zlib library and headers to be present.
 *
 * Uncomment to enable use of ZLIB
 */
//#define POLARSSL_ZLIB_SUPPORT
/* \} name SECTION: PolarSSL feature support */

/**
 * \name SECTION: PolarSSL modules
 *
 * This section enables or disables entire modules in PolarSSL
 * \{
 */

/**
 * \def POLARSSL_AESNI_C
 *
 * Enable AES-NI support on x86-64.
 *
 * Module:  library/aesni.c
 * Caller:  library/aes.c
 *
 * Requires: POLARSSL_HAVE_ASM
 *
 * This modules adds support for the AES-NI instructions on x86-64
 */
#define POLARSSL_AESNI_C

/**
 * \def POLARSSL_AES_C
 *
 * Enable the AES block cipher.
 *
 * Module:  library/aes.c
 * Caller:  library/ssl_tls.c
 *          library/pem.c
 *          library/ctr_drbg.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
 *      TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
 *      TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
 *      TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
 *      TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 *      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 *      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 *      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 *      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 *      TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 *      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
 *      TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
 *      TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
 *      TLS_DHE_PSK_WITH_AES_256_CBC_SHA
 *      TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
 *      TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
 *      TLS_DHE_PSK_WITH_AES_128_CBC_SHA
 *      TLS_RSA_WITH_AES_256_GCM_SHA384
 *      TLS_RSA_WITH_AES_256_CBC_SHA256
 *      TLS_RSA_WITH_AES_256_CBC_SHA
 *      TLS_RSA_WITH_AES_128_GCM_SHA256
 *      TLS_RSA_WITH_AES_128_CBC_SHA256
 *      TLS_RSA_WITH_AES_128_CBC_SHA
 *      TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
 *      TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_RSA_PSK_WITH_AES_256_CBC_SHA
 *      TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
 *      TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_RSA_PSK_WITH_AES_128_CBC_SHA
 *      TLS_PSK_WITH_AES_256_GCM_SHA384
 *      TLS_PSK_WITH_AES_256_CBC_SHA384
 *      TLS_PSK_WITH_AES_256_CBC_SHA
 *      TLS_PSK_WITH_AES_128_GCM_SHA256
 *      TLS_PSK_WITH_AES_128_CBC_SHA256
 *      TLS_PSK_WITH_AES_128_CBC_SHA
 *
 * PEM_PARSE uses AES for decrypting encrypted keys.
 */
#define POLARSSL_AES_C

/**
 * \def POLARSSL_ARC4_C
 *
 * Enable the ARCFOUR stream cipher.
 *
 * Module:  library/arc4.c
 * Caller:  library/ssl_tls.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDH_ECDSA_WITH_RC4_128_SHA
 *      TLS_ECDH_RSA_WITH_RC4_128_SHA
 *      TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
 *      TLS_ECDHE_RSA_WITH_RC4_128_SHA
 *      TLS_ECDHE_PSK_WITH_RC4_128_SHA
 *      TLS_DHE_PSK_WITH_RC4_128_SHA
 *      TLS_RSA_WITH_RC4_128_SHA
 *      TLS_RSA_WITH_RC4_128_MD5
 *      TLS_RSA_PSK_WITH_RC4_128_SHA
 *      TLS_PSK_WITH_RC4_128_SHA
 */
#define POLARSSL_ARC4_C

/**
 * \def POLARSSL_ASN1_PARSE_C
 *
 * Enable the generic ASN1 parser.
 *
 * Module:  library/asn1.c
 * Caller:  library/x509.c
 *          library/dhm.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/pkparse.c
 */
#define POLARSSL_ASN1_PARSE_C

/**
 * \def POLARSSL_ASN1_WRITE_C
 *
 * Enable the generic ASN1 writer.
 *
 * Module:  library/asn1write.c
 * Caller:  library/ecdsa.c
 *          library/pkwrite.c
 *          library/x509_create.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 */
#define POLARSSL_ASN1_WRITE_C

/**
 * \def POLARSSL_BASE64_C
 *
 * Enable the Base64 module.
 *
 * Module:  library/base64.c
 * Caller:  library/pem.c
 *
 * This module is required for PEM support (required by X.509).
 */
#define POLARSSL_BASE64_C

/**
 * \def POLARSSL_BIGNUM_C
 *
 * Enable the multi-precision integer library.
 *
 * Module:  library/bignum.c
 * Caller:  library/dhm.c
 *          library/ecp.c
 *          library/ecdsa.c
 *          library/rsa.c
 *          library/ssl_tls.c
 *
 * This module is required for RSA, DHM and ECC (ECDH, ECDSA) support.
 */
#define POLARSSL_BIGNUM_C

/**
 * \def POLARSSL_BLOWFISH_C
 *
 * Enable the Blowfish block cipher.
 *
 * Module:  library/blowfish.c
 */
#define POLARSSL_BLOWFISH_C

/**
 * \def POLARSSL_CAMELLIA_C
 *
 * Enable the Camellia block cipher.
 *
 * Module:  library/camellia.c
 * Caller:  library/ssl_tls.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
#define POLARSSL_CAMELLIA_C

/**
 * \def POLARSSL_CCM_C
 *
 * Enable the Counter with CBC-MAC (CCM) mode for 128-bit block cipher.
 *
 * Module:  library/ccm.c
 *
 * Requires: POLARSSL_AES_C or POLARSSL_CAMELLIA_C
 *
 * This module enables the AES-CCM ciphersuites, if other requisites are
 * enabled as well.
 */
#define POLARSSL_CCM_C

/**
 * \def POLARSSL_CERTS_C
 *
 * Enable the test certificates.
 *
 * Module:  library/certs.c
 * Caller:
 *
 * Requires: POLARSSL_PEM_PARSE_C
 *
 * This module is used for testing (ssl_client/server).
 */
#define POLARSSL_CERTS_C

/**
 * \def POLARSSL_CIPHER_C
 *
 * Enable the generic cipher layer.
 *
 * Module:  library/cipher.c
 * Caller:  library/ssl_tls.c
 *
 * Uncomment to enable generic cipher wrappers.
 */
#define POLARSSL_CIPHER_C

/**
 * \def POLARSSL_CTR_DRBG_C
 *
 * Enable the CTR_DRBG AES-256-based random generator.
 *
 * Module:  library/ctr_drbg.c
 * Caller:
 *
 * Requires: POLARSSL_AES_C
 *
 * This module provides the CTR_DRBG AES-256 random number generator.
 */
#define POLARSSL_CTR_DRBG_C

/**
 * \def POLARSSL_DEBUG_C
 *
 * Enable the debug functions.
 *
 * Module:  library/debug.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *
 * This module provides debugging functions.
 */
#define POLARSSL_DEBUG_C

/**
 * \def POLARSSL_DES_C
 *
 * Enable the DES block cipher.
 *
 * Module:  library/des.c
 * Caller:  library/pem.c
 *          library/ssl_tls.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
 *      TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
 *      TLS_RSA_WITH_3DES_EDE_CBC_SHA
 *      TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
 *      TLS_PSK_WITH_3DES_EDE_CBC_SHA
 *
 * PEM_PARSE uses DES/3DES for decrypting encrypted keys.
 */
//#define POLARSSL_DES_C

/**
 * \def POLARSSL_DHM_C
 *
 * Enable the Diffie-Hellman-Merkle module.
 *
 * Module:  library/dhm.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * This module is used by the following key exchanges:
 *      DHE-RSA, DHE-PSK
 */
//#define POLARSSL_DHM_C

/**
 * \def POLARSSL_ECDH_C
 *
 * Enable the elliptic curve Diffie-Hellman library.
 *
 * Module:  library/ecdh.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA, ECDHE-RSA, DHE-PSK
 *
 * Requires: POLARSSL_ECP_C
 */
//#define POLARSSL_ECDH_C

/**
 * \def POLARSSL_ECDSA_C
 *
 * Enable the elliptic curve DSA library.
 *
 * Module:  library/ecdsa.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA
 *
 * Requires: POLARSSL_ECP_C, POLARSSL_ASN1_WRITE_C, POLARSSL_ASN1_PARSE_C
 */
//#define POLARSSL_ECDSA_C

/**
 * \def POLARSSL_ECP_C
 *
 * Enable the elliptic curve over GF(p) library.
 *
 * Module:  library/ecp.c
 * Caller:  library/ecdh.c
 *          library/ecdsa.c
 *
 * Requires: POLARSSL_BIGNUM_C and at least one POLARSSL_ECP_DP_XXX_ENABLED
 */
//#define POLARSSL_ECP_C

/**
 * \def POLARSSL_ENTROPY_C
 *
 * Enable the platform-specific entropy code.
 *
 * Module:  library/entropy.c
 * Caller:
 *
 * Requires: POLARSSL_SHA512_C or POLARSSL_SHA256_C
 *
 * This module provides a generic entropy pool
 */
#define POLARSSL_ENTROPY_C

/**
 * \def POLARSSL_ERROR_C
 *
 * Enable error code to error string conversion.
 *
 * Module:  library/error.c
 * Caller:
 *
 * This module enables polarssl_strerror().
 */
#define POLARSSL_ERROR_C

/**
 * \def POLARSSL_GCM_C
 *
 * Enable the Galois/Counter Mode (GCM) for AES.
 *
 * Module:  library/gcm.c
 *
 * Requires: POLARSSL_AES_C or POLARSSL_CAMELLIA_C
 *
 * This module enables the AES-GCM and CAMELLIA-GCM ciphersuites, if other
 * requisites are enabled as well.
 */
#define POLARSSL_GCM_C

/**
 * \def POLARSSL_HAVEGE_C
 *
 * Enable the HAVEGE random generator.
 *
 * Warning: the HAVEGE random generator is not suitable for virtualized
 *          environments
 *
 * Warning: the HAVEGE random generator is dependent on timing and specific
 *          processor traits. It is therefore not advised to use HAVEGE as
 *          your applications primary random generator or primary entropy pool
 *          input. As a secondary input to your entropy pool, it IS able add
 *          the (limited) extra entropy it provides.
 *
 * Module:  library/havege.c
 * Caller:
 *
 * Requires: POLARSSL_TIMING_C
 *
 * Uncomment to enable the HAVEGE random generator.
 */
//#define POLARSSL_HAVEGE_C

/**
 * \def POLARSSL_HMAC_DRBG_C
 *
 * Enable the HMAC_DRBG random generator.
 *
 * Module:  library/hmac_drbg.c
 * Caller:
 *
 * Requires: POLARSSL_MD_C
 *
 * Uncomment to enable the HMAC_DRBG random number geerator.
 */
#define POLARSSL_HMAC_DRBG_C

/**
 * \def POLARSSL_MD_C
 *
 * Enable the generic message digest layer.
 *
 * Module:  library/md.c
 * Caller:
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define POLARSSL_MD_C

/**
 * \def POLARSSL_MD2_C
 *
 * Enable the MD2 hash algorithm.
 *
 * Module:  library/md2.c
 * Caller:
 *
 * Uncomment to enable support for (rare) MD2-signed X.509 certs.
 */
//#define POLARSSL_MD2_C

/**
 * \def POLARSSL_MD4_C
 *
 * Enable the MD4 hash algorithm.
 *
 * Module:  library/md4.c
 * Caller:
 *
 * Uncomment to enable support for (rare) MD4-signed X.509 certs.
 */
//#define POLARSSL_MD4_C

/**
 * \def POLARSSL_MD5_C
 *
 * Enable the MD5 hash algorithm.
 *
 * Module:  library/md5.c
 * Caller:  library/md.c
 *          library/pem.c
 *          library/ssl_tls.c
 *
 * This module is required for SSL/TLS and X.509.
 * PEM_PARSE uses MD5 for decrypting encrypted keys.
 */
#define POLARSSL_MD5_C

/**
 * \def POLARSSL_MEMORY_C
 * Deprecated since 1.3.5. Please use POLARSSL_PLATFORM_MEMORY instead.
 */
//#define POLARSSL_MEMORY_C

/**
 * \def POLARSSL_MEMORY_BUFFER_ALLOC_C
 *
 * Enable the buffer allocator implementation that makes use of a (stack)
 * based buffer to 'allocate' dynamic memory. (replaces malloc() and free()
 * calls)
 *
 * Module:  library/memory_buffer_alloc.c
 *
 * Requires: POLARSSL_PLATFORM_C
 *           POLARSSL_PLATFORM_MEMORY (to use it within PolarSSL)
 *
 * Enable this module to enable the buffer memory allocator.
 */
//#define POLARSSL_MEMORY_BUFFER_ALLOC_C

/**
 * \def POLARSSL_NET_C
 *
 * Enable the TCP/IP networking routines.
 *
 * Module:  library/net.c
 *
 * This module provides TCP/IP networking routines.
 */
#define POLARSSL_NET_C

/**
 * \def POLARSSL_OID_C
 *
 * Enable the OID database.
 *
 * Module:  library/oid.c
 * Caller:  library/asn1write.c
 *          library/pkcs5.c
 *          library/pkparse.c
 *          library/pkwrite.c
 *          library/rsa.c
 *          library/x509.c
 *          library/x509_create.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * This modules translates between OIDs and internal values.
 */
#define POLARSSL_OID_C

/**
 * \def POLARSSL_PADLOCK_C
 *
 * Enable VIA Padlock support on x86.
 *
 * Module:  library/padlock.c
 * Caller:  library/aes.c
 *
 * Requires: POLARSSL_HAVE_ASM
 *
 * This modules adds support for the VIA PadLock on x86.
 */
#define POLARSSL_PADLOCK_C

/**
 * \def POLARSSL_PBKDF2_C
 *
 * Enable PKCS#5 PBKDF2 key derivation function.
 * DEPRECATED: Use POLARSSL_PKCS5_C instead
 *
 * Module:  library/pbkdf2.c
 *
 * Requires: POLARSSL_PKCS5_C
 *
 * This module adds support for the PKCS#5 PBKDF2 key derivation function.
 */
#define POLARSSL_PBKDF2_C

/**
 * \def POLARSSL_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: POLARSSL_BASE64_C
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define POLARSSL_PEM_PARSE_C

/**
 * \def POLARSSL_PEM_WRITE_C
 *
 * Enable PEM encoding / writing.
 *
 * Module:  library/pem.c
 * Caller:  library/pkwrite.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * Requires: POLARSSL_BASE64_C
 *
 * This modules adds support for encoding / writing PEM files.
 */
#define POLARSSL_PEM_WRITE_C

/**
 * \def POLARSSL_PK_C
 *
 * Enable the generic public (asymetric) key layer.
 *
 * Module:  library/pk.c
 * Caller:  library/ssl_tls.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * Requires: POLARSSL_RSA_C or POLARSSL_ECP_C
 *
 * Uncomment to enable generic public key wrappers.
 */
#define POLARSSL_PK_C

/**
 * \def POLARSSL_PK_PARSE_C
 *
 * Enable the generic public (asymetric) key parser.
 *
 * Module:  library/pkparse.c
 * Caller:  library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: POLARSSL_PK_C
 *
 * Uncomment to enable generic public key parse functions.
 */
#define POLARSSL_PK_PARSE_C

/**
 * \def POLARSSL_PK_WRITE_C
 *
 * Enable the generic public (asymetric) key writer.
 *
 * Module:  library/pkwrite.c
 * Caller:  library/x509write.c
 *
 * Requires: POLARSSL_PK_C
 *
 * Uncomment to enable generic public key write functions.
 */
#define POLARSSL_PK_WRITE_C

/**
 * \def POLARSSL_PKCS5_C
 *
 * Enable PKCS#5 functions.
 *
 * Module:  library/pkcs5.c
 *
 * Requires: POLARSSL_MD_C
 *
 * This module adds support for the PKCS#5 functions.
 */
#define POLARSSL_PKCS5_C

/**
 * \def POLARSSL_PKCS11_C
 *
 * Enable wrapper for PKCS#11 smartcard support.
 *
 * Module:  library/pkcs11.c
 * Caller:  library/pk.c
 *
 * Requires: POLARSSL_PK_C
 *
 * This module enables SSL/TLS PKCS #11 smartcard support.
 * Requires the presence of the PKCS#11 helper library (libpkcs11-helper)
 */
//#define POLARSSL_PKCS11_C

/**
 * \def POLARSSL_PKCS12_C
 *
 * Enable PKCS#12 PBE functions.
 * Adds algorithms for parsing PKCS#8 encrypted private keys
 *
 * Module:  library/pkcs12.c
 * Caller:  library/pkparse.c
 *
 * Requires: POLARSSL_ASN1_PARSE_C, POLARSSL_CIPHER_C, POLARSSL_MD_C
 * Can use:  POLARSSL_ARC4_C
 *
 * This module enables PKCS#12 functions.
 */
#define POLARSSL_PKCS12_C

/**
 * \def POLARSSL_PLATFORM_C
 *
 * Enable the platform abstraction layer that allows you to re-assign
 * functions like malloc(), free(), printf(), fprintf()
 *
 * Module:  library/platform.c
 * Caller:  Most other .c files
 *
 * This module enables abstraction of common (libc) functions.
 */
#define POLARSSL_PLATFORM_C

/**
 * \def POLARSSL_RIPEMD160_C
 *
 * Enable the RIPEMD-160 hash algorithm.
 *
 * Module:  library/ripemd160.c
 * Caller:  library/md.c
 *
 */
#define POLARSSL_RIPEMD160_C

/**
 * \def POLARSSL_RSA_C
 *
 * Enable the RSA public-key cryptosystem.
 *
 * Module:  library/rsa.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *          library/x509.c
 *
 * This module is used by the following key exchanges:
 *      RSA, DHE-RSA, ECDHE-RSA, RSA-PSK
 *
 * Requires: POLARSSL_BIGNUM_C, POLARSSL_OID_C
 */
#define POLARSSL_RSA_C

/**
 * \def POLARSSL_SHA1_C
 *
 * Enable the SHA1 cryptographic hash algorithm.
 *
 * Module:  library/sha1.c
 * Caller:  library/md.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *          library/x509write_crt.c
 *
 * This module is required for SSL/TLS and SHA1-signed certificates.
 */
#define POLARSSL_SHA1_C

/**
 * \def POLARSSL_SHA256_C
 *
 * Enable the SHA-224 and SHA-256 cryptographic hash algorithms.
 * (Used to be POLARSSL_SHA2_C)
 *
 * Module:  library/sha256.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *
 * This module adds support for SHA-224 and SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define POLARSSL_SHA256_C

/**
 * \def POLARSSL_SHA512_C
 *
 * Enable the SHA-384 and SHA-512 cryptographic hash algorithms.
 * (Used to be POLARSSL_SHA4_C)
 *
 * Module:  library/sha512.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * This module adds support for SHA-384 and SHA-512.
 */
#define POLARSSL_SHA512_C

/**
 * \def POLARSSL_SSL_CACHE_C
 *
 * Enable simple SSL cache implementation.
 *
 * Module:  library/ssl_cache.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_CACHE_C
 */
#define POLARSSL_SSL_CACHE_C

/**
 * \def POLARSSL_SSL_CLI_C
 *
 * Enable the SSL/TLS client code.
 *
 * Module:  library/ssl_cli.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_TLS_C
 *
 * This module is required for SSL/TLS client support.
 */
#define POLARSSL_SSL_CLI_C

/**
 * \def POLARSSL_SSL_SRV_C
 *
 * Enable the SSL/TLS server code.
 *
 * Module:  library/ssl_srv.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_TLS_C
 *
 * This module is required for SSL/TLS server support.
 */
#define POLARSSL_SSL_SRV_C

/**
 * \def POLARSSL_SSL_TLS_C
 *
 * Enable the generic SSL/TLS code.
 *
 * Module:  library/ssl_tls.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * Requires: POLARSSL_CIPHER_C, POLARSSL_MD_C
 *           and at least one of the POLARSSL_SSL_PROTO_* defines
 *
 * This module is required for SSL/TLS.
 */
#define POLARSSL_SSL_TLS_C

/**
 * \def POLARSSL_THREADING_C
 *
 * Enable the threading abstraction layer.
 * By default PolarSSL assumes it is used in a non-threaded environment or that
 * contexts are not shared between threads. If you do intend to use contexts
 * between threads, you will need to enable this layer to prevent race
 * conditions.
 *
 * Module:  library/threading.c
 *
 * This allows different threading implementations (self-implemented or
 * provided).
 *
 * You will have to enable either POLARSSL_THREADING_ALT or
 * POLARSSL_THREADING_PTHREAD.
 *
 * Enable this layer to allow use of mutexes within PolarSSL
 */
//#define POLARSSL_THREADING_C

/**
 * \def POLARSSL_TIMING_C
 *
 * Enable the portable timing interface.
 *
 * Module:  library/timing.c
 * Caller:  library/havege.c
 *
 * This module is used by the HAVEGE random number generator.
 */
#define POLARSSL_TIMING_C

/**
 * \def POLARSSL_VERSION_C
 *
 * Enable run-time version information.
 *
 * Module:  library/version.c
 *
 * This module provides run-time version information.
 */
#define POLARSSL_VERSION_C

/**
 * \def POLARSSL_X509_USE_C
 *
 * Enable X.509 core for using certificates.
 *
 * Module:  library/x509.c
 * Caller:  library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: POLARSSL_ASN1_PARSE_C, POLARSSL_BIGNUM_C, POLARSSL_OID_C,
 *           POLARSSL_PK_PARSE_C
 *
 * This module is required for the X.509 parsing modules.
 */
#define POLARSSL_X509_USE_C

/**
 * \def POLARSSL_X509_CRT_PARSE_C
 *
 * Enable X.509 certificate parsing.
 *
 * Module:  library/x509_crt.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *
 * Requires: POLARSSL_X509_USE_C
 *
 * This module is required for X.509 certificate parsing.
 */
#define POLARSSL_X509_CRT_PARSE_C

/**
 * \def POLARSSL_X509_CRL_PARSE_C
 *
 * Enable X.509 CRL parsing.
 *
 * Module:  library/x509_crl.c
 * Caller:  library/x509_crt.c
 *
 * Requires: POLARSSL_X509_USE_C
 *
 * This module is required for X.509 CRL parsing.
 */
#define POLARSSL_X509_CRL_PARSE_C

/**
 * \def POLARSSL_X509_CSR_PARSE_C
 *
 * Enable X.509 Certificate Signing Request (CSR) parsing.
 *
 * Module:  library/x509_csr.c
 * Caller:  library/x509_crt_write.c
 *
 * Requires: POLARSSL_X509_USE_C
 *
 * This module is used for reading X.509 certificate request.
 */
#define POLARSSL_X509_CSR_PARSE_C

/**
 * \def POLARSSL_X509_CREATE_C
 *
 * Enable X.509 core for creating certificates.
 *
 * Module:  library/x509_create.c
 *
 * Requires: POLARSSL_BIGNUM_C, POLARSSL_OID_C, POLARSSL_PK_WRITE_C
 *
 * This module is the basis for creating X.509 certificates and CSRs.
 */
#define POLARSSL_X509_CREATE_C

/**
 * \def POLARSSL_X509_CRT_WRITE_C
 *
 * Enable creating X.509 certificates.
 *
 * Module:  library/x509_crt_write.c
 *
 * Requires: POLARSSL_CREATE_C
 *
 * This module is required for X.509 certificate creation.
 */
#define POLARSSL_X509_CRT_WRITE_C

/**
 * \def POLARSSL_X509_CSR_WRITE_C
 *
 * Enable creating X.509 Certificate Signing Requests (CSR).
 *
 * Module:  library/x509_csr_write.c
 *
 * Requires: POLARSSL_CREATE_C
 *
 * This module is required for X.509 certificate request writing.
 */
#define POLARSSL_X509_CSR_WRITE_C

/**
 * \def POLARSSL_XTEA_C
 *
 * Enable the XTEA block cipher.
 *
 * Module:  library/xtea.c
 * Caller:
 */
#define POLARSSL_XTEA_C

/* \} name SECTION: PolarSSL modules */

/**
 * \name SECTION: Module configuration options
 *
 * This section allows for the setting of module specific sizes and
 * configuration options. The default values are already present in the
 * relevant header files and should suffice for the regular use cases.
 *
 * Our advice is to enable options and change their values here
 * only if you have a good reason and know the consequences.
 *
 * Please check the respective header file for documentation on these
 * parameters (to prevent duplicate documentation).
 * \{
 */

/* MPI / BIGNUM options */
//#define POLARSSL_MPI_WINDOW_SIZE            6 /**< Maximum windows size used. */
//#define POLARSSL_MPI_MAX_SIZE            1024 /**< Maximum number of bytes for usable MPIs. */

/* CTR_DRBG options */
//#define CTR_DRBG_ENTROPY_LEN               48 /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
//#define CTR_DRBG_RESEED_INTERVAL        10000 /**< Interval before reseed is performed by default */
//#define CTR_DRBG_MAX_INPUT                256 /**< Maximum number of additional input bytes */
//#define CTR_DRBG_MAX_REQUEST             1024 /**< Maximum number of requested bytes per call */
//#define CTR_DRBG_MAX_SEED_INPUT           384 /**< Maximum size of (re)seed buffer */

/* HMAC_DRBG options */
//#define POLARSSL_HMAC_DRBG_RESEED_INTERVAL   10000 /**< Interval before reseed is performed by default */
//#define POLARSSL_HMAC_DRBG_MAX_INPUT           256 /**< Maximum number of additional input bytes */
//#define POLARSSL_HMAC_DRBG_MAX_REQUEST        1024 /**< Maximum number of requested bytes per call */
//#define POLARSSL_HMAC_DRBG_MAX_SEED_INPUT      384 /**< Maximum size of (re)seed buffer */

/* ECP options */
//#define POLARSSL_ECP_MAX_BITS             521 /**< Maximum bit size of groups */
//#define POLARSSL_ECP_WINDOW_SIZE            6 /**< Maximum window size used */
//#define POLARSSL_ECP_FIXED_POINT_OPTIM      1 /**< Enable fixed-point speed-up */

/* Entropy options */
//#define ENTROPY_MAX_SOURCES                20 /**< Maximum number of sources supported */
//#define ENTROPY_MAX_GATHER                128 /**< Maximum amount requested from entropy sources */

/* Memory buffer allocator options */
//#define POLARSSL_MEMORY_ALIGN_MULTIPLE      4 /**< Align on multiples of this value */

/* Platform options */
//#define POLARSSL_PLATFORM_STD_MEM_HDR <stdlib.h> /**< Header to include if POLARSSL_PLATFORM_NO_STD_FUNCTIONS is defined. Don't define if no header is needed. */
//#define POLARSSL_PLATFORM_STD_MALLOC   malloc /**< Default allocator to use, can be undefined */
//#define POLARSSL_PLATFORM_STD_FREE       free /**< Default free to use, can be undefined */
//#define POLARSSL_PLATFORM_STD_PRINTF   printf /**< Default printf to use, can be undefined */
//#define POLARSSL_PLATFORM_STD_FPRINTF fprintf /**< Default fprintf to use, can be undefined */

/* SSL Cache options */
//#define SSL_CACHE_DEFAULT_TIMEOUT       86400 /**< 1 day  */
//#define SSL_CACHE_DEFAULT_MAX_ENTRIES      50 /**< Maximum entries in cache */

/* SSL options */
//#define SSL_MAX_CONTENT_LEN             16384 /**< Size of the input / output buffer */
//#define SSL_DEFAULT_TICKET_LIFETIME     86400 /**< Lifetime of session tickets (if enabled) */
//#define POLARSSL_PSK_MAX_LEN               32 /**< Max size of TLS pre-shared keys, in bytes (default 256 bits) */

/**
 * Complete list of ciphersuites to use, in order of preference.
 *
 * \warning No dependency checking is done on that field! This soption can only
 * be used to restrict the set of available ciphersuites. It is your
 * responsibility to make sure the needed modules are active.
 *
 * Use this to save a few hundred bytes of ROM (default ordering of all
 * available ciphersuites) and a few to a few hundred bytes of RAM.
 *
 * The value below is only an example, not the default.
 */
//#define SSL_CIPHERSUITES TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

/* Debug options */
//#define POLARSSL_DEBUG_DFL_MODE POLARSSL_DEBUG_LOG_FULL /**< Default log: Full or Raw */

/* \} name SECTION: Module configuration options */

//#include "check_config.h"

#endif /* POLARSSL_CONFIG_H */
/**
 * \file check_config.h
 *
 * \brief Consistency checks for configuration options
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * It is recommended to include this file from your config.h
 * in order to catch dependency issues early.
 */

#ifndef POLARSSL_CHECK_CONFIG_H
#define POLARSSL_CHECK_CONFIG_H

#if defined(POLARSSL_AESNI_C) && !defined(POLARSSL_HAVE_ASM)
#error "POLARSSL_AESNI_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_CERTS_C) && !defined(POLARSSL_PEM_PARSE_C)
#error "POLARSSL_CERTS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_CTR_DRBG_C) && !defined(POLARSSL_AES_C)
#error "POLARSSL_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_DHM_C) && !defined(POLARSSL_BIGNUM_C)
#error "POLARSSL_DHM_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDH_C) && !defined(POLARSSL_ECP_C)
#error "POLARSSL_ECDH_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDSA_C) &&            \
    ( !defined(POLARSSL_ECP_C) ||           \
      !defined(POLARSSL_ASN1_PARSE_C) ||    \
      !defined(POLARSSL_ASN1_WRITE_C) )
#error "POLARSSL_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDSA_DETERMINISTIC) && !defined(POLARSSL_HMAC_DRBG_C)
#error "POLARSSL_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECP_C) && ( !defined(POLARSSL_BIGNUM_C) || (   \
    !defined(POLARSSL_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP256K1_ENABLED) ) )
#error "POLARSSL_ECP_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ENTROPY_C) && (!defined(POLARSSL_SHA512_C) &&      \
                                    !defined(POLARSSL_SHA256_C))
#error "POLARSSL_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(POLARSSL_ENTROPY_C) && defined(POLARSSL_SHA512_C) &&         \
    defined(CTR_DRBG_ENTROPY_LEN) && (CTR_DRBG_ENTROPY_LEN > 64)
#error "CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(POLARSSL_ENTROPY_C) &&                                            \
    ( !defined(POLARSSL_SHA512_C) || defined(POLARSSL_ENTROPY_FORCE_SHA256) ) \
    && defined(CTR_DRBG_ENTROPY_LEN) && (CTR_DRBG_ENTROPY_LEN > 32)
#error "CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(POLARSSL_ENTROPY_C) && \
    defined(POLARSSL_ENTROPY_FORCE_SHA256) && !defined(POLARSSL_SHA256_C)
#error "POLARSSL_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_GCM_C) && (                                        \
        !defined(POLARSSL_AES_C) && !defined(POLARSSL_CAMELLIA_C) )
#error "POLARSSL_GCM_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_HAVEGE_C) && !defined(POLARSSL_TIMING_C)
#error "POLARSSL_HAVEGE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_HMAC_DRBG) && !defined(POLARSSL_MD_C)
#error "POLARSSL_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_X509_CRT_PARSE_C) )
#error "POLARSSL_KEY_EXCHANGE_ECDH_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDH_RSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_X509_CRT_PARSE_C) )
#error "POLARSSL_KEY_EXCHANGE_ECDH_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(POLARSSL_DHM_C)
#error "POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(POLARSSL_ECDH_C)
#error "POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(POLARSSL_DHM_C) || !defined(POLARSSL_RSA_C) ||           \
      !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_RSA_C) ||          \
      !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_ECDSA_C) ||          \
      !defined(POLARSSL_X509_CRT_PARSE_C) )
#error "POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_X509_CRT_PARSE_C) ||\
      !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_X509_CRT_PARSE_C) ||\
      !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(POLARSSL_PLATFORM_C) || !defined(POLARSSL_PLATFORM_MEMORY) )
#error "POLARSSL_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PADLOCK_C) && !defined(POLARSSL_HAVE_ASM)
#error "POLARSSL_PADLOCK_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PBKDF2_C) && !defined(POLARSSL_MD_C)
#error "POLARSSL_PBKDF2_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PEM_PARSE_C) && !defined(POLARSSL_BASE64_C)
#error "POLARSSL_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PEM_WRITE_C) && !defined(POLARSSL_BASE64_C)
#error "POLARSSL_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PK_PARSE_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PK_WRITE_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PKCS11_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PKCS11_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_RSA_C) && ( !defined(POLARSSL_BIGNUM_C) ||         \
    !defined(POLARSSL_OID_C) )
#error "POLARSSL_RSA_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_RSASSA_PSS_SUPPORT) &&                        \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_PKCS1_V21) )
#error "POLARSSL_X509_RSASSA_PSS_SUPPORT defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_SSL3) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_SSL3 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_TLS1 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1_1) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_TLS1_1 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1_2) && ( !defined(POLARSSL_SHA1_C) &&     \
    !defined(POLARSSL_SHA256_C) && !defined(POLARSSL_SHA512_C) )
#error "POLARSSL_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_CLI_C) && !defined(POLARSSL_SSL_TLS_C)
#error "POLARSSL_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_TLS_C) && ( !defined(POLARSSL_CIPHER_C) ||     \
    !defined(POLARSSL_MD_C) )
#error "POLARSSL_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_SRV_C) && !defined(POLARSSL_SSL_TLS_C)
#error "POLARSSL_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (!defined(POLARSSL_SSL_PROTO_SSL3) && \
    !defined(POLARSSL_SSL_PROTO_TLS1) && !defined(POLARSSL_SSL_PROTO_TLS1_1) && \
    !defined(POLARSSL_SSL_PROTO_TLS1_2))
#error "POLARSSL_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_SSL3) && \
    defined(POLARSSL_SSL_PROTO_TLS1_1) && !defined(POLARSSL_SSL_PROTO_TLS1))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_TLS1) && \
    defined(POLARSSL_SSL_PROTO_TLS1_2) && !defined(POLARSSL_SSL_PROTO_TLS1_1))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_SSL3) && \
    defined(POLARSSL_SSL_PROTO_TLS1_2) && (!defined(POLARSSL_SSL_PROTO_TLS1) || \
    !defined(POLARSSL_SSL_PROTO_TLS1_1)))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_SESSION_TICKETS) && defined(POLARSSL_SSL_TLS_C) && \
    ( !defined(POLARSSL_AES_C) || !defined(POLARSSL_SHA256_C) ||            \
      !defined(POLARSSL_CIPHER_MODE_CBC) )
#error "POLARSSL_SSL_SESSION_TICKETS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION) && \
        !defined(POLARSSL_X509_CRT_PARSE_C)
#error "POLARSSL_SSL_SERVER_NAME_INDICATION defined, but not all prerequisites"
#endif

#if defined(POLARSSL_THREADING_PTHREAD)
#if !defined(POLARSSL_THREADING_C) || defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define POLARSSL_THREADING_IMPL
#endif

#if defined(POLARSSL_THREADING_ALT)
#if !defined(POLARSSL_THREADING_C) || defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_ALT defined, but not all prerequisites"
#endif
#define POLARSSL_THREADING_IMPL
#endif

#if defined(POLARSSL_THREADING_C) && !defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_C defined, single threading implementation required"
#endif
#undef POLARSSL_THREADING_IMPL

#if defined(POLARSSL_VERSION_FEATURES) && !defined(POLARSSL_VERSION_C)
#error "POLARSSL_VERSION_FEATURES defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_USE_C) && ( !defined(POLARSSL_BIGNUM_C) ||  \
    !defined(POLARSSL_OID_C) || !defined(POLARSSL_ASN1_PARSE_C) ||      \
    !defined(POLARSSL_PK_PARSE_C) )
#error "POLARSSL_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CREATE_C) && ( !defined(POLARSSL_BIGNUM_C) ||  \
    !defined(POLARSSL_OID_C) || !defined(POLARSSL_ASN1_WRITE_C) ||       \
    !defined(POLARSSL_PK_WRITE_C) )
#error "POLARSSL_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRT_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRL_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CSR_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRT_WRITE_C) && ( !defined(POLARSSL_X509_CREATE_C) )
#error "POLARSSL_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CSR_WRITE_C) && ( !defined(POLARSSL_X509_CREATE_C) )
#error "POLARSSL_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#endif /* POLARSSL_CHECK_CONFIG_H */
/**
 * \file aes.h
 *
 * \brief AES block cipher
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_AES_H
#define POLARSSL_AES_H

//#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
//#else
//#include POLARSSL_CONFIG_FILE
//#endif

#include <string.h>

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

/* padlock.c and aesni.c rely on these values! */
#define AES_ENCRYPT     1
#define AES_DECRYPT     0

#define POLARSSL_ERR_AES_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define POLARSSL_ERR_AES_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */

#if !defined(POLARSSL_AES_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AES context structure
 *
 * \note           buf is able to hold 32 extra bytes, which can be used:
 *                 - for alignment purposes if VIA padlock is used, and/or
 *                 - to simplify key expansion in the 256-bit case by
 *                 generating an extra round key
 */
typedef struct
{
    int nr;                     /*!<  number of rounds  */
    uint32_t *rk;               /*!<  AES round keys    */
    uint32_t buf[68];           /*!<  unaligned data    */
}
aes_context;

/**
 * \brief          Initialize AES context
 *
 * \param ctx      AES context to be initialized
 */
static void aes_init( aes_context *ctx );

/**
 * \brief          Clear AES context
 *
 * \param ctx      AES context to be cleared
 */
static void aes_free( aes_context *ctx );

/**
 * \brief          AES key schedule (encryption)
 *
 * \param ctx      AES context to be initialized
 * \param key      encryption key
 * \param keysize  must be 128, 192 or 256
 *
 * \return         0 if successful, or POLARSSL_ERR_AES_INVALID_KEY_LENGTH
 */
static int aes_setkey_enc( aes_context *ctx, const unsigned char *key,
                    unsigned int keysize );

/**
 * \brief          AES key schedule (decryption)
 *
 * \param ctx      AES context to be initialized
 * \param key      decryption key
 * \param keysize  must be 128, 192 or 256
 *
 * \return         0 if successful, or POLARSSL_ERR_AES_INVALID_KEY_LENGTH
 */
static int aes_setkey_dec( aes_context *ctx, const unsigned char *key,
                    unsigned int keysize );

/**
 * \brief          AES-ECB block encryption/decryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful
 */
static int aes_crypt_ecb( aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] );

#if defined(POLARSSL_CIPHER_MODE_CBC)
/**
 * \brief          AES-CBC buffer encryption/decryption
 *                 Length should be a multiple of the block
 *                 size (16 bytes)
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or POLARSSL_ERR_AES_INVALID_INPUT_LENGTH
 */
static int aes_crypt_cbc( aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /* POLARSSL_CIPHER_MODE_CBC */

#if defined(POLARSSL_CIPHER_MODE_CFB)
/**
 * \brief          AES-CFB128 buffer encryption/decryption.
 *
 * Note: Due to the nature of CFB you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * aes_setkey_enc() for both AES_ENCRYPT and AES_DECRYPT.
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param length   length of the input data
 * \param iv_off   offset in IV (updated after use)
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful
 */
static int aes_crypt_cfb128( aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output );

/**
 * \brief          AES-CFB8 buffer encryption/decryption.
 *
 * Note: Due to the nature of CFB you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * aes_setkey_enc() for both AES_ENCRYPT and AES_DECRYPT.
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful
 */
static int aes_crypt_cfb8( aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /*POLARSSL_CIPHER_MODE_CFB */

#if defined(POLARSSL_CIPHER_MODE_CTR)
/**
 * \brief               AES-CTR buffer encryption/decryption
 *
 * Warning: You have to keep the maximum use of your counter in mind!
 *
 * Note: Due to the nature of CTR you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * aes_setkey_enc() for both AES_ENCRYPT and AES_DECRYPT.
 *
 * \param ctx           AES context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 128-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return         0 if successful
 */
static int aes_crypt_ctr( aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output );
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef __cplusplus
}
#endif

#else  /* POLARSSL_AES_ALT */
//#include "aes_alt.h"
#endif /* POLARSSL_AES_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
static int aes_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* aes.h */
/**
 * \file padlock.h
 *
 * \brief VIA PadLock ACE for HW encryption/decryption supported by some
 *        processors
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_PADLOCK_H
#define POLARSSL_PADLOCK_H

//#include "aes.h"

#define POLARSSL_ERR_PADLOCK_DATA_MISALIGNED               -0x0030  /**< Input data should be aligned. */

#if defined(POLARSSL_HAVE_ASM) && defined(__GNUC__) && defined(__i386__)

#ifndef POLARSSL_HAVE_X86
#define POLARSSL_HAVE_X86
#endif

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
typedef INT32 int32_t;
#else
#include <inttypes.h>
#endif


#define PADLOCK_RNG 0x000C
#define PADLOCK_ACE 0x00C0
#define PADLOCK_PHE 0x0C00
#define PADLOCK_PMM 0x3000

#define PADLOCK_ALIGN16(x) (uint32_t *) (16 + ((int32_t) x & ~15))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          PadLock detection routine
 *
 * \param feature  The feature to detect
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
static int padlock_supports( int feature );

/**
 * \brief          PadLock AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if success, 1 if operation failed
 */
static int padlock_xcryptecb( aes_context *ctx,
                       int mode,
                       const unsigned char input[16],
                       unsigned char output[16] );

/**
 * \brief          PadLock AES-CBC buffer en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if success, 1 if operation failed
 */
static int padlock_xcryptcbc( aes_context *ctx,
                       int mode,
                       size_t length,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif /* HAVE_X86  */

#endif /* padlock.h */
/**
 * \file aesni.h
 *
 * \brief AES-NI for hardware AES acceleration on some Intel processors
 *
 *  Copyright (C) 2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_AESNI_H
#define POLARSSL_AESNI_H

//#include "aes.h"

#define POLARSSL_AESNI_AES      0x02000000u
#define POLARSSL_AESNI_CLMUL    0x00000002u

#if defined(POLARSSL_HAVE_ASM) && defined(__GNUC__) &&  \
    ( defined(__amd64__) || defined(__x86_64__) )   &&  \
    ! defined(POLARSSL_HAVE_X86_64)
#define POLARSSL_HAVE_X86_64
#endif

#if defined(POLARSSL_HAVE_X86_64)

/**
 * \brief          AES-NI features detection routine
 *
 * \param what     The feature to detect
 *                 (POLARSSL_AESNI_AES or POLARSSL_AESNI_CLMUL)
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
static int aesni_supports( unsigned int what );

/**
 * \brief          AES-NI AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
static int aesni_crypt_ecb( aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] );

/**
 * \brief          GCM multiplication: c = a * b in GF(2^128)
 *
 * \param c        Result
 * \param a        First operand
 * \param b        Second operand
 *
 * \note           Both operands and result are bit strings interpreted as
 *                 elements of GF(2^128) as per the GCM spec.
 */
static void aesni_gcm_mult( unsigned char c[16],
                     const unsigned char a[16],
                     const unsigned char b[16] );

/**
 * \brief           Compute decryption round keys from encryption round keys
 *
 * \param invkey    Round keys for the equivalent inverse cipher
 * \param fwdkey    Original round keys (for encryption)
 * \param nr        Number of rounds (that is, number of round keys minus one)
 */
static void aesni_inverse_key( unsigned char *invkey,
                        const unsigned char *fwdkey, int nr );

/**
 * \brief           Perform key expansion (for encryption)
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 * \param bits      Key size in bits (must be 128, 192 or 256)
 *
 * \return          0 if successful, or POLARSSL_ERR_AES_INVALID_KEY_LENGTH
 */
static int aesni_setkey_enc( unsigned char *rk,
                      const unsigned char *key,
                      size_t bits );

#endif /* POLARSSL_HAVE_X86_64 */

#endif /* POLARSSL_AESNI_H */
/**
 * \file platform.h
 *
 * \brief PolarSSL Platform abstraction layer
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_PLATFORM_H
#define POLARSSL_PLATFORM_H

//#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
//#else
//#include POLARSSL_CONFIG_FILE
//#endif

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(POLARSSL_PLATFORM_NO_STD_FUNCTIONS)
#include <stdlib.h>
#if !defined(POLARSSL_PLATFORM_STD_PRINTF)
#define POLARSSL_PLATFORM_STD_PRINTF   printf /**< Default printf to use  */
#endif
#if !defined(POLARSSL_PLATFORM_STD_FPRINTF)
#define POLARSSL_PLATFORM_STD_FPRINTF fprintf /**< Default fprintf to use */
#endif
#if !defined(POLARSSL_PLATFORM_STD_MALLOC)
#define POLARSSL_PLATFORM_STD_MALLOC   malloc /**< Default allocator to use */
#endif
#if !defined(POLARSSL_PLATFORM_STD_FREE)
#define POLARSSL_PLATFORM_STD_FREE       free /**< Default free to use */
#endif
#else /* POLARSSL_PLATFORM_NO_STD_FUNCTIONS */
#if defined(POLARSSL_PLATFORM_STD_MEM_HDR)
//#include POLARSSL_PLATFORM_STD_MEM_HDR
#endif
#endif /* POLARSSL_PLATFORM_NO_STD_FUNCTIONS */

/* \} name SECTION: Module settings */

/*
 * The function pointers for malloc and free
 */
#if defined(POLARSSL_PLATFORM_MEMORY)
extern void * (*polarssl_malloc)( size_t len );
extern void (*polarssl_free)( void *ptr );

/**
 * \brief   Set your own memory implementation function pointers
 *
 * \param malloc_func   the malloc function implementation
 * \param free_func     the free function implementation
 *
 * \return              0 if successful
 */
static int platform_set_malloc_free( void * (*malloc_func)( size_t ),
                              void (*free_func)( void * ) );
#else /* POLARSSL_PLATFORM_ENTROPY */
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif /* POLARSSL_PLATFORM_ENTROPY */

/*
 * The function pointers for printf
 */
#if defined(POLARSSL_PLATFORM_PRINTF_ALT)
extern int (*polarssl_printf)( const char *format, ... );

/**
 * \brief   Set your own printf function pointer
 *
 * \param printf_func   the printf function implementation
 *
 * \return              0
 */
static int platform_set_printf( int (*printf_func)( const char *, ... ) );
#else /* POLARSSL_PLATFORM_PRINTF_ALT */
#define polarssl_printf     printf
#endif /* POLARSSL_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for fprintf
 */
#if defined(POLARSSL_PLATFORM_FPRINTF_ALT)
extern int (*polarssl_fprintf)( FILE *stream, const char *format, ... );

static int platform_set_fprintf( int (*fprintf_func)( FILE *stream, const char *,
                                               ... ) );
#else
#define polarssl_fprintf    fprintf
#endif

#ifdef __cplusplus
}
#endif

#endif /* platform.h */
/**
 * \file bn_mul.h
 *
 * \brief  Multi-precision integer library
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *      Multiply source vector [s] with b, add result
 *       to destination vector [d] and set carry c.
 *
 *      Currently supports:
 *
 *         . IA-32 (386+)         . AMD64 / EM64T
 *         . IA-32 (SSE2)         . Motorola 68000
 *         . PowerPC, 32-bit      . MicroBlaze
 *         . PowerPC, 64-bit      . TriCore
 *         . SPARC v8             . ARM v3+
 *         . Alpha                . MIPS32
 *         . C, longlong          . C, generic
 */
#ifndef POLARSSL_BN_MUL_H
#define POLARSSL_BN_MUL_H

//#include "bignum.h"

#if defined(POLARSSL_HAVE_ASM)

#if defined(__GNUC__)
#if defined(__i386__)

#define MULADDC_INIT                        \
    asm(                                    \
        "movl   %%ebx, %0           \n\t"   \
        "movl   %5, %%esi           \n\t"   \
        "movl   %6, %%edi           \n\t"   \
        "movl   %7, %%ecx           \n\t"   \
        "movl   %8, %%ebx           \n\t"

#define MULADDC_CORE                        \
        "lodsl                      \n\t"   \
        "mull   %%ebx               \n\t"   \
        "addl   %%ecx,   %%eax      \n\t"   \
        "adcl   $0,      %%edx      \n\t"   \
        "addl   (%%edi), %%eax      \n\t"   \
        "adcl   $0,      %%edx      \n\t"   \
        "movl   %%edx,   %%ecx      \n\t"   \
        "stosl                      \n\t"

#if defined(POLARSSL_HAVE_SSE2)

#define MULADDC_HUIT                            \
        "movd     %%ecx,     %%mm1      \n\t"   \
        "movd     %%ebx,     %%mm0      \n\t"   \
        "movd     (%%edi),   %%mm3      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     (%%esi),   %%mm2      \n\t"   \
        "pmuludq  %%mm0,     %%mm2      \n\t"   \
        "movd     4(%%esi),  %%mm4      \n\t"   \
        "pmuludq  %%mm0,     %%mm4      \n\t"   \
        "movd     8(%%esi),  %%mm6      \n\t"   \
        "pmuludq  %%mm0,     %%mm6      \n\t"   \
        "movd     12(%%esi), %%mm7      \n\t"   \
        "pmuludq  %%mm0,     %%mm7      \n\t"   \
        "paddq    %%mm2,     %%mm1      \n\t"   \
        "movd     4(%%edi),  %%mm3      \n\t"   \
        "paddq    %%mm4,     %%mm3      \n\t"   \
        "movd     8(%%edi),  %%mm5      \n\t"   \
        "paddq    %%mm6,     %%mm5      \n\t"   \
        "movd     12(%%edi), %%mm4      \n\t"   \
        "paddq    %%mm4,     %%mm7      \n\t"   \
        "movd     %%mm1,     (%%edi)    \n\t"   \
        "movd     16(%%esi), %%mm2      \n\t"   \
        "pmuludq  %%mm0,     %%mm2      \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     20(%%esi), %%mm4      \n\t"   \
        "pmuludq  %%mm0,     %%mm4      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     24(%%esi), %%mm6      \n\t"   \
        "pmuludq  %%mm0,     %%mm6      \n\t"   \
        "movd     %%mm1,     4(%%edi)   \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     28(%%esi), %%mm3      \n\t"   \
        "pmuludq  %%mm0,     %%mm3      \n\t"   \
        "paddq    %%mm5,     %%mm1      \n\t"   \
        "movd     16(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm2      \n\t"   \
        "movd     %%mm1,     8(%%edi)   \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm7,     %%mm1      \n\t"   \
        "movd     20(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm4      \n\t"   \
        "movd     %%mm1,     12(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm2,     %%mm1      \n\t"   \
        "movd     24(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm6      \n\t"   \
        "movd     %%mm1,     16(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm4,     %%mm1      \n\t"   \
        "movd     28(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm3      \n\t"   \
        "movd     %%mm1,     20(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm6,     %%mm1      \n\t"   \
        "movd     %%mm1,     24(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     %%mm1,     28(%%edi)  \n\t"   \
        "addl     $32,       %%edi      \n\t"   \
        "addl     $32,       %%esi      \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     %%mm1,     %%ecx      \n\t"

#define MULADDC_STOP                    \
        "emms                   \n\t"   \
        "movl   %4, %%ebx       \n\t"   \
        "movl   %%ecx, %1       \n\t"   \
        "movl   %%edi, %2       \n\t"   \
        "movl   %%esi, %3       \n\t"   \
        : "=m" (t), "=m" (c), "=m" (d), "=m" (s)        \
        : "m" (t), "m" (s), "m" (d), "m" (c), "m" (b)   \
        : "eax", "ecx", "edx", "esi", "edi"             \
    );

#else

#define MULADDC_STOP                    \
        "movl   %4, %%ebx       \n\t"   \
        "movl   %%ecx, %1       \n\t"   \
        "movl   %%edi, %2       \n\t"   \
        "movl   %%esi, %3       \n\t"   \
        : "=m" (t), "=m" (c), "=m" (d), "=m" (s)        \
        : "m" (t), "m" (s), "m" (d), "m" (c), "m" (b)   \
        : "eax", "ecx", "edx", "esi", "edi"             \
    );
#endif /* SSE2 */
#endif /* i386 */

#if defined(__amd64__) || defined (__x86_64__)

#define MULADDC_INIT                        \
    asm(                                    \
        "movq   %3, %%rsi           \n\t"   \
        "movq   %4, %%rdi           \n\t"   \
        "movq   %5, %%rcx           \n\t"   \
        "movq   %6, %%rbx           \n\t"   \
        "xorq   %%r8, %%r8          \n\t"

#define MULADDC_CORE                        \
        "movq   (%%rsi), %%rax      \n\t"   \
        "mulq   %%rbx               \n\t"   \
        "addq   $8,      %%rsi      \n\t"   \
        "addq   %%rcx,   %%rax      \n\t"   \
        "movq   %%r8,    %%rcx      \n\t"   \
        "adcq   $0,      %%rdx      \n\t"   \
        "nop                        \n\t"   \
        "addq   %%rax,   (%%rdi)    \n\t"   \
        "adcq   %%rdx,   %%rcx      \n\t"   \
        "addq   $8,      %%rdi      \n\t"

#define MULADDC_STOP                        \
        "movq   %%rcx, %0           \n\t"   \
        "movq   %%rdi, %1           \n\t"   \
        "movq   %%rsi, %2           \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)                      \
        : "m" (s), "m" (d), "m" (c), "m" (b)                \
        : "rax", "rcx", "rdx", "rbx", "rsi", "rdi", "r8"    \
    );

#endif /* AMD64 */

#if defined(__mc68020__) || defined(__mcpu32__)

#define MULADDC_INIT                    \
    asm(                                \
        "movl   %3, %%a2        \n\t"   \
        "movl   %4, %%a3        \n\t"   \
        "movl   %5, %%d3        \n\t"   \
        "movl   %6, %%d2        \n\t"   \
        "moveq  #0, %%d0        \n\t"

#define MULADDC_CORE                    \
        "movel  %%a2@+, %%d1    \n\t"   \
        "mulul  %%d2, %%d4:%%d1 \n\t"   \
        "addl   %%d3, %%d1      \n\t"   \
        "addxl  %%d0, %%d4      \n\t"   \
        "moveq  #0,   %%d3      \n\t"   \
        "addl   %%d1, %%a3@+    \n\t"   \
        "addxl  %%d4, %%d3      \n\t"

#define MULADDC_STOP                    \
        "movl   %%d3, %0        \n\t"   \
        "movl   %%a3, %1        \n\t"   \
        "movl   %%a2, %2        \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "d0", "d1", "d2", "d3", "d4", "a2", "a3"  \
    );

#define MULADDC_HUIT                        \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"

#endif /* MC68000 */

#if defined(__powerpc64__) || defined(__ppc64__)

#if defined(__MACH__) && defined(__APPLE__)

#define MULADDC_INIT                        \
    asm(                                    \
        "ld     r3, %3              \n\t"   \
        "ld     r4, %4              \n\t"   \
        "ld     r5, %5              \n\t"   \
        "ld     r6, %6              \n\t"   \
        "addi   r3, r3, -8          \n\t"   \
        "addi   r4, r4, -8          \n\t"   \
        "addic  r5, r5,  0          \n\t"

#define MULADDC_CORE                        \
        "ldu    r7, 8(r3)           \n\t"   \
        "mulld  r8, r7, r6          \n\t"   \
        "mulhdu r9, r7, r6          \n\t"   \
        "adde   r8, r8, r5          \n\t"   \
        "ld     r7, 8(r4)           \n\t"   \
        "addze  r5, r9              \n\t"   \
        "addc   r8, r8, r7          \n\t"   \
        "stdu   r8, 8(r4)           \n\t"

#define MULADDC_STOP                        \
        "addze  r5, r5              \n\t"   \
        "addi   r4, r4, 8           \n\t"   \
        "addi   r3, r3, 8           \n\t"   \
        "std    r5, %0              \n\t"   \
        "std    r4, %1              \n\t"   \
        "std    r3, %2              \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );


#else /* __MACH__ && __APPLE__ */

#define MULADDC_INIT                        \
    asm(                                    \
        "ld     %%r3, %3            \n\t"   \
        "ld     %%r4, %4            \n\t"   \
        "ld     %%r5, %5            \n\t"   \
        "ld     %%r6, %6            \n\t"   \
        "addi   %%r3, %%r3, -8      \n\t"   \
        "addi   %%r4, %%r4, -8      \n\t"   \
        "addic  %%r5, %%r5,  0      \n\t"

#define MULADDC_CORE                        \
        "ldu    %%r7, 8(%%r3)       \n\t"   \
        "mulld  %%r8, %%r7, %%r6    \n\t"   \
        "mulhdu %%r9, %%r7, %%r6    \n\t"   \
        "adde   %%r8, %%r8, %%r5    \n\t"   \
        "ld     %%r7, 8(%%r4)       \n\t"   \
        "addze  %%r5, %%r9          \n\t"   \
        "addc   %%r8, %%r8, %%r7    \n\t"   \
        "stdu   %%r8, 8(%%r4)       \n\t"

#define MULADDC_STOP                        \
        "addze  %%r5, %%r5          \n\t"   \
        "addi   %%r4, %%r4, 8       \n\t"   \
        "addi   %%r3, %%r3, 8       \n\t"   \
        "std    %%r5, %0            \n\t"   \
        "std    %%r4, %1            \n\t"   \
        "std    %%r3, %2            \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );

#endif /* __MACH__ && __APPLE__ */

#elif defined(__powerpc__) || defined(__ppc__) /* end PPC64/begin PPC32  */

#if defined(__MACH__) && defined(__APPLE__)

#define MULADDC_INIT                    \
    asm(                                \
        "lwz    r3, %3          \n\t"   \
        "lwz    r4, %4          \n\t"   \
        "lwz    r5, %5          \n\t"   \
        "lwz    r6, %6          \n\t"   \
        "addi   r3, r3, -4      \n\t"   \
        "addi   r4, r4, -4      \n\t"   \
        "addic  r5, r5,  0      \n\t"

#define MULADDC_CORE                    \
        "lwzu   r7, 4(r3)       \n\t"   \
        "mullw  r8, r7, r6      \n\t"   \
        "mulhwu r9, r7, r6      \n\t"   \
        "adde   r8, r8, r5      \n\t"   \
        "lwz    r7, 4(r4)       \n\t"   \
        "addze  r5, r9          \n\t"   \
        "addc   r8, r8, r7      \n\t"   \
        "stwu   r8, 4(r4)       \n\t"

#define MULADDC_STOP                    \
        "addze  r5, r5          \n\t"   \
        "addi   r4, r4, 4       \n\t"   \
        "addi   r3, r3, 4       \n\t"   \
        "stw    r5, %0          \n\t"   \
        "stw    r4, %1          \n\t"   \
        "stw    r3, %2          \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );

#else /* __MACH__ && __APPLE__ */

#define MULADDC_INIT                        \
    asm(                                    \
        "lwz    %%r3, %3            \n\t"   \
        "lwz    %%r4, %4            \n\t"   \
        "lwz    %%r5, %5            \n\t"   \
        "lwz    %%r6, %6            \n\t"   \
        "addi   %%r3, %%r3, -4      \n\t"   \
        "addi   %%r4, %%r4, -4      \n\t"   \
        "addic  %%r5, %%r5,  0      \n\t"

#define MULADDC_CORE                        \
        "lwzu   %%r7, 4(%%r3)       \n\t"   \
        "mullw  %%r8, %%r7, %%r6    \n\t"   \
        "mulhwu %%r9, %%r7, %%r6    \n\t"   \
        "adde   %%r8, %%r8, %%r5    \n\t"   \
        "lwz    %%r7, 4(%%r4)       \n\t"   \
        "addze  %%r5, %%r9          \n\t"   \
        "addc   %%r8, %%r8, %%r7    \n\t"   \
        "stwu   %%r8, 4(%%r4)       \n\t"

#define MULADDC_STOP                        \
        "addze  %%r5, %%r5          \n\t"   \
        "addi   %%r4, %%r4, 4       \n\t"   \
        "addi   %%r3, %%r3, 4       \n\t"   \
        "stw    %%r5, %0            \n\t"   \
        "stw    %%r4, %1            \n\t"   \
        "stw    %%r3, %2            \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );

#endif /* __MACH__ && __APPLE__ */

#endif /* PPC32 */

/*
 * The Sparc64 assembly is reported to be broken.
 * Disable it for now, until we're able to fix it.
 */
#if 0 && defined(__sparc__) && defined(__sparc64__)

#define MULADDC_INIT                                    \
    asm(                                                \
                "ldx     %3, %%o0               \n\t"   \
                "ldx     %4, %%o1               \n\t"   \
                "ld      %5, %%o2               \n\t"   \
                "ld      %6, %%o3               \n\t"

#define MULADDC_CORE                                    \
                "ld      [%%o0], %%o4           \n\t"   \
                "inc     4, %%o0                \n\t"   \
                "ld      [%%o1], %%o5           \n\t"   \
                "umul    %%o3, %%o4, %%o4       \n\t"   \
                "addcc   %%o4, %%o2, %%o4       \n\t"   \
                "rd      %%y, %%g1              \n\t"   \
                "addx    %%g1, 0, %%g1          \n\t"   \
                "addcc   %%o4, %%o5, %%o4       \n\t"   \
                "st      %%o4, [%%o1]           \n\t"   \
                "addx    %%g1, 0, %%o2          \n\t"   \
                "inc     4, %%o1                \n\t"

        #define MULADDC_STOP                            \
                "st      %%o2, %0               \n\t"   \
                "stx     %%o1, %1               \n\t"   \
                "stx     %%o0, %2               \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)          \
        : "m" (s), "m" (d), "m" (c), "m" (b)    \
        : "g1", "o0", "o1", "o2", "o3", "o4",   \
          "o5"                                  \
        );
#endif /* SPARCv9 */

#if defined(__sparc__) && !defined(__sparc64__)

#define MULADDC_INIT                                    \
    asm(                                                \
                "ld      %3, %%o0               \n\t"   \
                "ld      %4, %%o1               \n\t"   \
                "ld      %5, %%o2               \n\t"   \
                "ld      %6, %%o3               \n\t"

#define MULADDC_CORE                                    \
                "ld      [%%o0], %%o4           \n\t"   \
                "inc     4, %%o0                \n\t"   \
                "ld      [%%o1], %%o5           \n\t"   \
                "umul    %%o3, %%o4, %%o4       \n\t"   \
                "addcc   %%o4, %%o2, %%o4       \n\t"   \
                "rd      %%y, %%g1              \n\t"   \
                "addx    %%g1, 0, %%g1          \n\t"   \
                "addcc   %%o4, %%o5, %%o4       \n\t"   \
                "st      %%o4, [%%o1]           \n\t"   \
                "addx    %%g1, 0, %%o2          \n\t"   \
                "inc     4, %%o1                \n\t"

#define MULADDC_STOP                                    \
                "st      %%o2, %0               \n\t"   \
                "st      %%o1, %1               \n\t"   \
                "st      %%o0, %2               \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)          \
        : "m" (s), "m" (d), "m" (c), "m" (b)    \
        : "g1", "o0", "o1", "o2", "o3", "o4",   \
          "o5"                                  \
        );

#endif /* SPARCv8 */

#if defined(__microblaze__) || defined(microblaze)

#define MULADDC_INIT                    \
    asm(                                \
        "lwi   r3,   %3         \n\t"   \
        "lwi   r4,   %4         \n\t"   \
        "lwi   r5,   %5         \n\t"   \
        "lwi   r6,   %6         \n\t"   \
        "andi  r7,   r6, 0xffff \n\t"   \
        "bsrli r6,   r6, 16     \n\t"

#define MULADDC_CORE                    \
        "lhui  r8,   r3,   0    \n\t"   \
        "addi  r3,   r3,   2    \n\t"   \
        "lhui  r9,   r3,   0    \n\t"   \
        "addi  r3,   r3,   2    \n\t"   \
        "mul   r10,  r9,  r6    \n\t"   \
        "mul   r11,  r8,  r7    \n\t"   \
        "mul   r12,  r9,  r7    \n\t"   \
        "mul   r13,  r8,  r6    \n\t"   \
        "bsrli  r8, r10,  16    \n\t"   \
        "bsrli  r9, r11,  16    \n\t"   \
        "add   r13, r13,  r8    \n\t"   \
        "add   r13, r13,  r9    \n\t"   \
        "bslli r10, r10,  16    \n\t"   \
        "bslli r11, r11,  16    \n\t"   \
        "add   r12, r12, r10    \n\t"   \
        "addc  r13, r13,  r0    \n\t"   \
        "add   r12, r12, r11    \n\t"   \
        "addc  r13, r13,  r0    \n\t"   \
        "lwi   r10,  r4,   0    \n\t"   \
        "add   r12, r12, r10    \n\t"   \
        "addc  r13, r13,  r0    \n\t"   \
        "add   r12, r12,  r5    \n\t"   \
        "addc   r5, r13,  r0    \n\t"   \
        "swi   r12,  r4,   0    \n\t"   \
        "addi   r4,  r4,   4    \n\t"

#define MULADDC_STOP                    \
        "swi   r5,   %0         \n\t"   \
        "swi   r4,   %1         \n\t"   \
        "swi   r3,   %2         \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4"  "r5", "r6", "r7", "r8",       \
          "r9", "r10", "r11", "r12", "r13"          \
    );

#endif /* MicroBlaze */

#if defined(__tricore__)

#define MULADDC_INIT                            \
    asm(                                        \
        "ld.a   %%a2, %3                \n\t"   \
        "ld.a   %%a3, %4                \n\t"   \
        "ld.w   %%d4, %5                \n\t"   \
        "ld.w   %%d1, %6                \n\t"   \
        "xor    %%d5, %%d5              \n\t"

#define MULADDC_CORE                            \
        "ld.w   %%d0,   [%%a2+]         \n\t"   \
        "madd.u %%e2, %%e4, %%d0, %%d1  \n\t"   \
        "ld.w   %%d0,   [%%a3]          \n\t"   \
        "addx   %%d2,    %%d2,  %%d0    \n\t"   \
        "addc   %%d3,    %%d3,    0     \n\t"   \
        "mov    %%d4,    %%d3           \n\t"   \
        "st.w  [%%a3+],  %%d2           \n\t"

#define MULADDC_STOP                            \
        "st.w   %0, %%d4                \n\t"   \
        "st.a   %1, %%a3                \n\t"   \
        "st.a   %2, %%a2                \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)          \
        : "m" (s), "m" (d), "m" (c), "m" (b)    \
        : "d0", "d1", "e2", "d4", "a2", "a3"    \
    );

#endif /* TriCore */

#if defined(__arm__)

#if defined(__thumb__) && !defined(__thumb2__)

#define MULADDC_INIT                                    \
    asm(                                                \
            "ldr    r0, %3                      \n\t"   \
            "ldr    r1, %4                      \n\t"   \
            "ldr    r2, %5                      \n\t"   \
            "ldr    r3, %6                      \n\t"   \
            "lsr    r7, r3, #16                 \n\t"   \
            "mov    r9, r7                      \n\t"   \
            "lsl    r7, r3, #16                 \n\t"   \
            "lsr    r7, r7, #16                 \n\t"   \
            "mov    r8, r7                      \n\t"

#define MULADDC_CORE                                    \
            "ldmia  r0!, {r6}                   \n\t"   \
            "lsr    r7, r6, #16                 \n\t"   \
            "lsl    r6, r6, #16                 \n\t"   \
            "lsr    r6, r6, #16                 \n\t"   \
            "mov    r4, r8                      \n\t"   \
            "mul    r4, r6                      \n\t"   \
            "mov    r3, r9                      \n\t"   \
            "mul    r6, r3                      \n\t"   \
            "mov    r5, r9                      \n\t"   \
            "mul    r5, r7                      \n\t"   \
            "mov    r3, r8                      \n\t"   \
            "mul    r7, r3                      \n\t"   \
            "lsr    r3, r6, #16                 \n\t"   \
            "add    r5, r5, r3                  \n\t"   \
            "lsr    r3, r7, #16                 \n\t"   \
            "add    r5, r5, r3                  \n\t"   \
            "add    r4, r4, r2                  \n\t"   \
            "mov    r2, #0                      \n\t"   \
            "adc    r5, r2                      \n\t"   \
            "lsl    r3, r6, #16                 \n\t"   \
            "add    r4, r4, r3                  \n\t"   \
            "adc    r5, r2                      \n\t"   \
            "lsl    r3, r7, #16                 \n\t"   \
            "add    r4, r4, r3                  \n\t"   \
            "adc    r5, r2                      \n\t"   \
            "ldr    r3, [r1]                    \n\t"   \
            "add    r4, r4, r3                  \n\t"   \
            "adc    r2, r5                      \n\t"   \
            "stmia  r1!, {r4}                   \n\t"

#define MULADDC_STOP                                    \
            "str    r2, %0                      \n\t"   \
            "str    r1, %1                      \n\t"   \
            "str    r0, %2                      \n\t"   \
         : "=m" (c),  "=m" (d), "=m" (s)        \
         : "m" (s), "m" (d), "m" (c), "m" (b)   \
         : "r0", "r1", "r2", "r3", "r4", "r5",  \
           "r6", "r7", "r8", "r9", "cc"         \
         );

#else

#define MULADDC_INIT                                    \
    asm(                                                \
            "ldr    r0, %3                      \n\t"   \
            "ldr    r1, %4                      \n\t"   \
            "ldr    r2, %5                      \n\t"   \
            "ldr    r3, %6                      \n\t"

#define MULADDC_CORE                                    \
            "ldr    r4, [r0], #4                \n\t"   \
            "mov    r5, #0                      \n\t"   \
            "ldr    r6, [r1]                    \n\t"   \
            "umlal  r2, r5, r3, r4              \n\t"   \
            "adds   r7, r6, r2                  \n\t"   \
            "adc    r2, r5, #0                  \n\t"   \
            "str    r7, [r1], #4                \n\t"

#define MULADDC_STOP                                    \
            "str    r2, %0                      \n\t"   \
            "str    r1, %1                      \n\t"   \
            "str    r0, %2                      \n\t"   \
         : "=m" (c),  "=m" (d), "=m" (s)        \
         : "m" (s), "m" (d), "m" (c), "m" (b)   \
         : "r0", "r1", "r2", "r3", "r4", "r5",  \
           "r6", "r7", "cc"                     \
         );

#endif /* Thumb */

#endif /* ARMv3 */

#if defined(__alpha__)

#define MULADDC_INIT                    \
    asm(                                \
        "ldq    $1, %3          \n\t"   \
        "ldq    $2, %4          \n\t"   \
        "ldq    $3, %5          \n\t"   \
        "ldq    $4, %6          \n\t"

#define MULADDC_CORE                    \
        "ldq    $6,  0($1)      \n\t"   \
        "addq   $1,  8, $1      \n\t"   \
        "mulq   $6, $4, $7      \n\t"   \
        "umulh  $6, $4, $6      \n\t"   \
        "addq   $7, $3, $7      \n\t"   \
        "cmpult $7, $3, $3      \n\t"   \
        "ldq    $5,  0($2)      \n\t"   \
        "addq   $7, $5, $7      \n\t"   \
        "cmpult $7, $5, $5      \n\t"   \
        "stq    $7,  0($2)      \n\t"   \
        "addq   $2,  8, $2      \n\t"   \
        "addq   $6, $3, $3      \n\t"   \
        "addq   $5, $3, $3      \n\t"

#define MULADDC_STOP                                    \
        "stq    $3, %0          \n\t"   \
        "stq    $2, %1          \n\t"   \
        "stq    $1, %2          \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "$1", "$2", "$3", "$4", "$5", "$6", "$7"  \
    );
#endif /* Alpha */

#if defined(__mips__) && !defined(__mips64__)

#define MULADDC_INIT                    \
    asm(                                \
        "lw     $10, %3         \n\t"   \
        "lw     $11, %4         \n\t"   \
        "lw     $12, %5         \n\t"   \
        "lw     $13, %6         \n\t"

#define MULADDC_CORE                    \
        "lw     $14, 0($10)     \n\t"   \
        "multu  $13, $14        \n\t"   \
        "addi   $10, $10, 4     \n\t"   \
        "mflo   $14             \n\t"   \
        "mfhi   $9              \n\t"   \
        "addu   $14, $12, $14   \n\t"   \
        "lw     $15, 0($11)     \n\t"   \
        "sltu   $12, $14, $12   \n\t"   \
        "addu   $15, $14, $15   \n\t"   \
        "sltu   $14, $15, $14   \n\t"   \
        "addu   $12, $12, $9    \n\t"   \
        "sw     $15, 0($11)     \n\t"   \
        "addu   $12, $12, $14   \n\t"   \
        "addi   $11, $11, 4     \n\t"

#define MULADDC_STOP                    \
        "sw     $12, %0         \n\t"   \
        "sw     $11, %1         \n\t"   \
        "sw     $10, %2         \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)                      \
        : "m" (s), "m" (d), "m" (c), "m" (b)                \
        : "$9", "$10", "$11", "$12", "$13", "$14", "$15"    \
    );

#endif /* MIPS */
#endif /* GNUC */

#if (defined(_MSC_VER) && defined(_M_IX86)) || defined(__WATCOMC__)

#define MULADDC_INIT                            \
    __asm   mov     esi, s                      \
    __asm   mov     edi, d                      \
    __asm   mov     ecx, c                      \
    __asm   mov     ebx, b

#define MULADDC_CORE                            \
    __asm   lodsd                               \
    __asm   mul     ebx                         \
    __asm   add     eax, ecx                    \
    __asm   adc     edx, 0                      \
    __asm   add     eax, [edi]                  \
    __asm   adc     edx, 0                      \
    __asm   mov     ecx, edx                    \
    __asm   stosd

#if defined(POLARSSL_HAVE_SSE2)

#define EMIT __asm _emit

#define MULADDC_HUIT                            \
    EMIT 0x0F  EMIT 0x6E  EMIT 0xC9             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0xC3             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x1F             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCB             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x16             \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xD0             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x66  EMIT 0x04  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xE0             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x76  EMIT 0x08  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xF0             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x7E  EMIT 0x0C  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xF8             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCA             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x5F  EMIT 0x04  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xDC             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x08  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xEE             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x67  EMIT 0x0C  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xFC             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x0F             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x56  EMIT 0x10  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xD0             \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x66  EMIT 0x14  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xE0             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCB             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x76  EMIT 0x18  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xF0             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x04  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x5E  EMIT 0x1C  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xD8             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCD             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x10  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xD5             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x08  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCF             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x14  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xE5             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x0C  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCA             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x18  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xF5             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x10  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCC             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x1C  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xDD             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x14  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCE             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x18  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCB             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x1C  \
    EMIT 0x83  EMIT 0xC7  EMIT 0x20             \
    EMIT 0x83  EMIT 0xC6  EMIT 0x20             \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0x7E  EMIT 0xC9

#define MULADDC_STOP                            \
    EMIT 0x0F  EMIT 0x77                        \
    __asm   mov     c, ecx                      \
    __asm   mov     d, edi                      \
    __asm   mov     s, esi                      \

#else

#define MULADDC_STOP                            \
    __asm   mov     c, ecx                      \
    __asm   mov     d, edi                      \
    __asm   mov     s, esi                      \

#endif /* SSE2 */
#endif /* MSVC */

#endif /* POLARSSL_HAVE_ASM */

#if !defined(MULADDC_CORE)
#if defined(POLARSSL_HAVE_UDBL)

#define MULADDC_INIT                    \
{                                       \
    t_udbl r;                           \
    t_uint r0, r1;

#define MULADDC_CORE                    \
    r   = *(s++) * (t_udbl) b;          \
    r0  = (t_uint) r;                   \
    r1  = (t_uint)( r >> biL );         \
    r0 += c;  r1 += (r0 <  c);          \
    r0 += *d; r1 += (r0 < *d);          \
    c = r1; *(d++) = r0;

#define MULADDC_STOP                    \
}

#else
#define MULADDC_INIT                    \
{                                       \
    t_uint s0, s1, b0, b1;              \
    t_uint r0, r1, rx, ry;              \
    b0 = ( b << biH ) >> biH;           \
    b1 = ( b >> biH );

#define MULADDC_CORE                    \
    s0 = ( *s << biH ) >> biH;          \
    s1 = ( *s >> biH ); s++;            \
    rx = s0 * b1; r0 = s0 * b0;         \
    ry = s1 * b0; r1 = s1 * b1;         \
    r1 += ( rx >> biH );                \
    r1 += ( ry >> biH );                \
    rx <<= biH; ry <<= biH;             \
    r0 += rx; r1 += (r0 < rx);          \
    r0 += ry; r1 += (r0 < ry);          \
    r0 +=  c; r1 += (r0 <  c);          \
    r0 += *d; r1 += (r0 < *d);          \
    c = r1; *(d++) = r0;

#define MULADDC_STOP                    \
}

#endif /* C (generic)  */
#endif /* C (longlong) */

#endif /* bn_mul.h */
/**
 * \file bignum.h
 *
 * \brief  Multi-precision integer library
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_BIGNUM_H
#define POLARSSL_BIGNUM_H

#include <stdio.h>
#include <string.h>

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
#if (_MSC_VER <= 1200)
typedef   signed short  int16_t;
typedef unsigned short uint16_t;
#else
typedef  INT16  int16_t;
typedef UINT16 uint16_t;
#endif
typedef  INT32  int32_t;
typedef  INT64  int64_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
#else
#include <inttypes.h>
#endif /* _MSC_VER && !EFIX64 && !EFI32 */

#define POLARSSL_ERR_MPI_FILE_IO_ERROR                     -0x0002  /**< An error occurred while reading from or writing to a file. */
#define POLARSSL_ERR_MPI_BAD_INPUT_DATA                    -0x0004  /**< Bad input parameters to function. */
#define POLARSSL_ERR_MPI_INVALID_CHARACTER                 -0x0006  /**< There is an invalid character in the digit string. */
#define POLARSSL_ERR_MPI_BUFFER_TOO_SMALL                  -0x0008  /**< The buffer is too small to write to. */
#define POLARSSL_ERR_MPI_NEGATIVE_VALUE                    -0x000A  /**< The input arguments are negative or result in illegal output. */
#define POLARSSL_ERR_MPI_DIVISION_BY_ZERO                  -0x000C  /**< The input argument for division is zero, which is not allowed. */
#define POLARSSL_ERR_MPI_NOT_ACCEPTABLE                    -0x000E  /**< The input arguments are not acceptable. */
#define POLARSSL_ERR_MPI_MALLOC_FAILED                     -0x0010  /**< Memory allocation failed. */

#define MPI_CHK(f) do { if( ( ret = f ) != 0 ) goto cleanup; } while( 0 )

/*
 * Maximum size MPIs are allowed to grow to in number of limbs.
 */
#define POLARSSL_MPI_MAX_LIMBS                             10000

#if !defined(POLARSSL_MPI_WINDOW_SIZE)
/*
 * Maximum window size used for modular exponentiation. Default: 6
 * Minimum value: 1. Maximum value: 6.
 *
 * Result is an array of ( 2 << POLARSSL_MPI_WINDOW_SIZE ) MPIs used
 * for the sliding window calculation. (So 64 by default)
 *
 * Reduction in size, reduces speed.
 */
#define POLARSSL_MPI_WINDOW_SIZE                           6        /**< Maximum windows size used. */
#endif /* !POLARSSL_MPI_WINDOW_SIZE */

#if !defined(POLARSSL_MPI_MAX_SIZE)
/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * ( Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits )
 *
 * Note: Calculations can results temporarily in larger MPIs. So the number
 * of limbs required (POLARSSL_MPI_MAX_LIMBS) is higher.
 */
#define POLARSSL_MPI_MAX_SIZE                              1024     /**< Maximum number of bytes for usable MPIs. */
#endif /* !POLARSSL_MPI_MAX_SIZE */

#define POLARSSL_MPI_MAX_BITS                              ( 8 * POLARSSL_MPI_MAX_SIZE )    /**< Maximum number of bits for usable MPIs. */

/*
 * When reading from files with mpi_read_file() and writing to files with
 * mpi_write_file() the buffer should have space
 * for a (short) label, the MPI (in the provided radix), the newline
 * characters and the '\0'.
 *
 * By default we assume at least a 10 char label, a minimum radix of 10
 * (decimal) and a maximum of 4096 bit numbers (1234 decimal chars).
 * Autosized at compile time for at least a 10 char label, a minimum radix
 * of 10 (decimal) for a number of POLARSSL_MPI_MAX_BITS size.
 *
 * This used to be statically sized to 1250 for a maximum of 4096 bit
 * numbers (1234 decimal chars).
 *
 * Calculate using the formula:
 *  POLARSSL_MPI_RW_BUFFER_SIZE = ceil(POLARSSL_MPI_MAX_BITS / ln(10) * ln(2)) +
 *                                LabelSize + 6
 */
#define POLARSSL_MPI_MAX_BITS_SCALE100          ( 100 * POLARSSL_MPI_MAX_BITS )
#define LN_2_DIV_LN_10_SCALE100                 332
#define POLARSSL_MPI_RW_BUFFER_SIZE             ( ((POLARSSL_MPI_MAX_BITS_SCALE100 + LN_2_DIV_LN_10_SCALE100 - 1) / LN_2_DIV_LN_10_SCALE100) + 10 + 6 )

/*
 * Define the base integer type, architecture-wise
 */
#if defined(POLARSSL_HAVE_INT8)
typedef   signed char  t_sint;
typedef unsigned char  t_uint;
typedef uint16_t       t_udbl;
#define POLARSSL_HAVE_UDBL
#else
#if defined(POLARSSL_HAVE_INT16)
typedef  int16_t t_sint;
typedef uint16_t t_uint;
typedef uint32_t t_udbl;
#define POLARSSL_HAVE_UDBL
#else
  /*
   * 32-bit integers can be forced on 64-bit arches (eg. for testing purposes)
   * by defining POLARSSL_HAVE_INT32 and undefining POLARSSL_HAVE_ASM
   */
  #if ( ! defined(POLARSSL_HAVE_INT32) && \
          defined(_MSC_VER) && defined(_M_AMD64) )
    #define POLARSSL_HAVE_INT64
    typedef  int64_t t_sint;
    typedef uint64_t t_uint;
  #else
    #if ( ! defined(POLARSSL_HAVE_INT32) &&               \
          defined(__GNUC__) && (                          \
          defined(__amd64__) || defined(__x86_64__)    || \
          defined(__ppc64__) || defined(__powerpc64__) || \
          defined(__ia64__)  || defined(__alpha__)     || \
          (defined(__sparc__) && defined(__arch64__))  || \
          defined(__s390x__) ) )
       #define POLARSSL_HAVE_INT64
       typedef  int64_t t_sint;
       typedef uint64_t t_uint;
       typedef unsigned int t_udbl __attribute__((mode(TI)));
       #define POLARSSL_HAVE_UDBL
    #else
       #define POLARSSL_HAVE_INT32
       typedef  int32_t t_sint;
       typedef uint32_t t_uint;
       #if ( defined(_MSC_VER) && defined(_M_IX86) )
         typedef uint64_t t_udbl;
         #define POLARSSL_HAVE_UDBL
       #else
         #if defined( POLARSSL_HAVE_LONGLONG )
           typedef unsigned long long t_udbl;
           #define POLARSSL_HAVE_UDBL
         #endif
       #endif
    #endif /* !POLARSSL_HAVE_INT32 && __GNUC__ && 64-bit platform */
  #endif /* !POLARSSL_HAVE_INT32 && _MSC_VER && _M_AMD64 */
#endif /* POLARSSL_HAVE_INT16 */
#endif /* POLARSSL_HAVE_INT8  */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          MPI structure
 */
typedef struct
{
    int s;              /*!<  integer sign      */
    size_t n;           /*!<  total # of limbs  */
    t_uint *p;          /*!<  pointer to limbs  */
}
mpi;

/**
 * \brief           Initialize one MPI
 *
 * \param X         One MPI to initialize.
 */
static void mpi_init( mpi *X );

/**
 * \brief          Unallocate one MPI
 *
 * \param X        One MPI to unallocate.
 */
static void mpi_free( mpi *X );

/**
 * \brief          Enlarge to the specified number of limbs
 *
 * \param X        MPI to grow
 * \param nblimbs  The target number of limbs
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_grow( mpi *X, size_t nblimbs );

/**
 * \brief          Resize down, keeping at least the specified number of limbs
 *
 * \param X        MPI to shrink
 * \param nblimbs  The minimum number of limbs to keep
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_shrink( mpi *X, size_t nblimbs );

/**
 * \brief          Copy the contents of Y into X
 *
 * \param X        Destination MPI
 * \param Y        Source MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_copy( mpi *X, const mpi *Y );

/**
 * \brief          Swap the contents of X and Y
 *
 * \param X        First MPI value
 * \param Y        Second MPI value
 */
static void mpi_swap( mpi *X, mpi *Y );

/**
 * \brief          Safe conditional assignement X = Y if assign is 1
 *
 * \param X        MPI to conditionally assign to
 * \param Y        Value to be assigned
 * \param assign   1: perform the assignment, 0: keep X's original value
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *
 * \note           This function is equivalent to
 *                      if( assign ) mpi_copy( X, Y );
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not (the above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis).
 */
static int mpi_safe_cond_assign( mpi *X, const mpi *Y, unsigned char assign );

/**
 * \brief          Safe conditional swap X <-> Y if swap is 1
 *
 * \param X        First mpi value
 * \param Y        Second mpi value
 * \param assign   1: perform the swap, 0: keep X and Y's original values
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *
 * \note           This function is equivalent to
 *                      if( assign ) mpi_swap( X, Y );
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not (the above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis).
 */
static int mpi_safe_cond_swap( mpi *X, mpi *Y, unsigned char assign );

/**
 * \brief          Set value from integer
 *
 * \param X        MPI to set
 * \param z        Value to use
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_lset( mpi *X, t_sint z );

/**
 * \brief          Get a specific bit from X
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit in X
 *
 * \return         Either a 0 or a 1
 */
static int mpi_get_bit( const mpi *X, size_t pos );

/**
 * \brief          Set a bit of X to a specific value of 0 or 1
 *
 * \note           Will grow X if necessary to set a bit to 1 in a not yet
 *                 existing limb. Will not grow if bit should be set to 0
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit in X
 * \param val      The value to set the bit to (0 or 1)
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if val is not 0 or 1
 */
static int mpi_set_bit( mpi *X, size_t pos, unsigned char val );

/**
 * \brief          Return the number of zero-bits before the least significant
 *                 '1' bit
 *
 * Note: Thus also the zero-based index of the least significant '1' bit
 *
 * \param X        MPI to use
 */
static size_t mpi_lsb( const mpi *X );

/**
 * \brief          Return the number of bits up to and including the most
 *                 significant '1' bit'
 *
 * Note: Thus also the one-based index of the most significant '1' bit
 *
 * \param X        MPI to use
 */
static size_t mpi_msb( const mpi *X );

/**
 * \brief          Return the total size in bytes
 *
 * \param X        MPI to use
 */
static size_t mpi_size( const mpi *X );

/**
 * \brief          Import from an ASCII string
 *
 * \param X        Destination MPI
 * \param radix    Input numeric base
 * \param s        Null-terminated string buffer
 *
 * \return         0 if successful, or a POLARSSL_ERR_MPI_XXX error code
 */
static int mpi_read_string( mpi *X, int radix, const char *s );

/**
 * \brief          Export into an ASCII string
 *
 * \param X        Source MPI
 * \param radix    Output numeric base
 * \param s        String buffer
 * \param slen     String buffer size
 *
 * \return         0 if successful, or a POLARSSL_ERR_MPI_XXX error code.
 *                 *slen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *
 * \note           Call this function with *slen = 0 to obtain the
 *                 minimum required buffer size in *slen.
 */
static int mpi_write_string( const mpi *X, int radix, char *s, size_t *slen );

#if defined(POLARSSL_FS_IO)
/**
 * \brief          Read X from an opened file
 *
 * \param X        Destination MPI
 * \param radix    Input numeric base
 * \param fin      Input file handle
 *
 * \return         0 if successful, POLARSSL_ERR_MPI_BUFFER_TOO_SMALL if
 *                 the file read buffer is too small or a
 *                 POLARSSL_ERR_MPI_XXX error code
 */
static int mpi_read_file( mpi *X, int radix, FILE *fin );

/**
 * \brief          Write X into an opened file, or stdout if fout is NULL
 *
 * \param p        Prefix, can be NULL
 * \param X        Source MPI
 * \param radix    Output numeric base
 * \param fout     Output file handle (can be NULL)
 *
 * \return         0 if successful, or a POLARSSL_ERR_MPI_XXX error code
 *
 * \note           Set fout == NULL to print X on the console.
 */
static int mpi_write_file( const char *p, const mpi *X, int radix, FILE *fout );
#endif /* POLARSSL_FS_IO */

/**
 * \brief          Import X from unsigned binary data, big endian
 *
 * \param X        Destination MPI
 * \param buf      Input buffer
 * \param buflen   Input buffer size
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_read_binary( mpi *X, const unsigned char *buf, size_t buflen );

/**
 * \brief          Export X into unsigned binary data, big endian.
 *                 Always fills the whole buffer, which will start with zeros
 *                 if the number is smaller.
 *
 * \param X        Source MPI
 * \param buf      Output buffer
 * \param buflen   Output buffer size
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_BUFFER_TOO_SMALL if buf isn't large enough
 */
static int mpi_write_binary( const mpi *X, unsigned char *buf, size_t buflen );

/**
 * \brief          Left-shift: X <<= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_shift_l( mpi *X, size_t count );

/**
 * \brief          Right-shift: X >>= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_shift_r( mpi *X, size_t count );

/**
 * \brief          Compare unsigned values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if |X| is greater than |Y|,
 *                -1 if |X| is lesser  than |Y| or
 *                 0 if |X| is equal to |Y|
 */
static int mpi_cmp_abs( const mpi *X, const mpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser  than Y or
 *                 0 if X is equal to Y
 */
static int mpi_cmp_mpi( const mpi *X, const mpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param z        The integer value to compare to
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser  than z or
 *                 0 if X is equal to z
 */
static int mpi_cmp_int( const mpi *X, t_sint z );

/**
 * \brief          Unsigned addition: X = |A| + |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_add_abs( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Unsigned subtraction: X = |A| - |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if B is greater than A
 */
static int mpi_sub_abs( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed addition: X = A + B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_add_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed subtraction: X = A - B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_sub_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed addition: X = A + b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to add
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_add_int( mpi *X, const mpi *A, t_sint b );

/**
 * \brief          Signed subtraction: X = A - b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to subtract
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_sub_int( mpi *X, const mpi *A, t_sint b );

/**
 * \brief          Baseline multiplication: X = A * B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_mul_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Baseline multiplication: X = A * b
 *                 Note: despite the functon signature, b is treated as a
 *                 t_uint.  Negative values of b are treated as large positive
 *                 values.
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to multiply with
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_mul_int( mpi *X, const mpi *A, t_sint b );

/**
 * \brief          Division by mpi: A = Q * B + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0
 *
 * \note           Either Q or R can be NULL.
 */
static int mpi_div_mpi( mpi *Q, mpi *R, const mpi *A, const mpi *B );

/**
 * \brief          Division by int: A = Q * b + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0
 *
 * \note           Either Q or R can be NULL.
 */
static int mpi_div_int( mpi *Q, mpi *R, const mpi *A, t_sint b );

/**
 * \brief          Modulo: R = A mod B
 *
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if B < 0
 */
static int mpi_mod_mpi( mpi *R, const mpi *A, const mpi *B );

/**
 * \brief          Modulo: r = A mod b
 *
 * \param r        Destination t_uint
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if b < 0
 */
static int mpi_mod_int( t_uint *r, const mpi *A, t_sint b );

/**
 * \brief          Sliding-window exponentiation: X = A^E mod N
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param E        Exponent MPI
 * \param N        Modular MPI
 * \param _RR      Speed-up MPI used for recalculations
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if N is negative or even or
 *                 if E is negative
 *
 * \note           _RR is used to avoid re-computing R*R mod N across
 *                 multiple calls, which speeds up things a bit. It can
 *                 be set to NULL if the extra performance is unneeded.
 */
static int mpi_exp_mod( mpi *X, const mpi *A, const mpi *E, const mpi *N, mpi *_RR );

/**
 * \brief          Fill an MPI X with size bytes of random
 *
 * \param X        Destination MPI
 * \param size     Size in bytes
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_fill_random( mpi *X, size_t size,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          Greatest common divisor: G = gcd(A, B)
 *
 * \param G        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
static int mpi_gcd( mpi *G, const mpi *A, const mpi *B );

/**
 * \brief          Modular inverse: X = A^-1 mod N
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param N        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if N is negative or nil
                   POLARSSL_ERR_MPI_NOT_ACCEPTABLE if A has no inverse mod N
 */
static int mpi_inv_mod( mpi *X, const mpi *A, const mpi *N );

/**
 * \brief          Miller-Rabin primality test
 *
 * \param X        MPI to check
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful (probably prime),
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_NOT_ACCEPTABLE if X is not prime
 */
static int mpi_is_prime( mpi *X,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng );

/**
 * \brief          Prime number generation
 *
 * \param X        Destination MPI
 * \param nbits    Required size of X in bits
 *                 ( 3 <= nbits <= POLARSSL_MPI_MAX_BITS )
 * \param dh_flag  If 1, then (X-1)/2 will be prime too
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful (probably prime),
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if nbits is < 3
 */
static int mpi_gen_prime( mpi *X, size_t nbits, int dh_flag,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
static int mpi_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* bignum.h */
/**
 * \file ctr_drbg.h
 *
 * \brief CTR_DRBG based on AES-256 (NIST SP 800-90)
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_CTR_DRBG_H
#define POLARSSL_CTR_DRBG_H

#include <string.h>

//#include "aes.h"

#define POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED        -0x0034  /**< The entropy source failed. */
#define POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG              -0x0036  /**< Too many random requested in single call. */
#define POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG                -0x0038  /**< Input too large (Entropy + additional). */
#define POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR                -0x003A  /**< Read/write error in file. */

#define CTR_DRBG_BLOCKSIZE          16      /**< Block size used by the cipher                  */
#define CTR_DRBG_KEYSIZE            32      /**< Key size used by the cipher                    */
#define CTR_DRBG_KEYBITS            ( CTR_DRBG_KEYSIZE * 8 )
#define CTR_DRBG_SEEDLEN            ( CTR_DRBG_KEYSIZE + CTR_DRBG_BLOCKSIZE )
                                            /**< The seed length (counter + AES key)            */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(CTR_DRBG_ENTROPY_LEN)
#if defined(POLARSSL_SHA512_C) && !defined(POLARSSL_ENTROPY_FORCE_SHA256)
#define CTR_DRBG_ENTROPY_LEN        48      /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
#else
#define CTR_DRBG_ENTROPY_LEN        32      /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
#endif
#endif

#if !defined(CTR_DRBG_RESEED_INTERVAL)
#define CTR_DRBG_RESEED_INTERVAL    10000   /**< Interval before reseed is performed by default */
#endif

#if !defined(CTR_DRBG_MAX_INPUT)
#define CTR_DRBG_MAX_INPUT          256     /**< Maximum number of additional input bytes */
#endif

#if !defined(CTR_DRBG_MAX_REQUEST)
#define CTR_DRBG_MAX_REQUEST        1024    /**< Maximum number of requested bytes per call */
#endif

#if !defined(CTR_DRBG_MAX_SEED_INPUT)
#define CTR_DRBG_MAX_SEED_INPUT     384     /**< Maximum size of (re)seed buffer */
#endif

/* \} name SECTION: Module settings */

#define CTR_DRBG_PR_OFF             0       /**< No prediction resistance       */
#define CTR_DRBG_PR_ON              1       /**< Prediction resistance enabled  */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          CTR_DRBG context structure
 */
typedef struct
{
    unsigned char counter[16];  /*!<  counter (V)       */
    int reseed_counter;         /*!<  reseed counter    */
    int prediction_resistance;  /*!<  enable prediction resistance (Automatic
                                      reseed before every random generation)  */
    size_t entropy_len;         /*!<  amount of entropy grabbed on each
                                      (re)seed          */
    int reseed_interval;        /*!<  reseed interval   */

    aes_context aes_ctx;        /*!<  AES context       */

    /*
     * Callbacks (Entropy)
     */
    int (*f_entropy)(void *, unsigned char *, size_t);

    void *p_entropy;            /*!<  context for the entropy function */
}
ctr_drbg_context;

/**
 * \brief               CTR_DRBG initialization
 *
 * Note: Personalization data can be provided in addition to the more generic
 *       entropy source to make this instantiation as unique as possible.
 *
 * \param ctx           CTR_DRBG context to be initialized
 * \param f_entropy     Entropy callback (p_entropy, buffer to fill, buffer
 *                      length)
 * \param p_entropy     Entropy context
 * \param custom        Personalization data (Device specific identifiers)
 *                      (Can be NULL)
 * \param len           Length of personalization data
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 */
static int ctr_drbg_init( ctr_drbg_context *ctx,
                   int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy,
                   const unsigned char *custom,
                   size_t len );

/**
 * \brief               Clear CTR_CRBG context data
 *
 * \param ctx           CTR_DRBG context to clear
 */
static void ctr_drbg_free( ctr_drbg_context *ctx );

/**
 * \brief               Enable / disable prediction resistance (Default: Off)
 *
 * Note: If enabled, entropy is used for ctx->entropy_len before each call!
 *       Only use this if you have ample supply of good entropy!
 *
 * \param ctx           CTR_DRBG context
 * \param resistance    CTR_DRBG_PR_ON or CTR_DRBG_PR_OFF
 */
static void ctr_drbg_set_prediction_resistance( ctr_drbg_context *ctx,
                                         int resistance );

/**
 * \brief               Set the amount of entropy grabbed on each (re)seed
 *                      (Default: CTR_DRBG_ENTROPY_LEN)
 *
 * \param ctx           CTR_DRBG context
 * \param len           Amount of entropy to grab
 */
static void ctr_drbg_set_entropy_len( ctr_drbg_context *ctx,
                               size_t len );

/**
 * \brief               Set the reseed interval
 *                      (Default: CTR_DRBG_RESEED_INTERVAL)
 *
 * \param ctx           CTR_DRBG context
 * \param interval      Reseed interval
 */
static void ctr_drbg_set_reseed_interval( ctr_drbg_context *ctx,
                                   int interval );

/**
 * \brief               CTR_DRBG reseeding (extracts data from entropy source)
 *
 * \param ctx           CTR_DRBG context
 * \param additional    Additional data to add to state (Can be NULL)
 * \param len           Length of additional data
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 */
static int ctr_drbg_reseed( ctr_drbg_context *ctx,
                     const unsigned char *additional, size_t len );

/**
 * \brief               CTR_DRBG update state
 *
 * \param ctx           CTR_DRBG context
 * \param additional    Additional data to update state with
 * \param add_len       Length of additional data
 */
static void ctr_drbg_update( ctr_drbg_context *ctx,
                      const unsigned char *additional, size_t add_len );

/**
 * \brief               CTR_DRBG generate random with additional update input
 *
 * Note: Automatically reseeds if reseed_counter is reached.
 *
 * \param p_rng         CTR_DRBG context
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 * \param additional    Additional data to update with (Can be NULL)
 * \param add_len       Length of additional data
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG
 */
static int ctr_drbg_random_with_add( void *p_rng,
                              unsigned char *output, size_t output_len,
                              const unsigned char *additional, size_t add_len );

/**
 * \brief               CTR_DRBG generate random
 *
 * Note: Automatically reseeds if reseed_counter is reached.
 *
 * \param p_rng         CTR_DRBG context
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG
 */
static int ctr_drbg_random( void *p_rng,
                     unsigned char *output, size_t output_len );

#if defined(POLARSSL_FS_IO)
/**
 * \brief               Write a seed file
 *
 * \param ctx           CTR_DRBG context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR on file error, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 */
static int ctr_drbg_write_seed_file( ctr_drbg_context *ctx, const char *path );

/**
 * \brief               Read and update a seed file. Seed is added to this
 *                      instance
 *
 * \param ctx           CTR_DRBG context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR on file error,
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *                      POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG
 */
static int ctr_drbg_update_seed_file( ctr_drbg_context *ctx, const char *path );
#endif /* POLARSSL_FS_IO */

/**
 * \brief               Checkup routine
 *
 * \return              0 if successful, or 1 if the test failed
 */
static int ctr_drbg_self_test( int verbose );

/* Internal functions (do not call directly) */
static int ctr_drbg_init_entropy_len( ctr_drbg_context *,
                               int (*)(void *, unsigned char *, size_t), void *,
                               const unsigned char *, size_t, size_t );

#ifdef __cplusplus
}
#endif

#endif /* ctr_drbg.h */
/**
 * \file sha512.h
 *
 * \brief SHA-384 and SHA-512 cryptographic hash function
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_SHA512_H
#define POLARSSL_SHA512_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#include <string.h>

#if defined(_MSC_VER) || defined(__WATCOMC__)
  #define UL64(x) x##ui64
  typedef unsigned __int64 uint64_t;
#else
  #include <inttypes.h>
  #define UL64(x) x##ULL
#endif

#define POLARSSL_ERR_SHA512_FILE_IO_ERROR              -0x007A  /**< Read/write error in file. */

#if !defined(POLARSSL_SHA512_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SHA-512 context structure
 */
typedef struct
{
    uint64_t total[2];          /*!< number of bytes processed  */
    uint64_t state[8];          /*!< intermediate digest state  */
    unsigned char buffer[128];  /*!< data block being processed */

    unsigned char ipad[128];    /*!< HMAC: inner padding        */
    unsigned char opad[128];    /*!< HMAC: outer padding        */
    int is384;                  /*!< 0 => SHA-512, else SHA-384 */
}
sha512_context;

/**
 * \brief          Initialize SHA-512 context
 *
 * \param ctx      SHA-512 context to be initialized
 */
static void sha512_init( sha512_context *ctx );

/**
 * \brief          Clear SHA-512 context
 *
 * \param ctx      SHA-512 context to be cleared
 */
static void sha512_free( sha512_context *ctx );

/**
 * \brief          SHA-512 context setup
 *
 * \param ctx      context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
static void sha512_starts( sha512_context *ctx, int is384 );

/**
 * \brief          SHA-512 process buffer
 *
 * \param ctx      SHA-512 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
static void sha512_update( sha512_context *ctx, const unsigned char *input,
                    size_t ilen );

/**
 * \brief          SHA-512 final digest
 *
 * \param ctx      SHA-512 context
 * \param output   SHA-384/512 checksum result
 */
static void sha512_finish( sha512_context *ctx, unsigned char output[64] );

#ifdef __cplusplus
}
#endif

#else  /* POLARSSL_SHA512_ALT */
//#include "sha512_alt.h"
#endif /* POLARSSL_SHA512_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = SHA-512( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-384/512 checksum result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
static void sha512( const unsigned char *input, size_t ilen,
             unsigned char output[64], int is384 );

/**
 * \brief          Output = SHA-512( file contents )
 *
 * \param path     input file name
 * \param output   SHA-384/512 checksum result
 * \param is384    0 = use SHA512, 1 = use SHA384
 *
 * \return         0 if successful, or POLARSSL_ERR_SHA512_FILE_IO_ERROR
 */
static int sha512_file( const char *path, unsigned char output[64], int is384 );

/**
 * \brief          SHA-512 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
static void sha512_hmac_starts( sha512_context *ctx, const unsigned char *key,
                         size_t keylen, int is384 );

/**
 * \brief          SHA-512 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
static void sha512_hmac_update( sha512_context *ctx, const unsigned char *input,
                         size_t ilen );

/**
 * \brief          SHA-512 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SHA-384/512 HMAC checksum result
 */
static void sha512_hmac_finish( sha512_context *ctx, unsigned char output[64] );

/**
 * \brief          SHA-512 HMAC context reset
 *
 * \param ctx      HMAC context to be reset
 */
static void sha512_hmac_reset( sha512_context *ctx );

/**
 * \brief          Output = HMAC-SHA-512( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SHA-384/512 result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
static void sha512_hmac( const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char output[64], int is384 );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
static int sha512_self_test( int verbose );

/* Internal use */
static void sha512_process( sha512_context *ctx, const unsigned char data[128] );

#ifdef __cplusplus
}
#endif

#endif /* sha512.h */
/**
 * \file entropy.h
 *
 * \brief Entropy accumulator implementation
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_ENTROPY_H
#define POLARSSL_ENTROPY_H

#include <string.h>

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_SHA512_C) && !defined(POLARSSL_ENTROPY_FORCE_SHA256)
//#include "sha512.h"
#define POLARSSL_ENTROPY_SHA512_ACCUMULATOR
#else
#if defined(POLARSSL_SHA256_C)
#define POLARSSL_ENTROPY_SHA256_ACCUMULATOR
//#include "sha256.h"
#endif
#endif

#if defined(POLARSSL_THREADING_C)
//#include "threading.h"
#endif

#if defined(POLARSSL_HAVEGE_C)
//#include "havege.h"
#endif

#define POLARSSL_ERR_ENTROPY_SOURCE_FAILED                 -0x003C  /**< Critical entropy source failure. */
#define POLARSSL_ERR_ENTROPY_MAX_SOURCES                   -0x003E  /**< No more sources can be added. */
#define POLARSSL_ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040  /**< No sources have been added to poll. */
#define POLARSSL_ERR_ENTROPY_FILE_IO_ERROR                 -0x0058  /**< Read/write error in file. */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(ENTROPY_MAX_SOURCES)
#define ENTROPY_MAX_SOURCES     20      /**< Maximum number of sources supported */
#endif

#if !defined(ENTROPY_MAX_GATHER)
#define ENTROPY_MAX_GATHER      128     /**< Maximum amount requested from entropy sources */
#endif

/* \} name SECTION: Module settings */

#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
#define ENTROPY_BLOCK_SIZE      64      /**< Block size of entropy accumulator (SHA-512) */
#else
#define ENTROPY_BLOCK_SIZE      32      /**< Block size of entropy accumulator (SHA-256) */
#endif

#define ENTROPY_MAX_SEED_SIZE   1024    /**< Maximum size of seed we read from seed file */
#define ENTROPY_SOURCE_MANUAL   ENTROPY_MAX_SOURCES

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Entropy poll callback pointer
 *
 * \param data      Callback-specific data pointer
 * \param output    Data to fill
 * \param len       Maximum size to provide
 * \param olen      The actual amount of bytes put into the buffer (Can be 0)
 *
 * \return          0 if no critical failures occurred,
 *                  POLARSSL_ERR_ENTROPY_SOURCE_FAILED otherwise
 */
typedef int (*f_source_ptr)(void *data, unsigned char *output, size_t len,
                            size_t *olen);

/**
 * \brief           Entropy source state
 */
typedef struct
{
    f_source_ptr    f_source;   /**< The entropy source callback */
    void *          p_source;   /**< The callback data pointer */
    size_t          size;       /**< Amount received */
    size_t          threshold;  /**< Minimum level required before release */
}
source_state;

/**
 * \brief           Entropy context structure
 */
typedef struct
{
#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
    sha512_context  accumulator;
#else
    sha256_context  accumulator;
#endif
    int             source_count;
    source_state    source[ENTROPY_MAX_SOURCES];
#if defined(POLARSSL_HAVEGE_C)
    havege_state    havege_data;
#endif
#if defined(POLARSSL_THREADING_C)
    threading_mutex_t mutex;    /*!< mutex                  */
#endif
}
entropy_context;

/**
 * \brief           Initialize the context
 *
 * \param ctx       Entropy context to initialize
 */
static void entropy_init( entropy_context *ctx );

/**
 * \brief           Free the data in the context
 *
 * \param ctx       Entropy context to free
 */
static void entropy_free( entropy_context *ctx );

/**
 * \brief           Adds an entropy source to poll
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *                  ( with entropy_func() )
 *
 * \return          0 if successful or POLARSSL_ERR_ENTROPY_MAX_SOURCES
 */
static int entropy_add_source( entropy_context *ctx,
                        f_source_ptr f_source, void *p_source,
                        size_t threshold );

/**
 * \brief           Trigger an extra gather poll for the accumulator
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful, or POLARSSL_ERR_ENTROPY_SOURCE_FAILED
 */
static int entropy_gather( entropy_context *ctx );

/**
 * \brief           Retrieve entropy from the accumulator
 *                  (Maximum length: ENTROPY_BLOCK_SIZE)
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param data      Entropy context
 * \param output    Buffer to fill
 * \param len       Number of bytes desired, must be at most ENTROPY_BLOCK_SIZE
 *
 * \return          0 if successful, or POLARSSL_ERR_ENTROPY_SOURCE_FAILED
 */
static int entropy_func( void *data, unsigned char *output, size_t len );

/**
 * \brief           Add data to the accumulator manually
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param data      Data to add
 * \param len       Length of data
 *
 * \return          0 if successful
 */
static int entropy_update_manual( entropy_context *ctx,
                           const unsigned char *data, size_t len );

#if defined(POLARSSL_FS_IO)
/**
 * \brief               Write a seed file
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      POLARSSL_ERR_ENTROPY_FILE_IO_ERROR on file error, or
 *                      POLARSSL_ERR_ENTROPY_SOURCE_FAILED
 */
static int entropy_write_seed_file( entropy_context *ctx, const char *path );

/**
 * \brief               Read and update a seed file. Seed is added to this
 *                      instance. No more than ENTROPY_MAX_SEED_SIZE bytes are
 *                      read from the seed file. The rest is ignored.
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      POLARSSL_ERR_ENTROPY_FILE_IO_ERROR on file error,
 *                      POLARSSL_ERR_ENTROPY_SOURCE_FAILED
 */
static int entropy_update_seed_file( entropy_context *ctx, const char *path );
#endif /* POLARSSL_FS_IO */

#if defined(POLARSSL_SELF_TEST)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
static int entropy_self_test( int verbose );
#endif /* POLARSSL_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* entropy.h */
/**
 * \file entropy_poll.h
 *
 * \brief Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_ENTROPY_POLL_H
#define POLARSSL_ENTROPY_POLL_H

#include <string.h>

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default thresholds for built-in sources
 */
#define ENTROPY_MIN_PLATFORM    128     /**< Minimum for platform source    */
#define ENTROPY_MIN_HAVEGE      128     /**< Minimum for HAVEGE             */
#define ENTROPY_MIN_HARDCLOCK    32     /**< Minimum for hardclock()        */

#if !defined(POLARSSL_NO_PLATFORM_ENTROPY)
/**
 * \brief           Platform-specific entropy poll callback
 */
static int platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(POLARSSL_HAVEGE_C)
/**
 * \brief           HAVEGE based entropy poll callback
 *
 * Requires an HAVEGE state as its data pointer.
 */
static int havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(POLARSSL_TIMING_C)
/**
 * \brief           hardclock-based entropy poll callback
 */
static int hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen );
#endif

#ifdef __cplusplus
}
#endif

#endif /* entropy_poll.h */
/**
 * \file timing.h
 *
 * \brief Portable interface to the CPU cycle counter
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_TIMING_H
#define POLARSSL_TIMING_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if !defined(POLARSSL_TIMING_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          timer structure
 */
struct hr_time
{
    unsigned char opaque[32];
};

/*extern volatile int alarmed;*/
static volatile int alarmed = 0;

/**
 * \brief          Return the CPU cycle counter value
 */
static unsigned long hardclock( void );

/**
 * \brief          Return the elapsed time in milliseconds
 *
 * \param val      points to a timer structure
 * \param reset    if set to 1, the timer is restarted
 */
static unsigned long get_timer( struct hr_time *val, int reset );

/**
 * \brief          Setup an alarm clock
 *
 * \param seconds  delay before the "alarmed" flag is set
 */
static void set_alarm( int seconds );

/**
 * \brief          Sleep for a certain amount of time
 *
 * \param milliseconds  delay in milliseconds
 */
static void m_sleep( int milliseconds );

#if defined(POLARSSL_SELF_TEST)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
static int timing_self_test( int verbose );
#endif

#ifdef __cplusplus
}
#endif

#else  /* POLARSSL_TIMING_ALT */
//#include "timing_alt.h"
#endif /* POLARSSL_TIMING_ALT */

#endif /* timing.h */
/**
 * \file md.h
 *
 * \brief Generic message digest wrapper
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_MD_H
#define POLARSSL_MD_H

#include <string.h>

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

#define POLARSSL_ERR_MD_FEATURE_UNAVAILABLE                -0x5080  /**< The selected feature is not available. */
#define POLARSSL_ERR_MD_BAD_INPUT_DATA                     -0x5100  /**< Bad input parameters to function. */
#define POLARSSL_ERR_MD_ALLOC_FAILED                       -0x5180  /**< Failed to allocate memory. */
#define POLARSSL_ERR_MD_FILE_IO_ERROR                      -0x5200  /**< Opening or reading of file failed. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLARSSL_MD_NONE=0,
    POLARSSL_MD_MD2,
    POLARSSL_MD_MD4,
    POLARSSL_MD_MD5,
    POLARSSL_MD_SHA1,
    POLARSSL_MD_SHA224,
    POLARSSL_MD_SHA256,
    POLARSSL_MD_SHA384,
    POLARSSL_MD_SHA512,
    POLARSSL_MD_RIPEMD160,
} md_type_t;

#if defined(POLARSSL_SHA512_C)
#define POLARSSL_MD_MAX_SIZE         64  /* longest known is SHA512 */
#else
#define POLARSSL_MD_MAX_SIZE         32  /* longest known is SHA256 or less */
#endif

/**
 * Message digest information. Allows message digest functions to be called
 * in a generic way.
 */
typedef struct {
    /** Digest identifier */
    md_type_t type;

    /** Name of the message digest */
    const char * name;

    /** Output length of the digest function */
    int size;

    /** Digest initialisation function */
    void (*starts_func)( void *ctx );

    /** Digest update function */
    void (*update_func)( void *ctx, const unsigned char *input, size_t ilen );

    /** Digest finalisation function */
    void (*finish_func)( void *ctx, unsigned char *output );

    /** Generic digest function */
    void (*digest_func)( const unsigned char *input, size_t ilen,
                         unsigned char *output );

    /** Generic file digest function */
    int (*file_func)( const char *path, unsigned char *output );

    /** HMAC Initialisation function */
    void (*hmac_starts_func)( void *ctx, const unsigned char *key,
                              size_t keylen );

    /** HMAC update function */
    void (*hmac_update_func)( void *ctx, const unsigned char *input,
                              size_t ilen );

    /** HMAC finalisation function */
    void (*hmac_finish_func)( void *ctx, unsigned char *output);

    /** HMAC context reset function */
    void (*hmac_reset_func)( void *ctx );

    /** Generic HMAC function */
    void (*hmac_func)( const unsigned char *key, size_t keylen,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

    /** Internal use only */
    void (*process_func)( void *ctx, const unsigned char *input );
} md_info_t;

/**
 * Generic message digest context.
 */
typedef struct {
    /** Information about the associated message digest */
    const md_info_t *md_info;

    /** Digest-specific context */
    void *md_ctx;
} md_context_t;

#define MD_CONTEXT_T_INIT { \
    NULL, /* md_info */ \
    NULL, /* md_ctx */ \
}

/**
 * \brief Returns the list of digests supported by the generic digest module.
 *
 * \return          a statically allocated array of digests, the last entry
 *                  is 0.
 */
static const int *md_list( void );

/**
 * \brief           Returns the message digest information associated with the
 *                  given digest name.
 *
 * \param md_name   Name of the digest to search for.
 *
 * \return          The message digest information associated with md_name or
 *                  NULL if not found.
 */
static const md_info_t *md_info_from_string( const char *md_name );

/**
 * \brief           Returns the message digest information associated with the
 *                  given digest type.
 *
 * \param md_type   type of digest to search for.
 *
 * \return          The message digest information associated with md_type or
 *                  NULL if not found.
 */
static const md_info_t *md_info_from_type( md_type_t md_type );

/**
 * \brief               Initialize a md_context (as NONE)
 */
static void md_init( md_context_t *ctx );

/**
 * \brief               Free and clear the message-specific context of ctx.
 *                      Freeing ctx itself remains the responsibility of the
 *                      caller.
 */
static void md_free( md_context_t *ctx );

/**
 * \brief          Initialises and fills the message digest context structure
 *                 with the appropriate values.
 *
 * \note           Currently also clears structure. In future versions you
 *                 will be required to call md_init() on the structure
 *                 first.
 *
 * \param ctx      context to initialise. May not be NULL. The
 *                 digest-specific context (ctx->md_ctx) must be NULL. It will
 *                 be allocated, and must be freed using md_free_ctx() later.
 * \param md_info  message digest to use.
 *
 * \returns        \c 0 on success, \c POLARSSL_ERR_MD_BAD_INPUT_DATA on
 *                 parameter failure, \c POLARSSL_ERR_MD_ALLOC_FAILED if
 *                 allocation of the digest-specific context failed.
 */
static int md_init_ctx( md_context_t *ctx, const md_info_t *md_info );

/**
 * \brief          Free the message-specific context of ctx. Freeing ctx itself
 *                 remains the responsibility of the caller.
 *
 * \note           Deprecated: Redirects to md_free()
 *
 * \param ctx      Free the message-specific context
 *
 * \returns        0
 */
static int md_free_ctx( md_context_t *ctx );

/**
 * \brief           Returns the size of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          size of the message digest output.
 */
static inline unsigned char md_get_size( const md_info_t *md_info )
{
    if( md_info == NULL )
        return( 0 );

    return md_info->size;
}

/**
 * \brief           Returns the type of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          type of the message digest output.
 */
static inline md_type_t md_get_type( const md_info_t *md_info )
{
    if( md_info == NULL )
        return( POLARSSL_MD_NONE );

    return md_info->type;
}

/**
 * \brief           Returns the name of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          name of the message digest output.
 */
static inline const char *md_get_name( const md_info_t *md_info )
{
    if( md_info == NULL )
        return( NULL );

    return md_info->name;
}

/**
 * \brief          Set-up the given context for a new message digest
 *
 * \param ctx      generic message digest context.
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_starts( md_context_t *ctx );

/**
 * \brief          Generic message digest process buffer
 *
 * \param ctx      Generic message digest context
 * \param input    buffer holding the  datal
 * \param ilen     length of the input data
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_update( md_context_t *ctx, const unsigned char *input, size_t ilen );

/**
 * \brief          Generic message digest final digest
 *
 * \param ctx      Generic message digest context
 * \param output   Generic message digest checksum result
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_finish( md_context_t *ctx, unsigned char *output );

/**
 * \brief          Output = message_digest( input buffer )
 *
 * \param md_info  message digest info
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic message digest checksum result
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md( const md_info_t *md_info, const unsigned char *input, size_t ilen,
        unsigned char *output );

/**
 * \brief          Output = message_digest( file contents )
 *
 * \param md_info  message digest info
 * \param path     input file name
 * \param output   generic message digest checksum result
 *
 * \return         0 if successful, POLARSSL_ERR_MD_FILE_OPEN_FAILED if fopen
 *                 failed, POLARSSL_ERR_MD_FILE_READ_FAILED if fread failed,
 *                 POLARSSL_ERR_MD_BAD_INPUT_DATA if md_info was NULL.
 */
static int md_file( const md_info_t *md_info, const char *path,
             unsigned char *output );

/**
 * \brief          Generic HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_hmac_starts( md_context_t *ctx, const unsigned char *key,
                    size_t keylen );

/**
 * \brief          Generic HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_hmac_update( md_context_t *ctx, const unsigned char *input,
                    size_t ilen );

/**
 * \brief          Generic HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   Generic HMAC checksum result
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_hmac_finish( md_context_t *ctx, unsigned char *output);

/**
 * \brief          Generic HMAC context reset
 *
 * \param ctx      HMAC context to be reset
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_hmac_reset( md_context_t *ctx );

/**
 * \brief          Output = Generic_HMAC( hmac key, input buffer )
 *
 * \param md_info  message digest info
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic HMAC-result
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
static int md_hmac( const md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output );

/* Internal use */
static int md_process( md_context_t *ctx, const unsigned char *data );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_MD_H */
/**
 * \file md_wrap.h
 *
 * \brief Message digest wrappers.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_MD_WRAP_H
#define POLARSSL_MD_WRAP_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif
//#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(POLARSSL_MD2_C)
extern const md_info_t md2_info;
#endif
#if defined(POLARSSL_MD4_C)
extern const md_info_t md4_info;
#endif
#if defined(POLARSSL_MD5_C)
extern const md_info_t md5_info;
#endif
#if defined(POLARSSL_RIPEMD160_C)
extern const md_info_t ripemd160_info;
#endif
#if defined(POLARSSL_SHA1_C)
extern const md_info_t sha1_info;
#endif
#if defined(POLARSSL_SHA256_C)
extern const md_info_t sha224_info;
extern const md_info_t sha256_info;
#endif
#if defined(POLARSSL_SHA512_C)
extern const md_info_t sha384_info;
extern const md_info_t sha512_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_MD_WRAP_H */
/**
 * \file net.h
 *
 * \brief Network communication functions
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_NET_H
#define POLARSSL_NET_H

#include <string.h>

#define POLARSSL_ERR_NET_UNKNOWN_HOST                      -0x0056  /**< Failed to get an IP address for the given hostname. */
#define POLARSSL_ERR_NET_SOCKET_FAILED                     -0x0042  /**< Failed to open a socket. */
#define POLARSSL_ERR_NET_CONNECT_FAILED                    -0x0044  /**< The connection to the given server / port failed. */
#define POLARSSL_ERR_NET_BIND_FAILED                       -0x0046  /**< Binding of the socket failed. */
#define POLARSSL_ERR_NET_LISTEN_FAILED                     -0x0048  /**< Could not listen on the socket. */
#define POLARSSL_ERR_NET_ACCEPT_FAILED                     -0x004A  /**< Could not accept the incoming connection. */
#define POLARSSL_ERR_NET_RECV_FAILED                       -0x004C  /**< Reading information from the socket failed. */
#define POLARSSL_ERR_NET_SEND_FAILED                       -0x004E  /**< Sending information through the socket failed. */
#define POLARSSL_ERR_NET_CONN_RESET                        -0x0050  /**< Connection was reset by peer. */
#define POLARSSL_ERR_NET_WANT_READ                         -0x0052  /**< Connection requires a read call. */
#define POLARSSL_ERR_NET_WANT_WRITE                        -0x0054  /**< Connection requires a write call. */

#define POLARSSL_NET_LISTEN_BACKLOG         10 /**< The backlog that listen() should use. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initiate a TCP connection with host:port
 *
 * \param fd       Socket to use
 * \param host     Host to connect to
 * \param port     Port to connect to
 *
 * \return         0 if successful, or one of:
 *                      POLARSSL_ERR_NET_SOCKET_FAILED,
 *                      POLARSSL_ERR_NET_UNKNOWN_HOST,
 *                      POLARSSL_ERR_NET_CONNECT_FAILED
 */
static int net_connect( int *fd, const char *host, int port );

/**
 * \brief          Create a listening socket on bind_ip:port.
 *                 If bind_ip == NULL, all interfaces are binded.
 *
 * \param fd       Socket to use
 * \param bind_ip  IP to bind to, can be NULL
 * \param port     Port number to use
 *
 * \return         0 if successful, or one of:
 *                      POLARSSL_ERR_NET_SOCKET_FAILED,
 *                      POLARSSL_ERR_NET_BIND_FAILED,
 *                      POLARSSL_ERR_NET_LISTEN_FAILED
 */
static int net_bind( int *fd, const char *bind_ip, int port );

/**
 * \brief           Accept a connection from a remote client
 *
 * \param bind_fd   Relevant socket
 * \param client_fd Will contain the connected client socket
 * \param client_ip Will contain the client IP address
 *                  Must be at least 4 bytes, or 16 if IPv6 is supported
 *
 * \return          0 if successful, POLARSSL_ERR_NET_ACCEPT_FAILED, or
 *                  POLARSSL_ERR_NET_WANT_READ is bind_fd was set to
 *                  non-blocking and accept() is blocking.
 */
static int net_accept( int bind_fd, int *client_fd, void *client_ip );

/**
 * \brief          Set the socket blocking
 *
 * \param fd       Socket to set
 *
 * \return         0 if successful, or a non-zero error code
 */
static int net_set_block( int fd );

/**
 * \brief          Set the socket non-blocking
 *
 * \param fd       Socket to set
 *
 * \return         0 if successful, or a non-zero error code
 */
static int net_set_nonblock( int fd );

/**
 * \brief          Portable usleep helper
 *
 * \param usec     Amount of microseconds to sleep
 *
 * \note           Real amount of time slept will not be less than
 *                 select()'s timeout granularity (typically, 10ms).
 */
static void net_usleep( unsigned long usec );

/**
 * \brief          Read at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Socket
 * \param buf      The buffer to write to
 * \param len      Maximum length of the buffer
 *
 * \return         This function returns the number of bytes received,
 *                 or a non-zero error code; POLARSSL_ERR_NET_WANT_READ
 *                 indicates read() is blocking.
 */
static int net_recv( void *ctx, unsigned char *buf, size_t len );

/**
 * \brief          Write at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Socket
 * \param buf      The buffer to read from
 * \param len      The length of the buffer
 *
 * \return         This function returns the number of bytes sent,
 *                 or a non-zero error code; POLARSSL_ERR_NET_WANT_WRITE
 *                 indicates write() is blocking.
 */
static int net_send( void *ctx, const unsigned char *buf, size_t len );

/**
 * \brief          Gracefully shutdown the connection
 *
 * \param fd       The socket to close
 */
static void net_close( int fd );

#ifdef __cplusplus
}
#endif

#endif /* net.h */
/**
 * \file rsa.h
 *
 * \brief The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_RSA_H
#define POLARSSL_RSA_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

//#include "bignum.h"
//#include "md.h"

#if defined(POLARSSL_THREADING_C)
//#include "threading.h"
#endif

/*
 * RSA Error codes
 */
#define POLARSSL_ERR_RSA_BAD_INPUT_DATA                    -0x4080  /**< Bad input parameters to function. */
#define POLARSSL_ERR_RSA_INVALID_PADDING                   -0x4100  /**< Input data contains invalid padding and is rejected. */
#define POLARSSL_ERR_RSA_KEY_GEN_FAILED                    -0x4180  /**< Something failed during generation of a key. */
#define POLARSSL_ERR_RSA_KEY_CHECK_FAILED                  -0x4200  /**< Key failed to pass the libraries validity check. */
#define POLARSSL_ERR_RSA_PUBLIC_FAILED                     -0x4280  /**< The public key operation failed. */
#define POLARSSL_ERR_RSA_PRIVATE_FAILED                    -0x4300  /**< The private key operation failed. */
#define POLARSSL_ERR_RSA_VERIFY_FAILED                     -0x4380  /**< The PKCS#1 verification failed. */
#define POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE                  -0x4400  /**< The output buffer for decryption is not large enough. */
#define POLARSSL_ERR_RSA_RNG_FAILED                        -0x4480  /**< The random generator failed to generate non-zeros. */

/*
 * RSA constants
 */
#define RSA_PUBLIC      0
#define RSA_PRIVATE     1

#define RSA_PKCS_V15    0
#define RSA_PKCS_V21    1

#define RSA_SIGN        1
#define RSA_CRYPT       2

#define RSA_SALT_LEN_ANY    -1

/*
 * The above constants may be used even if the RSA module is compile out,
 * eg for alternative (PKCS#11) RSA implemenations in the PK layers.
 */
#if defined(POLARSSL_RSA_C)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          RSA context structure
 */
typedef struct
{
    int ver;                    /*!<  always 0          */
    size_t len;                 /*!<  size(N) in chars  */

    mpi N;                      /*!<  public modulus    */
    mpi E;                      /*!<  public exponent   */

    mpi D;                      /*!<  private exponent  */
    mpi P;                      /*!<  1st prime factor  */
    mpi Q;                      /*!<  2nd prime factor  */
    mpi DP;                     /*!<  D % (P - 1)       */
    mpi DQ;                     /*!<  D % (Q - 1)       */
    mpi QP;                     /*!<  1 / (Q % P)       */

    mpi RN;                     /*!<  cached R^2 mod N  */
    mpi RP;                     /*!<  cached R^2 mod P  */
    mpi RQ;                     /*!<  cached R^2 mod Q  */

#if !defined(POLARSSL_RSA_NO_CRT)
    mpi Vi;                     /*!<  cached blinding value     */
    mpi Vf;                     /*!<  cached un-blinding value  */
#endif

    int padding;                /*!<  RSA_PKCS_V15 for 1.5 padding and
                                      RSA_PKCS_v21 for OAEP/PSS         */
    int hash_id;                /*!<  Hash identifier of md_type_t as
                                      specified in the md.h header file
                                      for the EME-OAEP and EMSA-PSS
                                      encoding                          */
#if defined(POLARSSL_THREADING_C)
    threading_mutex_t mutex;    /*!<  Thread-safety mutex       */
#endif
}
rsa_context;

/**
 * \brief          Initialize an RSA context
 *
 *                 Note: Set padding to RSA_PKCS_V21 for the RSAES-OAEP
 *                 encryption scheme and the RSASSA-PSS signature scheme.
 *
 * \param ctx      RSA context to be initialized
 * \param padding  RSA_PKCS_V15 or RSA_PKCS_V21
 * \param hash_id  RSA_PKCS_V21 hash identifier
 *
 * \note           The hash_id parameter is actually ignored
 *                 when using RSA_PKCS_V15 padding.
 *
 * \note           Choice of padding mode is strictly enforced for private key
 *                 operations, since there might be security concerns in
 *                 mixing padding modes. For public key operations it's merely
 *                 a default value, which can be overriden by calling specific
 *                 rsa_rsaes_xxx or rsa_rsassa_xxx functions.
 *
 * \note           The chosen hash is always used for OEAP encryption.
 *                 For PSS signatures, it's always used for making signatures,
 *                 but can be overriden (and always is, if set to
 *                 POLARSSL_MD_NONE) for verifying them.
 */
static void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id);

/**
 * \brief          Set padding for an already initialized RSA context
 *                 See \c rsa_init() for details.
 *
 * \param ctx      RSA context to be set
 * \param padding  RSA_PKCS_V15 or RSA_PKCS_V21
 * \param hash_id  RSA_PKCS_V21 hash identifier
 */
static void rsa_set_padding( rsa_context *ctx, int padding, int hash_id);

/**
 * \brief          Generate an RSA keypair
 *
 * \param ctx      RSA context that will hold the key
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 * \param nbits    size of the public key in bits
 * \param exponent public exponent (e.g., 65537)
 *
 * \note           rsa_init() must be called beforehand to setup
 *                 the RSA context.
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
static int rsa_gen_key( rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent );

/**
 * \brief          Check a public RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
static int rsa_check_pubkey( const rsa_context *ctx );

/**
 * \brief          Check a private RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
static int rsa_check_privkey( const rsa_context *ctx );

/**
 * \brief          Do an RSA public key operation
 *
 * \param ctx      RSA context
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           This function does NOT take care of message
 *                 padding. Also, be sure to set input[0] = 0 or assure that
 *                 input is smaller than N.
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
static int rsa_public( rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output );

/**
 * \brief          Do an RSA private key operation
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for blinding)
 * \param p_rng    RNG parameter
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
static int rsa_private( rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output );

/**
 * \brief          Generic wrapper to perform a PKCS#1 encryption using the
 *                 mode from the context. Add the message padding, then do an
 *                 RSA operation.
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and PKCS#1 v2.1 encoding
 *                               and RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
static int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t ilen,
                       const unsigned char *input,
                       unsigned char *output );

/**
 * \brief          Perform a PKCS#1 v1.5 encryption (RSAES-PKCS1-v1_5-ENCRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
static int rsa_rsaes_pkcs1_v15_encrypt( rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output );

/**
 * \brief          Perform a PKCS#1 v2.1 OAEP encryption (RSAES-OAEP-ENCRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and PKCS#1 v2.1 encoding
 *                               and RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param label    buffer holding the custom label to use
 * \param label_len contains the label length
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
static int rsa_rsaes_oaep_encrypt( rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output );

/**
 * \brief          Generic wrapper to perform a PKCS#1 decryption using the
 *                 mode from the context. Do an RSA operation, then remove
 *                 the message padding
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
static int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len );

/**
 * \brief          Perform a PKCS#1 v1.5 decryption (RSAES-PKCS1-v1_5-DECRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
static int rsa_rsaes_pkcs1_v15_decrypt( rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len );

/**
 * \brief          Perform a PKCS#1 v2.1 OAEP decryption (RSAES-OAEP-DECRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param label    buffer holding the custom label to use
 * \param label_len contains the label length
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
static int rsa_rsaes_oaep_decrypt( rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len );

/**
 * \brief          Generic wrapper to perform a PKCS#1 signature using the
 *                 mode from the context. Do a private RSA operation to sign
 *                 a message digest
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for PKCS#1 v2.1 encoding and for
 *                               RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param md_alg   a POLARSSL_MD_* (use POLARSSL_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for POLARSSL_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           In case of PKCS#1 v2.1 encoding, see comments on
 * \note           \c rsa_rsassa_pss_sign() for details on md_alg and hash_id.
 */
static int rsa_pkcs1_sign( rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    int mode,
                    md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v1.5 signature (RSASSA-PKCS1-v1_5-SIGN)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param md_alg   a POLARSSL_MD_* (use POLARSSL_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for POLARSSL_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
static int rsa_rsassa_pkcs1_v15_sign( rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS signature (RSASSA-PSS-SIGN)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for PKCS#1 v2.1 encoding and for
 *                               RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param md_alg   a POLARSSL_MD_* (use POLARSSL_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for POLARSSL_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The hash_id in the RSA context is the one used for the
 *                 encoding. md_alg in the function call is the type of hash
 *                 that is encoded. According to RFC 3447 it is advised to
 *                 keep both hashes the same.
 */
static int rsa_rsassa_pss_sign( rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         int mode,
                         md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig );

/**
 * \brief          Generic wrapper to perform a PKCS#1 verification using the
 *                 mode from the context. Do a public RSA operation and check
 *                 the message digest
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param md_alg   a POLARSSL_MD_* (use POLARSSL_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for POLARSSL_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           In case of PKCS#1 v2.1 encoding, see comments on
 *                 \c rsa_rsassa_pss_verify() about md_alg and hash_id.
 */
static int rsa_pkcs1_verify( rsa_context *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng,
                      int mode,
                      md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v1.5 verification (RSASSA-PKCS1-v1_5-VERIFY)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param md_alg   a POLARSSL_MD_* (use POLARSSL_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for POLARSSL_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
static int rsa_rsassa_pkcs1_v15_verify( rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode,
                                 md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS verification (RSASSA-PSS-VERIFY)
 *                 (This is the "simple" version.)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param md_alg   a POLARSSL_MD_* (use POLARSSL_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for POLARSSL_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The hash_id in the RSA context is the one used for the
 *                 verification. md_alg in the function call is the type of
 *                 hash that is verified. According to RFC 3447 it is advised to
 *                 keep both hashes the same. If hash_id in the RSA context is
 *                 unset, the md_alg from the function call is used.
 */
static int rsa_rsassa_pss_verify( rsa_context *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           int mode,
                           md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS verification (RSASSA-PSS-VERIFY)
 *                 (This is the version with "full" options.)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param md_alg   a POLARSSL_MD_* (use POLARSSL_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for POLARSSL_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param mgf1_hash_id message digest used for mask generation
 * \param expected_salt_len Length of the salt used in padding, use
 *                 RSA_SALT_LEN_ANY to accept any salt length
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The hash_id in the RSA context is ignored.
 */
static int rsa_rsassa_pss_verify_ext( rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig );

/**
 * \brief          Copy the components of an RSA context
 *
 * \param dst      Destination context
 * \param src      Source context
 *
 * \return         O on success,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED on memory allocation failure
 */
static int rsa_copy( rsa_context *dst, const rsa_context *src );

/**
 * \brief          Free the components of an RSA key
 *
 * \param ctx      RSA Context to free
 */
static void rsa_free( rsa_context *ctx );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
static int rsa_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_RSA_C */

#endif /* rsa.h */
/**
 * \file asn1.h
 *
 * \brief Generic ASN.1 parsing
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_ASN1_H
#define POLARSSL_ASN1_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_BIGNUM_C)
//#include "bignum.h"
#endif

#include <string.h>

/**
 * \addtogroup asn1_module
 * \{
 */

/**
 * \name ASN1 Error codes
 * These error codes are OR'ed to X509 error codes for
 * higher error granularity.
 * ASN1 is a standard to specify data structures.
 * \{
 */
#define POLARSSL_ERR_ASN1_OUT_OF_DATA                      -0x0060  /**< Out of data when parsing an ASN1 data structure. */
#define POLARSSL_ERR_ASN1_UNEXPECTED_TAG                   -0x0062  /**< ASN1 tag was of an unexpected value. */
#define POLARSSL_ERR_ASN1_INVALID_LENGTH                   -0x0064  /**< Error when trying to determine the length or invalid length. */
#define POLARSSL_ERR_ASN1_LENGTH_MISMATCH                  -0x0066  /**< Actual length differs from expected length. */
#define POLARSSL_ERR_ASN1_INVALID_DATA                     -0x0068  /**< Data is invalid. (not used) */
#define POLARSSL_ERR_ASN1_MALLOC_FAILED                    -0x006A  /**< Memory allocation failed */
#define POLARSSL_ERR_ASN1_BUF_TOO_SMALL                    -0x006C  /**< Buffer too small when writing ASN.1 data structure. */

/* \} name */

/**
 * \name DER constants
 * These constants comply with DER encoded the ANS1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::x509_buf.
 * \{
 */
#define ASN1_BOOLEAN                 0x01
#define ASN1_INTEGER                 0x02
#define ASN1_BIT_STRING              0x03
#define ASN1_OCTET_STRING            0x04
#define ASN1_NULL                    0x05
#define ASN1_OID                     0x06
#define ASN1_UTF8_STRING             0x0C
#define ASN1_SEQUENCE                0x10
#define ASN1_SET                     0x11
#define ASN1_PRINTABLE_STRING        0x13
#define ASN1_T61_STRING              0x14
#define ASN1_IA5_STRING              0x16
#define ASN1_UTC_TIME                0x17
#define ASN1_GENERALIZED_TIME        0x18
#define ASN1_UNIVERSAL_STRING        0x1C
#define ASN1_BMP_STRING              0x1E
#define ASN1_PRIMITIVE               0x00
#define ASN1_CONSTRUCTED             0x20
#define ASN1_CONTEXT_SPECIFIC        0x80
/* \} name */
/* \} addtogroup asn1_module */

/** Returns the size of the binary string, without the trailing \\0 */
#define OID_SIZE(x) (sizeof(x) - 1)

/**
 * Compares an asn1_buf structure to a reference OID.
 *
 * Only works for 'defined' oid_str values (OID_HMAC_SHA1), you cannot use a
 * 'unsigned char *oid' here!
 *
 * Warning: returns true when the OIDs are equal (unlike memcmp)!
 */
#define OID_CMP(oid_str, oid_buf)                                   \
        ( ( OID_SIZE(oid_str) == (oid_buf)->len ) &&                \
          memcmp( (oid_str), (oid_buf)->p, (oid_buf)->len) == 0 )

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name Functions to parse ASN.1 data structures
 * \{
 */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef struct _asn1_buf
{
    int tag;                /**< ASN1 type, e.g. ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, e.g. in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
}
asn1_buf;

/**
 * Container for ASN1 bit strings.
 */
typedef struct _asn1_bitstring
{
    size_t len;                 /**< ASN1 length, e.g. in octets. */
    unsigned char unused_bits;  /**< Number of unused bits at the end of the string */
    unsigned char *p;           /**< Raw ASN1 data for the bit string */
}
asn1_bitstring;

/**
 * Container for a sequence of ASN.1 items
 */
typedef struct _asn1_sequence
{
    asn1_buf buf;                   /**< Buffer containing the given ASN.1 item. */
    struct _asn1_sequence *next;    /**< The next entry in the sequence. */
}
asn1_sequence;

/**
 * Container for a sequence or list of 'named' ASN.1 data items
 */
typedef struct _asn1_named_data
{
    asn1_buf oid;                   /**< The object identifier. */
    asn1_buf val;                   /**< The named value. */
    struct _asn1_named_data *next;  /**< The next entry in the sequence. */
}
asn1_named_data;

/**
 * \brief       Get the length of an ASN.1 element.
 *              Updates the pointer to immediately behind the length.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param len   The variable that will receive the value
 *
 * \return      0 if successful, POLARSSL_ERR_ASN1_OUT_OF_DATA on reaching
 *              end of data, POLARSSL_ERR_ASN1_INVALID_LENGTH if length is
 *              unparseable.
 */
static int asn1_get_len( unsigned char **p,
                  const unsigned char *end,
                  size_t *len );

/**
 * \brief       Get the tag and length of the tag. Check for the requested tag.
 *              Updates the pointer to immediately behind the tag and length.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param len   The variable that will receive the length
 * \param tag   The expected tag
 *
 * \return      0 if successful, POLARSSL_ERR_ASN1_UNEXPECTED_TAG if tag did
 *              not match requested tag, or another specific ASN.1 error code.
 */
static int asn1_get_tag( unsigned char **p,
                  const unsigned char *end,
                  size_t *len, int tag );

/**
 * \brief       Retrieve a boolean ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param val   The variable that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
static int asn1_get_bool( unsigned char **p,
                   const unsigned char *end,
                   int *val );

/**
 * \brief       Retrieve an integer ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param val   The variable that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
static int asn1_get_int( unsigned char **p,
                  const unsigned char *end,
                  int *val );

/**
 * \brief       Retrieve a bitstring ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param bs    The variable that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
static int asn1_get_bitstring( unsigned char **p, const unsigned char *end,
                        asn1_bitstring *bs);

/**
 * \brief       Retrieve a bitstring ASN.1 tag without unused bits and its
 *              value.
 *              Updates the pointer to the beginning of the bit/octet string.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param len   Length of the actual bit/octect string in bytes
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
static int asn1_get_bitstring_null( unsigned char **p, const unsigned char *end,
                             size_t *len );

/**
 * \brief       Parses and splits an ASN.1 "SEQUENCE OF <tag>"
 *              Updated the pointer to immediately behind the full sequence tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param cur   First variable in the chain to fill
 * \param tag   Type of sequence
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
static int asn1_get_sequence_of( unsigned char **p,
                          const unsigned char *end,
                          asn1_sequence *cur,
                          int tag);

#if defined(POLARSSL_BIGNUM_C)
/**
 * \brief       Retrieve a MPI value from an integer ASN.1 tag.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param X     The MPI that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 or MPI error code.
 */
static int asn1_get_mpi( unsigned char **p,
                  const unsigned char *end,
                  mpi *X );
#endif /* POLARSSL_BIGNUM_C */

/**
 * \brief       Retrieve an AlgorithmIdentifier ASN.1 sequence.
 *              Updates the pointer to immediately behind the full
 *              AlgorithmIdentifier.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param alg   The buffer to receive the OID
 * \param params The buffer to receive the params (if any)
 *
 * \return      0 if successful or a specific ASN.1 or MPI error code.
 */
static int asn1_get_alg( unsigned char **p,
                  const unsigned char *end,
                  asn1_buf *alg, asn1_buf *params );

/**
 * \brief       Retrieve an AlgorithmIdentifier ASN.1 sequence with NULL or no
 *              params.
 *              Updates the pointer to immediately behind the full
 *              AlgorithmIdentifier.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param alg   The buffer to receive the OID
 *
 * \return      0 if successful or a specific ASN.1 or MPI error code.
 */
static int asn1_get_alg_null( unsigned char **p,
                       const unsigned char *end,
                       asn1_buf *alg );

/**
 * \brief       Find a specific named_data entry in a sequence or list based on
 *              the OID.
 *
 * \param list  The list to seek through
 * \param oid   The OID to look for
 * \param len   Size of the OID
 *
 * \return      NULL if not found, or a pointer to the existing entry.
 */
static asn1_named_data *asn1_find_named_data( asn1_named_data *list,
                                       const char *oid, size_t len );

/**
 * \brief       Free a asn1_named_data entry
 *
 * \param entry The named data entry to free
 */
static void asn1_free_named_data( asn1_named_data *entry );

/**
 * \brief       Free all entries in a asn1_named_data list
 *              Head will be set to NULL
 *
 * \param head  Pointer to the head of the list of named data entries to free
 */
static void asn1_free_named_data_list( asn1_named_data **head );

#ifdef __cplusplus
}
#endif

#endif /* asn1.h */
/**
 * \file pk.h
 *
 * \brief Public Key abstraction layer
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef POLARSSL_PK_H
#define POLARSSL_PK_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

//#include "md.h"

#if defined(POLARSSL_RSA_C)
//#include "rsa.h"
#endif

#if defined(POLARSSL_ECP_C)
//#include "ecp.h"
#endif

#if defined(POLARSSL_ECDSA_C)
//#include "ecdsa.h"
#endif

#define POLARSSL_ERR_PK_MALLOC_FAILED       -0x2F80  /**< Memory alloation failed. */
#define POLARSSL_ERR_PK_TYPE_MISMATCH       -0x2F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define POLARSSL_ERR_PK_BAD_INPUT_DATA      -0x2E80  /**< Bad input parameters to function. */
#define POLARSSL_ERR_PK_FILE_IO_ERROR       -0x2E00  /**< Read/write of file failed. */
#define POLARSSL_ERR_PK_KEY_INVALID_VERSION -0x2D80  /**< Unsupported key version */
#define POLARSSL_ERR_PK_KEY_INVALID_FORMAT  -0x2D00  /**< Invalid key tag or value. */
#define POLARSSL_ERR_PK_UNKNOWN_PK_ALG      -0x2C80  /**< Key algorithm is unsupported (only RSA and EC are supported). */
#define POLARSSL_ERR_PK_PASSWORD_REQUIRED   -0x2C00  /**< Private key password can't be empty. */
#define POLARSSL_ERR_PK_PASSWORD_MISMATCH   -0x2B80  /**< Given private key password does not allow for correct decryption. */
#define POLARSSL_ERR_PK_INVALID_PUBKEY      -0x2B00  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
#define POLARSSL_ERR_PK_INVALID_ALG         -0x2A80  /**< The algorithm tag or value is invalid. */
#define POLARSSL_ERR_PK_UNKNOWN_NAMED_CURVE -0x2A00  /**< Elliptic curve is unsupported (only NIST curves are supported). */
#define POLARSSL_ERR_PK_FEATURE_UNAVAILABLE -0x2980  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
#define POLARSSL_ERR_PK_SIG_LEN_MISMATCH    -0x2000  /**< The signature is valid but its length is less than expected. */


#if defined(POLARSSL_RSA_C)
/**
 * Quick access to an RSA context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an RSA context
 * before using this macro!
 */
#define pk_rsa( pk )        ( (rsa_context *) (pk).pk_ctx )
#endif /* POLARSSL_RSA_C */

#if defined(POLARSSL_ECP_C)
/**
 * Quick access to an EC context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an EC context
 * before using this macro!
 */
#define pk_ec( pk )         ( (ecp_keypair *) (pk).pk_ctx )
#endif /* POLARSSL_ECP_C */


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Public key types
 */
typedef enum {
    POLARSSL_PK_NONE=0,
    POLARSSL_PK_RSA,
    POLARSSL_PK_ECKEY,
    POLARSSL_PK_ECKEY_DH,
    POLARSSL_PK_ECDSA,
    POLARSSL_PK_RSA_ALT,
    POLARSSL_PK_RSASSA_PSS,
} pk_type_t;

/**
 * \brief           Options for RSASSA-PSS signature verification.
 *                  See \c rsa_rsassa_pss_verify_ext()
 */
typedef struct
{
    md_type_t mgf1_hash_id;
    int expected_salt_len;

} pk_rsassa_pss_options;

/**
 * \brief           Types for interfacing with the debug module
 */
typedef enum
{
    POLARSSL_PK_DEBUG_NONE = 0,
    POLARSSL_PK_DEBUG_MPI,
    POLARSSL_PK_DEBUG_ECP,
} pk_debug_type;

/**
 * \brief           Item to send to the debug module
 */
typedef struct
{
    pk_debug_type type;
    const char *name;
    void *value;
} pk_debug_item;

/** Maximum number of item send for debugging, plus 1 */
#define POLARSSL_PK_DEBUG_MAX_ITEMS 3

/**
 * \brief           Public key information and operations
 */
typedef struct
{
    /** Public key type */
    pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_size)( const void * );

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)( pk_type_t type );

    /** Verify signature */
    int (*verify_func)( void *ctx, md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len );

    /** Make signature */
    int (*sign_func)( void *ctx, md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

    /** Decrypt message */
    int (*decrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Encrypt message */
    int (*encrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

    /** Interface with the debug module */
    void (*debug_func)( const void *ctx, pk_debug_item *items );

} pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct
{
    const pk_info_t *   pk_info;    /**< Public key informations        */
    void *              pk_ctx;     /**< Underlying public key context  */
} pk_context;

/**
 * \brief           Types for RSA-alt abstraction
 */
typedef int (*pk_rsa_alt_decrypt_func)( void *ctx, int mode, size_t *olen,
                    const unsigned char *input, unsigned char *output,
                    size_t output_max_len );
typedef int (*pk_rsa_alt_sign_func)( void *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                    int mode, md_type_t md_alg, unsigned int hashlen,
                    const unsigned char *hash, unsigned char *sig );
typedef size_t (*pk_rsa_alt_key_len_func)( void *ctx );

/**
 * \brief           Return information associated with the given PK type
 *
 * \param pk_type   PK type to search for.
 *
 * \return          The PK info associated with the type or NULL if not found.
 */
static const pk_info_t *pk_info_from_type( pk_type_t pk_type );

/**
 * \brief           Initialize a pk_context (as NONE)
 */
static void pk_init( pk_context *ctx );

/**
 * \brief           Free a pk_context
 */
static void pk_free( pk_context *ctx );

/**
 * \brief           Initialize a PK context with the information given
 *                  and allocates the type-specific PK subcontext.
 *
 * \param ctx       Context to initialize. Must be empty (type NONE).
 * \param info      Information to use
 *
 * \return          0 on success,
 *                  POLARSSL_ERR_PK_BAD_INPUT_DATA on invalid input,
 *                  POLARSSL_ERR_PK_MALLOC_FAILED on allocation failure.
 *
 * \note            For contexts holding an RSA-alt key, use
 *                  \c pk_init_ctx_rsa_alt() instead.
 */
static int pk_init_ctx( pk_context *ctx, const pk_info_t *info );

/**
 * \brief           Initialize an RSA-alt context
 *
 * \param ctx       Context to initialize. Must be empty (type NONE).
 * \param key       RSA key pointer
 * \param decrypt_func  Decryption function
 * \param sign_func     Signing function
 * \param key_len_func  Function returning key length in bytes
 *
 * \return          0 on success, or POLARSSL_ERR_PK_BAD_INPUT_DATA if the
 *                  context wasn't already initialized as RSA_ALT.
 *
 * \note            This function replaces \c pk_init_ctx() for RSA-alt.
 */
static int pk_init_ctx_rsa_alt( pk_context *ctx, void * key,
                         pk_rsa_alt_decrypt_func decrypt_func,
                         pk_rsa_alt_sign_func sign_func,
                         pk_rsa_alt_key_len_func key_len_func );

/**
 * \brief           Get the size in bits of the underlying key
 *
 * \param ctx       Context to use
 *
 * \return          Key size in bits, or 0 on error
 */
size_t pk_get_size( const pk_context *ctx );

/**
 * \brief           Get the length in bytes of the underlying key
 * \param ctx       Context to use
 *
 * \return          Key length in bytes, or 0 on error
 */
static inline size_t pk_get_len( const pk_context *ctx )
{
    return( ( pk_get_size( ctx ) + 7 ) / 8 );
}

/**
 * \brief           Tell if a context can do the operation given by type
 *
 * \param ctx       Context to test
 * \param type      Target type
 *
 * \return          0 if context can't do the operations,
 *                  1 otherwise.
 */
static int pk_can_do( pk_context *ctx, pk_type_t type );

/**
 * \brief           Verify signature (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  POLARSSL_ERR_PK_SIG_LEN_MISMATCH if the signature is
 *                  valid but its actual length is less than sig_len,
 *                  or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  Use \c pk_verify_ext( POLARSSL_PK_RSASSA_PSS, ... )
 *                  to verify RSASSA_PSS signatures.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be POLARSSL_MD_NONE, only if hash_len != 0
 */
static int pk_verify( pk_context *ctx, md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len );

/**
 * \brief           Verify signature, with options.
 *                  (Includes verification of the padding depending on type.)
 *
 * \param type      Signature type (inc. possible padding type) to verify
 * \param options   Pointer to type-specific options, or NULL
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  POLARSSL_ERR_PK_TYPE_MISMATCH if the PK context can't be
 *                  used for this type of signatures,
 *                  POLARSSL_ERR_PK_SIG_LEN_MISMATCH if the signature is
 *                  valid but its actual length is less than sig_len,
 *                  or a specific error code.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be POLARSSL_MD_NONE, only if hash_len != 0
 *
 * \note            If type is POLARSSL_PK_RSASSA_PSS, then options must point
 *                  to a pk_rsassa_pss_options structure,
 *                  otherwise it must be NULL.
 */
static int pk_verify_ext( pk_type_t type, const void *options,
                   pk_context *ctx, md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len );

/**
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Place to write the signature
 * \param sig_len   Number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be POLARSSL_MD_NONE, only if hash_len != 0
 */
static int pk_sign( pk_context *ctx, md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Decrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param input     Input to decrypt
 * \param ilen      Input size
 * \param output    Decrypted output
 * \param olen      Decrypted message length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
static int pk_decrypt( pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Encrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param input     Message to encrypt
 * \param ilen      Message size
 * \param output    Encrypted output
 * \param olen      Encrypted output length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
static int pk_encrypt( pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Export debug information
 *
 * \param ctx       Context to use
 * \param items     Place to write debug items
 *
 * \return          0 on success or POLARSSL_ERR_PK_BAD_INPUT_DATA
 */
static int pk_debug( const pk_context *ctx, pk_debug_item *items );

/**
 * \brief           Access the type name
 *
 * \param ctx       Context to use
 *
 * \return          Type name on success, or "invalid PK"
 */
static const char * pk_get_name( const pk_context *ctx );

/**
 * \brief           Get the key type
 *
 * \param ctx       Context to use
 *
 * \return          Type on success, or POLARSSL_PK_NONE
 */
static pk_type_t pk_get_type( const pk_context *ctx );

#if defined(POLARSSL_PK_PARSE_C)
/** \ingroup pk_module */
/**
 * \brief           Parse a private key
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 * \param pwd       password for decryption (optional)
 * \param pwdlen    size of the password
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with pk_init() or reset with pk_free(). If you need a
 *                  specific key type, check the result with pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
static int pk_parse_key( pk_context *ctx,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen );

/** \ingroup pk_module */
/**
 * \brief           Parse a public key
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with pk_init() or reset with pk_free(). If you need a
 *                  specific key type, check the result with pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
static int pk_parse_public_key( pk_context *ctx,
                         const unsigned char *key, size_t keylen );

#if defined(POLARSSL_FS_IO)
/** \ingroup pk_module */
/**
 * \brief           Load and parse a private key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the private key from
 * \param password  password to decrypt the file (can be NULL)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with pk_init() or reset with pk_free(). If you need a
 *                  specific key type, check the result with pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
static int pk_parse_keyfile( pk_context *ctx,
                      const char *path, const char *password );

/** \ingroup pk_module */
/**
 * \brief           Load and parse a public key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the private key from
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with pk_init() or reset with pk_free(). If you need a
 *                  specific key type, check the result with pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
static int pk_parse_public_keyfile( pk_context *ctx, const char *path );
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PK_PARSE_C */

#if defined(POLARSSL_PK_WRITE_C)
/**
 * \brief           Write a private key to a PKCS#1 or SEC1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
static int pk_write_key_der( pk_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
static int pk_write_pubkey_der( pk_context *ctx, unsigned char *buf, size_t size );

#if defined(POLARSSL_PEM_WRITE_C)
/**
 * \brief           Write a public key to a PEM string
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 successful, or a specific error code
 */
static int pk_write_pubkey_pem( pk_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a private key to a PKCS#1 or SEC1 PEM string
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 successful, or a specific error code
 */
static int pk_write_key_pem( pk_context *ctx, unsigned char *buf, size_t size );
#endif /* POLARSSL_PEM_WRITE_C */
#endif /* POLARSSL_PK_WRITE_C */

/*
 * WARNING: Low-level functions. You probably do not want to use these unless
 *          you are certain you do ;)
 */

#if defined(POLARSSL_PK_PARSE_C)
/**
 * \brief           Parse a SubjectPublicKeyInfo DER structure
 *
 * \param p         the position in the ASN.1 data
 * \param end       end of the buffer
 * \param pk        the key to fill
 *
 * \return          0 if successful, or a specific PK error code
 */
static int pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        pk_context *pk );
#endif /* POLARSSL_PK_PARSE_C */

#if defined(POLARSSL_PK_WRITE_C)
/**
 * \brief           Write a subjectPublicKey to ASN.1 data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param key       public key to write away
 *
 * \return          the length written or a negative error code
 */
static int pk_write_pubkey( unsigned char **p, unsigned char *start,
                     const pk_context *key );
#endif /* POLARSSL_PK_WRITE_C */

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_PK_H */
/**
 * \file cipher.h
 *
 * \brief Generic cipher wrapper.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef POLARSSL_CIPHER_H
#define POLARSSL_CIPHER_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_GCM_C) || defined(POLARSSL_CCM_C)
#define POLARSSL_CIPHER_MODE_AEAD
#endif

#if defined(POLARSSL_CIPHER_MODE_CBC)
#define POLARSSL_CIPHER_MODE_WITH_PADDING
#endif

#include <string.h>

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

#define POLARSSL_ERR_CIPHER_FEATURE_UNAVAILABLE            -0x6080  /**< The selected feature is not available. */
#define POLARSSL_ERR_CIPHER_BAD_INPUT_DATA                 -0x6100  /**< Bad input parameters to function. */
#define POLARSSL_ERR_CIPHER_ALLOC_FAILED                   -0x6180  /**< Failed to allocate memory. */
#define POLARSSL_ERR_CIPHER_INVALID_PADDING                -0x6200  /**< Input data contains invalid padding and is rejected. */
#define POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED            -0x6280  /**< Decryption of block requires a full block. */
#define POLARSSL_ERR_CIPHER_AUTH_FAILED                    -0x6300  /**< Authentication failed (for AEAD modes). */

#define POLARSSL_CIPHER_VARIABLE_IV_LEN     0x01    /**< Cipher accepts IVs of variable length */
#define POLARSSL_CIPHER_VARIABLE_KEY_LEN    0x02    /**< Cipher accepts keys of variable length */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLARSSL_CIPHER_ID_NONE = 0,
    POLARSSL_CIPHER_ID_NULL,
    POLARSSL_CIPHER_ID_AES,
    POLARSSL_CIPHER_ID_DES,
    POLARSSL_CIPHER_ID_3DES,
    POLARSSL_CIPHER_ID_CAMELLIA,
    POLARSSL_CIPHER_ID_BLOWFISH,
    POLARSSL_CIPHER_ID_ARC4,
} cipher_id_t;

typedef enum {
    POLARSSL_CIPHER_NONE = 0,
    POLARSSL_CIPHER_NULL,
    POLARSSL_CIPHER_AES_128_ECB,
    POLARSSL_CIPHER_AES_192_ECB,
    POLARSSL_CIPHER_AES_256_ECB,
    POLARSSL_CIPHER_AES_128_CBC,
    POLARSSL_CIPHER_AES_192_CBC,
    POLARSSL_CIPHER_AES_256_CBC,
    POLARSSL_CIPHER_AES_128_CFB128,
    POLARSSL_CIPHER_AES_192_CFB128,
    POLARSSL_CIPHER_AES_256_CFB128,
    POLARSSL_CIPHER_AES_128_CTR,
    POLARSSL_CIPHER_AES_192_CTR,
    POLARSSL_CIPHER_AES_256_CTR,
    POLARSSL_CIPHER_AES_128_GCM,
    POLARSSL_CIPHER_AES_192_GCM,
    POLARSSL_CIPHER_AES_256_GCM,
    POLARSSL_CIPHER_CAMELLIA_128_ECB,
    POLARSSL_CIPHER_CAMELLIA_192_ECB,
    POLARSSL_CIPHER_CAMELLIA_256_ECB,
    POLARSSL_CIPHER_CAMELLIA_128_CBC,
    POLARSSL_CIPHER_CAMELLIA_192_CBC,
    POLARSSL_CIPHER_CAMELLIA_256_CBC,
    POLARSSL_CIPHER_CAMELLIA_128_CFB128,
    POLARSSL_CIPHER_CAMELLIA_192_CFB128,
    POLARSSL_CIPHER_CAMELLIA_256_CFB128,
    POLARSSL_CIPHER_CAMELLIA_128_CTR,
    POLARSSL_CIPHER_CAMELLIA_192_CTR,
    POLARSSL_CIPHER_CAMELLIA_256_CTR,
    POLARSSL_CIPHER_CAMELLIA_128_GCM,
    POLARSSL_CIPHER_CAMELLIA_192_GCM,
    POLARSSL_CIPHER_CAMELLIA_256_GCM,
    POLARSSL_CIPHER_DES_ECB,
    POLARSSL_CIPHER_DES_CBC,
    POLARSSL_CIPHER_DES_EDE_ECB,
    POLARSSL_CIPHER_DES_EDE_CBC,
    POLARSSL_CIPHER_DES_EDE3_ECB,
    POLARSSL_CIPHER_DES_EDE3_CBC,
    POLARSSL_CIPHER_BLOWFISH_ECB,
    POLARSSL_CIPHER_BLOWFISH_CBC,
    POLARSSL_CIPHER_BLOWFISH_CFB64,
    POLARSSL_CIPHER_BLOWFISH_CTR,
    POLARSSL_CIPHER_ARC4_128,
    POLARSSL_CIPHER_AES_128_CCM,
    POLARSSL_CIPHER_AES_192_CCM,
    POLARSSL_CIPHER_AES_256_CCM,
    POLARSSL_CIPHER_CAMELLIA_128_CCM,
    POLARSSL_CIPHER_CAMELLIA_192_CCM,
    POLARSSL_CIPHER_CAMELLIA_256_CCM,
} cipher_type_t;

typedef enum {
    POLARSSL_MODE_NONE = 0,
    POLARSSL_MODE_ECB,
    POLARSSL_MODE_CBC,
    POLARSSL_MODE_CFB,
    POLARSSL_MODE_OFB, /* Unused! */
    POLARSSL_MODE_CTR,
    POLARSSL_MODE_GCM,
    POLARSSL_MODE_STREAM,
    POLARSSL_MODE_CCM,
} cipher_mode_t;

typedef enum {
    POLARSSL_PADDING_PKCS7 = 0,     /**< PKCS7 padding (default)        */
    POLARSSL_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding         */
    POLARSSL_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding             */
    POLARSSL_PADDING_ZEROS,         /**< zero padding (not reversible!) */
    POLARSSL_PADDING_NONE,          /**< never pad (full blocks only)   */
} cipher_padding_t;

typedef enum {
    POLARSSL_OPERATION_NONE = -1,
    POLARSSL_DECRYPT = 0,
    POLARSSL_ENCRYPT,
} operation_t;

enum {
    /** Undefined key length */
    POLARSSL_KEY_LENGTH_NONE = 0,
    /** Key length, in bits (including parity), for DES keys */
    POLARSSL_KEY_LENGTH_DES  = 64,
    /** Key length, in bits (including parity), for DES in two key EDE */
    POLARSSL_KEY_LENGTH_DES_EDE = 128,
    /** Key length, in bits (including parity), for DES in three-key EDE */
    POLARSSL_KEY_LENGTH_DES_EDE3 = 192,
};

/** Maximum length of any IV, in bytes */
#define POLARSSL_MAX_IV_LENGTH      16
/** Maximum block size of any cipher, in bytes */
#define POLARSSL_MAX_BLOCK_LENGTH   16

/**
 * Base cipher information. The non-mode specific functions and values.
 */
typedef struct {

    /** Base Cipher type (e.g. POLARSSL_CIPHER_ID_AES) */
    cipher_id_t cipher;

    /** Encrypt using ECB */
    int (*ecb_func)( void *ctx, operation_t mode,
                     const unsigned char *input, unsigned char *output );

    /** Encrypt using CBC */
    int (*cbc_func)( void *ctx, operation_t mode, size_t length,
                     unsigned char *iv, const unsigned char *input,
                     unsigned char *output );

    /** Encrypt using CFB (Full length) */
    int (*cfb_func)( void *ctx, operation_t mode, size_t length, size_t *iv_off,
                     unsigned char *iv, const unsigned char *input,
                     unsigned char *output );

    /** Encrypt using CTR */
    int (*ctr_func)( void *ctx, size_t length, size_t *nc_off,
                     unsigned char *nonce_counter, unsigned char *stream_block,
                     const unsigned char *input, unsigned char *output );

    /** Encrypt using STREAM */
    int (*stream_func)( void *ctx, size_t length,
                        const unsigned char *input, unsigned char *output );

    /** Set key for encryption purposes */
    int (*setkey_enc_func)( void *ctx, const unsigned char *key,
                            unsigned int key_length );

    /** Set key for decryption purposes */
    int (*setkey_dec_func)( void *ctx, const unsigned char *key,
                            unsigned int key_length);

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

} cipher_base_t;

/**
 * Cipher information. Allows cipher functions to be called in a generic way.
 */
typedef struct {
    /** Full cipher identifier (e.g. POLARSSL_CIPHER_AES_256_CBC) */
    cipher_type_t type;

    /** Cipher mode (e.g. POLARSSL_MODE_CBC) */
    cipher_mode_t mode;

    /** Cipher key length, in bits (default length for variable sized ciphers)
     *  (Includes parity bits for ciphers like DES) */
    unsigned int key_length;

    /** Name of the cipher */
    const char * name;

    /** IV/NONCE size, in bytes.
     *  For cipher that accept many sizes: recommended size */
    unsigned int iv_size;

    /** Flags for variable IV size, variable key size, etc. */
    int flags;

    /** block size, in bytes */
    unsigned int block_size;

    /** Base cipher information and functions */
    const cipher_base_t *base;

} cipher_info_t;

/**
 * Generic cipher context.
 */
typedef struct {
    /** Information about the associated cipher */
    const cipher_info_t *cipher_info;

    /** Key length to use */
    int key_length;

    /** Operation that the context's key has been initialised for */
    operation_t operation;

    /** Padding functions to use, if relevant for cipher mode */
    void (*add_padding)( unsigned char *output, size_t olen, size_t data_len );
    int (*get_padding)( unsigned char *input, size_t ilen, size_t *data_len );

    /** Buffer for data that hasn't been encrypted yet */
    unsigned char unprocessed_data[POLARSSL_MAX_BLOCK_LENGTH];

    /** Number of bytes that still need processing */
    size_t unprocessed_len;

    /** Current IV or NONCE_COUNTER for CTR-mode */
    unsigned char iv[POLARSSL_MAX_IV_LENGTH];

    /** IV size in bytes (for ciphers with variable-length IVs) */
    size_t iv_size;

    /** Cipher-specific context */
    void *cipher_ctx;
} cipher_context_t;

/**
 * \brief Returns the list of ciphers supported by the generic cipher module.
 *
 * \return              a statically allocated array of ciphers, the last entry
 *                      is 0.
 */
static const int *cipher_list( void );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher name.
 *
 * \param cipher_name   Name of the cipher to search for.
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_name, or NULL if not found.
 */
static const cipher_info_t *cipher_info_from_string( const char *cipher_name );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher type.
 *
 * \param cipher_type   Type of the cipher to search for.
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_type, or NULL if not found.
 */
static const cipher_info_t *cipher_info_from_type( const cipher_type_t cipher_type );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher id, key size and mode.
 *
 * \param cipher_id     Id of the cipher to search for
 *                      (e.g. POLARSSL_CIPHER_ID_AES)
 * \param key_length    Length of the key in bits
 * \param mode          Cipher mode (e.g. POLARSSL_MODE_CBC)
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_type, or NULL if not found.
 */
static const cipher_info_t *cipher_info_from_values( const cipher_id_t cipher_id,
                                              int key_length,
                                              const cipher_mode_t mode );

/**
 * \brief               Initialize a cipher_context (as NONE)
 */
static void cipher_init( cipher_context_t *ctx );

/**
 * \brief               Free and clear the cipher-specific context of ctx.
 *                      Freeing ctx itself remains the responsibility of the
 *                      caller.
 */
static void cipher_free( cipher_context_t *ctx );

/**
 * \brief               Initialises and fills the cipher context structure with
 *                      the appropriate values.
 *
 * \note                Currently also clears structure. In future versions you
 *                      will be required to call cipher_init() on the structure
 *                      first.
 *
 * \param ctx           context to initialise. May not be NULL.
 * \param cipher_info   cipher to use.
 *
 * \return              0 on success,
 *                      POLARSSL_ERR_CIPHER_BAD_INPUT_DATA on parameter failure,
 *                      POLARSSL_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context failed.
 */
static int cipher_init_ctx( cipher_context_t *ctx, const cipher_info_t *cipher_info );

/**
 * \brief               Free the cipher-specific context of ctx. Freeing ctx
 *                      itself remains the responsibility of the caller.
 *
 * \note                Deprecated: Redirects to cipher_free()
 *
 * \param ctx           Free the cipher-specific context
 *
 * \returns             0
 */
static int cipher_free_ctx( cipher_context_t *ctx );

/**
 * \brief               Returns the block size of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              size of the cipher's blocks, or 0 if ctx has not been
 *                      initialised.
 */
static inline unsigned int cipher_get_block_size( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    return ctx->cipher_info->block_size;
}

/**
 * \brief               Returns the mode of operation for the cipher.
 *                      (e.g. POLARSSL_MODE_CBC)
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              mode of operation, or POLARSSL_MODE_NONE if ctx
 *                      has not been initialised.
 */
static inline cipher_mode_t cipher_get_cipher_mode( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_MODE_NONE;

    return ctx->cipher_info->mode;
}

/**
 * \brief               Returns the size of the cipher's IV/NONCE in bytes.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              If IV has not been set yet: (recommended) IV size
 *                      (0 for ciphers not using IV/NONCE).
 *                      If IV has already been set: actual size.
 */
static inline int cipher_get_iv_size( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    if( ctx->iv_size != 0 )
        return (int) ctx->iv_size;

    return ctx->cipher_info->iv_size;
}

/**
 * \brief               Returns the type of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              type of the cipher, or POLARSSL_CIPHER_NONE if ctx has
 *                      not been initialised.
 */
static inline cipher_type_t cipher_get_type( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_CIPHER_NONE;

    return ctx->cipher_info->type;
}

/**
 * \brief               Returns the name of the given cipher, as a string.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              name of the cipher, or NULL if ctx was not initialised.
 */
static inline const char *cipher_get_name( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    return ctx->cipher_info->name;
}

/**
 * \brief               Returns the key length of the cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              cipher's key length, in bits, or
 *                      POLARSSL_KEY_LENGTH_NONE if ctx has not been
 *                      initialised.
 */
static inline int cipher_get_key_size ( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_KEY_LENGTH_NONE;

    return ctx->cipher_info->key_length;
}

/**
 * \brief               Returns the operation of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              operation (POLARSSL_ENCRYPT or POLARSSL_DECRYPT),
 *                      or POLARSSL_OPERATION_NONE if ctx has not been
 *                      initialised.
 */
static inline operation_t cipher_get_operation( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_OPERATION_NONE;

    return ctx->operation;
}

/**
 * \brief               Set the key to use with the given context.
 *
 * \param ctx           generic cipher context. May not be NULL. Must have been
 *                      initialised using cipher_context_from_type or
 *                      cipher_context_from_string.
 * \param key           The key to use.
 * \param key_length    key length to use, in bits.
 * \param operation     Operation that the key will be used for, either
 *                      POLARSSL_ENCRYPT or POLARSSL_DECRYPT.
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails or a cipher specific
 *                      error code.
 */
static int cipher_setkey( cipher_context_t *ctx, const unsigned char *key,
                   int key_length, const operation_t operation );

#if defined(POLARSSL_CIPHER_MODE_WITH_PADDING)
/**
 * \brief               Set padding mode, for cipher modes that use padding.
 *                      (Default: PKCS7 padding.)
 *
 * \param ctx           generic cipher context
 * \param mode          padding mode
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_FEATURE_UNAVAILABLE
 *                      if selected padding mode is not supported, or
 *                      POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if the cipher mode
 *                      does not support padding.
 */
static int cipher_set_padding_mode( cipher_context_t *ctx, cipher_padding_t mode );
#endif /* POLARSSL_CIPHER_MODE_WITH_PADDING */

/**
 * \brief               Set the initialization vector (IV) or nonce
 *
 * \param ctx           generic cipher context
 * \param iv            IV to use (or NONCE_COUNTER for CTR-mode ciphers)
 * \param iv_len        IV length for ciphers with variable-size IV;
 *                      discarded by ciphers with fixed-size IV.
 *
 * \returns             0 on success, or POLARSSL_ERR_CIPHER_BAD_INPUT_DATA
 *
 * \note                Some ciphers don't use IVs nor NONCE. For these
 *                      ciphers, this function has no effect.
 */
static int cipher_set_iv( cipher_context_t *ctx,
                   const unsigned char *iv, size_t iv_len );

/**
 * \brief               Finish preparation of the given context
 *
 * \param ctx           generic cipher context
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
static int cipher_reset( cipher_context_t *ctx );

#if defined(POLARSSL_GCM_C)
/**
 * \brief               Add additional data (for AEAD ciphers).
 *                      Currently only supported with GCM.
 *                      Must be called exactly once, after cipher_reset().
 *
 * \param ctx           generic cipher context
 * \param ad            Additional data to use.
 * \param ad_len        Length of ad.
 *
 * \return              0 on success, or a specific error code.
 */
static int cipher_update_ad( cipher_context_t *ctx,
                      const unsigned char *ad, size_t ad_len );
#endif /* POLARSSL_GCM_C */

/**
 * \brief               Generic cipher update function. Encrypts/decrypts
 *                      using the given cipher context. Writes as many block
 *                      size'd blocks of data as possible to output. Any data
 *                      that cannot be written immediately will either be added
 *                      to the next block, or flushed when cipher_final is
 *                      called.
 *                      Exception: for POLARSSL_MODE_ECB, expects single block
 *                                 in size (e.g. 16 bytes for AES)
 *
 * \param ctx           generic cipher context
 * \param input         buffer holding the input data
 * \param ilen          length of the input data
 * \param output        buffer for the output data. Should be able to hold at
 *                      least ilen + block_size. Cannot be the same buffer as
 *                      input!
 * \param olen          length of the output data, will be filled with the
 *                      actual number of bytes written.
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails,
 *                      POLARSSL_ERR_CIPHER_FEATURE_UNAVAILABLE on an
 *                      unsupported mode for a cipher or a cipher specific
 *                      error code.
 *
 * \note                If the underlying cipher is GCM, all calls to this
 *                      function, except the last one before cipher_finish(),
 *                      must have ilen a multiple of the block size.
 */
static int cipher_update( cipher_context_t *ctx, const unsigned char *input,
                   size_t ilen, unsigned char *output, size_t *olen );

/**
 * \brief               Generic cipher finalisation function. If data still
 *                      needs to be flushed from an incomplete block, data
 *                      contained within it will be padded with the size of
 *                      the last block, and written to the output buffer.
 *
 * \param ctx           Generic cipher context
 * \param output        buffer to write data to. Needs block_size available.
 * \param olen          length of the data written to the output buffer.
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails,
 *                      POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED if decryption
 *                      expected a full block but was not provided one,
 *                      POLARSSL_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting or a cipher specific error code.
 */
static int cipher_finish( cipher_context_t *ctx,
                   unsigned char *output, size_t *olen );

#if defined(POLARSSL_GCM_C)
/**
 * \brief               Write tag for AEAD ciphers.
 *                      Currently only supported with GCM.
 *                      Must be called after cipher_finish().
 *
 * \param ctx           Generic cipher context
 * \param tag           buffer to write the tag
 * \param tag_len       Length of the tag to write
 *
 * \return              0 on success, or a specific error code.
 */
static int cipher_write_tag( cipher_context_t *ctx,
                      unsigned char *tag, size_t tag_len );

/**
 * \brief               Check tag for AEAD ciphers.
 *                      Currently only supported with GCM.
 *                      Must be called after cipher_finish().
 *
 * \param ctx           Generic cipher context
 * \param tag           Buffer holding the tag
 * \param tag_len       Length of the tag to check
 *
 * \return              0 on success, or a specific error code.
 */
static int cipher_check_tag( cipher_context_t *ctx,
                      const unsigned char *tag, size_t tag_len );
#endif /* POLARSSL_GCM_C */

/**
 * \brief               Generic all-in-one encryption/decryption
 *                      (for all ciphers except AEAD constructs).
 *
 * \param ctx           generic cipher context
 * \param iv            IV to use (or NONCE_COUNTER for CTR-mode ciphers)
 * \param iv_len        IV length for ciphers with variable-size IV;
 *                      discarded by ciphers with fixed-size IV.
 * \param input         buffer holding the input data
 * \param ilen          length of the input data
 * \param output        buffer for the output data. Should be able to hold at
 *                      least ilen + block_size. Cannot be the same buffer as
 *                      input!
 * \param olen          length of the output data, will be filled with the
 *                      actual number of bytes written.
 *
 * \note                Some ciphers don't use IVs nor NONCE. For these
 *                      ciphers, use iv = NULL and iv_len = 0.
 *
 * \returns             0 on success, or
 *                      POLARSSL_ERR_CIPHER_BAD_INPUT_DATA, or
 *                      POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED if decryption
 *                      expected a full block but was not provided one, or
 *                      POLARSSL_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting, or
 *                      a cipher specific error code.
 */
static int cipher_crypt( cipher_context_t *ctx,
                  const unsigned char *iv, size_t iv_len,
                  const unsigned char *input, size_t ilen,
                  unsigned char *output, size_t *olen );

#if defined(POLARSSL_CIPHER_MODE_AEAD)
/**
 * \brief               Generic autenticated encryption (AEAD ciphers).
 *
 * \param ctx           generic cipher context
 * \param iv            IV to use (or NONCE_COUNTER for CTR-mode ciphers)
 * \param iv_len        IV length for ciphers with variable-size IV;
 *                      discarded by ciphers with fixed-size IV.
 * \param ad            Additional data to authenticate.
 * \param ad_len        Length of ad.
 * \param input         buffer holding the input data
 * \param ilen          length of the input data
 * \param output        buffer for the output data.
 *                      Should be able to hold at least ilen.
 * \param olen          length of the output data, will be filled with the
 *                      actual number of bytes written.
 * \param tag           buffer for the authentication tag
 * \param tag_len       desired tag length
 *
 * \returns             0 on success, or
 *                      POLARSSL_ERR_CIPHER_BAD_INPUT_DATA, or
 *                      a cipher specific error code.
 */
static int cipher_auth_encrypt( cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *ad, size_t ad_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen,
                         unsigned char *tag, size_t tag_len );

/**
 * \brief               Generic autenticated decryption (AEAD ciphers).
 *
 * \param ctx           generic cipher context
 * \param iv            IV to use (or NONCE_COUNTER for CTR-mode ciphers)
 * \param iv_len        IV length for ciphers with variable-size IV;
 *                      discarded by ciphers with fixed-size IV.
 * \param ad            Additional data to be authenticated.
 * \param ad_len        Length of ad.
 * \param input         buffer holding the input data
 * \param ilen          length of the input data
 * \param output        buffer for the output data.
 *                      Should be able to hold at least ilen.
 * \param olen          length of the output data, will be filled with the
 *                      actual number of bytes written.
 * \param tag           buffer holding the authentication tag
 * \param tag_len       length of the authentication tag
 *
 * \returns             0 on success, or
 *                      POLARSSL_ERR_CIPHER_BAD_INPUT_DATA, or
 *                      POLARSSL_ERR_CIPHER_AUTH_FAILED if data isn't authentic,
 *                      or a cipher specific error code.
 *
 * \note                If the data is not authentic, then the output buffer
 *                      is zeroed out to prevent the unauthentic plaintext to
 *                      be used by mistake, making this interface safer.
 */
static int cipher_auth_decrypt( cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *ad, size_t ad_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen,
                         const unsigned char *tag, size_t tag_len );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
static int cipher_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_CIPHER_H */
/**
 * \file x509.h
 *
 * \brief X.509 generic defines and structures
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_X509_H
#define POLARSSL_X509_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

//#include "asn1.h"
//#include "pk.h"

#if defined(POLARSSL_RSA_C)
//#include "rsa.h"
#endif

/**
 * \addtogroup x509_module
 * \{
 */

/**
 * \name X509 Error codes
 * \{
 */
#define POLARSSL_ERR_X509_FEATURE_UNAVAILABLE              -0x2080  /**< Unavailable feature, e.g. RSA hashing/encryption combination. */
#define POLARSSL_ERR_X509_UNKNOWN_OID                      -0x2100  /**< Requested OID is unknown. */
#define POLARSSL_ERR_X509_INVALID_FORMAT                   -0x2180  /**< The CRT/CRL/CSR format is invalid, e.g. different type expected. */
#define POLARSSL_ERR_X509_INVALID_VERSION                  -0x2200  /**< The CRT/CRL/CSR version element is invalid. */
#define POLARSSL_ERR_X509_INVALID_SERIAL                   -0x2280  /**< The serial tag or value is invalid. */
#define POLARSSL_ERR_X509_INVALID_ALG                      -0x2300  /**< The algorithm tag or value is invalid. */
#define POLARSSL_ERR_X509_INVALID_NAME                     -0x2380  /**< The name tag or value is invalid. */
#define POLARSSL_ERR_X509_INVALID_DATE                     -0x2400  /**< The date tag or value is invalid. */
#define POLARSSL_ERR_X509_INVALID_SIGNATURE                -0x2480  /**< The signature tag or value invalid. */
#define POLARSSL_ERR_X509_INVALID_EXTENSIONS               -0x2500  /**< The extension tag or value is invalid. */
#define POLARSSL_ERR_X509_UNKNOWN_VERSION                  -0x2580  /**< CRT/CRL/CSR has an unsupported version number. */
#define POLARSSL_ERR_X509_UNKNOWN_SIG_ALG                  -0x2600  /**< Signature algorithm (oid) is unsupported. */
#define POLARSSL_ERR_X509_SIG_MISMATCH                     -0x2680  /**< Signature algorithms do not match. (see \c ::x509_crt sig_oid) */
#define POLARSSL_ERR_X509_CERT_VERIFY_FAILED               -0x2700  /**< Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define POLARSSL_ERR_X509_CERT_UNKNOWN_FORMAT              -0x2780  /**< Format not recognized as DER or PEM. */
#define POLARSSL_ERR_X509_BAD_INPUT_DATA                   -0x2800  /**< Input invalid. */
#define POLARSSL_ERR_X509_MALLOC_FAILED                    -0x2880  /**< Allocation of memory failed. */
#define POLARSSL_ERR_X509_FILE_IO_ERROR                    -0x2900  /**< Read/write of file failed. */
/* \} name */

/**
 * \name X509 Verify codes
 * \{
 */
#define BADCERT_EXPIRED             0x01  /**< The certificate validity has expired. */
#define BADCERT_REVOKED             0x02  /**< The certificate has been revoked (is on a CRL). */
#define BADCERT_CN_MISMATCH         0x04  /**< The certificate Common Name (CN) does not match with the expected CN. */
#define BADCERT_NOT_TRUSTED         0x08  /**< The certificate is not correctly signed by the trusted CA. */
#define BADCRL_NOT_TRUSTED          0x10  /**< CRL is not correctly signed by the trusted CA. */
#define BADCRL_EXPIRED              0x20  /**< CRL is expired. */
#define BADCERT_MISSING             0x40  /**< Certificate was missing. */
#define BADCERT_SKIP_VERIFY         0x80  /**< Certificate verification was skipped. */
#define BADCERT_OTHER             0x0100  /**< Other reason (can be used by verify callback) */
#define BADCERT_FUTURE            0x0200  /**< The certificate validity starts in the future. */
#define BADCRL_FUTURE             0x0400  /**< The CRL is from the future */
/* \} name */
/* \} addtogroup x509_module */

/*
 * X.509 v3 Key Usage Extension flags
 */
#define KU_DIGITAL_SIGNATURE            (0x80)  /* bit 0 */
#define KU_NON_REPUDIATION              (0x40)  /* bit 1 */
#define KU_KEY_ENCIPHERMENT             (0x20)  /* bit 2 */
#define KU_DATA_ENCIPHERMENT            (0x10)  /* bit 3 */
#define KU_KEY_AGREEMENT                (0x08)  /* bit 4 */
#define KU_KEY_CERT_SIGN                (0x04)  /* bit 5 */
#define KU_CRL_SIGN                     (0x02)  /* bit 6 */

/*
 * Netscape certificate types
 * (http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html)
 */

#define NS_CERT_TYPE_SSL_CLIENT         (0x80)  /* bit 0 */
#define NS_CERT_TYPE_SSL_SERVER         (0x40)  /* bit 1 */
#define NS_CERT_TYPE_EMAIL              (0x20)  /* bit 2 */
#define NS_CERT_TYPE_OBJECT_SIGNING     (0x10)  /* bit 3 */
#define NS_CERT_TYPE_RESERVED           (0x08)  /* bit 4 */
#define NS_CERT_TYPE_SSL_CA             (0x04)  /* bit 5 */
#define NS_CERT_TYPE_EMAIL_CA           (0x02)  /* bit 6 */
#define NS_CERT_TYPE_OBJECT_SIGNING_CA  (0x01)  /* bit 7 */

/*
 * X.509 extension types
 *
 * Comments refer to the status for using certificates. Status can be
 * different for writing certificates or reading CRLs or CSRs.
 */
#define EXT_AUTHORITY_KEY_IDENTIFIER    (1 << 0)
#define EXT_SUBJECT_KEY_IDENTIFIER      (1 << 1)
#define EXT_KEY_USAGE                   (1 << 2)    /* Parsed but not used */
#define EXT_CERTIFICATE_POLICIES        (1 << 3)
#define EXT_POLICY_MAPPINGS             (1 << 4)
#define EXT_SUBJECT_ALT_NAME            (1 << 5)    /* Supported (DNS) */
#define EXT_ISSUER_ALT_NAME             (1 << 6)
#define EXT_SUBJECT_DIRECTORY_ATTRS     (1 << 7)
#define EXT_BASIC_CONSTRAINTS           (1 << 8)    /* Supported */
#define EXT_NAME_CONSTRAINTS            (1 << 9)
#define EXT_POLICY_CONSTRAINTS          (1 << 10)
#define EXT_EXTENDED_KEY_USAGE          (1 << 11)   /* Parsed but not used */
#define EXT_CRL_DISTRIBUTION_POINTS     (1 << 12)
#define EXT_INIHIBIT_ANYPOLICY          (1 << 13)
#define EXT_FRESHEST_CRL                (1 << 14)

#define EXT_NS_CERT_TYPE                (1 << 16)   /* Parsed (and then ?) */

/*
 * Storage format identifiers
 * Recognized formats: PEM and DER
 */
#define X509_FORMAT_DER                 1
#define X509_FORMAT_PEM                 2

#define X509_MAX_DN_NAME_SIZE         256 /**< Maximum value size of a DN entry */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures for parsing X.509 certificates, CRLs and CSRs
 * \{
 */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef asn1_buf x509_buf;

/**
 * Container for ASN1 bit strings.
 */
typedef asn1_bitstring x509_bitstring;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=polarssl,ou=code,etc.).
 */
typedef asn1_named_data x509_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef asn1_sequence x509_sequence;

/** Container for date and time (precision in seconds). */
typedef struct _x509_time
{
    int year, mon, day;         /**< Date. */
    int hour, min, sec;         /**< Time. */
}
x509_time;

/** \} name Structures for parsing X.509 certificates, CRLs and CSRs */
/** \} addtogroup x509_module */

/**
 * \brief          Store the certificate DN in printable form into buf;
 *                 no more than size characters will be written.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param dn       The X509 name to represent
 *
 * \return         The amount of data written to the buffer, or -1 in
 *                 case of an error.
 */
static int x509_dn_gets( char *buf, size_t size, const x509_name *dn );

/**
 * \brief          Store the certificate serial in printable form into buf;
 *                 no more than size characters will be written.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param serial   The X509 serial to represent
 *
 * \return         The amount of data written to the buffer, or -1 in
 *                 case of an error.
 */
static int x509_serial_gets( char *buf, size_t size, const x509_buf *serial );

/**
 * \brief          Give an known OID, return its descriptive string.
 *                 (Deprecated. Use oid_get_extended_key_usage() instead.)
 *                 Warning: only works for extended_key_usage OIDs!
 *
 * \param oid      buffer containing the oid
 *
 * \return         Return a string if the OID is known,
 *                 or NULL otherwise.
 */
static const char *x509_oid_get_description( x509_buf *oid );

/**
 * \brief          Give an OID, return a string version of its OID number.
 *                 (Deprecated. Use oid_get_numeric_string() instead)
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param oid      Buffer containing the OID
 *
 * \return         Length of the string written (excluding final NULL) or
 *                 POLARSSL_ERR_OID_BUF_TO_SMALL in case of error
 */
static int x509_oid_get_numeric_string( char *buf, size_t size, x509_buf *oid );

/**
 * \brief          Check a given x509_time against the system time and check
 *                 if it is not expired.
 *
 * \param time     x509_time to check
 *
 * \return         0 if the x509_time is still valid,
 *                 1 otherwise.
 */
static int x509_time_expired( const x509_time *time );

/**
 * \brief          Check a given x509_time against the system time and check
 *                 if it is not from the future.
 *
 * \param time     x509_time to check
 *
 * \return         0 if the x509_time is already valid,
 *                 1 otherwise.
 */
static int x509_time_future( const x509_time *time );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
static int x509_self_test( int verbose );

/*
 * Internal module functions. You probably do not want to use these unless you
 * know you do.
 */
static int x509_get_name( unsigned char **p, const unsigned char *end,
                   x509_name *cur );
static int x509_get_alg_null( unsigned char **p, const unsigned char *end,
                       x509_buf *alg );
static int x509_get_alg( unsigned char **p, const unsigned char *end,
                  x509_buf *alg, x509_buf *params );
#if defined(POLARSSL_X509_RSASSA_PSS_SUPPORT)
static int x509_get_rsassa_pss_params( const x509_buf *params,
                                md_type_t *md_alg, md_type_t *mgf_md,
                                int *salt_len );
#endif
static int x509_get_sig( unsigned char **p, const unsigned char *end, x509_buf *sig );
static int x509_get_sig_alg( const x509_buf *sig_oid, const x509_buf *sig_params,
                      md_type_t *md_alg, pk_type_t *pk_alg,
                      void **sig_opts );
static int x509_get_time( unsigned char **p, const unsigned char *end,
                   x509_time *time );
static int x509_get_serial( unsigned char **p, const unsigned char *end,
                     x509_buf *serial );
static int x509_get_ext( unsigned char **p, const unsigned char *end,
                  x509_buf *ext, int tag );
static int x509_load_file( const char *path, unsigned char **buf, size_t *n );
static int x509_sig_alg_gets( char *buf, size_t size, const x509_buf *sig_oid,
                       pk_type_t pk_alg, md_type_t md_alg,
                       const void *sig_opts );
static int x509_key_size_helper( char *buf, size_t size, const char *name );
static int x509_string_to_names( asn1_named_data **head, const char *name );
static int x509_set_extension( asn1_named_data **head, const char *oid, size_t oid_len,
                        int critical, const unsigned char *val,
                        size_t val_len );
static int x509_write_extensions( unsigned char **p, unsigned char *start,
                           asn1_named_data *first );
static int x509_write_names( unsigned char **p, unsigned char *start,
                      asn1_named_data *first );
static int x509_write_sig( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len,
                    unsigned char *sig, size_t size );

#ifdef __cplusplus
}
#endif

#endif /* x509.h */
/**
 * \file oid.h
 *
 * \brief Object Identifier (OID) database
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_OID_H
#define POLARSSL_OID_H

#include <string.h>
#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif
//#include "asn1.h"
//#include "pk.h"
#if defined(POLARSSL_CIPHER_C)
//#include "cipher.h"
#endif

#if defined(POLARSSL_MD_C)
//#include "md.h"
#endif

#if defined(POLARSSL_X509_USE_C) || defined(POLARSSL_X509_CREATE_C)
//#include "x509.h"
#endif

#define POLARSSL_ERR_OID_NOT_FOUND                         -0x002E  /**< OID is not found. */
#define POLARSSL_ERR_OID_BUF_TOO_SMALL                     -0x000B  /**< output buffer is too small */

/*
 * Top level OID tuples
 */
#define OID_ISO_MEMBER_BODIES           "\x2a"          /* {iso(1) member-body(2)} */
#define OID_ISO_IDENTIFIED_ORG          "\x2b"          /* {iso(1) identified-organization(3)} */
#define OID_ISO_CCITT_DS                "\x55"          /* {joint-iso-ccitt(2) ds(5)} */
#define OID_ISO_ITU_COUNTRY             "\x60"          /* {joint-iso-itu-t(2) country(16)} */

/*
 * ISO Member bodies OID parts
 */
#define OID_COUNTRY_US                  "\x86\x48"      /* {us(840)} */
#define OID_ORG_RSA_DATA_SECURITY       "\x86\xf7\x0d"  /* {rsadsi(113549)} */
#define OID_RSA_COMPANY                 OID_ISO_MEMBER_BODIES OID_COUNTRY_US \
                                        OID_ORG_RSA_DATA_SECURITY /* {iso(1) member-body(2) us(840) rsadsi(113549)} */
#define OID_ORG_ANSI_X9_62              "\xce\x3d" /* ansi-X9-62(10045) */
#define OID_ANSI_X9_62                  OID_ISO_MEMBER_BODIES OID_COUNTRY_US \
                                        OID_ORG_ANSI_X9_62

/*
 * ISO Identified organization OID parts
 */
#define OID_ORG_DOD                     "\x06"          /* {dod(6)} */
#define OID_ORG_OIW                     "\x0e"
#define OID_OIW_SECSIG                  OID_ORG_OIW "\x03"
#define OID_OIW_SECSIG_ALG              OID_OIW_SECSIG "\x02"
#define OID_OIW_SECSIG_SHA1             OID_OIW_SECSIG_ALG "\x1a"
#define OID_ORG_CERTICOM                "\x81\x04"  /* certicom(132) */
#define OID_CERTICOM                    OID_ISO_IDENTIFIED_ORG OID_ORG_CERTICOM
#define OID_ORG_TELETRUST               "\x24" /* teletrust(36) */
#define OID_TELETRUST                   OID_ISO_IDENTIFIED_ORG OID_ORG_TELETRUST

/*
 * ISO ITU OID parts
 */
#define OID_ORGANIZATION                "\x01"          /* {organization(1)} */
#define OID_ISO_ITU_US_ORG              OID_ISO_ITU_COUNTRY OID_COUNTRY_US OID_ORGANIZATION /* {joint-iso-itu-t(2) country(16) us(840) organization(1)} */

#define OID_ORG_GOV                     "\x65"          /* {gov(101)} */
#define OID_GOV                         OID_ISO_ITU_US_ORG OID_ORG_GOV /* {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)} */

#define OID_ORG_NETSCAPE                "\x86\xF8\x42"  /* {netscape(113730)} */
#define OID_NETSCAPE                    OID_ISO_ITU_US_ORG OID_ORG_NETSCAPE /* Netscape OID {joint-iso-itu-t(2) country(16) us(840) organization(1) netscape(113730)} */

/* ISO arc for standard certificate and CRL extensions */
#define OID_ID_CE                       OID_ISO_CCITT_DS "\x1D" /**< id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29} */

/**
 * Private Internet Extensions
 * { iso(1) identified-organization(3) dod(6) internet(1)
 *                      security(5) mechanisms(5) pkix(7) }
 */
#define OID_PKIX                        OID_ISO_IDENTIFIED_ORG OID_ORG_DOD "\x01\x05\x05\x07"

/*
 * Arc for standard naming attributes
 */
#define OID_AT                          OID_ISO_CCITT_DS "\x04" /**< id-at OBJECT IDENTIFIER ::= {joint-iso-ccitt(2) ds(5) 4} */
#define OID_AT_CN                       OID_AT "\x03" /**< id-at-commonName AttributeType:= {id-at 3} */
#define OID_AT_SUR_NAME                 OID_AT "\x04" /**< id-at-surName AttributeType:= {id-at 4} */
#define OID_AT_SERIAL_NUMBER            OID_AT "\x05" /**< id-at-serialNumber AttributeType:= {id-at 5} */
#define OID_AT_COUNTRY                  OID_AT "\x06" /**< id-at-countryName AttributeType:= {id-at 6} */
#define OID_AT_LOCALITY                 OID_AT "\x07" /**< id-at-locality AttributeType:= {id-at 7} */
#define OID_AT_STATE                    OID_AT "\x08" /**< id-at-state AttributeType:= {id-at 8} */
#define OID_AT_ORGANIZATION             OID_AT "\x0A" /**< id-at-organizationName AttributeType:= {id-at 10} */
#define OID_AT_ORG_UNIT                 OID_AT "\x0B" /**< id-at-organizationalUnitName AttributeType:= {id-at 11} */
#define OID_AT_TITLE                    OID_AT "\x0C" /**< id-at-title AttributeType:= {id-at 12} */
#define OID_AT_POSTAL_ADDRESS           OID_AT "\x10" /**< id-at-postalAddress AttributeType:= {id-at 16} */
#define OID_AT_POSTAL_CODE              OID_AT "\x11" /**< id-at-postalCode AttributeType:= {id-at 17} */
#define OID_AT_GIVEN_NAME               OID_AT "\x2A" /**< id-at-givenName AttributeType:= {id-at 42} */
#define OID_AT_INITIALS                 OID_AT "\x2B" /**< id-at-initials AttributeType:= {id-at 43} */
#define OID_AT_GENERATION_QUALIFIER     OID_AT "\x2C" /**< id-at-generationQualifier AttributeType:= {id-at 44} */
#define OID_AT_DN_QUALIFIER             OID_AT "\x2E" /**< id-at-dnQualifier AttributeType:= {id-at 46} */
#define OID_AT_PSEUDONYM                OID_AT "\x41" /**< id-at-pseudonym AttributeType:= {id-at 65} */

#define OID_DOMAIN_COMPONENT            "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19" /** id-domainComponent AttributeType:= {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) domainComponent(25)} */

/*
 * OIDs for standard certificate extensions
 */
#define OID_AUTHORITY_KEY_IDENTIFIER    OID_ID_CE "\x23" /**< id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 } */
#define OID_SUBJECT_KEY_IDENTIFIER      OID_ID_CE "\x0E" /**< id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 } */
#define OID_KEY_USAGE                   OID_ID_CE "\x0F" /**< id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 } */
#define OID_CERTIFICATE_POLICIES        OID_ID_CE "\x20" /**< id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 } */
#define OID_POLICY_MAPPINGS             OID_ID_CE "\x21" /**< id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 } */
#define OID_SUBJECT_ALT_NAME            OID_ID_CE "\x11" /**< id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 } */
#define OID_ISSUER_ALT_NAME             OID_ID_CE "\x12" /**< id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 } */
#define OID_SUBJECT_DIRECTORY_ATTRS     OID_ID_CE "\x09" /**< id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 } */
#define OID_BASIC_CONSTRAINTS           OID_ID_CE "\x13" /**< id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 } */
#define OID_NAME_CONSTRAINTS            OID_ID_CE "\x1E" /**< id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 } */
#define OID_POLICY_CONSTRAINTS          OID_ID_CE "\x24" /**< id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 } */
#define OID_EXTENDED_KEY_USAGE          OID_ID_CE "\x25" /**< id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 } */
#define OID_CRL_DISTRIBUTION_POINTS     OID_ID_CE "\x1F" /**< id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 } */
#define OID_INIHIBIT_ANYPOLICY          OID_ID_CE "\x36" /**< id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 } */
#define OID_FRESHEST_CRL                OID_ID_CE "\x2E" /**< id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 } */

/*
 * Netscape certificate extensions
 */
#define OID_NS_CERT                 OID_NETSCAPE "\x01"
#define OID_NS_CERT_TYPE            OID_NS_CERT  "\x01"
#define OID_NS_BASE_URL             OID_NS_CERT  "\x02"
#define OID_NS_REVOCATION_URL       OID_NS_CERT  "\x03"
#define OID_NS_CA_REVOCATION_URL    OID_NS_CERT  "\x04"
#define OID_NS_RENEWAL_URL          OID_NS_CERT  "\x07"
#define OID_NS_CA_POLICY_URL        OID_NS_CERT  "\x08"
#define OID_NS_SSL_SERVER_NAME      OID_NS_CERT  "\x0C"
#define OID_NS_COMMENT              OID_NS_CERT  "\x0D"
#define OID_NS_DATA_TYPE            OID_NETSCAPE "\x02"
#define OID_NS_CERT_SEQUENCE        OID_NS_DATA_TYPE "\x05"

/*
 * OIDs for CRL extensions
 */
#define OID_PRIVATE_KEY_USAGE_PERIOD    OID_ID_CE "\x10"
#define OID_CRL_NUMBER                  OID_ID_CE "\x14" /**< id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 } */

/*
 * X.509 v3 Extended key usage OIDs
 */
#define OID_ANY_EXTENDED_KEY_USAGE      OID_EXTENDED_KEY_USAGE "\x00" /**< anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 } */

#define OID_KP                          OID_PKIX "\x03" /**< id-kp OBJECT IDENTIFIER ::= { id-pkix 3 } */
#define OID_SERVER_AUTH                 OID_KP "\x01" /**< id-kp-serverAuth OBJECT IDENTIFIER ::= { id-kp 1 } */
#define OID_CLIENT_AUTH                 OID_KP "\x02" /**< id-kp-clientAuth OBJECT IDENTIFIER ::= { id-kp 2 } */
#define OID_CODE_SIGNING                OID_KP "\x03" /**< id-kp-codeSigning OBJECT IDENTIFIER ::= { id-kp 3 } */
#define OID_EMAIL_PROTECTION            OID_KP "\x04" /**< id-kp-emailProtection OBJECT IDENTIFIER ::= { id-kp 4 } */
#define OID_TIME_STAMPING               OID_KP "\x08" /**< id-kp-timeStamping OBJECT IDENTIFIER ::= { id-kp 8 } */
#define OID_OCSP_SIGNING                OID_KP "\x09" /**< id-kp-OCSPSigning OBJECT IDENTIFIER ::= { id-kp 9 } */

/*
 * PKCS definition OIDs
 */

#define OID_PKCS                OID_RSA_COMPANY "\x01" /**< pkcs OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) 1 } */
#define OID_PKCS1               OID_PKCS "\x01" /**< pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 } */
#define OID_PKCS5               OID_PKCS "\x05" /**< pkcs-5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 } */
#define OID_PKCS9               OID_PKCS "\x09" /**< pkcs-9 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 } */
#define OID_PKCS12              OID_PKCS "\x0c" /**< pkcs-12 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 } */

/*
 * PKCS#1 OIDs
 */
#define OID_PKCS1_RSA           OID_PKCS1 "\x01" /**< rsaEncryption OBJECT IDENTIFIER ::= { pkcs-1 1 } */
#define OID_PKCS1_MD2           OID_PKCS1 "\x02" /**< md2WithRSAEncryption ::= { pkcs-1 2 } */
#define OID_PKCS1_MD4           OID_PKCS1 "\x03" /**< md4WithRSAEncryption ::= { pkcs-1 3 } */
#define OID_PKCS1_MD5           OID_PKCS1 "\x04" /**< md5WithRSAEncryption ::= { pkcs-1 4 } */
#define OID_PKCS1_SHA1          OID_PKCS1 "\x05" /**< sha1WithRSAEncryption ::= { pkcs-1 5 } */
#define OID_PKCS1_SHA224        OID_PKCS1 "\x0e" /**< sha224WithRSAEncryption ::= { pkcs-1 14 } */
#define OID_PKCS1_SHA256        OID_PKCS1 "\x0b" /**< sha256WithRSAEncryption ::= { pkcs-1 11 } */
#define OID_PKCS1_SHA384        OID_PKCS1 "\x0c" /**< sha384WithRSAEncryption ::= { pkcs-1 12 } */
#define OID_PKCS1_SHA512        OID_PKCS1 "\x0d" /**< sha512WithRSAEncryption ::= { pkcs-1 13 } */

#define OID_RSA_SHA_OBS         "\x2B\x0E\x03\x02\x1D"

#define OID_PKCS9_EMAIL         OID_PKCS9 "\x01" /**< emailAddress AttributeType ::= { pkcs-9 1 } */

/* RFC 4055 */
#define OID_RSASSA_PSS          OID_PKCS1 "\x0a" /**< id-RSASSA-PSS ::= { pkcs-1 10 } */
#define OID_MGF1                OID_PKCS1 "\x08" /**< id-mgf1 ::= { pkcs-1 8 } */

/*
 * Digest algorithms
 */
#define OID_DIGEST_ALG_MD2              OID_RSA_COMPANY "\x02\x02" /**< id-md2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 2 } */
#define OID_DIGEST_ALG_MD4              OID_RSA_COMPANY "\x02\x04" /**< id-md4 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 4 } */
#define OID_DIGEST_ALG_MD5              OID_RSA_COMPANY "\x02\x05" /**< id-md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5 } */
#define OID_DIGEST_ALG_SHA1             OID_ISO_IDENTIFIED_ORG OID_OIW_SECSIG_SHA1 /**< id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 } */
#define OID_DIGEST_ALG_SHA224           OID_GOV "\x03\x04\x02\x04" /**< id-sha224 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 4 } */
#define OID_DIGEST_ALG_SHA256           OID_GOV "\x03\x04\x02\x01" /**< id-sha256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1 } */

#define OID_DIGEST_ALG_SHA384           OID_GOV "\x03\x04\x02\x02" /**< id-sha384 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 2 } */

#define OID_DIGEST_ALG_SHA512           OID_GOV "\x03\x04\x02\x03" /**< id-sha512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 3 } */

#define OID_HMAC_SHA1                   OID_RSA_COMPANY "\x02\x07" /**< id-hmacWithSHA1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 7 } */

/*
 * Encryption algorithms
 */
#define OID_DES_CBC                     OID_ISO_IDENTIFIED_ORG OID_OIW_SECSIG_ALG "\x07" /**< desCBC OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 7 } */
#define OID_DES_EDE3_CBC                OID_RSA_COMPANY "\x03\x07" /**< des-ede3-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2) -- us(840) rsadsi(113549) encryptionAlgorithm(3) 7 } */

/*
 * PKCS#5 OIDs
 */
#define OID_PKCS5_PBKDF2                OID_PKCS5 "\x0c" /**< id-PBKDF2 OBJECT IDENTIFIER ::= {pkcs-5 12} */
#define OID_PKCS5_PBES2                 OID_PKCS5 "\x0d" /**< id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13} */
#define OID_PKCS5_PBMAC1                OID_PKCS5 "\x0e" /**< id-PBMAC1 OBJECT IDENTIFIER ::= {pkcs-5 14} */

/*
 * PKCS#5 PBES1 algorithms
 */
#define OID_PKCS5_PBE_MD2_DES_CBC       OID_PKCS5 "\x01" /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */
#define OID_PKCS5_PBE_MD2_RC2_CBC       OID_PKCS5 "\x04" /**< pbeWithMD2AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 4} */
#define OID_PKCS5_PBE_MD5_DES_CBC       OID_PKCS5 "\x03" /**< pbeWithMD5AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 3} */
#define OID_PKCS5_PBE_MD5_RC2_CBC       OID_PKCS5 "\x06" /**< pbeWithMD5AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 6} */
#define OID_PKCS5_PBE_SHA1_DES_CBC      OID_PKCS5 "\x0a" /**< pbeWithSHA1AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 10} */
#define OID_PKCS5_PBE_SHA1_RC2_CBC      OID_PKCS5 "\x0b" /**< pbeWithSHA1AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 11} */

/*
 * PKCS#8 OIDs
 */
#define OID_PKCS9_CSR_EXT_REQ           OID_PKCS9 "\x0e" /**< extensionRequest OBJECT IDENTIFIER ::= {pkcs-9 14} */

/*
 * PKCS#12 PBE OIDs
 */
#define OID_PKCS12_PBE                      OID_PKCS12 "\x01" /**< pkcs-12PbeIds OBJECT IDENTIFIER ::= {pkcs-12 1} */

#define OID_PKCS12_PBE_SHA1_RC4_128         OID_PKCS12_PBE "\x01" /**< pbeWithSHAAnd128BitRC4 OBJECT IDENTIFIER ::= {pkcs-12PbeIds 1} */
#define OID_PKCS12_PBE_SHA1_RC4_40          OID_PKCS12_PBE "\x02" /**< pbeWithSHAAnd40BitRC4 OBJECT IDENTIFIER ::= {pkcs-12PbeIds 2} */
#define OID_PKCS12_PBE_SHA1_DES3_EDE_CBC    OID_PKCS12_PBE "\x03" /**< pbeWithSHAAnd3-KeyTripleDES-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 3} */
#define OID_PKCS12_PBE_SHA1_DES2_EDE_CBC    OID_PKCS12_PBE "\x04" /**< pbeWithSHAAnd2-KeyTripleDES-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 4} */
#define OID_PKCS12_PBE_SHA1_RC2_128_CBC     OID_PKCS12_PBE "\x05" /**< pbeWithSHAAnd128BitRC2-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 5} */
#define OID_PKCS12_PBE_SHA1_RC2_40_CBC      OID_PKCS12_PBE "\x06" /**< pbeWithSHAAnd40BitRC2-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 6} */

/*
 * EC key algorithms from RFC 5480
 */

/* id-ecPublicKey OBJECT IDENTIFIER ::= {
 *       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 } */
#define OID_EC_ALG_UNRESTRICTED         OID_ANSI_X9_62 "\x02\01"

/*   id-ecDH OBJECT IDENTIFIER ::= {
 *     iso(1) identified-organization(3) certicom(132)
 *     schemes(1) ecdh(12) } */
#define OID_EC_ALG_ECDH                 OID_CERTICOM "\x01\x0c"

/*
 * ECParameters namedCurve identifiers, from RFC 5480, RFC 5639, and SEC2
 */

/* secp192r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 1 } */
#define OID_EC_GRP_SECP192R1        OID_ANSI_X9_62 "\x03\x01\x01"

/* secp224r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 33 } */
#define OID_EC_GRP_SECP224R1        OID_CERTICOM "\x00\x21"

/* secp256r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 } */
#define OID_EC_GRP_SECP256R1        OID_ANSI_X9_62 "\x03\x01\x07"

/* secp384r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 34 } */
#define OID_EC_GRP_SECP384R1        OID_CERTICOM "\x00\x22"

/* secp521r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 35 } */
#define OID_EC_GRP_SECP521R1        OID_CERTICOM "\x00\x23"

/* secp192k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 31 } */
#define OID_EC_GRP_SECP192K1        OID_CERTICOM "\x00\x1f"

/* secp224k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 32 } */
#define OID_EC_GRP_SECP224K1        OID_CERTICOM "\x00\x20"

/* secp256k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 10 } */
#define OID_EC_GRP_SECP256K1        OID_CERTICOM "\x00\x0a"

/* RFC 5639 4.1
 * ecStdCurvesAndGeneration OBJECT IDENTIFIER::= {iso(1)
 * identified-organization(3) teletrust(36) algorithm(3) signature-
 * algorithm(3) ecSign(2) 8}
 * ellipticCurve OBJECT IDENTIFIER ::= {ecStdCurvesAndGeneration 1}
 * versionOne OBJECT IDENTIFIER ::= {ellipticCurve 1} */
#define OID_EC_BRAINPOOL_V1         OID_TELETRUST "\x03\x03\x02\x08\x01\x01"

/* brainpoolP256r1 OBJECT IDENTIFIER ::= {versionOne 7} */
#define OID_EC_GRP_BP256R1          OID_EC_BRAINPOOL_V1 "\x07"

/* brainpoolP384r1 OBJECT IDENTIFIER ::= {versionOne 11} */
#define OID_EC_GRP_BP384R1          OID_EC_BRAINPOOL_V1 "\x0B"

/* brainpoolP512r1 OBJECT IDENTIFIER ::= {versionOne 13} */
#define OID_EC_GRP_BP512R1          OID_EC_BRAINPOOL_V1 "\x0D"

/*
 * SEC1 C.1
 *
 * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
 * id-fieldType OBJECT IDENTIFIER ::= { ansi-X9-62 fieldType(1)}
 */
#define OID_ANSI_X9_62_FIELD_TYPE   OID_ANSI_X9_62 "\x01"
#define OID_ANSI_X9_62_PRIME_FIELD  OID_ANSI_X9_62_FIELD_TYPE "\x01"

/*
 * ECDSA signature identifiers, from RFC 5480
 */
#define OID_ANSI_X9_62_SIG          OID_ANSI_X9_62 "\x04" /* signatures(4) */
#define OID_ANSI_X9_62_SIG_SHA2     OID_ANSI_X9_62_SIG "\x03" /* ecdsa-with-SHA2(3) */

/* ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) 1 } */
#define OID_ECDSA_SHA1              OID_ANSI_X9_62_SIG "\x01"

/* ecdsa-with-SHA224 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 1 } */
#define OID_ECDSA_SHA224            OID_ANSI_X9_62_SIG_SHA2 "\x01"

/* ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 2 } */
#define OID_ECDSA_SHA256            OID_ANSI_X9_62_SIG_SHA2 "\x02"

/* ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 3 } */
#define OID_ECDSA_SHA384            OID_ANSI_X9_62_SIG_SHA2 "\x03"

/* ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 4 } */
#define OID_ECDSA_SHA512            OID_ANSI_X9_62_SIG_SHA2 "\x04"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Base OID descriptor structure
 */
typedef struct {
    const char *asn1;               /*!< OID ASN.1 representation       */
    size_t asn1_len;                /*!< length of asn1                 */
    const char *name;               /*!< official name (e.g. from RFC)  */
    const char *description;        /*!< human friendly description     */
} oid_descriptor_t;

/**
 * \brief           Translate an ASN.1 OID into its numeric representation
 *                  (e.g. "\x2A\x86\x48\x86\xF7\x0D" into "1.2.840.113549")
 *
 * \param buf       buffer to put representation in
 * \param size      size of the buffer
 * \param oid       OID to translate
 *
 * \return          Length of the string written (excluding final NULL) or
 *                  POLARSSL_ERR_OID_BUF_TO_SMALL in case of error
 */
static int oid_get_numeric_string( char *buf, size_t size, const asn1_buf *oid );

#if defined(POLARSSL_X509_USE_C) || defined(POLARSSL_X509_CREATE_C)
/**
 * \brief          Translate an X.509 extension OID into local values
 *
 * \param oid      OID to use
 * \param ext_type place to store the extension type
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_x509_ext_type( const asn1_buf *oid, int *ext_type );
#endif

/**
 * \brief          Translate an X.509 attribute type OID into the short name
 *                 (e.g. the OID for an X520 Common Name into "CN")
 *
 * \param oid      OID to use
 * \param short_name    place to store the string pointer
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_attr_short_name( const asn1_buf *oid, const char **short_name );

/**
 * \brief          Translate PublicKeyAlgorithm OID into pk_type
 *
 * \param oid      OID to use
 * \param pk_alg   place to store public key algorithm
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_pk_alg( const asn1_buf *oid, pk_type_t *pk_alg );

/**
 * \brief          Translate pk_type into PublicKeyAlgorithm OID
 *
 * \param pk_alg   Public key type to look for
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_oid_by_pk_alg( pk_type_t pk_alg,
                           const char **oid, size_t *olen );

#if defined(POLARSSL_ECP_C)
/**
 * \brief          Translate NamedCurve OID into an EC group identifier
 *
 * \param oid      OID to use
 * \param grp_id   place to store group id
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_ec_grp( const asn1_buf *oid, ecp_group_id *grp_id );

/**
 * \brief          Translate EC group identifier into NamedCurve OID
 *
 * \param grp_id   EC group identifier
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_oid_by_ec_grp( ecp_group_id grp_id,
                           const char **oid, size_t *olen );
#endif /* POLARSSL_ECP_C */

#if defined(POLARSSL_MD_C)
/**
 * \brief          Translate SignatureAlgorithm OID into md_type and pk_type
 *
 * \param oid      OID to use
 * \param md_alg   place to store message digest algorithm
 * \param pk_alg   place to store public key algorithm
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_sig_alg( const asn1_buf *oid,
                     md_type_t *md_alg, pk_type_t *pk_alg );

/**
 * \brief          Translate SignatureAlgorithm OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_sig_alg_desc( const asn1_buf *oid, const char **desc );

/**
 * \brief          Translate md_type and pk_type into SignatureAlgorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param pk_alg   public key algorithm
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_oid_by_sig_alg( pk_type_t pk_alg, md_type_t md_alg,
                            const char **oid, size_t *olen );

/**
 * \brief          Translate hash algorithm OID into md_type
 *
 * \param oid      OID to use
 * \param md_alg   place to store message digest algorithm
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_md_alg( const asn1_buf *oid, md_type_t *md_alg );
#endif /* POLARSSL_MD_C */

/**
 * \brief          Translate Extended Key Usage OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_extended_key_usage( const asn1_buf *oid, const char **desc );

/**
 * \brief          Translate md_type into hash algorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_oid_by_md( md_type_t md_alg, const char **oid, size_t *olen );

#if defined(POLARSSL_CIPHER_C)
/**
 * \brief          Translate encryption algorithm OID into cipher_type
 *
 * \param oid           OID to use
 * \param cipher_alg    place to store cipher algorithm
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_cipher_alg( const asn1_buf *oid, cipher_type_t *cipher_alg );
#endif /* POLARSSL_CIPHER_C */

#if defined(POLARSSL_PKCS12_C)
/**
 * \brief          Translate PKCS#12 PBE algorithm OID into md_type and
 *                 cipher_type
 *
 * \param oid           OID to use
 * \param md_alg        place to store message digest algorithm
 * \param cipher_alg    place to store cipher algorithm
 *
 * \return         0 if successful, or POLARSSL_ERR_OID_NOT_FOUND
 */
static int oid_get_pkcs12_pbe_alg( const asn1_buf *oid, md_type_t *md_alg,
                            cipher_type_t *cipher_alg );
#endif /* POLARSSL_PKCS12_C */

#ifdef __cplusplus
}
#endif

#endif /* oid.h */
/**
 * \file sha1.h
 *
 * \brief SHA-1 cryptographic hash function
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_SHA1_H
#define POLARSSL_SHA1_H

#if !defined(POLARSSL_CONFIG_FILE)
//#include "config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#include <string.h>

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

#define POLARSSL_ERR_SHA1_FILE_IO_ERROR                -0x0076  /**< Read/write error in file. */

#if !defined(POLARSSL_SHA1_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SHA-1 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */
}
sha1_context;

/**
 * \brief          Initialize SHA-1 context
 *
 * \param ctx      SHA-1 context to be initialized
 */
static void sha1_init( sha1_context *ctx );

/**
 * \brief          Clear SHA-1 context
 *
 * \param ctx      SHA-1 context to be cleared
 */
static void sha1_free( sha1_context *ctx );

/**
 * \brief          SHA-1 context setup
 *
 * \param ctx      context to be initialized
 */
static void sha1_starts( sha1_context *ctx );

/**
 * \brief          SHA-1 process buffer
 *
 * \param ctx      SHA-1 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
static void sha1_update( sha1_context *ctx, const unsigned char *input, size_t ilen );

/**
 * \brief          SHA-1 final digest
 *
 * \param ctx      SHA-1 context
 * \param output   SHA-1 checksum result
 */
static void sha1_finish( sha1_context *ctx, unsigned char output[20] );

/* Internal use */
static void sha1_process( sha1_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#else  /* POLARSSL_SHA1_ALT */
//#include "sha1_alt.h"
#endif /* POLARSSL_SHA1_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = SHA-1( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-1 checksum result
 */
static void sha1( const unsigned char *input, size_t ilen, unsigned char output[20] );

/**
 * \brief          Output = SHA-1( file contents )
 *
 * \param path     input file name
 * \param output   SHA-1 checksum result
 *
 * \return         0 if successful, or POLARSSL_ERR_SHA1_FILE_IO_ERROR
 */
static int sha1_file( const char *path, unsigned char output[20] );

/**
 * \brief          SHA-1 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
static void sha1_hmac_starts( sha1_context *ctx, const unsigned char *key,
                       size_t keylen );

/**
 * \brief          SHA-1 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
static void sha1_hmac_update( sha1_context *ctx, const unsigned char *input,
                       size_t ilen );

/**
 * \brief          SHA-1 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SHA-1 HMAC checksum result
 */
static void sha1_hmac_finish( sha1_context *ctx, unsigned char output[20] );

/**
 * \brief          SHA-1 HMAC context reset
 *
 * \param ctx      HMAC context to be reset
 */
static void sha1_hmac_reset( sha1_context *ctx );

/**
 * \brief          Output = HMAC-SHA-1( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SHA-1 result
 */
static void sha1_hmac( const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char output[20] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
static int sha1_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* sha1.h */
/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif


#if defined(POLARSSL_AES_C)

//#include "polarssl/aes.h"
#if defined(POLARSSL_PADLOCK_C)
//#include "polarssl/padlock.h"
#endif
#if defined(POLARSSL_AESNI_C)
//#include "polarssl/aesni.h"
#endif

#if defined(POLARSSL_PLATFORM_C)
//#include "polarssl/platform.h"
#else
#define polarssl_printf printf
#endif

#if !defined(POLARSSL_AES_ALT)

/* Implementation that should never be optimized out by the compiler */
static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
}
#endif

#if defined(POLARSSL_PADLOCK_C) && ( defined(POLARSSL_HAVE_X86) || defined(PADLOCK_ALIGN16) )
static int aes_padlock_ace = -1;
#endif

#if defined(POLARSSL_AES_ROM_TABLES)
/*
 * Forward S-box
 */
static const unsigned char FSb[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*
 * Forward tables
 */
#define FT \
\
    V(A5,63,63,C6), V(84,7C,7C,F8), V(99,77,77,EE), V(8D,7B,7B,F6), \
    V(0D,F2,F2,FF), V(BD,6B,6B,D6), V(B1,6F,6F,DE), V(54,C5,C5,91), \
    V(50,30,30,60), V(03,01,01,02), V(A9,67,67,CE), V(7D,2B,2B,56), \
    V(19,FE,FE,E7), V(62,D7,D7,B5), V(E6,AB,AB,4D), V(9A,76,76,EC), \
    V(45,CA,CA,8F), V(9D,82,82,1F), V(40,C9,C9,89), V(87,7D,7D,FA), \
    V(15,FA,FA,EF), V(EB,59,59,B2), V(C9,47,47,8E), V(0B,F0,F0,FB), \
    V(EC,AD,AD,41), V(67,D4,D4,B3), V(FD,A2,A2,5F), V(EA,AF,AF,45), \
    V(BF,9C,9C,23), V(F7,A4,A4,53), V(96,72,72,E4), V(5B,C0,C0,9B), \
    V(C2,B7,B7,75), V(1C,FD,FD,E1), V(AE,93,93,3D), V(6A,26,26,4C), \
    V(5A,36,36,6C), V(41,3F,3F,7E), V(02,F7,F7,F5), V(4F,CC,CC,83), \
    V(5C,34,34,68), V(F4,A5,A5,51), V(34,E5,E5,D1), V(08,F1,F1,F9), \
    V(93,71,71,E2), V(73,D8,D8,AB), V(53,31,31,62), V(3F,15,15,2A), \
    V(0C,04,04,08), V(52,C7,C7,95), V(65,23,23,46), V(5E,C3,C3,9D), \
    V(28,18,18,30), V(A1,96,96,37), V(0F,05,05,0A), V(B5,9A,9A,2F), \
    V(09,07,07,0E), V(36,12,12,24), V(9B,80,80,1B), V(3D,E2,E2,DF), \
    V(26,EB,EB,CD), V(69,27,27,4E), V(CD,B2,B2,7F), V(9F,75,75,EA), \
    V(1B,09,09,12), V(9E,83,83,1D), V(74,2C,2C,58), V(2E,1A,1A,34), \
    V(2D,1B,1B,36), V(B2,6E,6E,DC), V(EE,5A,5A,B4), V(FB,A0,A0,5B), \
    V(F6,52,52,A4), V(4D,3B,3B,76), V(61,D6,D6,B7), V(CE,B3,B3,7D), \
    V(7B,29,29,52), V(3E,E3,E3,DD), V(71,2F,2F,5E), V(97,84,84,13), \
    V(F5,53,53,A6), V(68,D1,D1,B9), V(00,00,00,00), V(2C,ED,ED,C1), \
    V(60,20,20,40), V(1F,FC,FC,E3), V(C8,B1,B1,79), V(ED,5B,5B,B6), \
    V(BE,6A,6A,D4), V(46,CB,CB,8D), V(D9,BE,BE,67), V(4B,39,39,72), \
    V(DE,4A,4A,94), V(D4,4C,4C,98), V(E8,58,58,B0), V(4A,CF,CF,85), \
    V(6B,D0,D0,BB), V(2A,EF,EF,C5), V(E5,AA,AA,4F), V(16,FB,FB,ED), \
    V(C5,43,43,86), V(D7,4D,4D,9A), V(55,33,33,66), V(94,85,85,11), \
    V(CF,45,45,8A), V(10,F9,F9,E9), V(06,02,02,04), V(81,7F,7F,FE), \
    V(F0,50,50,A0), V(44,3C,3C,78), V(BA,9F,9F,25), V(E3,A8,A8,4B), \
    V(F3,51,51,A2), V(FE,A3,A3,5D), V(C0,40,40,80), V(8A,8F,8F,05), \
    V(AD,92,92,3F), V(BC,9D,9D,21), V(48,38,38,70), V(04,F5,F5,F1), \
    V(DF,BC,BC,63), V(C1,B6,B6,77), V(75,DA,DA,AF), V(63,21,21,42), \
    V(30,10,10,20), V(1A,FF,FF,E5), V(0E,F3,F3,FD), V(6D,D2,D2,BF), \
    V(4C,CD,CD,81), V(14,0C,0C,18), V(35,13,13,26), V(2F,EC,EC,C3), \
    V(E1,5F,5F,BE), V(A2,97,97,35), V(CC,44,44,88), V(39,17,17,2E), \
    V(57,C4,C4,93), V(F2,A7,A7,55), V(82,7E,7E,FC), V(47,3D,3D,7A), \
    V(AC,64,64,C8), V(E7,5D,5D,BA), V(2B,19,19,32), V(95,73,73,E6), \
    V(A0,60,60,C0), V(98,81,81,19), V(D1,4F,4F,9E), V(7F,DC,DC,A3), \
    V(66,22,22,44), V(7E,2A,2A,54), V(AB,90,90,3B), V(83,88,88,0B), \
    V(CA,46,46,8C), V(29,EE,EE,C7), V(D3,B8,B8,6B), V(3C,14,14,28), \
    V(79,DE,DE,A7), V(E2,5E,5E,BC), V(1D,0B,0B,16), V(76,DB,DB,AD), \
    V(3B,E0,E0,DB), V(56,32,32,64), V(4E,3A,3A,74), V(1E,0A,0A,14), \
    V(DB,49,49,92), V(0A,06,06,0C), V(6C,24,24,48), V(E4,5C,5C,B8), \
    V(5D,C2,C2,9F), V(6E,D3,D3,BD), V(EF,AC,AC,43), V(A6,62,62,C4), \
    V(A8,91,91,39), V(A4,95,95,31), V(37,E4,E4,D3), V(8B,79,79,F2), \
    V(32,E7,E7,D5), V(43,C8,C8,8B), V(59,37,37,6E), V(B7,6D,6D,DA), \
    V(8C,8D,8D,01), V(64,D5,D5,B1), V(D2,4E,4E,9C), V(E0,A9,A9,49), \
    V(B4,6C,6C,D8), V(FA,56,56,AC), V(07,F4,F4,F3), V(25,EA,EA,CF), \
    V(AF,65,65,CA), V(8E,7A,7A,F4), V(E9,AE,AE,47), V(18,08,08,10), \
    V(D5,BA,BA,6F), V(88,78,78,F0), V(6F,25,25,4A), V(72,2E,2E,5C), \
    V(24,1C,1C,38), V(F1,A6,A6,57), V(C7,B4,B4,73), V(51,C6,C6,97), \
    V(23,E8,E8,CB), V(7C,DD,DD,A1), V(9C,74,74,E8), V(21,1F,1F,3E), \
    V(DD,4B,4B,96), V(DC,BD,BD,61), V(86,8B,8B,0D), V(85,8A,8A,0F), \
    V(90,70,70,E0), V(42,3E,3E,7C), V(C4,B5,B5,71), V(AA,66,66,CC), \
    V(D8,48,48,90), V(05,03,03,06), V(01,F6,F6,F7), V(12,0E,0E,1C), \
    V(A3,61,61,C2), V(5F,35,35,6A), V(F9,57,57,AE), V(D0,B9,B9,69), \
    V(91,86,86,17), V(58,C1,C1,99), V(27,1D,1D,3A), V(B9,9E,9E,27), \
    V(38,E1,E1,D9), V(13,F8,F8,EB), V(B3,98,98,2B), V(33,11,11,22), \
    V(BB,69,69,D2), V(70,D9,D9,A9), V(89,8E,8E,07), V(A7,94,94,33), \
    V(B6,9B,9B,2D), V(22,1E,1E,3C), V(92,87,87,15), V(20,E9,E9,C9), \
    V(49,CE,CE,87), V(FF,55,55,AA), V(78,28,28,50), V(7A,DF,DF,A5), \
    V(8F,8C,8C,03), V(F8,A1,A1,59), V(80,89,89,09), V(17,0D,0D,1A), \
    V(DA,BF,BF,65), V(31,E6,E6,D7), V(C6,42,42,84), V(B8,68,68,D0), \
    V(C3,41,41,82), V(B0,99,99,29), V(77,2D,2D,5A), V(11,0F,0F,1E), \
    V(CB,B0,B0,7B), V(FC,54,54,A8), V(D6,BB,BB,6D), V(3A,16,16,2C)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t FT3[256] = { FT };
#undef V

#undef FT

/*
 * Reverse S-box
 */
static const unsigned char RSb[256] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/*
 * Reverse tables
 */
#define RT \
\
    V(50,A7,F4,51), V(53,65,41,7E), V(C3,A4,17,1A), V(96,5E,27,3A), \
    V(CB,6B,AB,3B), V(F1,45,9D,1F), V(AB,58,FA,AC), V(93,03,E3,4B), \
    V(55,FA,30,20), V(F6,6D,76,AD), V(91,76,CC,88), V(25,4C,02,F5), \
    V(FC,D7,E5,4F), V(D7,CB,2A,C5), V(80,44,35,26), V(8F,A3,62,B5), \
    V(49,5A,B1,DE), V(67,1B,BA,25), V(98,0E,EA,45), V(E1,C0,FE,5D), \
    V(02,75,2F,C3), V(12,F0,4C,81), V(A3,97,46,8D), V(C6,F9,D3,6B), \
    V(E7,5F,8F,03), V(95,9C,92,15), V(EB,7A,6D,BF), V(DA,59,52,95), \
    V(2D,83,BE,D4), V(D3,21,74,58), V(29,69,E0,49), V(44,C8,C9,8E), \
    V(6A,89,C2,75), V(78,79,8E,F4), V(6B,3E,58,99), V(DD,71,B9,27), \
    V(B6,4F,E1,BE), V(17,AD,88,F0), V(66,AC,20,C9), V(B4,3A,CE,7D), \
    V(18,4A,DF,63), V(82,31,1A,E5), V(60,33,51,97), V(45,7F,53,62), \
    V(E0,77,64,B1), V(84,AE,6B,BB), V(1C,A0,81,FE), V(94,2B,08,F9), \
    V(58,68,48,70), V(19,FD,45,8F), V(87,6C,DE,94), V(B7,F8,7B,52), \
    V(23,D3,73,AB), V(E2,02,4B,72), V(57,8F,1F,E3), V(2A,AB,55,66), \
    V(07,28,EB,B2), V(03,C2,B5,2F), V(9A,7B,C5,86), V(A5,08,37,D3), \
    V(F2,87,28,30), V(B2,A5,BF,23), V(BA,6A,03,02), V(5C,82,16,ED), \
    V(2B,1C,CF,8A), V(92,B4,79,A7), V(F0,F2,07,F3), V(A1,E2,69,4E), \
    V(CD,F4,DA,65), V(D5,BE,05,06), V(1F,62,34,D1), V(8A,FE,A6,C4), \
    V(9D,53,2E,34), V(A0,55,F3,A2), V(32,E1,8A,05), V(75,EB,F6,A4), \
    V(39,EC,83,0B), V(AA,EF,60,40), V(06,9F,71,5E), V(51,10,6E,BD), \
    V(F9,8A,21,3E), V(3D,06,DD,96), V(AE,05,3E,DD), V(46,BD,E6,4D), \
    V(B5,8D,54,91), V(05,5D,C4,71), V(6F,D4,06,04), V(FF,15,50,60), \
    V(24,FB,98,19), V(97,E9,BD,D6), V(CC,43,40,89), V(77,9E,D9,67), \
    V(BD,42,E8,B0), V(88,8B,89,07), V(38,5B,19,E7), V(DB,EE,C8,79), \
    V(47,0A,7C,A1), V(E9,0F,42,7C), V(C9,1E,84,F8), V(00,00,00,00), \
    V(83,86,80,09), V(48,ED,2B,32), V(AC,70,11,1E), V(4E,72,5A,6C), \
    V(FB,FF,0E,FD), V(56,38,85,0F), V(1E,D5,AE,3D), V(27,39,2D,36), \
    V(64,D9,0F,0A), V(21,A6,5C,68), V(D1,54,5B,9B), V(3A,2E,36,24), \
    V(B1,67,0A,0C), V(0F,E7,57,93), V(D2,96,EE,B4), V(9E,91,9B,1B), \
    V(4F,C5,C0,80), V(A2,20,DC,61), V(69,4B,77,5A), V(16,1A,12,1C), \
    V(0A,BA,93,E2), V(E5,2A,A0,C0), V(43,E0,22,3C), V(1D,17,1B,12), \
    V(0B,0D,09,0E), V(AD,C7,8B,F2), V(B9,A8,B6,2D), V(C8,A9,1E,14), \
    V(85,19,F1,57), V(4C,07,75,AF), V(BB,DD,99,EE), V(FD,60,7F,A3), \
    V(9F,26,01,F7), V(BC,F5,72,5C), V(C5,3B,66,44), V(34,7E,FB,5B), \
    V(76,29,43,8B), V(DC,C6,23,CB), V(68,FC,ED,B6), V(63,F1,E4,B8), \
    V(CA,DC,31,D7), V(10,85,63,42), V(40,22,97,13), V(20,11,C6,84), \
    V(7D,24,4A,85), V(F8,3D,BB,D2), V(11,32,F9,AE), V(6D,A1,29,C7), \
    V(4B,2F,9E,1D), V(F3,30,B2,DC), V(EC,52,86,0D), V(D0,E3,C1,77), \
    V(6C,16,B3,2B), V(99,B9,70,A9), V(FA,48,94,11), V(22,64,E9,47), \
    V(C4,8C,FC,A8), V(1A,3F,F0,A0), V(D8,2C,7D,56), V(EF,90,33,22), \
    V(C7,4E,49,87), V(C1,D1,38,D9), V(FE,A2,CA,8C), V(36,0B,D4,98), \
    V(CF,81,F5,A6), V(28,DE,7A,A5), V(26,8E,B7,DA), V(A4,BF,AD,3F), \
    V(E4,9D,3A,2C), V(0D,92,78,50), V(9B,CC,5F,6A), V(62,46,7E,54), \
    V(C2,13,8D,F6), V(E8,B8,D8,90), V(5E,F7,39,2E), V(F5,AF,C3,82), \
    V(BE,80,5D,9F), V(7C,93,D0,69), V(A9,2D,D5,6F), V(B3,12,25,CF), \
    V(3B,99,AC,C8), V(A7,7D,18,10), V(6E,63,9C,E8), V(7B,BB,3B,DB), \
    V(09,78,26,CD), V(F4,18,59,6E), V(01,B7,9A,EC), V(A8,9A,4F,83), \
    V(65,6E,95,E6), V(7E,E6,FF,AA), V(08,CF,BC,21), V(E6,E8,15,EF), \
    V(D9,9B,E7,BA), V(CE,36,6F,4A), V(D4,09,9F,EA), V(D6,7C,B0,29), \
    V(AF,B2,A4,31), V(31,23,3F,2A), V(30,94,A5,C6), V(C0,66,A2,35), \
    V(37,BC,4E,74), V(A6,CA,82,FC), V(B0,D0,90,E0), V(15,D8,A7,33), \
    V(4A,98,04,F1), V(F7,DA,EC,41), V(0E,50,CD,7F), V(2F,F6,91,17), \
    V(8D,D6,4D,76), V(4D,B0,EF,43), V(54,4D,AA,CC), V(DF,04,96,E4), \
    V(E3,B5,D1,9E), V(1B,88,6A,4C), V(B8,1F,2C,C1), V(7F,51,65,46), \
    V(04,EA,5E,9D), V(5D,35,8C,01), V(73,74,87,FA), V(2E,41,0B,FB), \
    V(5A,1D,67,B3), V(52,D2,DB,92), V(33,56,10,E9), V(13,47,D6,6D), \
    V(8C,61,D7,9A), V(7A,0C,A1,37), V(8E,14,F8,59), V(89,3C,13,EB), \
    V(EE,27,A9,CE), V(35,C9,61,B7), V(ED,E5,1C,E1), V(3C,B1,47,7A), \
    V(59,DF,D2,9C), V(3F,73,F2,55), V(79,CE,14,18), V(BF,37,C7,73), \
    V(EA,CD,F7,53), V(5B,AA,FD,5F), V(14,6F,3D,DF), V(86,DB,44,78), \
    V(81,F3,AF,CA), V(3E,C4,68,B9), V(2C,34,24,38), V(5F,40,A3,C2), \
    V(72,C3,1D,16), V(0C,25,E2,BC), V(8B,49,3C,28), V(41,95,0D,FF), \
    V(71,01,A8,39), V(DE,B3,0C,08), V(9C,E4,B4,D8), V(90,C1,56,64), \
    V(61,84,CB,7B), V(70,B6,32,D5), V(74,5C,6C,48), V(42,57,B8,D0)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t RT0[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t RT1[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t RT2[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t RT3[256] = { RT };
#undef V

#undef RT

/*
 * Round constants
 */
static const uint32_t RCON[10] =
{
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x0000001B, 0x00000036
};

#else /* POLARSSL_AES_ROM_TABLES */

/*
 * Forward S-box & tables
 */
static unsigned char FSb[256];
static uint32_t FT0[256];
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

/*
 * Reverse S-box & tables
 */
static unsigned char RSb[256];
static uint32_t RT0[256];
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];

/*
 * Round constants
 */
static uint32_t RCON[10];

/*
 * Tables generation code
 */
#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )

static int aes_init_done = 0;

static void aes_gen_tables( void )
{
    int i, x, y, z;
    int pow[256];
    int log[256];

    /*
     * compute pow and log tables over GF(2^8)
     */
    for( i = 0, x = 1; i < 256; i++ )
    {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }

    /*
     * calculate the round constants
     */
    for( i = 0, x = 1; i < 10; i++ )
    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }

    /*
     * generate the forward and reverse S-boxes
     */
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y  = x; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char) x;
        RSb[x] = (unsigned char) i;
    }

    /*
     * generate the forward and reverse tables
     */
    for( i = 0; i < 256; i++ )
    {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^
                 ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^
                 ( (uint32_t) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
    }
}

#endif /* POLARSSL_AES_ROM_TABLES */

void aes_init( aes_context *ctx )
{
    memset( ctx, 0, sizeof( aes_context ) );
}

void aes_free( aes_context *ctx )
{
    if( ctx == NULL )
        return;

    polarssl_zeroize( ctx, sizeof( aes_context ) );
}

/*
 * AES key schedule (encryption)
 */
int aes_setkey_enc( aes_context *ctx, const unsigned char *key,
                    unsigned int keysize )
{
    unsigned int i;
    uint32_t *RK;

#if !defined(POLARSSL_AES_ROM_TABLES)
    if( aes_init_done == 0 )
    {
        aes_gen_tables();
        aes_init_done = 1;

    }
#endif

    switch( keysize )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( POLARSSL_ERR_AES_INVALID_KEY_LENGTH );
    }

#if defined(POLARSSL_PADLOCK_C) && defined(PADLOCK_ALIGN16)
    if( aes_padlock_ace == -1 )
        aes_padlock_ace = padlock_supports( PADLOCK_ACE );

    if( aes_padlock_ace )
        ctx->rk = RK = PADLOCK_ALIGN16( ctx->buf );
    else
#endif
    ctx->rk = RK = ctx->buf;

#if defined(POLARSSL_AESNI_C) && defined(POLARSSL_HAVE_X86_64)
    if( aesni_supports( POLARSSL_AESNI_AES ) )
        return( aesni_setkey_enc( (unsigned char *) ctx->rk, key, keysize ) );
#endif

    for( i = 0; i < ( keysize >> 5 ); i++ )
    {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( ctx->nr )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
    }

    return( 0 );
}

/*
 * AES key schedule (decryption)
 */
int aes_setkey_dec( aes_context *ctx, const unsigned char *key,
                    unsigned int keysize )
{
    int i, j, ret;
    aes_context cty;
    uint32_t *RK;
    uint32_t *SK;

    aes_init( &cty );

#if defined(POLARSSL_PADLOCK_C) && defined(PADLOCK_ALIGN16)
    if( aes_padlock_ace == -1 )
        aes_padlock_ace = padlock_supports( PADLOCK_ACE );

    if( aes_padlock_ace )
        ctx->rk = RK = PADLOCK_ALIGN16( ctx->buf );
    else
#endif
    ctx->rk = RK = ctx->buf;

    /* Also checks keysize */
    if( ( ret = aes_setkey_enc( &cty, key, keysize ) ) != 0 )
        goto exit;

    ctx->nr = cty.nr;

#if defined(POLARSSL_AESNI_C) && defined(POLARSSL_HAVE_X86_64)
    if( aesni_supports( POLARSSL_AESNI_AES ) )
    {
        aesni_inverse_key( (unsigned char *) ctx->rk,
                           (const unsigned char *) cty.rk, ctx->nr );
        goto exit;
    }
#endif

    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8 )
    {
        for( j = 0; j < 4; j++, SK++ )
        {
            *RK++ = RT0[ FSb[ ( *SK       ) & 0xFF ] ] ^
                    RT1[ FSb[ ( *SK >>  8 ) & 0xFF ] ] ^
                    RT2[ FSb[ ( *SK >> 16 ) & 0xFF ] ] ^
                    RT3[ FSb[ ( *SK >> 24 ) & 0xFF ] ];
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

exit:
    aes_free( &cty );

    return( ret );
}

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ FT0[ ( Y0       ) & 0xFF ] ^   \
                 FT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ FT0[ ( Y1       ) & 0xFF ] ^   \
                 FT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y0 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ FT0[ ( Y2       ) & 0xFF ] ^   \
                 FT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ FT0[ ( Y3       ) & 0xFF ] ^   \
                 FT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y2 >> 24 ) & 0xFF ];    \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ RT0[ ( Y0       ) & 0xFF ] ^   \
                 RT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ RT0[ ( Y1       ) & 0xFF ] ^   \
                 RT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y2 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ RT0[ ( Y2       ) & 0xFF ] ^   \
                 RT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ RT0[ ( Y3       ) & 0xFF ] ^   \
                 RT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y0 >> 24 ) & 0xFF ];    \
}

/*
 * AES-ECB block encryption/decryption
 */
int aes_crypt_ecb( aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

#if defined(POLARSSL_AESNI_C) && defined(POLARSSL_HAVE_X86_64)
    if( aesni_supports( POLARSSL_AESNI_AES ) )
        return( aesni_crypt_ecb( ctx, mode, input, output ) );
#endif

#if defined(POLARSSL_PADLOCK_C) && defined(POLARSSL_HAVE_X86)
    if( aes_padlock_ace )
    {
        if( padlock_xcryptecb( ctx, mode, input, output ) == 0 )
            return( 0 );

        // If padlock data misaligned, we just fall back to
        // unaccelerated mode
        //
    }
#endif

    RK = ctx->rk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++;
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

    if( mode == AES_DECRYPT )
    {
        for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
        {
            AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );
    }
    else /* AES_ENCRYPT */
    {
        for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
        {
            AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );
    }

    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );

    return( 0 );
}

#if defined(POLARSSL_CIPHER_MODE_CBC)
/*
 * AES-CBC buffer encryption/decryption
 */
int aes_crypt_cbc( aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];

    if( length % 16 )
        return( POLARSSL_ERR_AES_INVALID_INPUT_LENGTH );

#if defined(POLARSSL_PADLOCK_C) && defined(POLARSSL_HAVE_X86)
    if( aes_padlock_ace )
    {
        if( padlock_xcryptcbc( ctx, mode, length, iv, input, output ) == 0 )
            return( 0 );

        // If padlock data misaligned, we just fall back to
        // unaccelerated mode
        //
    }
#endif

    if( mode == AES_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            aes_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            aes_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }

    return( 0 );
}
#endif /* POLARSSL_CIPHER_MODE_CBC */

#if defined(POLARSSL_CIPHER_MODE_CFB)
/*
 * AES-CFB128 buffer encryption/decryption
 */
int aes_crypt_cfb128( aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    size_t n = *iv_off;

    if( mode == AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                aes_crypt_ecb( ctx, AES_ENCRYPT, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = ( n + 1 ) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                aes_crypt_ecb( ctx, AES_ENCRYPT, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0x0F;
        }
    }

    *iv_off = n;

    return( 0 );
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
#include <stdio.h>
int aes_crypt_cfb8( aes_context *ctx,
                       int mode,
                       size_t length,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    unsigned char c;
    unsigned char ov[17];

    while( length-- )
    {
        memcpy( ov, iv, 16 );
        aes_crypt_ecb( ctx, AES_ENCRYPT, iv, iv );

        if( mode == AES_DECRYPT )
            ov[16] = *input;

        c = *output++ = (unsigned char)( iv[0] ^ *input++ );

        if( mode == AES_ENCRYPT )
            ov[16] = c;

        memcpy( iv, ov + 1, 16 );
    }

    return( 0 );
}
#endif /*POLARSSL_CIPHER_MODE_CFB */

#if defined(POLARSSL_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
int aes_crypt_ctr( aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c, i;
    size_t n = *nc_off;

    while( length-- )
    {
        if( n == 0 ) {
            aes_crypt_ecb( ctx, AES_ENCRYPT, nonce_counter, stream_block );

            for( i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* POLARSSL_CIPHER_MODE_CTR */

#endif /* !POLARSSL_AES_ALT */

#if defined(POLARSSL_SELF_TEST)

#include <stdio.h>

/*
 * AES test vectors from:
 *
 * http://csrc.nist.gov/archive/aes/rijndael/rijndael-vals.zip
 */
static const unsigned char aes_test_ecb_dec[3][16] =
{
    { 0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58,
      0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0 },
    { 0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
      0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4 },
    { 0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
      0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE }
};

static const unsigned char aes_test_ecb_enc[3][16] =
{
    { 0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
      0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F },
    { 0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11,
      0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14 },
    { 0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D,
      0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4 }
};

#if defined(POLARSSL_CIPHER_MODE_CBC)
static const unsigned char aes_test_cbc_dec[3][16] =
{
    { 0xFA, 0xCA, 0x37, 0xE0, 0xB0, 0xC8, 0x53, 0x73,
      0xDF, 0x70, 0x6E, 0x73, 0xF7, 0xC9, 0xAF, 0x86 },
    { 0x5D, 0xF6, 0x78, 0xDD, 0x17, 0xBA, 0x4E, 0x75,
      0xB6, 0x17, 0x68, 0xC6, 0xAD, 0xEF, 0x7C, 0x7B },
    { 0x48, 0x04, 0xE1, 0x81, 0x8F, 0xE6, 0x29, 0x75,
      0x19, 0xA3, 0xE8, 0x8C, 0x57, 0x31, 0x04, 0x13 }
};

static const unsigned char aes_test_cbc_enc[3][16] =
{
    { 0x8A, 0x05, 0xFC, 0x5E, 0x09, 0x5A, 0xF4, 0x84,
      0x8A, 0x08, 0xD3, 0x28, 0xD3, 0x68, 0x8E, 0x3D },
    { 0x7B, 0xD9, 0x66, 0xD5, 0x3A, 0xD8, 0xC1, 0xBB,
      0x85, 0xD2, 0xAD, 0xFA, 0xE8, 0x7B, 0xB1, 0x04 },
    { 0xFE, 0x3C, 0x53, 0x65, 0x3E, 0x2F, 0x45, 0xB5,
      0x6F, 0xCD, 0x88, 0xB2, 0xCC, 0x89, 0x8F, 0xF0 }
};
#endif /* POLARSSL_CIPHER_MODE_CBC */

#if defined(POLARSSL_CIPHER_MODE_CFB)
/*
 * AES-CFB128 test vectors from:
 *
 * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 */
static const unsigned char aes_test_cfb128_key[3][32] =
{
    { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C },
    { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
      0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
      0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B },
    { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
      0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
      0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
      0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 }
};

static const unsigned char aes_test_cfb128_iv[16] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const unsigned char aes_test_cfb128_pt[64] =
{
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

static const unsigned char aes_test_cfb128_ct[3][64] =
{
    { 0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20,
      0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
      0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F,
      0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C, 0xE5, 0x8B,
      0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40,
      0xB1, 0x80, 0x8C, 0xF1, 0x87, 0xA4, 0xF4, 0xDF,
      0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E,
      0xEA, 0xC4, 0xC6, 0x6F, 0x9F, 0xF7, 0xF2, 0xE6 },
    { 0xCD, 0xC8, 0x0D, 0x6F, 0xDD, 0xF1, 0x8C, 0xAB,
      0x34, 0xC2, 0x59, 0x09, 0xC9, 0x9A, 0x41, 0x74,
      0x67, 0xCE, 0x7F, 0x7F, 0x81, 0x17, 0x36, 0x21,
      0x96, 0x1A, 0x2B, 0x70, 0x17, 0x1D, 0x3D, 0x7A,
      0x2E, 0x1E, 0x8A, 0x1D, 0xD5, 0x9B, 0x88, 0xB1,
      0xC8, 0xE6, 0x0F, 0xED, 0x1E, 0xFA, 0xC4, 0xC9,
      0xC0, 0x5F, 0x9F, 0x9C, 0xA9, 0x83, 0x4F, 0xA0,
      0x42, 0xAE, 0x8F, 0xBA, 0x58, 0x4B, 0x09, 0xFF },
    { 0xDC, 0x7E, 0x84, 0xBF, 0xDA, 0x79, 0x16, 0x4B,
      0x7E, 0xCD, 0x84, 0x86, 0x98, 0x5D, 0x38, 0x60,
      0x39, 0xFF, 0xED, 0x14, 0x3B, 0x28, 0xB1, 0xC8,
      0x32, 0x11, 0x3C, 0x63, 0x31, 0xE5, 0x40, 0x7B,
      0xDF, 0x10, 0x13, 0x24, 0x15, 0xE5, 0x4B, 0x92,
      0xA1, 0x3E, 0xD0, 0xA8, 0x26, 0x7A, 0xE2, 0xF9,
      0x75, 0xA3, 0x85, 0x74, 0x1A, 0xB9, 0xCE, 0xF8,
      0x20, 0x31, 0x62, 0x3D, 0x55, 0xB1, 0xE4, 0x71 }
};
#endif /* POLARSSL_CIPHER_MODE_CFB */

#if defined(POLARSSL_CIPHER_MODE_CTR)
/*
 * AES-CTR test vectors from:
 *
 * http://www.faqs.org/rfcs/rfc3686.html
 */

static const unsigned char aes_test_ctr_key[3][16] =
{
    { 0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
      0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E },
    { 0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
      0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63 },
    { 0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8,
      0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC }
};

static const unsigned char aes_test_ctr_nonce_counter[3][16] =
{
    { 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
    { 0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59,
      0xDA, 0x48, 0xD9, 0x0B, 0x00, 0x00, 0x00, 0x01 },
    { 0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F,
      0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x01 }
};

static const unsigned char aes_test_ctr_pt[3][48] =
{
    { 0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
      0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67 },

    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },

    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0x20, 0x21, 0x22, 0x23 }
};

static const unsigned char aes_test_ctr_ct[3][48] =
{
    { 0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
      0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8 },
    { 0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
      0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
      0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
      0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28 },
    { 0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9,
      0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
      0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36,
      0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
      0x25, 0xB2, 0x07, 0x2F }
};

static const int aes_test_ctr_len[3] =
    { 16, 32, 36 };
#endif /* POLARSSL_CIPHER_MODE_CTR */

/*
 * Checkup routine
 */
int aes_self_test( int verbose )
{
    int ret = 0, i, j, u, v;
    unsigned char key[32];
    unsigned char buf[64];
    unsigned char iv[16];
#if defined(POLARSSL_CIPHER_MODE_CBC)
    unsigned char prv[16];
#endif
#if defined(POLARSSL_CIPHER_MODE_CTR) || defined(POLARSSL_CIPHER_MODE_CFB)
    size_t offset;
#endif
#if defined(POLARSSL_CIPHER_MODE_CTR)
    int len;
    unsigned char nonce_counter[16];
    unsigned char stream_block[16];
#endif
    aes_context ctx;

    memset( key, 0, 32 );
    aes_init( &ctx );

    /*
     * ECB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            polarssl_printf( "  AES-ECB-%3d (%s): ", 128 + u * 64,
                             ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memset( buf, 0, 16 );

        if( v == AES_DECRYPT )
        {
            aes_setkey_dec( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_ecb( &ctx, v, buf, buf );

            if( memcmp( buf, aes_test_ecb_dec[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }
        else
        {
            aes_setkey_enc( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_ecb( &ctx, v, buf, buf );

            if( memcmp( buf, aes_test_ecb_enc[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }

        if( verbose != 0 )
            polarssl_printf( "passed\n" );
    }

    if( verbose != 0 )
        polarssl_printf( "\n" );

#if defined(POLARSSL_CIPHER_MODE_CBC)
    /*
     * CBC mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            polarssl_printf( "  AES-CBC-%3d (%s): ", 128 + u * 64,
                             ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memset( iv , 0, 16 );
        memset( prv, 0, 16 );
        memset( buf, 0, 16 );

        if( v == AES_DECRYPT )
        {
            aes_setkey_dec( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_cbc( &ctx, v, 16, iv, buf, buf );

            if( memcmp( buf, aes_test_cbc_dec[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }
        else
        {
            aes_setkey_enc( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
            {
                unsigned char tmp[16];

                aes_crypt_cbc( &ctx, v, 16, iv, buf, buf );

                memcpy( tmp, prv, 16 );
                memcpy( prv, buf, 16 );
                memcpy( buf, tmp, 16 );
            }

            if( memcmp( prv, aes_test_cbc_enc[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }

        if( verbose != 0 )
            polarssl_printf( "passed\n" );
    }

    if( verbose != 0 )
        polarssl_printf( "\n" );
#endif /* POLARSSL_CIPHER_MODE_CBC */

#if defined(POLARSSL_CIPHER_MODE_CFB)
    /*
     * CFB128 mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            polarssl_printf( "  AES-CFB128-%3d (%s): ", 128 + u * 64,
                             ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memcpy( iv,  aes_test_cfb128_iv, 16 );
        memcpy( key, aes_test_cfb128_key[u], 16 + u * 8 );

        offset = 0;
        aes_setkey_enc( &ctx, key, 128 + u * 64 );

        if( v == AES_DECRYPT )
        {
            memcpy( buf, aes_test_cfb128_ct[u], 64 );
            aes_crypt_cfb128( &ctx, v, 64, &offset, iv, buf, buf );

            if( memcmp( buf, aes_test_cfb128_pt, 64 ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }
        else
        {
            memcpy( buf, aes_test_cfb128_pt, 64 );
            aes_crypt_cfb128( &ctx, v, 64, &offset, iv, buf, buf );

            if( memcmp( buf, aes_test_cfb128_ct[u], 64 ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }

        if( verbose != 0 )
            polarssl_printf( "passed\n" );
    }

    if( verbose != 0 )
        polarssl_printf( "\n" );
#endif /* POLARSSL_CIPHER_MODE_CFB */

#if defined(POLARSSL_CIPHER_MODE_CTR)
    /*
     * CTR mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            polarssl_printf( "  AES-CTR-128 (%s): ",
                             ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memcpy( nonce_counter, aes_test_ctr_nonce_counter[u], 16 );
        memcpy( key, aes_test_ctr_key[u], 16 );

        offset = 0;
        aes_setkey_enc( &ctx, key, 128 );

        if( v == AES_DECRYPT )
        {
            len = aes_test_ctr_len[u];
            memcpy( buf, aes_test_ctr_ct[u], len );

            aes_crypt_ctr( &ctx, len, &offset, nonce_counter, stream_block,
                           buf, buf );

            if( memcmp( buf, aes_test_ctr_pt[u], len ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }
        else
        {
            len = aes_test_ctr_len[u];
            memcpy( buf, aes_test_ctr_pt[u], len );

            aes_crypt_ctr( &ctx, len, &offset, nonce_counter, stream_block,
                           buf, buf );

            if( memcmp( buf, aes_test_ctr_ct[u], len ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }

        if( verbose != 0 )
            polarssl_printf( "passed\n" );
    }

    if( verbose != 0 )
        polarssl_printf( "\n" );
#endif /* POLARSSL_CIPHER_MODE_CTR */

    ret = 0;

exit:
    aes_free( &ctx );

    return( ret );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_AES_C */

/*
 *  AES-NI support functions
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * [AES-WP] http://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set
 * [CLMUL-WP] http://software.intel.com/en-us/articles/intel-carry-less-multiplication-instruction-and-its-usage-for-computing-the-gcm-mode/
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_AESNI_C)

//#include "polarssl/aesni.h"
#include <stdio.h>

#if defined(POLARSSL_HAVE_X86_64)

/*
 * AES-NI support detection routine
 */
int aesni_supports( unsigned int what )
{
    static int done = 0;
    static unsigned int c = 0;

    if( ! done )
    {
        asm( "movl  $1, %%eax   \n\t"
             "cpuid             \n\t"
             : "=c" (c)
             :
             : "eax", "ebx", "edx" );
        done = 1;
    }

    return( ( c & what ) != 0 );
}

/*
 * Binutils needs to be at least 2.19 to support AES-NI instructions.
 * Unfortunately, a lot of users have a lower version now (2014-04).
 * Emit bytecode directly in order to support "old" version of gas.
 *
 * Opcodes from the Intel architecture reference manual, vol. 3.
 * We always use registers, so we don't need prefixes for memory operands.
 * Operand macros are in gas order (src, dst) as opposed to Intel order
 * (dst, src) in order to blend better into the surrounding assembly code.
 */
#define AESDEC      ".byte 0x66,0x0F,0x38,0xDE,"
#define AESDECLAST  ".byte 0x66,0x0F,0x38,0xDF,"
#define AESENC      ".byte 0x66,0x0F,0x38,0xDC,"
#define AESENCLAST  ".byte 0x66,0x0F,0x38,0xDD,"
#define AESIMC      ".byte 0x66,0x0F,0x38,0xDB,"
#define AESKEYGENA  ".byte 0x66,0x0F,0x3A,0xDF,"
#define PCLMULQDQ   ".byte 0x66,0x0F,0x3A,0x44,"

#define xmm0_xmm0   "0xC0"
#define xmm0_xmm1   "0xC8"
#define xmm0_xmm2   "0xD0"
#define xmm0_xmm3   "0xD8"
#define xmm0_xmm4   "0xE0"
#define xmm1_xmm0   "0xC1"
#define xmm1_xmm2   "0xD1"

/*
 * AES-NI AES-ECB block en(de)cryption
 */
int aesni_crypt_ecb( aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] )
{
    asm( "movdqu    (%3), %%xmm0    \n\t" // load input
         "movdqu    (%1), %%xmm1    \n\t" // load round key 0
         "pxor      %%xmm1, %%xmm0  \n\t" // round 0
         "addq      $16, %1         \n\t" // point to next round key
         "subl      $1, %0          \n\t" // normal rounds = nr - 1
         "test      %2, %2          \n\t" // mode?
         "jz        2f              \n\t" // 0 = decrypt

         "1:                        \n\t" // encryption loop
         "movdqu    (%1), %%xmm1    \n\t" // load round key
         AESENC     xmm1_xmm0      "\n\t" // do round
         "addq      $16, %1         \n\t" // point to next round key
         "subl      $1, %0          \n\t" // loop
         "jnz       1b              \n\t"
         "movdqu    (%1), %%xmm1    \n\t" // load round key
         AESENCLAST xmm1_xmm0      "\n\t" // last round
         "jmp       3f              \n\t"

         "2:                        \n\t" // decryption loop
         "movdqu    (%1), %%xmm1    \n\t"
         AESDEC     xmm1_xmm0      "\n\t" // do round
         "addq      $16, %1         \n\t"
         "subl      $1, %0          \n\t"
         "jnz       2b              \n\t"
         "movdqu    (%1), %%xmm1    \n\t" // load round key
         AESDECLAST xmm1_xmm0      "\n\t" // last round

         "3:                        \n\t"
         "movdqu    %%xmm0, (%4)    \n\t" // export output
         :
         : "r" (ctx->nr), "r" (ctx->rk), "r" (mode), "r" (input), "r" (output)
         : "memory", "cc", "xmm0", "xmm1" );


    return( 0 );
}

/*
 * GCM multiplication: c = a times b in GF(2^128)
 * Based on [CLMUL-WP] algorithms 1 (with equation 27) and 5.
 */
void aesni_gcm_mult( unsigned char c[16],
                     const unsigned char a[16],
                     const unsigned char b[16] )
{
    unsigned char aa[16], bb[16], cc[16];
    size_t i;

    /* The inputs are in big-endian order, so byte-reverse them */
    for( i = 0; i < 16; i++ )
    {
        aa[i] = a[15 - i];
        bb[i] = b[15 - i];
    }

    asm( "movdqu (%0), %%xmm0               \n\t" // a1:a0
         "movdqu (%1), %%xmm1               \n\t" // b1:b0

         /*
          * Caryless multiplication xmm2:xmm1 = xmm0 * xmm1
          * using [CLMUL-WP] algorithm 1 (p. 13).
          */
         "movdqa %%xmm1, %%xmm2             \n\t" // copy of b1:b0
         "movdqa %%xmm1, %%xmm3             \n\t" // same
         "movdqa %%xmm1, %%xmm4             \n\t" // same
         PCLMULQDQ xmm0_xmm1 ",0x00         \n\t" // a0*b0 = c1:c0
         PCLMULQDQ xmm0_xmm2 ",0x11         \n\t" // a1*b1 = d1:d0
         PCLMULQDQ xmm0_xmm3 ",0x10         \n\t" // a0*b1 = e1:e0
         PCLMULQDQ xmm0_xmm4 ",0x01         \n\t" // a1*b0 = f1:f0
         "pxor %%xmm3, %%xmm4               \n\t" // e1+f1:e0+f0
         "movdqa %%xmm4, %%xmm3             \n\t" // same
         "psrldq $8, %%xmm4                 \n\t" // 0:e1+f1
         "pslldq $8, %%xmm3                 \n\t" // e0+f0:0
         "pxor %%xmm4, %%xmm2               \n\t" // d1:d0+e1+f1
         "pxor %%xmm3, %%xmm1               \n\t" // c1+e0+f1:c0

         /*
          * Now shift the result one bit to the left,
          * taking advantage of [CLMUL-WP] eq 27 (p. 20)
          */
         "movdqa %%xmm1, %%xmm3             \n\t" // r1:r0
         "movdqa %%xmm2, %%xmm4             \n\t" // r3:r2
         "psllq $1, %%xmm1                  \n\t" // r1<<1:r0<<1
         "psllq $1, %%xmm2                  \n\t" // r3<<1:r2<<1
         "psrlq $63, %%xmm3                 \n\t" // r1>>63:r0>>63
         "psrlq $63, %%xmm4                 \n\t" // r3>>63:r2>>63
         "movdqa %%xmm3, %%xmm5             \n\t" // r1>>63:r0>>63
         "pslldq $8, %%xmm3                 \n\t" // r0>>63:0
         "pslldq $8, %%xmm4                 \n\t" // r2>>63:0
         "psrldq $8, %%xmm5                 \n\t" // 0:r1>>63
         "por %%xmm3, %%xmm1                \n\t" // r1<<1|r0>>63:r0<<1
         "por %%xmm4, %%xmm2                \n\t" // r3<<1|r2>>62:r2<<1
         "por %%xmm5, %%xmm2                \n\t" // r3<<1|r2>>62:r2<<1|r1>>63

         /*
          * Now reduce modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1
          * using [CLMUL-WP] algorithm 5 (p. 20).
          * Currently xmm2:xmm1 holds x3:x2:x1:x0 (already shifted).
          */
         /* Step 2 (1) */
         "movdqa %%xmm1, %%xmm3             \n\t" // x1:x0
         "movdqa %%xmm1, %%xmm4             \n\t" // same
         "movdqa %%xmm1, %%xmm5             \n\t" // same
         "psllq $63, %%xmm3                 \n\t" // x1<<63:x0<<63 = stuff:a
         "psllq $62, %%xmm4                 \n\t" // x1<<62:x0<<62 = stuff:b
         "psllq $57, %%xmm5                 \n\t" // x1<<57:x0<<57 = stuff:c

         /* Step 2 (2) */
         "pxor %%xmm4, %%xmm3               \n\t" // stuff:a+b
         "pxor %%xmm5, %%xmm3               \n\t" // stuff:a+b+c
         "pslldq $8, %%xmm3                 \n\t" // a+b+c:0
         "pxor %%xmm3, %%xmm1               \n\t" // x1+a+b+c:x0 = d:x0

         /* Steps 3 and 4 */
         "movdqa %%xmm1,%%xmm0              \n\t" // d:x0
         "movdqa %%xmm1,%%xmm4              \n\t" // same
         "movdqa %%xmm1,%%xmm5              \n\t" // same
         "psrlq $1, %%xmm0                  \n\t" // e1:x0>>1 = e1:e0'
         "psrlq $2, %%xmm4                  \n\t" // f1:x0>>2 = f1:f0'
         "psrlq $7, %%xmm5                  \n\t" // g1:x0>>7 = g1:g0'
         "pxor %%xmm4, %%xmm0               \n\t" // e1+f1:e0'+f0'
         "pxor %%xmm5, %%xmm0               \n\t" // e1+f1+g1:e0'+f0'+g0'
         // e0'+f0'+g0' is almost e0+f0+g0, ex\tcept for some missing
         // bits carried from d. Now get those\t bits back in.
         "movdqa %%xmm1,%%xmm3              \n\t" // d:x0
         "movdqa %%xmm1,%%xmm4              \n\t" // same
         "movdqa %%xmm1,%%xmm5              \n\t" // same
         "psllq $63, %%xmm3                 \n\t" // d<<63:stuff
         "psllq $62, %%xmm4                 \n\t" // d<<62:stuff
         "psllq $57, %%xmm5                 \n\t" // d<<57:stuff
         "pxor %%xmm4, %%xmm3               \n\t" // d<<63+d<<62:stuff
         "pxor %%xmm5, %%xmm3               \n\t" // missing bits of d:stuff
         "psrldq $8, %%xmm3                 \n\t" // 0:missing bits of d
         "pxor %%xmm3, %%xmm0               \n\t" // e1+f1+g1:e0+f0+g0
         "pxor %%xmm1, %%xmm0               \n\t" // h1:h0
         "pxor %%xmm2, %%xmm0               \n\t" // x3+h1:x2+h0

         "movdqu %%xmm0, (%2)               \n\t" // done
         :
         : "r" (aa), "r" (bb), "r" (cc)
         : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5" );

    /* Now byte-reverse the outputs */
    for( i = 0; i < 16; i++ )
        c[i] = cc[15 - i];

    return;
}

/*
 * Compute decryption round keys from encryption round keys
 */
void aesni_inverse_key( unsigned char *invkey,
                        const unsigned char *fwdkey, int nr )
{
    unsigned char *ik = invkey;
    const unsigned char *fk = fwdkey + 16 * nr;

    memcpy( ik, fk, 16 );

    for( fk -= 16, ik += 16; fk > fwdkey; fk -= 16, ik += 16 )
        asm( "movdqu (%0), %%xmm0       \n\t"
             AESIMC  xmm0_xmm0         "\n\t"
             "movdqu %%xmm0, (%1)       \n\t"
             :
             : "r" (fk), "r" (ik)
             : "memory", "xmm0" );

    memcpy( ik, fk, 16 );
}

/*
 * Key expansion, 128-bit case
 */
static void aesni_setkey_enc_128( unsigned char *rk,
                                  const unsigned char *key )
{
    asm( "movdqu (%1), %%xmm0               \n\t" // copy the original key
         "movdqu %%xmm0, (%0)               \n\t" // as round key 0
         "jmp 2f                            \n\t" // skip auxiliary routine

         /*
          * Finish generating the next round key.
          *
          * On entry xmm0 is r3:r2:r1:r0 and xmm1 is X:stuff:stuff:stuff
          * with X = rot( sub( r3 ) ) ^ RCON.
          *
          * On exit, xmm0 is r7:r6:r5:r4
          * with r4 = X + r0, r5 = r4 + r1, r6 = r5 + r2, r7 = r6 + r3
          * and those are written to the round key buffer.
          */
         "1:                                \n\t"
         "pshufd $0xff, %%xmm1, %%xmm1      \n\t" // X:X:X:X
         "pxor %%xmm0, %%xmm1               \n\t" // X+r3:X+r2:X+r1:r4
         "pslldq $4, %%xmm0                 \n\t" // r2:r1:r0:0
         "pxor %%xmm0, %%xmm1               \n\t" // X+r3+r2:X+r2+r1:r5:r4
         "pslldq $4, %%xmm0                 \n\t" // etc
         "pxor %%xmm0, %%xmm1               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm1, %%xmm0               \n\t" // update xmm0 for next time!
         "add $16, %0                       \n\t" // point to next round key
         "movdqu %%xmm0, (%0)               \n\t" // write it
         "ret                               \n\t"

         /* Main "loop" */
         "2:                                \n\t"
         AESKEYGENA xmm0_xmm1 ",0x01        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x02        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x04        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x08        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x10        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x20        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x40        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x80        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x1B        \n\tcall 1b \n\t"
         AESKEYGENA xmm0_xmm1 ",0x36        \n\tcall 1b \n\t"
         :
         : "r" (rk), "r" (key)
         : "memory", "cc", "0" );
}

/*
 * Key expansion, 192-bit case
 */
static void aesni_setkey_enc_192( unsigned char *rk,
                                  const unsigned char *key )
{
    asm( "movdqu (%1), %%xmm0   \n\t" // copy original round key
         "movdqu %%xmm0, (%0)   \n\t"
         "add $16, %0           \n\t"
         "movq 16(%1), %%xmm1   \n\t"
         "movq %%xmm1, (%0)     \n\t"
         "add $8, %0            \n\t"
         "jmp 2f                \n\t" // skip auxiliary routine

         /*
          * Finish generating the next 6 quarter-keys.
          *
          * On entry xmm0 is r3:r2:r1:r0, xmm1 is stuff:stuff:r5:r4
          * and xmm2 is stuff:stuff:X:stuff with X = rot( sub( r3 ) ) ^ RCON.
          *
          * On exit, xmm0 is r9:r8:r7:r6 and xmm1 is stuff:stuff:r11:r10
          * and those are written to the round key buffer.
          */
         "1:                            \n\t"
         "pshufd $0x55, %%xmm2, %%xmm2  \n\t" // X:X:X:X
         "pxor %%xmm0, %%xmm2           \n\t" // X+r3:X+r2:X+r1:r4
         "pslldq $4, %%xmm0             \n\t" // etc
         "pxor %%xmm0, %%xmm2           \n\t"
         "pslldq $4, %%xmm0             \n\t"
         "pxor %%xmm0, %%xmm2           \n\t"
         "pslldq $4, %%xmm0             \n\t"
         "pxor %%xmm2, %%xmm0           \n\t" // update xmm0 = r9:r8:r7:r6
         "movdqu %%xmm0, (%0)           \n\t"
         "add $16, %0                   \n\t"
         "pshufd $0xff, %%xmm0, %%xmm2  \n\t" // r9:r9:r9:r9
         "pxor %%xmm1, %%xmm2           \n\t" // stuff:stuff:r9+r5:r10
         "pslldq $4, %%xmm1             \n\t" // r2:r1:r0:0
         "pxor %%xmm2, %%xmm1           \n\t" // xmm1 = stuff:stuff:r11:r10
         "movq %%xmm1, (%0)             \n\t"
         "add $8, %0                    \n\t"
         "ret                           \n\t"

         "2:                            \n\t"
         AESKEYGENA xmm1_xmm2 ",0x01    \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x02    \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x04    \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x08    \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x10    \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x20    \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x40    \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x80    \n\tcall 1b \n\t"

         :
         : "r" (rk), "r" (key)
         : "memory", "cc", "0" );
}

/*
 * Key expansion, 256-bit case
 */
static void aesni_setkey_enc_256( unsigned char *rk,
                                  const unsigned char *key )
{
    asm( "movdqu (%1), %%xmm0           \n\t"
         "movdqu %%xmm0, (%0)           \n\t"
         "add $16, %0                   \n\t"
         "movdqu 16(%1), %%xmm1         \n\t"
         "movdqu %%xmm1, (%0)           \n\t"
         "jmp 2f                        \n\t" // skip auxiliary routine

         /*
          * Finish generating the next two round keys.
          *
          * On entry xmm0 is r3:r2:r1:r0, xmm1 is r7:r6:r5:r4 and
          * xmm2 is X:stuff:stuff:stuff with X = rot( sub( r7 )) ^ RCON
          *
          * On exit, xmm0 is r11:r10:r9:r8 and xmm1 is r15:r14:r13:r12
          * and those have been written to the output buffer.
          */
         "1:                                \n\t"
         "pshufd $0xff, %%xmm2, %%xmm2      \n\t"
         "pxor %%xmm0, %%xmm2               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm0, %%xmm2               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm0, %%xmm2               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm2, %%xmm0               \n\t"
         "add $16, %0                       \n\t"
         "movdqu %%xmm0, (%0)               \n\t"

         /* Set xmm2 to stuff:Y:stuff:stuff with Y = subword( r11 )
          * and proceed to generate next round key from there */
         AESKEYGENA xmm0_xmm2 ",0x00        \n\t"
         "pshufd $0xaa, %%xmm2, %%xmm2      \n\t"
         "pxor %%xmm1, %%xmm2               \n\t"
         "pslldq $4, %%xmm1                 \n\t"
         "pxor %%xmm1, %%xmm2               \n\t"
         "pslldq $4, %%xmm1                 \n\t"
         "pxor %%xmm1, %%xmm2               \n\t"
         "pslldq $4, %%xmm1                 \n\t"
         "pxor %%xmm2, %%xmm1               \n\t"
         "add $16, %0                       \n\t"
         "movdqu %%xmm1, (%0)               \n\t"
         "ret                               \n\t"

         /*
          * Main "loop" - Generating one more key than necessary,
          * see definition of aes_context.buf
          */
         "2:                                \n\t"
         AESKEYGENA xmm1_xmm2 ",0x01        \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x02        \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x04        \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x08        \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x10        \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x20        \n\tcall 1b \n\t"
         AESKEYGENA xmm1_xmm2 ",0x40        \n\tcall 1b \n\t"
         :
         : "r" (rk), "r" (key)
         : "memory", "cc", "0" );
}

/*
 * Key expansion, wrapper
 */
int aesni_setkey_enc( unsigned char *rk,
                      const unsigned char *key,
                      size_t bits )
{
    switch( bits )
    {
        case 128: aesni_setkey_enc_128( rk, key ); break;
        case 192: aesni_setkey_enc_192( rk, key ); break;
        case 256: aesni_setkey_enc_256( rk, key ); break;
        default : return( POLARSSL_ERR_AES_INVALID_KEY_LENGTH );
    }

    return( 0 );
}

#endif /* POLARSSL_HAVE_X86_64 */

#endif /* POLARSSL_AESNI_C */
/*
 *  Multi-precision integer library
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  This MPI implementation is based on:
 *
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf
 *  http://www.stillhq.com/extracted/gnupg-api/mpi/
 *  http://math.libtomcrypt.com/files/tommath.pdf
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_BIGNUM_C)

//#include "polarssl/bignum.h"
//#include "polarssl/bn_mul.h"

#if defined(POLARSSL_PLATFORM_C)
//#include "polarssl/platform.h"
#else
#define polarssl_printf     printf
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#include <stdlib.h>

/* Implementation that should never be optimized out by the compiler */
//static void polarssl_zeroize( void *v, size_t n ) {
//    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
//}

#define ciL    (sizeof(t_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 */
#define BITS_TO_LIMBS(i)  (((i) + biL - 1) / biL)
#define CHARS_TO_LIMBS(i) (((i) + ciL - 1) / ciL)

/*
 * Initialize one MPI
 */
void mpi_init( mpi *X )
{
    if( X == NULL )
        return;

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Unallocate one MPI
 */
void mpi_free( mpi *X )
{
    if( X == NULL )
        return;

    if( X->p != NULL )
    {
        polarssl_zeroize( X->p, X->n * ciL );
        polarssl_free( X->p );
    }

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Enlarge to the specified number of limbs
 */
static int mpi_grow( mpi *X, size_t nblimbs )
{
    t_uint *p;

    if( nblimbs > POLARSSL_MPI_MAX_LIMBS )
        return( POLARSSL_ERR_MPI_MALLOC_FAILED );

    if( X->n < nblimbs )
    {
        if( ( p = (t_uint *) polarssl_malloc( nblimbs * ciL ) ) == NULL )
            return( POLARSSL_ERR_MPI_MALLOC_FAILED );

        memset( p, 0, nblimbs * ciL );

        if( X->p != NULL )
        {
            memcpy( p, X->p, X->n * ciL );
            polarssl_zeroize( X->p, X->n * ciL );
            polarssl_free( X->p );
        }

        X->n = nblimbs;
        X->p = p;
    }

    return( 0 );
}

/*
 * Resize down as much as possible,
 * while keeping at least the specified number of limbs
 */
static int mpi_shrink( mpi *X, size_t nblimbs )
{
    t_uint *p;
    size_t i;

    /* Actually resize up in this case */
    if( X->n <= nblimbs )
        return( mpi_grow( X, nblimbs ) );

    for( i = X->n - 1; i > 0; i-- )
        if( X->p[i] != 0 )
            break;
    i++;

    if( i < nblimbs )
        i = nblimbs;

    if( ( p = (t_uint *) polarssl_malloc( i * ciL ) ) == NULL )
        return( POLARSSL_ERR_MPI_MALLOC_FAILED );

    memset( p, 0, i * ciL );

    if( X->p != NULL )
    {
        memcpy( p, X->p, i * ciL );
        polarssl_zeroize( X->p, X->n * ciL );
        polarssl_free( X->p );
    }

    X->n = i;
    X->p = p;

    return( 0 );
}

/*
 * Copy the contents of Y into X
 */
static int mpi_copy( mpi *X, const mpi *Y )
{
    int ret;
    size_t i;

    if( X == Y )
        return( 0 );

    if( Y->p == NULL )
    {
        mpi_free( X );
        return( 0 );
    }

    for( i = Y->n - 1; i > 0; i-- )
        if( Y->p[i] != 0 )
            break;
    i++;

    X->s = Y->s;

    MPI_CHK( mpi_grow( X, i ) );

    memset( X->p, 0, X->n * ciL );
    memcpy( X->p, Y->p, i * ciL );

cleanup:

    return( ret );
}

/*
 * Swap the contents of X and Y
 */
void mpi_swap( mpi *X, mpi *Y )
{
    mpi T;

    memcpy( &T,  X, sizeof( mpi ) );
    memcpy(  X,  Y, sizeof( mpi ) );
    memcpy(  Y, &T, sizeof( mpi ) );
}

/*
 * Conditionally assign X = Y, without leaking information
 * about whether the assignment was made or not.
 * (Leaking information about the respective sizes of X and Y is ok however.)
 */
static int mpi_safe_cond_assign( mpi *X, const mpi *Y, unsigned char assign )
{
    int ret = 0;
    size_t i;

    /* make sure assign is 0 or 1 */
    assign = ( assign != 0 );

    MPI_CHK( mpi_grow( X, Y->n ) );

    X->s = X->s * ( 1 - assign ) + Y->s * assign;

    for( i = 0; i < Y->n; i++ )
        X->p[i] = X->p[i] * ( 1 - assign ) + Y->p[i] * assign;

    for( ; i < X->n; i++ )
        X->p[i] *= ( 1 - assign );

cleanup:
    return( ret );
}

/*
 * Conditionally swap X and Y, without leaking information
 * about whether the swap was made or not.
 * Here it is not ok to simply swap the pointers, which whould lead to
 * different memory access patterns when X and Y are used afterwards.
 */
static int mpi_safe_cond_swap( mpi *X, mpi *Y, unsigned char swap )
{
    int ret, s;
    size_t i;
    t_uint tmp;

    if( X == Y )
        return( 0 );

    /* make sure swap is 0 or 1 */
    swap = ( swap != 0 );

    MPI_CHK( mpi_grow( X, Y->n ) );
    MPI_CHK( mpi_grow( Y, X->n ) );

    s = X->s;
    X->s = X->s * ( 1 - swap ) + Y->s * swap;
    Y->s = Y->s * ( 1 - swap ) +    s * swap;


    for( i = 0; i < X->n; i++ )
    {
        tmp = X->p[i];
        X->p[i] = X->p[i] * ( 1 - swap ) + Y->p[i] * swap;
        Y->p[i] = Y->p[i] * ( 1 - swap ) +     tmp * swap;
    }

cleanup:
    return( ret );
}

/*
 * Set value from integer
 */
static int mpi_lset( mpi *X, t_sint z )
{
    int ret;

    MPI_CHK( mpi_grow( X, 1 ) );
    memset( X->p, 0, X->n * ciL );

    X->p[0] = ( z < 0 ) ? -z : z;
    X->s    = ( z < 0 ) ? -1 : 1;

cleanup:

    return( ret );
}

/*
 * Get a specific bit
 */
static int mpi_get_bit( const mpi *X, size_t pos )
{
    if( X->n * biL <= pos )
        return( 0 );

    return( ( X->p[pos / biL] >> ( pos % biL ) ) & 0x01 );
}

/*
 * Set a bit to a specific value of 0 or 1
 */
static int mpi_set_bit( mpi *X, size_t pos, unsigned char val )
{
    int ret = 0;
    size_t off = pos / biL;
    size_t idx = pos % biL;

    if( val != 0 && val != 1 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    if( X->n * biL <= pos )
    {
        if( val == 0 )
            return( 0 );

        MPI_CHK( mpi_grow( X, off + 1 ) );
    }

    X->p[off] &= ~( (t_uint) 0x01 << idx );
    X->p[off] |= (t_uint) val << idx;

cleanup:

    return( ret );
}

/*
 * Return the number of least significant bits
 */
size_t mpi_lsb( const mpi *X )
{
    size_t i, j, count = 0;

    for( i = 0; i < X->n; i++ )
        for( j = 0; j < biL; j++, count++ )
            if( ( ( X->p[i] >> j ) & 1 ) != 0 )
                return( count );

    return( 0 );
}

/*
 * Return the number of most significant bits
 */
size_t mpi_msb( const mpi *X )
{
    size_t i, j;

    for( i = X->n - 1; i > 0; i-- )
        if( X->p[i] != 0 )
            break;

    for( j = biL; j > 0; j-- )
        if( ( ( X->p[i] >> ( j - 1 ) ) & 1 ) != 0 )
            break;

    return( ( i * biL ) + j );
}

/*
 * Return the total size in bytes
 */
size_t mpi_size( const mpi *X )
{
    return( ( mpi_msb( X ) + 7 ) >> 3 );
}

/*
 * Convert an ASCII character to digit value
 */
static int mpi_get_digit( t_uint *d, int radix, char c )
{
    *d = 255;

    if( c >= 0x30 && c <= 0x39 ) *d = c - 0x30;
    if( c >= 0x41 && c <= 0x46 ) *d = c - 0x37;
    if( c >= 0x61 && c <= 0x66 ) *d = c - 0x57;

    if( *d >= (t_uint) radix )
        return( POLARSSL_ERR_MPI_INVALID_CHARACTER );

    return( 0 );
}

/*
 * Import from an ASCII string
 */
static int mpi_read_string( mpi *X, int radix, const char *s )
{
    int ret;
    size_t i, j, slen, n;
    t_uint d;
    mpi T;

    if( radix < 2 || radix > 16 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    mpi_init( &T );

    slen = strlen( s );

    if( radix == 16 )
    {
        n = BITS_TO_LIMBS( slen << 2 );

        MPI_CHK( mpi_grow( X, n ) );
        MPI_CHK( mpi_lset( X, 0 ) );

        for( i = slen, j = 0; i > 0; i--, j++ )
        {
            if( i == 1 && s[i - 1] == '-' )
            {
                X->s = -1;
                break;
            }

            MPI_CHK( mpi_get_digit( &d, radix, s[i - 1] ) );
            X->p[j / ( 2 * ciL )] |= d << ( ( j % ( 2 * ciL ) ) << 2 );
        }
    }
    else
    {
        MPI_CHK( mpi_lset( X, 0 ) );

        for( i = 0; i < slen; i++ )
        {
            if( i == 0 && s[i] == '-' )
            {
                X->s = -1;
                continue;
            }

            MPI_CHK( mpi_get_digit( &d, radix, s[i] ) );
            MPI_CHK( mpi_mul_int( &T, X, radix ) );

            if( X->s == 1 )
            {
                MPI_CHK( mpi_add_int( X, &T, d ) );
            }
            else
            {
                MPI_CHK( mpi_sub_int( X, &T, d ) );
            }
        }
    }

cleanup:

    mpi_free( &T );

    return( ret );
}

/*
 * Helper to write the digits high-order first
 */
static int mpi_write_hlp( mpi *X, int radix, char **p )
{
    int ret;
    t_uint r;

    if( radix < 2 || radix > 16 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    MPI_CHK( mpi_mod_int( &r, X, radix ) );
    MPI_CHK( mpi_div_int( X, NULL, X, radix ) );

    if( mpi_cmp_int( X, 0 ) != 0 )
        MPI_CHK( mpi_write_hlp( X, radix, p ) );

    if( r < 10 )
        *(*p)++ = (char)( r + 0x30 );
    else
        *(*p)++ = (char)( r + 0x37 );

cleanup:

    return( ret );
}

/*
 * Export into an ASCII string
 */
static int mpi_write_string( const mpi *X, int radix, char *s, size_t *slen )
{
    int ret = 0;
    size_t n;
    char *p;
    mpi T;

    if( radix < 2 || radix > 16 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    n = mpi_msb( X );
    if( radix >=  4 ) n >>= 1;
    if( radix >= 16 ) n >>= 1;
    n += 3;

    if( *slen < n )
    {
        *slen = n;
        return( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );
    }

    p = s;
    mpi_init( &T );

    if( X->s == -1 )
        *p++ = '-';

    if( radix == 16 )
    {
        int c;
        size_t i, j, k;

        for( i = X->n, k = 0; i > 0; i-- )
        {
            for( j = ciL; j > 0; j-- )
            {
                c = ( X->p[i - 1] >> ( ( j - 1 ) << 3) ) & 0xFF;

                if( c == 0 && k == 0 && ( i + j ) != 2 )
                    continue;

                *(p++) = "0123456789ABCDEF" [c / 16];
                *(p++) = "0123456789ABCDEF" [c % 16];
                k = 1;
            }
        }
    }
    else
    {
        MPI_CHK( mpi_copy( &T, X ) );

        if( T.s == -1 )
            T.s = 1;

        MPI_CHK( mpi_write_hlp( &T, radix, &p ) );
    }

    *p++ = '\0';
    *slen = p - s;

cleanup:

    mpi_free( &T );

    return( ret );
}

#if defined(POLARSSL_FS_IO)
/*
 * Read X from an opened file
 */
static int mpi_read_file( mpi *X, int radix, FILE *fin )
{
    t_uint d;
    size_t slen;
    char *p;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[ POLARSSL_MPI_RW_BUFFER_SIZE ];

    memset( s, 0, sizeof( s ) );
    if( fgets( s, sizeof( s ) - 1, fin ) == NULL )
        return( POLARSSL_ERR_MPI_FILE_IO_ERROR );

    slen = strlen( s );
    if( slen == sizeof( s ) - 2 )
        return( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );

    if( s[slen - 1] == '\n' ) { slen--; s[slen] = '\0'; }
    if( s[slen - 1] == '\r' ) { slen--; s[slen] = '\0'; }

    p = s + slen;
    while( --p >= s )
        if( mpi_get_digit( &d, radix, *p ) != 0 )
            break;

    return( mpi_read_string( X, radix, p + 1 ) );
}

/*
 * Write X into an opened file (or stdout if fout == NULL)
 */
static int mpi_write_file( const char *p, const mpi *X, int radix, FILE *fout )
{
    int ret;
    size_t n, slen, plen;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[ POLARSSL_MPI_RW_BUFFER_SIZE ];

    n = sizeof( s );
    memset( s, 0, n );
    n -= 2;

    MPI_CHK( mpi_write_string( X, radix, s, (size_t *) &n ) );

    if( p == NULL ) p = "";

    plen = strlen( p );
    slen = strlen( s );
    s[slen++] = '\r';
    s[slen++] = '\n';

    if( fout != NULL )
    {
        if( fwrite( p, 1, plen, fout ) != plen ||
            fwrite( s, 1, slen, fout ) != slen )
            return( POLARSSL_ERR_MPI_FILE_IO_ERROR );
    }
    else
        polarssl_printf( "%s%s", p, s );

cleanup:

    return( ret );
}
#endif /* POLARSSL_FS_IO */

/*
 * Import X from unsigned binary data, big endian
 */
static int mpi_read_binary( mpi *X, const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t i, j, n;

    for( n = 0; n < buflen; n++ )
        if( buf[n] != 0 )
            break;

    MPI_CHK( mpi_grow( X, CHARS_TO_LIMBS( buflen - n ) ) );
    MPI_CHK( mpi_lset( X, 0 ) );

    for( i = buflen, j = 0; i > n; i--, j++ )
        X->p[j / ciL] |= ((t_uint) buf[i - 1]) << ((j % ciL) << 3);

cleanup:

    return( ret );
}

/*
 * Export X into unsigned binary data, big endian
 */
static int mpi_write_binary( const mpi *X, unsigned char *buf, size_t buflen )
{
    size_t i, j, n;

    n = mpi_size( X );

    if( buflen < n )
        return( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );

    memset( buf, 0, buflen );

    for( i = buflen - 1, j = 0; n > 0; i--, j++, n-- )
        buf[i] = (unsigned char)( X->p[j / ciL] >> ((j % ciL) << 3) );

    return( 0 );
}

/*
 * Left-shift: X <<= count
 */
static int mpi_shift_l( mpi *X, size_t count )
{
    int ret;
    size_t i, v0, t1;
    t_uint r0 = 0, r1;

    v0 = count / (biL    );
    t1 = count & (biL - 1);

    i = mpi_msb( X ) + count;

    if( X->n * biL < i )
        MPI_CHK( mpi_grow( X, BITS_TO_LIMBS( i ) ) );

    ret = 0;

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = X->n; i > v0; i-- )
            X->p[i - 1] = X->p[i - v0 - 1];

        for( ; i > 0; i-- )
            X->p[i - 1] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( t1 > 0 )
    {
        for( i = v0; i < X->n; i++ )
        {
            r1 = X->p[i] >> (biL - t1);
            X->p[i] <<= t1;
            X->p[i] |= r0;
            r0 = r1;
        }
    }

cleanup:

    return( ret );
}

/*
 * Right-shift: X >>= count
 */
static int mpi_shift_r( mpi *X, size_t count )
{
    size_t i, v0, v1;
    t_uint r0 = 0, r1;

    v0 = count /  biL;
    v1 = count & (biL - 1);

    if( v0 > X->n || ( v0 == X->n && v1 > 0 ) )
        return mpi_lset( X, 0 );

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = 0; i < X->n - v0; i++ )
            X->p[i] = X->p[i + v0];

        for( ; i < X->n; i++ )
            X->p[i] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( v1 > 0 )
    {
        for( i = X->n; i > 0; i-- )
        {
            r1 = X->p[i - 1] << (biL - v1);
            X->p[i - 1] >>= v1;
            X->p[i - 1] |= r0;
            r0 = r1;
        }
    }

    return( 0 );
}

/*
 * Compare unsigned values
 */
static int mpi_cmp_abs( const mpi *X, const mpi *Y )
{
    size_t i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  1 );
    if( j > i ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  1 );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -1 );
    }

    return( 0 );
}

/*
 * Compare signed values
 */
static int mpi_cmp_mpi( const mpi *X, const mpi *Y )
{
    size_t i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  X->s );
    if( j > i ) return( -Y->s );

    if( X->s > 0 && Y->s < 0 ) return(  1 );
    if( Y->s > 0 && X->s < 0 ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  X->s );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -X->s );
    }

    return( 0 );
}

/*
 * Compare signed values
 */
static int mpi_cmp_int( const mpi *X, t_sint z )
{
    mpi Y;
    t_uint p[1];

    *p  = ( z < 0 ) ? -z : z;
    Y.s = ( z < 0 ) ? -1 : 1;
    Y.n = 1;
    Y.p = p;

    return( mpi_cmp_mpi( X, &Y ) );
}

/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
static int mpi_add_abs( mpi *X, const mpi *A, const mpi *B )
{
    int ret;
    size_t i, j;
    t_uint *o, *p, c;

    if( X == B )
    {
        const mpi *T = A; A = X; B = T;
    }

    if( X != A )
        MPI_CHK( mpi_copy( X, A ) );

    /*
     * X should always be positive as a result of unsigned additions.
     */
    X->s = 1;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    MPI_CHK( mpi_grow( X, j ) );

    o = B->p; p = X->p; c = 0;

    for( i = 0; i < j; i++, o++, p++ )
    {
        *p +=  c; c  = ( *p <  c );
        *p += *o; c += ( *p < *o );
    }

    while( c != 0 )
    {
        if( i >= X->n )
        {
            MPI_CHK( mpi_grow( X, i + 1 ) );
            p = X->p + i;
        }

        *p += c; c = ( *p < c ); i++; p++;
    }

cleanup:

    return( ret );
}

/*
 * Helper for mpi subtraction
 */
static void mpi_sub_hlp( size_t n, t_uint *s, t_uint *d )
{
    size_t i;
    t_uint c, z;

    for( i = c = 0; i < n; i++, s++, d++ )
    {
        z = ( *d <  c );     *d -=  c;
        c = ( *d < *s ) + z; *d -= *s;
    }

    while( c != 0 )
    {
        z = ( *d < c ); *d -= c;
        c = z; i++; d++;
    }
}

/*
 * Unsigned subtraction: X = |A| - |B|  (HAC 14.9)
 */
static int mpi_sub_abs( mpi *X, const mpi *A, const mpi *B )
{
    mpi TB;
    int ret;
    size_t n;

    if( mpi_cmp_abs( A, B ) < 0 )
        return( POLARSSL_ERR_MPI_NEGATIVE_VALUE );

    mpi_init( &TB );

    if( X == B )
    {
        MPI_CHK( mpi_copy( &TB, B ) );
        B = &TB;
    }

    if( X != A )
        MPI_CHK( mpi_copy( X, A ) );

    /*
     * X should always be positive as a result of unsigned subtractions.
     */
    X->s = 1;

    ret = 0;

    for( n = B->n; n > 0; n-- )
        if( B->p[n - 1] != 0 )
            break;

    mpi_sub_hlp( n, B->p, X->p );

cleanup:

    mpi_free( &TB );

    return( ret );
}

/*
 * Signed addition: X = A + B
 */
static int mpi_add_mpi( mpi *X, const mpi *A, const mpi *B )
{
    int ret, s = A->s;

    if( A->s * B->s < 0 )
    {
        if( mpi_cmp_abs( A, B ) >= 0 )
        {
            MPI_CHK( mpi_sub_abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            MPI_CHK( mpi_sub_abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        MPI_CHK( mpi_add_abs( X, A, B ) );
        X->s = s;
    }

cleanup:

    return( ret );
}

/*
 * Signed subtraction: X = A - B
 */
static int mpi_sub_mpi( mpi *X, const mpi *A, const mpi *B )
{
    int ret, s = A->s;

    if( A->s * B->s > 0 )
    {
        if( mpi_cmp_abs( A, B ) >= 0 )
        {
            MPI_CHK( mpi_sub_abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            MPI_CHK( mpi_sub_abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        MPI_CHK( mpi_add_abs( X, A, B ) );
        X->s = s;
    }

cleanup:

    return( ret );
}

/*
 * Signed addition: X = A + b
 */
static int mpi_add_int( mpi *X, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( mpi_add_mpi( X, A, &_B ) );
}

/*
 * Signed subtraction: X = A - b
 */
static int mpi_sub_int( mpi *X, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( mpi_sub_mpi( X, A, &_B ) );
}

/*
 * Helper for mpi multiplication
 */
static
#if defined(__APPLE__) && defined(__arm__)
/*
 * Apple LLVM version 4.2 (clang-425.0.24) (based on LLVM 3.2svn)
 * appears to need this to prevent bad ARM code generation at -O3.
 */
__attribute__ ((noinline))
#endif
void mpi_mul_hlp( size_t i, t_uint *s, t_uint *d, t_uint b )
{
    t_uint c = 0, t = 0;

#if defined(MULADDC_HUIT)
    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_HUIT
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#else /* MULADDC_HUIT */
    for( ; i >= 16; i -= 16 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#endif /* MULADDC_HUIT */

    t++;

    do {
        *d += c; c = ( *d < c ); d++;
    }
    while( c != 0 );
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
static int mpi_mul_mpi( mpi *X, const mpi *A, const mpi *B )
{
    int ret;
    size_t i, j;
    mpi TA, TB;

    mpi_init( &TA ); mpi_init( &TB );

    if( X == A ) { MPI_CHK( mpi_copy( &TA, A ) ); A = &TA; }
    if( X == B ) { MPI_CHK( mpi_copy( &TB, B ) ); B = &TB; }

    for( i = A->n; i > 0; i-- )
        if( A->p[i - 1] != 0 )
            break;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    MPI_CHK( mpi_grow( X, i + j ) );
    MPI_CHK( mpi_lset( X, 0 ) );

    for( i++; j > 0; j-- )
        mpi_mul_hlp( i - 1, A->p, X->p + j - 1, B->p[j - 1] );

    X->s = A->s * B->s;

cleanup:

    mpi_free( &TB ); mpi_free( &TA );

    return( ret );
}

/*
 * Baseline multiplication: X = A * b
 */
static int mpi_mul_int( mpi *X, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    _B.s = 1;
    _B.n = 1;
    _B.p = p;
    p[0] = b;

    return( mpi_mul_mpi( X, A, &_B ) );
}

/*
 * Division by mpi: A = Q * B + R  (HAC 14.20)
 */
static int mpi_div_mpi( mpi *Q, mpi *R, const mpi *A, const mpi *B )
{
    int ret;
    size_t i, n, t, k;
    mpi X, Y, Z, T1, T2;

    if( mpi_cmp_int( B, 0 ) == 0 )
        return( POLARSSL_ERR_MPI_DIVISION_BY_ZERO );

    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );
    mpi_init( &T1 ); mpi_init( &T2 );

    if( mpi_cmp_abs( A, B ) < 0 )
    {
        if( Q != NULL ) MPI_CHK( mpi_lset( Q, 0 ) );
        if( R != NULL ) MPI_CHK( mpi_copy( R, A ) );
        return( 0 );
    }

    MPI_CHK( mpi_copy( &X, A ) );
    MPI_CHK( mpi_copy( &Y, B ) );
    X.s = Y.s = 1;

    MPI_CHK( mpi_grow( &Z, A->n + 2 ) );
    MPI_CHK( mpi_lset( &Z,  0 ) );
    MPI_CHK( mpi_grow( &T1, 2 ) );
    MPI_CHK( mpi_grow( &T2, 3 ) );

    k = mpi_msb( &Y ) % biL;
    if( k < biL - 1 )
    {
        k = biL - 1 - k;
        MPI_CHK( mpi_shift_l( &X, k ) );
        MPI_CHK( mpi_shift_l( &Y, k ) );
    }
    else k = 0;

    n = X.n - 1;
    t = Y.n - 1;
    MPI_CHK( mpi_shift_l( &Y, biL * ( n - t ) ) );

    while( mpi_cmp_mpi( &X, &Y ) >= 0 )
    {
        Z.p[n - t]++;
        MPI_CHK( mpi_sub_mpi( &X, &X, &Y ) );
    }
    MPI_CHK( mpi_shift_r( &Y, biL * ( n - t ) ) );

    for( i = n; i > t ; i-- )
    {
        if( X.p[i] >= Y.p[t] )
            Z.p[i - t - 1] = ~0;
        else
        {
            /*
             * The version of Clang shipped by Apple with Mavericks around
             * 2014-03 can't handle 128-bit division properly. Disable
             * 128-bits division for this version. Let's be optimistic and
             * assume it'll be fixed in the next minor version (next
             * patchlevel is probably a bit too optimistic).
             */
#if defined(POLARSSL_HAVE_UDBL) &&                          \
    ! ( defined(__x86_64__) && defined(__APPLE__) &&        \
        defined(__clang_major__) && __clang_major__ == 5 && \
        defined(__clang_minor__) && __clang_minor__ == 0 )
            t_udbl r;

            r  = (t_udbl) X.p[i] << biL;
            r |= (t_udbl) X.p[i - 1];
            r /= Y.p[t];
            if( r > ( (t_udbl) 1 << biL ) - 1 )
                r = ( (t_udbl) 1 << biL ) - 1;

            Z.p[i - t - 1] = (t_uint) r;
#else
            /*
             * __udiv_qrnnd_c, from gmp/longlong.h
             */
            t_uint q0, q1, r0, r1;
            t_uint d0, d1, d, m;

            d  = Y.p[t];
            d0 = ( d << biH ) >> biH;
            d1 = ( d >> biH );

            q1 = X.p[i] / d1;
            r1 = X.p[i] - d1 * q1;
            r1 <<= biH;
            r1 |= ( X.p[i - 1] >> biH );

            m = q1 * d0;
            if( r1 < m )
            {
                q1--, r1 += d;
                while( r1 >= d && r1 < m )
                    q1--, r1 += d;
            }
            r1 -= m;

            q0 = r1 / d1;
            r0 = r1 - d1 * q0;
            r0 <<= biH;
            r0 |= ( X.p[i - 1] << biH ) >> biH;

            m = q0 * d0;
            if( r0 < m )
            {
                q0--, r0 += d;
                while( r0 >= d && r0 < m )
                    q0--, r0 += d;
            }
            r0 -= m;

            Z.p[i - t - 1] = ( q1 << biH ) | q0;
#endif /* POLARSSL_HAVE_UDBL && !64-bit Apple with Clang 5.0 */
        }

        Z.p[i - t - 1]++;
        do
        {
            Z.p[i - t - 1]--;

            MPI_CHK( mpi_lset( &T1, 0 ) );
            T1.p[0] = ( t < 1 ) ? 0 : Y.p[t - 1];
            T1.p[1] = Y.p[t];
            MPI_CHK( mpi_mul_int( &T1, &T1, Z.p[i - t - 1] ) );

            MPI_CHK( mpi_lset( &T2, 0 ) );
            T2.p[0] = ( i < 2 ) ? 0 : X.p[i - 2];
            T2.p[1] = ( i < 1 ) ? 0 : X.p[i - 1];
            T2.p[2] = X.p[i];
        }
        while( mpi_cmp_mpi( &T1, &T2 ) > 0 );

        MPI_CHK( mpi_mul_int( &T1, &Y, Z.p[i - t - 1] ) );
        MPI_CHK( mpi_shift_l( &T1,  biL * ( i - t - 1 ) ) );
        MPI_CHK( mpi_sub_mpi( &X, &X, &T1 ) );

        if( mpi_cmp_int( &X, 0 ) < 0 )
        {
            MPI_CHK( mpi_copy( &T1, &Y ) );
            MPI_CHK( mpi_shift_l( &T1, biL * ( i - t - 1 ) ) );
            MPI_CHK( mpi_add_mpi( &X, &X, &T1 ) );
            Z.p[i - t - 1]--;
        }
    }

    if( Q != NULL )
    {
        MPI_CHK( mpi_copy( Q, &Z ) );
        Q->s = A->s * B->s;
    }

    if( R != NULL )
    {
        MPI_CHK( mpi_shift_r( &X, k ) );
        X.s = A->s;
        MPI_CHK( mpi_copy( R, &X ) );

        if( mpi_cmp_int( R, 0 ) == 0 )
            R->s = 1;
    }

cleanup:

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
    mpi_free( &T1 ); mpi_free( &T2 );

    return( ret );
}

/*
 * Division by int: A = Q * b + R
 */
static int mpi_div_int( mpi *Q, mpi *R, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( mpi_div_mpi( Q, R, A, &_B ) );
}

/*
 * Modulo: R = A mod B
 */
static int mpi_mod_mpi( mpi *R, const mpi *A, const mpi *B )
{
    int ret;

    if( mpi_cmp_int( B, 0 ) < 0 )
        return( POLARSSL_ERR_MPI_NEGATIVE_VALUE );

    MPI_CHK( mpi_div_mpi( NULL, R, A, B ) );

    while( mpi_cmp_int( R, 0 ) < 0 )
      MPI_CHK( mpi_add_mpi( R, R, B ) );

    while( mpi_cmp_mpi( R, B ) >= 0 )
      MPI_CHK( mpi_sub_mpi( R, R, B ) );

cleanup:

    return( ret );
}

/*
 * Modulo: r = A mod b
 */
static int mpi_mod_int( t_uint *r, const mpi *A, t_sint b )
{
    size_t i;
    t_uint x, y, z;

    if( b == 0 )
        return( POLARSSL_ERR_MPI_DIVISION_BY_ZERO );

    if( b < 0 )
        return( POLARSSL_ERR_MPI_NEGATIVE_VALUE );

    /*
     * handle trivial cases
     */
    if( b == 1 )
    {
        *r = 0;
        return( 0 );
    }

    if( b == 2 )
    {
        *r = A->p[0] & 1;
        return( 0 );
    }

    /*
     * general case
     */
    for( i = A->n, y = 0; i > 0; i-- )
    {
        x  = A->p[i - 1];
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;

        x <<= biH;
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;
    }

    /*
     * If A is negative, then the current y represents a negative value.
     * Flipping it to the positive side.
     */
    if( A->s < 0 && y != 0 )
        y = b - y;

    *r = y;

    return( 0 );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */
static void mpi_montg_init( t_uint *mm, const mpi *N )
{
    t_uint x, m0 = N->p[0];
    unsigned int i;

    x  = m0;
    x += ( ( m0 + 2 ) & 4 ) << 1;

    for( i = biL; i >= 8; i /= 2 )
        x *= ( 2 - ( m0 * x ) );

    *mm = ~x + 1;
}

/*
 * Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 */
static void mpi_montmul( mpi *A, const mpi *B, const mpi *N, t_uint mm,
                         const mpi *T )
{
    size_t i, n, m;
    t_uint u0, u1, *d;

    memset( T->p, 0, T->n * ciL );

    d = T->p;
    n = N->n;
    m = ( B->n < n ) ? B->n : n;

    for( i = 0; i < n; i++ )
    {
        /*
         * T = (T + u0*B + u1*N) / 2^biL
         */
        u0 = A->p[i];
        u1 = ( d[0] + u0 * B->p[0] ) * mm;

        mpi_mul_hlp( m, B->p, d, u0 );
        mpi_mul_hlp( n, N->p, d, u1 );

        *d++ = u0; d[n + 1] = 0;
    }

    memcpy( A->p, d, ( n + 1 ) * ciL );

    if( mpi_cmp_abs( A, N ) >= 0 )
        mpi_sub_hlp( n, N->p, A->p );
    else
        /* prevent timing attacks */
        mpi_sub_hlp( n, A->p, T->p );
}

/*
 * Montgomery reduction: A = A * R^-1 mod N
 */
static void mpi_montred( mpi *A, const mpi *N, t_uint mm, const mpi *T )
{
    t_uint z = 1;
    mpi U;

    U.n = U.s = (int) z;
    U.p = &z;

    mpi_montmul( A, &U, N, mm, T );
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */
static int mpi_exp_mod( mpi *X, const mpi *A, const mpi *E, const mpi *N, mpi *_RR )
{
    int ret;
    size_t wbits, wsize, one = 1;
    size_t i, j, nblimbs;
    size_t bufsize, nbits;
    t_uint ei, mm, state;
    mpi RR, T, W[ 2 << POLARSSL_MPI_WINDOW_SIZE ], Apos;
    int neg;

    if( mpi_cmp_int( N, 0 ) < 0 || ( N->p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    if( mpi_cmp_int( E, 0 ) < 0 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    /*
     * Init temps and window size
     */
    mpi_montg_init( &mm, N );
    mpi_init( &RR ); mpi_init( &T );
    mpi_init( &Apos );
    memset( W, 0, sizeof( W ) );

    i = mpi_msb( E );

    wsize = ( i > 671 ) ? 6 : ( i > 239 ) ? 5 :
            ( i >  79 ) ? 4 : ( i >  23 ) ? 3 : 1;

    if( wsize > POLARSSL_MPI_WINDOW_SIZE )
        wsize = POLARSSL_MPI_WINDOW_SIZE;

    j = N->n + 1;
    MPI_CHK( mpi_grow( X, j ) );
    MPI_CHK( mpi_grow( &W[1],  j ) );
    MPI_CHK( mpi_grow( &T, j * 2 ) );

    /*
     * Compensate for negative A (and correct at the end)
     */
    neg = ( A->s == -1 );
    if( neg )
    {
        MPI_CHK( mpi_copy( &Apos, A ) );
        Apos.s = 1;
        A = &Apos;
    }

    /*
     * If 1st call, pre-compute R^2 mod N
     */
    if( _RR == NULL || _RR->p == NULL )
    {
        MPI_CHK( mpi_lset( &RR, 1 ) );
        MPI_CHK( mpi_shift_l( &RR, N->n * 2 * biL ) );
        MPI_CHK( mpi_mod_mpi( &RR, &RR, N ) );

        if( _RR != NULL )
            memcpy( _RR, &RR, sizeof( mpi ) );
    }
    else
        memcpy( &RR, _RR, sizeof( mpi ) );

    /*
     * W[1] = A * R^2 * R^-1 mod N = A * R mod N
     */
    if( mpi_cmp_mpi( A, N ) >= 0 )
        MPI_CHK( mpi_mod_mpi( &W[1], A, N ) );
    else
        MPI_CHK( mpi_copy( &W[1], A ) );

    mpi_montmul( &W[1], &RR, N, mm, &T );

    /*
     * X = R^2 * R^-1 mod N = R mod N
     */
    MPI_CHK( mpi_copy( X, &RR ) );
    mpi_montred( X, N, mm, &T );

    if( wsize > 1 )
    {
        /*
         * W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
         */
        j =  one << ( wsize - 1 );

        MPI_CHK( mpi_grow( &W[j], N->n + 1 ) );
        MPI_CHK( mpi_copy( &W[j], &W[1]    ) );

        for( i = 0; i < wsize - 1; i++ )
            mpi_montmul( &W[j], &W[j], N, mm, &T );

        /*
         * W[i] = W[i - 1] * W[1]
         */
        for( i = j + 1; i < ( one << wsize ); i++ )
        {
            MPI_CHK( mpi_grow( &W[i], N->n + 1 ) );
            MPI_CHK( mpi_copy( &W[i], &W[i - 1] ) );

            mpi_montmul( &W[i], &W[1], N, mm, &T );
        }
    }

    nblimbs = E->n;
    bufsize = 0;
    nbits   = 0;
    wbits   = 0;
    state   = 0;

    while( 1 )
    {
        if( bufsize == 0 )
        {
            if( nblimbs == 0 )
                break;

            nblimbs--;

            bufsize = sizeof( t_uint ) << 3;
        }

        bufsize--;

        ei = (E->p[nblimbs] >> bufsize) & 1;

        /*
         * skip leading 0s
         */
        if( ei == 0 && state == 0 )
            continue;

        if( ei == 0 && state == 1 )
        {
            /*
             * out of window, square X
             */
            mpi_montmul( X, X, N, mm, &T );
            continue;
        }

        /*
         * add ei to current window
         */
        state = 2;

        nbits++;
        wbits |= ( ei << ( wsize - nbits ) );

        if( nbits == wsize )
        {
            /*
             * X = X^wsize R^-1 mod N
             */
            for( i = 0; i < wsize; i++ )
                mpi_montmul( X, X, N, mm, &T );

            /*
             * X = X * W[wbits] R^-1 mod N
             */
            mpi_montmul( X, &W[wbits], N, mm, &T );

            state--;
            nbits = 0;
            wbits = 0;
        }
    }

    /*
     * process the remaining bits
     */
    for( i = 0; i < nbits; i++ )
    {
        mpi_montmul( X, X, N, mm, &T );

        wbits <<= 1;

        if( ( wbits & ( one << wsize ) ) != 0 )
            mpi_montmul( X, &W[1], N, mm, &T );
    }

    /*
     * X = A^E * R * R^-1 mod N = A^E mod N
     */
    mpi_montred( X, N, mm, &T );

    if( neg )
    {
        X->s = -1;
        MPI_CHK( mpi_add_mpi( X, N, X ) );
    }

cleanup:

    for( i = ( one << ( wsize - 1 ) ); i < ( one << wsize ); i++ )
        mpi_free( &W[i] );

    mpi_free( &W[1] ); mpi_free( &T ); mpi_free( &Apos );

    if( _RR == NULL || _RR->p == NULL )
        mpi_free( &RR );

    return( ret );
}

/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
static int mpi_gcd( mpi *G, const mpi *A, const mpi *B )
{
    int ret;
    size_t lz, lzt;
    mpi TG, TA, TB;

    mpi_init( &TG ); mpi_init( &TA ); mpi_init( &TB );

    MPI_CHK( mpi_copy( &TA, A ) );
    MPI_CHK( mpi_copy( &TB, B ) );

    lz = mpi_lsb( &TA );
    lzt = mpi_lsb( &TB );

    if( lzt < lz )
        lz = lzt;

    MPI_CHK( mpi_shift_r( &TA, lz ) );
    MPI_CHK( mpi_shift_r( &TB, lz ) );

    TA.s = TB.s = 1;

    while( mpi_cmp_int( &TA, 0 ) != 0 )
    {
        MPI_CHK( mpi_shift_r( &TA, mpi_lsb( &TA ) ) );
        MPI_CHK( mpi_shift_r( &TB, mpi_lsb( &TB ) ) );

        if( mpi_cmp_mpi( &TA, &TB ) >= 0 )
        {
            MPI_CHK( mpi_sub_abs( &TA, &TA, &TB ) );
            MPI_CHK( mpi_shift_r( &TA, 1 ) );
        }
        else
        {
            MPI_CHK( mpi_sub_abs( &TB, &TB, &TA ) );
            MPI_CHK( mpi_shift_r( &TB, 1 ) );
        }
    }

    MPI_CHK( mpi_shift_l( &TB, lz ) );
    MPI_CHK( mpi_copy( G, &TB ) );

cleanup:

    mpi_free( &TG ); mpi_free( &TA ); mpi_free( &TB );

    return( ret );
}

/*
 * Fill X with size bytes of random.
 *
 * Use a temporary bytes representation to make sure the result is the same
 * regardless of the platform endianness (useful when f_rng is actually
 * deterministic, eg for tests).
 */
static int mpi_fill_random( mpi *X, size_t size,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];

    if( size > POLARSSL_MPI_MAX_SIZE )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    MPI_CHK( f_rng( p_rng, buf, size ) );
    MPI_CHK( mpi_read_binary( X, buf, size ) );

cleanup:
    return( ret );
}

/*
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
static int mpi_inv_mod( mpi *X, const mpi *A, const mpi *N )
{
    int ret;
    mpi G, TA, TU, U1, U2, TB, TV, V1, V2;

    if( mpi_cmp_int( N, 0 ) <= 0 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    mpi_init( &TA ); mpi_init( &TU ); mpi_init( &U1 ); mpi_init( &U2 );
    mpi_init( &G ); mpi_init( &TB ); mpi_init( &TV );
    mpi_init( &V1 ); mpi_init( &V2 );

    MPI_CHK( mpi_gcd( &G, A, N ) );

    if( mpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    MPI_CHK( mpi_mod_mpi( &TA, A, N ) );
    MPI_CHK( mpi_copy( &TU, &TA ) );
    MPI_CHK( mpi_copy( &TB, N ) );
    MPI_CHK( mpi_copy( &TV, N ) );

    MPI_CHK( mpi_lset( &U1, 1 ) );
    MPI_CHK( mpi_lset( &U2, 0 ) );
    MPI_CHK( mpi_lset( &V1, 0 ) );
    MPI_CHK( mpi_lset( &V2, 1 ) );

    do
    {
        while( ( TU.p[0] & 1 ) == 0 )
        {
            MPI_CHK( mpi_shift_r( &TU, 1 ) );

            if( ( U1.p[0] & 1 ) != 0 || ( U2.p[0] & 1 ) != 0 )
            {
                MPI_CHK( mpi_add_mpi( &U1, &U1, &TB ) );
                MPI_CHK( mpi_sub_mpi( &U2, &U2, &TA ) );
            }

            MPI_CHK( mpi_shift_r( &U1, 1 ) );
            MPI_CHK( mpi_shift_r( &U2, 1 ) );
        }

        while( ( TV.p[0] & 1 ) == 0 )
        {
            MPI_CHK( mpi_shift_r( &TV, 1 ) );

            if( ( V1.p[0] & 1 ) != 0 || ( V2.p[0] & 1 ) != 0 )
            {
                MPI_CHK( mpi_add_mpi( &V1, &V1, &TB ) );
                MPI_CHK( mpi_sub_mpi( &V2, &V2, &TA ) );
            }

            MPI_CHK( mpi_shift_r( &V1, 1 ) );
            MPI_CHK( mpi_shift_r( &V2, 1 ) );
        }

        if( mpi_cmp_mpi( &TU, &TV ) >= 0 )
        {
            MPI_CHK( mpi_sub_mpi( &TU, &TU, &TV ) );
            MPI_CHK( mpi_sub_mpi( &U1, &U1, &V1 ) );
            MPI_CHK( mpi_sub_mpi( &U2, &U2, &V2 ) );
        }
        else
        {
            MPI_CHK( mpi_sub_mpi( &TV, &TV, &TU ) );
            MPI_CHK( mpi_sub_mpi( &V1, &V1, &U1 ) );
            MPI_CHK( mpi_sub_mpi( &V2, &V2, &U2 ) );
        }
    }
    while( mpi_cmp_int( &TU, 0 ) != 0 );

    while( mpi_cmp_int( &V1, 0 ) < 0 )
        MPI_CHK( mpi_add_mpi( &V1, &V1, N ) );

    while( mpi_cmp_mpi( &V1, N ) >= 0 )
        MPI_CHK( mpi_sub_mpi( &V1, &V1, N ) );

    MPI_CHK( mpi_copy( X, &V1 ) );

cleanup:

    mpi_free( &TA ); mpi_free( &TU ); mpi_free( &U1 ); mpi_free( &U2 );
    mpi_free( &G ); mpi_free( &TB ); mpi_free( &TV );
    mpi_free( &V1 ); mpi_free( &V2 );

    return( ret );
}

#if defined(POLARSSL_GENPRIME)

static const int small_prime[] =
{
        3,    5,    7,   11,   13,   17,   19,   23,
       29,   31,   37,   41,   43,   47,   53,   59,
       61,   67,   71,   73,   79,   83,   89,   97,
      101,  103,  107,  109,  113,  127,  131,  137,
      139,  149,  151,  157,  163,  167,  173,  179,
      181,  191,  193,  197,  199,  211,  223,  227,
      229,  233,  239,  241,  251,  257,  263,  269,
      271,  277,  281,  283,  293,  307,  311,  313,
      317,  331,  337,  347,  349,  353,  359,  367,
      373,  379,  383,  389,  397,  401,  409,  419,
      421,  431,  433,  439,  443,  449,  457,  461,
      463,  467,  479,  487,  491,  499,  503,  509,
      521,  523,  541,  547,  557,  563,  569,  571,
      577,  587,  593,  599,  601,  607,  613,  617,
      619,  631,  641,  643,  647,  653,  659,  661,
      673,  677,  683,  691,  701,  709,  719,  727,
      733,  739,  743,  751,  757,  761,  769,  773,
      787,  797,  809,  811,  821,  823,  827,  829,
      839,  853,  857,  859,  863,  877,  881,  883,
      887,  907,  911,  919,  929,  937,  941,  947,
      953,  967,  971,  977,  983,  991,  997, -103
};

/*
 * Small divisors test (X must be positive)
 *
 * Return values:
 * 0: no small factor (possible prime, more tests needed)
 * 1: certain prime
 * POLARSSL_ERR_MPI_NOT_ACCEPTABLE: certain non-prime
 * other negative: error
 */
static int mpi_check_small_factors( const mpi *X )
{
    int ret = 0;
    size_t i;
    t_uint r;

    if( ( X->p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_MPI_NOT_ACCEPTABLE );

    for( i = 0; small_prime[i] > 0; i++ )
    {
        if( mpi_cmp_int( X, small_prime[i] ) <= 0 )
            return( 1 );

        MPI_CHK( mpi_mod_int( &r, X, small_prime[i] ) );

        if( r == 0 )
            return( POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
    }

cleanup:
    return( ret );
}

/*
 * Miller-Rabin pseudo-primality test  (HAC 4.24)
 */
static int mpi_miller_rabin( const mpi *X,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{
    int ret;
    size_t i, j, n, s;
    mpi W, R, T, A, RR;

    mpi_init( &W ); mpi_init( &R ); mpi_init( &T ); mpi_init( &A );
    mpi_init( &RR );

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    MPI_CHK( mpi_sub_int( &W, X, 1 ) );
    s = mpi_lsb( &W );
    MPI_CHK( mpi_copy( &R, &W ) );
    MPI_CHK( mpi_shift_r( &R, s ) );

    i = mpi_msb( X );
    /*
     * HAC, table 4.4
     */
    n = ( ( i >= 1300 ) ?  2 : ( i >=  850 ) ?  3 :
          ( i >=  650 ) ?  4 : ( i >=  350 ) ?  8 :
          ( i >=  250 ) ? 12 : ( i >=  150 ) ? 18 : 27 );

    for( i = 0; i < n; i++ )
    {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        MPI_CHK( mpi_fill_random( &A, X->n * ciL, f_rng, p_rng ) );

        if( mpi_cmp_mpi( &A, &W ) >= 0 )
        {
            j = mpi_msb( &A ) - mpi_msb( &W );
            MPI_CHK( mpi_shift_r( &A, j + 1 ) );
        }
        A.p[0] |= 3;

        /*
         * A = A^R mod |X|
         */
        MPI_CHK( mpi_exp_mod( &A, &A, &R, X, &RR ) );

        if( mpi_cmp_mpi( &A, &W ) == 0 ||
            mpi_cmp_int( &A,  1 ) == 0 )
            continue;

        j = 1;
        while( j < s && mpi_cmp_mpi( &A, &W ) != 0 )
        {
            /*
             * A = A * A mod |X|
             */
            MPI_CHK( mpi_mul_mpi( &T, &A, &A ) );
            MPI_CHK( mpi_mod_mpi( &A, &T, X  ) );

            if( mpi_cmp_int( &A, 1 ) == 0 )
                break;

            j++;
        }

        /*
         * not prime if A != |X| - 1 or A == 1
         */
        if( mpi_cmp_mpi( &A, &W ) != 0 ||
            mpi_cmp_int( &A,  1 ) == 0 )
        {
            ret = POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:
    mpi_free( &W ); mpi_free( &R ); mpi_free( &T ); mpi_free( &A );
    mpi_free( &RR );

    return( ret );
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
static int mpi_is_prime( mpi *X,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng )
{
    int ret;
    mpi XX;

    XX.s = 1;
    XX.n = X->n;
    XX.p = X->p;

    if( mpi_cmp_int( &XX, 0 ) == 0 ||
        mpi_cmp_int( &XX, 1 ) == 0 )
        return( POLARSSL_ERR_MPI_NOT_ACCEPTABLE );

    if( mpi_cmp_int( &XX, 2 ) == 0 )
        return( 0 );

    if( ( ret = mpi_check_small_factors( &XX ) ) != 0 )
    {
        if( ret == 1 )
            return( 0 );

        return( ret );
    }

    return( mpi_miller_rabin( &XX, f_rng, p_rng ) );
}

/*
 * Prime number generation
 */
static int mpi_gen_prime( mpi *X, size_t nbits, int dh_flag,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng )
{
    int ret;
    size_t k, n;
    t_uint r;
    mpi Y;

    if( nbits < 3 || nbits > POLARSSL_MPI_MAX_BITS )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    mpi_init( &Y );

    n = BITS_TO_LIMBS( nbits );

    MPI_CHK( mpi_fill_random( X, n * ciL, f_rng, p_rng ) );

    k = mpi_msb( X );
    if( k < nbits ) MPI_CHK( mpi_shift_l( X, nbits - k ) );
    if( k > nbits ) MPI_CHK( mpi_shift_r( X, k - nbits ) );

    X->p[0] |= 3;

    if( dh_flag == 0 )
    {
        while( ( ret = mpi_is_prime( X, f_rng, p_rng ) ) != 0 )
        {
            if( ret != POLARSSL_ERR_MPI_NOT_ACCEPTABLE )
                goto cleanup;

            MPI_CHK( mpi_add_int( X, X, 2 ) );
        }
    }
    else
    {
        /*
         * An necessary condition for Y and X = 2Y + 1 to be prime
         * is X = 2 mod 3 (which is equivalent to Y = 2 mod 3).
         * Make sure it is satisfied, while keeping X = 3 mod 4
         */
        MPI_CHK( mpi_mod_int( &r, X, 3 ) );
        if( r == 0 )
            MPI_CHK( mpi_add_int( X, X, 8 ) );
        else if( r == 1 )
            MPI_CHK( mpi_add_int( X, X, 4 ) );

        /* Set Y = (X-1) / 2, which is X / 2 because X is odd */
        MPI_CHK( mpi_copy( &Y, X ) );
        MPI_CHK( mpi_shift_r( &Y, 1 ) );

        while( 1 )
        {
            /*
             * First, check small factors for X and Y
             * before doing Miller-Rabin on any of them
             */
            if( ( ret = mpi_check_small_factors(  X         ) ) == 0 &&
                ( ret = mpi_check_small_factors( &Y         ) ) == 0 &&
                ( ret = mpi_miller_rabin(  X, f_rng, p_rng  ) ) == 0 &&
                ( ret = mpi_miller_rabin( &Y, f_rng, p_rng  ) ) == 0 )
            {
                break;
            }

            if( ret != POLARSSL_ERR_MPI_NOT_ACCEPTABLE )
                goto cleanup;

            /*
             * Next candidates. We want to preserve Y = (X-1) / 2 and
             * Y = 1 mod 2 and Y = 2 mod 3 (eq X = 3 mod 4 and X = 2 mod 3)
             * so up Y by 6 and X by 12.
             */
            MPI_CHK( mpi_add_int(  X,  X, 12 ) );
            MPI_CHK( mpi_add_int( &Y, &Y, 6  ) );
        }
    }

cleanup:

    mpi_free( &Y );

    return( ret );
}

#endif /* POLARSSL_GENPRIME */

#if defined(POLARSSL_SELF_TEST)

#define GCD_PAIR_COUNT  3

static const int gcd_pairs[GCD_PAIR_COUNT][3] =
{
    { 693, 609, 21 },
    { 1764, 868, 28 },
    { 768454923, 542167814, 1 }
};

/*
 * Checkup routine
 */
static int mpi_self_test( int verbose )
{
    int ret, i;
    mpi A, E, N, X, Y, U, V;

    mpi_init( &A ); mpi_init( &E ); mpi_init( &N ); mpi_init( &X );
    mpi_init( &Y ); mpi_init( &U ); mpi_init( &V );

    MPI_CHK( mpi_read_string( &A, 16,
        "EFE021C2645FD1DC586E69184AF4A31E" \
        "D5F53E93B5F123FA41680867BA110131" \
        "944FE7952E2517337780CB0DB80E61AA" \
        "E7C8DDC6C5C6AADEB34EB38A2F40D5E6" ) );

    MPI_CHK( mpi_read_string( &E, 16,
        "B2E7EFD37075B9F03FF989C7C5051C20" \
        "34D2A323810251127E7BF8625A4F49A5" \
        "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
        "5B5C25763222FEFCCFC38B832366C29E" ) );

    MPI_CHK( mpi_read_string( &N, 16,
        "0066A198186C18C10B2F5ED9B522752A" \
        "9830B69916E535C8F047518A889A43A5" \
        "94B6BED27A168D31D4A52F88925AA8F5" ) );

    MPI_CHK( mpi_mul_mpi( &X, &A, &N ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "602AB7ECA597A3D6B56FF9829A5E8B85" \
        "9E857EA95A03512E2BAE7391688D264A" \
        "A5663B0341DB9CCFD2C4C5F421FEC814" \
        "8001B72E848A38CAE1C65F78E56ABDEF" \
        "E12D3C039B8A02D6BE593F0BBBDA56F1" \
        "ECF677152EF804370C1A305CAF3B5BF1" \
        "30879B56C61DE584A0F53A2447A51E" ) );

    if( verbose != 0 )
        polarssl_printf( "  MPI test #1 (mul_mpi): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    MPI_CHK( mpi_div_mpi( &X, &Y, &A, &N ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "256567336059E52CAE22925474705F39A94" ) );

    MPI_CHK( mpi_read_string( &V, 16,
        "6613F26162223DF488E9CD48CC132C7A" \
        "0AC93C701B001B092E4E5B9F73BCD27B" \
        "9EE50D0657C77F374E903CDFA4C642" ) );

    if( verbose != 0 )
        polarssl_printf( "  MPI test #2 (div_mpi): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 ||
        mpi_cmp_mpi( &Y, &V ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    MPI_CHK( mpi_exp_mod( &X, &A, &E, &N, NULL ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "36E139AEA55215609D2816998ED020BB" \
        "BD96C37890F65171D948E9BC7CBAA4D9" \
        "325D24D6A3C12710F10A09FA08AB87" ) );

    if( verbose != 0 )
        polarssl_printf( "  MPI test #3 (exp_mod): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    MPI_CHK( mpi_inv_mod( &X, &A, &N ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "003A0AAEDD7E784FC07D8F9EC6E3BFD5" \
        "C3DBA76456363A10869622EAC2DD84EC" \
        "C5B8A74DAC4D09E03B5E0BE779F2DF61" ) );

    if( verbose != 0 )
        polarssl_printf( "  MPI test #4 (inv_mod): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    if( verbose != 0 )
        polarssl_printf( "  MPI test #5 (simple gcd): " );

    for( i = 0; i < GCD_PAIR_COUNT; i++ )
    {
        MPI_CHK( mpi_lset( &X, gcd_pairs[i][0] ) );
        MPI_CHK( mpi_lset( &Y, gcd_pairs[i][1] ) );

        MPI_CHK( mpi_gcd( &A, &X, &Y ) );

        if( mpi_cmp_int( &A, gcd_pairs[i][2] ) != 0 )
        {
            if( verbose != 0 )
                polarssl_printf( "failed at %d\n", i );

            ret = 1;
            goto cleanup;
        }
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

cleanup:

    if( ret != 0 && verbose != 0 )
        polarssl_printf( "Unexpected error, return code = %08X\n", ret );

    mpi_free( &A ); mpi_free( &E ); mpi_free( &N ); mpi_free( &X );
    mpi_free( &Y ); mpi_free( &U ); mpi_free( &V );

    if( verbose != 0 )
        polarssl_printf( "\n" );

    return( ret );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_BIGNUM_C */
/*
 *  CTR_DRBG implementation based on AES-256 (NIST SP 800-90)
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  The NIST SP 800-90 DRBGs are described in the following publucation.
 *
 *  http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_CTR_DRBG_C)

//#include "polarssl/ctr_drbg.h"

#if defined(POLARSSL_FS_IO)
#include <stdio.h>
#endif

#if defined(POLARSSL_PLATFORM_C)
//#include "polarssl/platform.h"
#else
#define polarssl_printf printf
#endif

/* Implementation that should never be optimized out by the compiler */
//static void polarssl_zeroize( void *v, size_t n ) {
//    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
//}

/*
 * Non-public function wrapped by ctr_crbg_init(). Necessary to allow NIST
 * tests to succeed (which require known length fixed entropy)
 */
static int ctr_drbg_init_entropy_len(
                   ctr_drbg_context *ctx,
                   int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy,
                   const unsigned char *custom,
                   size_t len,
                   size_t entropy_len )
{
    int ret;
    unsigned char key[CTR_DRBG_KEYSIZE];

    memset( ctx, 0, sizeof(ctr_drbg_context) );
    memset( key, 0, CTR_DRBG_KEYSIZE );

    aes_init( &ctx->aes_ctx );

    ctx->f_entropy = f_entropy;
    ctx->p_entropy = p_entropy;

    ctx->entropy_len = entropy_len;
    ctx->reseed_interval = CTR_DRBG_RESEED_INTERVAL;

    /*
     * Initialize with an empty key
     */
    aes_setkey_enc( &ctx->aes_ctx, key, CTR_DRBG_KEYBITS );

    if( ( ret = ctr_drbg_reseed( ctx, custom, len ) ) != 0 )
        return( ret );

    return( 0 );
}

static int ctr_drbg_init( ctr_drbg_context *ctx,
                   int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy,
                   const unsigned char *custom,
                   size_t len )
{
    return( ctr_drbg_init_entropy_len( ctx, f_entropy, p_entropy, custom, len,
                                       CTR_DRBG_ENTROPY_LEN ) );
}

static void ctr_drbg_free( ctr_drbg_context *ctx )
{
    if( ctx == NULL )
        return;

    aes_free( &ctx->aes_ctx );
    polarssl_zeroize( ctx, sizeof( ctr_drbg_context ) );
}

static void ctr_drbg_set_prediction_resistance( ctr_drbg_context *ctx, int resistance )
{
    ctx->prediction_resistance = resistance;
}

static void ctr_drbg_set_entropy_len( ctr_drbg_context *ctx, size_t len )
{
    ctx->entropy_len = len;
}

static void ctr_drbg_set_reseed_interval( ctr_drbg_context *ctx, int interval )
{
    ctx->reseed_interval = interval;
}

static int block_cipher_df( unsigned char *output,
                            const unsigned char *data, size_t data_len )
{
    unsigned char buf[CTR_DRBG_MAX_SEED_INPUT + CTR_DRBG_BLOCKSIZE + 16];
    unsigned char tmp[CTR_DRBG_SEEDLEN];
    unsigned char key[CTR_DRBG_KEYSIZE];
    unsigned char chain[CTR_DRBG_BLOCKSIZE];
    unsigned char *p, *iv;
    aes_context aes_ctx;

    int i, j;
    size_t buf_len, use_len;

    memset( buf, 0, CTR_DRBG_MAX_SEED_INPUT + CTR_DRBG_BLOCKSIZE + 16 );
    aes_init( &aes_ctx );

    /*
     * Construct IV (16 bytes) and S in buffer
     * IV = Counter (in 32-bits) padded to 16 with zeroes
     * S = Length input string (in 32-bits) || Length of output (in 32-bits) ||
     *     data || 0x80
     *     (Total is padded to a multiple of 16-bytes with zeroes)
     */
    p = buf + CTR_DRBG_BLOCKSIZE;
    *p++ = ( data_len >> 24 ) & 0xff;
    *p++ = ( data_len >> 16 ) & 0xff;
    *p++ = ( data_len >> 8  ) & 0xff;
    *p++ = ( data_len       ) & 0xff;
    p += 3;
    *p++ = CTR_DRBG_SEEDLEN;
    memcpy( p, data, data_len );
    p[data_len] = 0x80;

    buf_len = CTR_DRBG_BLOCKSIZE + 8 + data_len + 1;

    for( i = 0; i < CTR_DRBG_KEYSIZE; i++ )
        key[i] = i;

    aes_setkey_enc( &aes_ctx, key, CTR_DRBG_KEYBITS );

    /*
     * Reduce data to POLARSSL_CTR_DRBG_SEEDLEN bytes of data
     */
    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE )
    {
        p = buf;
        memset( chain, 0, CTR_DRBG_BLOCKSIZE );
        use_len = buf_len;

        while( use_len > 0 )
        {
            for( i = 0; i < CTR_DRBG_BLOCKSIZE; i++ )
                chain[i] ^= p[i];
            p += CTR_DRBG_BLOCKSIZE;
            use_len -= ( use_len >= CTR_DRBG_BLOCKSIZE ) ?
                       CTR_DRBG_BLOCKSIZE : use_len;

            aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, chain, chain );
        }

        memcpy( tmp + j, chain, CTR_DRBG_BLOCKSIZE );

        /*
         * Update IV
         */
        buf[3]++;
    }

    /*
     * Do final encryption with reduced data
     */
    aes_setkey_enc( &aes_ctx, tmp, CTR_DRBG_KEYBITS );
    iv = tmp + CTR_DRBG_KEYSIZE;
    p = output;

    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE )
    {
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, iv, iv );
        memcpy( p, iv, CTR_DRBG_BLOCKSIZE );
        p += CTR_DRBG_BLOCKSIZE;
    }

    aes_free( &aes_ctx );

    return( 0 );
}

static int ctr_drbg_update_internal( ctr_drbg_context *ctx,
                              const unsigned char data[CTR_DRBG_SEEDLEN] )
{
    unsigned char tmp[CTR_DRBG_SEEDLEN];
    unsigned char *p = tmp;
    int i, j;

    memset( tmp, 0, CTR_DRBG_SEEDLEN );

    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE )
    {
        /*
         * Increase counter
         */
        for( i = CTR_DRBG_BLOCKSIZE; i > 0; i-- )
            if( ++ctx->counter[i - 1] != 0 )
                break;

        /*
         * Crypt counter block
         */
        aes_crypt_ecb( &ctx->aes_ctx, AES_ENCRYPT, ctx->counter, p );

        p += CTR_DRBG_BLOCKSIZE;
    }

    for( i = 0; i < CTR_DRBG_SEEDLEN; i++ )
        tmp[i] ^= data[i];

    /*
     * Update key and counter
     */
    aes_setkey_enc( &ctx->aes_ctx, tmp, CTR_DRBG_KEYBITS );
    memcpy( ctx->counter, tmp + CTR_DRBG_KEYSIZE, CTR_DRBG_BLOCKSIZE );

    return( 0 );
}

static void ctr_drbg_update( ctr_drbg_context *ctx,
                      const unsigned char *additional, size_t add_len )
{
    unsigned char add_input[CTR_DRBG_SEEDLEN];

    if( add_len > 0 )
    {
        block_cipher_df( add_input, additional, add_len );
        ctr_drbg_update_internal( ctx, add_input );
    }
}

static int ctr_drbg_reseed( ctr_drbg_context *ctx,
                     const unsigned char *additional, size_t len )
{
    unsigned char seed[CTR_DRBG_MAX_SEED_INPUT];
    size_t seedlen = 0;

    if( ctx->entropy_len + len > CTR_DRBG_MAX_SEED_INPUT )
        return( POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( seed, 0, CTR_DRBG_MAX_SEED_INPUT );

    /*
     * Gather entropy_len bytes of entropy to seed state
     */
    if( 0 != ctx->f_entropy( ctx->p_entropy, seed,
                             ctx->entropy_len ) )
    {
        return( POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED );
    }

    seedlen += ctx->entropy_len;

    /*
     * Add additional data
     */
    if( additional && len )
    {
        memcpy( seed + seedlen, additional, len );
        seedlen += len;
    }

    /*
     * Reduce to 384 bits
     */
    block_cipher_df( seed, seed, seedlen );

    /*
     * Update state
     */
    ctr_drbg_update_internal( ctx, seed );
    ctx->reseed_counter = 1;

    return( 0 );
}

static int ctr_drbg_random_with_add( void *p_rng,
                              unsigned char *output, size_t output_len,
                              const unsigned char *additional, size_t add_len )
{
    int ret = 0;
    ctr_drbg_context *ctx = (ctr_drbg_context *) p_rng;
    unsigned char add_input[CTR_DRBG_SEEDLEN];
    unsigned char *p = output;
    unsigned char tmp[CTR_DRBG_BLOCKSIZE];
    int i;
    size_t use_len;

    if( output_len > CTR_DRBG_MAX_REQUEST )
        return( POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG );

    if( add_len > CTR_DRBG_MAX_INPUT )
        return( POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( add_input, 0, CTR_DRBG_SEEDLEN );

    if( ctx->reseed_counter > ctx->reseed_interval ||
        ctx->prediction_resistance )
    {
        if( ( ret = ctr_drbg_reseed( ctx, additional, add_len ) ) != 0 )
            return( ret );

        add_len = 0;
    }

    if( add_len > 0 )
    {
        block_cipher_df( add_input, additional, add_len );
        ctr_drbg_update_internal( ctx, add_input );
    }

    while( output_len > 0 )
    {
        /*
         * Increase counter
         */
        for( i = CTR_DRBG_BLOCKSIZE; i > 0; i-- )
            if( ++ctx->counter[i - 1] != 0 )
                break;

        /*
         * Crypt counter block
         */
        aes_crypt_ecb( &ctx->aes_ctx, AES_ENCRYPT, ctx->counter, tmp );

        use_len = ( output_len > CTR_DRBG_BLOCKSIZE ) ? CTR_DRBG_BLOCKSIZE :
                                                       output_len;
        /*
         * Copy random block to destination
         */
        memcpy( p, tmp, use_len );
        p += use_len;
        output_len -= use_len;
    }

    ctr_drbg_update_internal( ctx, add_input );

    ctx->reseed_counter++;

    return( 0 );
}

static int ctr_drbg_random( void *p_rng, unsigned char *output, size_t output_len )
{
    return ctr_drbg_random_with_add( p_rng, output, output_len, NULL, 0 );
}

#if defined(POLARSSL_FS_IO)
static int ctr_drbg_write_seed_file( ctr_drbg_context *ctx, const char *path )
{
    int ret = POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR;
    FILE *f;
    unsigned char buf[ CTR_DRBG_MAX_INPUT ];

    if( ( f = fopen( path, "wb" ) ) == NULL )
        return( POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR );

    if( ( ret = ctr_drbg_random( ctx, buf, CTR_DRBG_MAX_INPUT ) ) != 0 )
        goto exit;

    if( fwrite( buf, 1, CTR_DRBG_MAX_INPUT, f ) != CTR_DRBG_MAX_INPUT )
    {
        ret = POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR;
        goto exit;
    }

    ret = 0;

exit:
    fclose( f );
    return( ret );
}

static int ctr_drbg_update_seed_file( ctr_drbg_context *ctx, const char *path )
{
    FILE *f;
    size_t n;
    unsigned char buf[ CTR_DRBG_MAX_INPUT ];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR );

    fseek( f, 0, SEEK_END );
    n = (size_t) ftell( f );
    fseek( f, 0, SEEK_SET );

    if( n > CTR_DRBG_MAX_INPUT )
    {
        fclose( f );
        return( POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG );
    }

    if( fread( buf, 1, n, f ) != n )
    {
        fclose( f );
        return( POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR );
    }

    fclose( f );

    ctr_drbg_update( ctx, buf, n );

    return( ctr_drbg_write_seed_file( ctx, path ) );
}
#endif /* POLARSSL_FS_IO */

#if defined(POLARSSL_SELF_TEST)

#include <stdio.h>

static unsigned char entropy_source_pr[96] =
    { 0xc1, 0x80, 0x81, 0xa6, 0x5d, 0x44, 0x02, 0x16,
      0x19, 0xb3, 0xf1, 0x80, 0xb1, 0xc9, 0x20, 0x02,
      0x6a, 0x54, 0x6f, 0x0c, 0x70, 0x81, 0x49, 0x8b,
      0x6e, 0xa6, 0x62, 0x52, 0x6d, 0x51, 0xb1, 0xcb,
      0x58, 0x3b, 0xfa, 0xd5, 0x37, 0x5f, 0xfb, 0xc9,
      0xff, 0x46, 0xd2, 0x19, 0xc7, 0x22, 0x3e, 0x95,
      0x45, 0x9d, 0x82, 0xe1, 0xe7, 0x22, 0x9f, 0x63,
      0x31, 0x69, 0xd2, 0x6b, 0x57, 0x47, 0x4f, 0xa3,
      0x37, 0xc9, 0x98, 0x1c, 0x0b, 0xfb, 0x91, 0x31,
      0x4d, 0x55, 0xb9, 0xe9, 0x1c, 0x5a, 0x5e, 0xe4,
      0x93, 0x92, 0xcf, 0xc5, 0x23, 0x12, 0xd5, 0x56,
      0x2c, 0x4a, 0x6e, 0xff, 0xdc, 0x10, 0xd0, 0x68 };

static unsigned char entropy_source_nopr[64] =
    { 0x5a, 0x19, 0x4d, 0x5e, 0x2b, 0x31, 0x58, 0x14,
      0x54, 0xde, 0xf6, 0x75, 0xfb, 0x79, 0x58, 0xfe,
      0xc7, 0xdb, 0x87, 0x3e, 0x56, 0x89, 0xfc, 0x9d,
      0x03, 0x21, 0x7c, 0x68, 0xd8, 0x03, 0x38, 0x20,
      0xf9, 0xe6, 0x5e, 0x04, 0xd8, 0x56, 0xf3, 0xa9,
      0xc4, 0x4a, 0x4c, 0xbd, 0xc1, 0xd0, 0x08, 0x46,
      0xf5, 0x98, 0x3d, 0x77, 0x1c, 0x1b, 0x13, 0x7e,
      0x4e, 0x0f, 0x9d, 0x8e, 0xf4, 0x09, 0xf9, 0x2e };

static const unsigned char nonce_pers_pr[16] =
    { 0xd2, 0x54, 0xfc, 0xff, 0x02, 0x1e, 0x69, 0xd2,
      0x29, 0xc9, 0xcf, 0xad, 0x85, 0xfa, 0x48, 0x6c };

static const unsigned char nonce_pers_nopr[16] =
    { 0x1b, 0x54, 0xb8, 0xff, 0x06, 0x42, 0xbf, 0xf5,
      0x21, 0xf1, 0x5c, 0x1c, 0x0b, 0x66, 0x5f, 0x3f };

static const unsigned char result_pr[16] =
    { 0x34, 0x01, 0x16, 0x56, 0xb4, 0x29, 0x00, 0x8f,
      0x35, 0x63, 0xec, 0xb5, 0xf2, 0x59, 0x07, 0x23 };

static const unsigned char result_nopr[16] =
    { 0xa0, 0x54, 0x30, 0x3d, 0x8a, 0x7e, 0xa9, 0x88,
      0x9d, 0x90, 0x3e, 0x07, 0x7c, 0x6f, 0x21, 0x8f };

static size_t test_offset;
static int ctr_drbg_self_test_entropy( void *data, unsigned char *buf,
                                       size_t len )
{
    const unsigned char *p = (unsigned char*)data;
    memcpy( buf, p + test_offset, len );
    test_offset += len;
    return( 0 );
}

#define CHK( c )    if( (c) != 0 )                          \
                    {                                       \
                        if( verbose != 0 )                  \
                            polarssl_printf( "failed\n" );  \
                        return( 1 );                        \
                    }

/*
 * Checkup routine
 */
static int ctr_drbg_self_test( int verbose )
{
    ctr_drbg_context ctx;
    unsigned char buf[16];

    /*
     * Based on a NIST CTR_DRBG test vector (PR = True)
     */
    if( verbose != 0 )
        polarssl_printf( "  CTR_DRBG (PR = TRUE) : " );

    test_offset = 0;
    CHK( ctr_drbg_init_entropy_len( &ctx, ctr_drbg_self_test_entropy,
                                entropy_source_pr, nonce_pers_pr, 16, 32 ) );
    ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
    CHK( ctr_drbg_random( &ctx, buf, CTR_DRBG_BLOCKSIZE ) );
    CHK( ctr_drbg_random( &ctx, buf, CTR_DRBG_BLOCKSIZE ) );
    CHK( memcmp( buf, result_pr, CTR_DRBG_BLOCKSIZE ) );

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    /*
     * Based on a NIST CTR_DRBG test vector (PR = FALSE)
     */
    if( verbose != 0 )
        polarssl_printf( "  CTR_DRBG (PR = FALSE): " );

    test_offset = 0;
    CHK( ctr_drbg_init_entropy_len( &ctx, ctr_drbg_self_test_entropy,
                            entropy_source_nopr, nonce_pers_nopr, 16, 32 ) );
    CHK( ctr_drbg_random( &ctx, buf, 16 ) );
    CHK( ctr_drbg_reseed( &ctx, NULL, 0 ) );
    CHK( ctr_drbg_random( &ctx, buf, 16 ) );
    CHK( memcmp( buf, result_nopr, 16 ) );

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    if( verbose != 0 )
            polarssl_printf( "\n" );

    return( 0 );
}
#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_CTR_DRBG_C */
/*
 *  Entropy accumulator implementation
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_ENTROPY_C)

//#include "polarssl/entropy.h"
//#include "polarssl/entropy_poll.h"

#if defined(POLARSSL_FS_IO)
#include <stdio.h>
#endif

#if defined(POLARSSL_HAVEGE_C)
//#include "polarssl/havege.h"
#endif

/* Implementation that should never be optimized out by the compiler */
//static void polarssl_zeroize( void *v, size_t n ) {
//    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
//}

#define ENTROPY_MAX_LOOP    256     /**< Maximum amount to loop before error */

static void entropy_init( entropy_context *ctx )
{
    memset( ctx, 0, sizeof(entropy_context) );

#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_init( &ctx->mutex );
#endif

#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
    sha512_starts( &ctx->accumulator, 0 );
#else
    sha256_starts( &ctx->accumulator, 0 );
#endif
#if defined(POLARSSL_HAVEGE_C)
    havege_init( &ctx->havege_data );
#endif

#if !defined(POLARSSL_NO_DEFAULT_ENTROPY_SOURCES)
#if !defined(POLARSSL_NO_PLATFORM_ENTROPY)
    entropy_add_source( ctx, platform_entropy_poll, NULL,
                        ENTROPY_MIN_PLATFORM );
#endif
#if defined(POLARSSL_TIMING_C)
    entropy_add_source( ctx, hardclock_poll, NULL, ENTROPY_MIN_HARDCLOCK );
#endif
#if defined(POLARSSL_HAVEGE_C)
    entropy_add_source( ctx, havege_poll, &ctx->havege_data,
                        ENTROPY_MIN_HAVEGE );
#endif
#endif /* POLARSSL_NO_DEFAULT_ENTROPY_SOURCES */
}

static void entropy_free( entropy_context *ctx )
{
#if defined(POLARSSL_HAVEGE_C)
    havege_free( &ctx->havege_data );
#endif
    polarssl_zeroize( ctx, sizeof( entropy_context ) );
#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_free( &ctx->mutex );
#endif
}

static int entropy_add_source( entropy_context *ctx,
                        f_source_ptr f_source, void *p_source,
                        size_t threshold )
{
    int index, ret = 0;

#if defined(POLARSSL_THREADING_C)
    if( ( ret = polarssl_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    index = ctx->source_count;
    if( index >= ENTROPY_MAX_SOURCES )
    {
        ret = POLARSSL_ERR_ENTROPY_MAX_SOURCES;
        goto exit;
    }

    ctx->source[index].f_source = f_source;
    ctx->source[index].p_source = p_source;
    ctx->source[index].threshold = threshold;

    ctx->source_count++;

exit:
#if defined(POLARSSL_THREADING_C)
    if( polarssl_mutex_unlock( &ctx->mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );
#endif

    return( ret );
}

/*
 * Entropy accumulator update
 */
static int entropy_update( entropy_context *ctx, unsigned char source_id,
                           const unsigned char *data, size_t len )
{
    unsigned char header[2];
    unsigned char tmp[ENTROPY_BLOCK_SIZE];
    size_t use_len = len;
    const unsigned char *p = data;

    if( use_len > ENTROPY_BLOCK_SIZE )
    {
#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
        sha512( data, len, tmp, 0 );
#else
        sha256( data, len, tmp, 0 );
#endif
        p = tmp;
        use_len = ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = use_len & 0xFF;

#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
    sha512_update( &ctx->accumulator, header, 2 );
    sha512_update( &ctx->accumulator, p, use_len );
#else
    sha256_update( &ctx->accumulator, header, 2 );
    sha256_update( &ctx->accumulator, p, use_len );
#endif

    return( 0 );
}

static int entropy_update_manual( entropy_context *ctx,
                           const unsigned char *data, size_t len )
{
    int ret;

#if defined(POLARSSL_THREADING_C)
    if( ( ret = polarssl_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    ret = entropy_update( ctx, ENTROPY_SOURCE_MANUAL, data, len );

#if defined(POLARSSL_THREADING_C)
    if( polarssl_mutex_unlock( &ctx->mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );
#endif

    return( ret );
}

/*
 * Run through the different sources to add entropy to our accumulator
 */
static int entropy_gather_internal( entropy_context *ctx )
{
    int ret, i;
    unsigned char buf[ENTROPY_MAX_GATHER];
    size_t olen;

    if( ctx->source_count == 0 )
        return( POLARSSL_ERR_ENTROPY_NO_SOURCES_DEFINED );

    /*
     * Run through our entropy sources
     */
    for( i = 0; i < ctx->source_count; i++ )
    {
        olen = 0;
        if( ( ret = ctx->source[i].f_source( ctx->source[i].p_source,
                        buf, ENTROPY_MAX_GATHER, &olen ) ) != 0 )
        {
            return( ret );
        }

        /*
         * Add if we actually gathered something
         */
        if( olen > 0 )
        {
            entropy_update( ctx, (unsigned char) i, buf, olen );
            ctx->source[i].size += olen;
        }
    }

    return( 0 );
}

/*
 * Thread-safe wrapper for entropy_gather_internal()
 */
static int entropy_gather( entropy_context *ctx )
{
    int ret;

#if defined(POLARSSL_THREADING_C)
    if( ( ret = polarssl_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    ret = entropy_gather_internal( ctx );

#if defined(POLARSSL_THREADING_C)
    if( polarssl_mutex_unlock( &ctx->mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );
#endif

    return( ret );
}

static int entropy_func( void *data, unsigned char *output, size_t len )
{
    int ret, count = 0, i, reached;
    entropy_context *ctx = (entropy_context *) data;
    unsigned char buf[ENTROPY_BLOCK_SIZE];

    if( len > ENTROPY_BLOCK_SIZE )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

#if defined(POLARSSL_THREADING_C)
    if( ( ret = polarssl_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    /*
     * Always gather extra entropy before a call
     */
    do
    {
        if( count++ > ENTROPY_MAX_LOOP )
        {
            ret = POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
            goto exit;
        }

        if( ( ret = entropy_gather_internal( ctx ) ) != 0 )
            goto exit;

        reached = 0;

        for( i = 0; i < ctx->source_count; i++ )
            if( ctx->source[i].size >= ctx->source[i].threshold )
                reached++;
    }
    while( reached != ctx->source_count );

    memset( buf, 0, ENTROPY_BLOCK_SIZE );

#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
    sha512_finish( &ctx->accumulator, buf );

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    memset( &ctx->accumulator, 0, sizeof( sha512_context ) );
    sha512_starts( &ctx->accumulator, 0 );
    sha512_update( &ctx->accumulator, buf, ENTROPY_BLOCK_SIZE );

    /*
     * Perform second SHA-512 on entropy
     */
    sha512( buf, ENTROPY_BLOCK_SIZE, buf, 0 );
#else /* POLARSSL_ENTROPY_SHA512_ACCUMULATOR */
    sha256_finish( &ctx->accumulator, buf );

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    memset( &ctx->accumulator, 0, sizeof( sha256_context ) );
    sha256_starts( &ctx->accumulator, 0 );
    sha256_update( &ctx->accumulator, buf, ENTROPY_BLOCK_SIZE );

    /*
     * Perform second SHA-256 on entropy
     */
    sha256( buf, ENTROPY_BLOCK_SIZE, buf, 0 );
#endif /* POLARSSL_ENTROPY_SHA512_ACCUMULATOR */

    for( i = 0; i < ctx->source_count; i++ )
        ctx->source[i].size = 0;

    memcpy( output, buf, len );

    ret = 0;

exit:
#if defined(POLARSSL_THREADING_C)
    if( polarssl_mutex_unlock( &ctx->mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );
#endif

    return( ret );
}

#if defined(POLARSSL_FS_IO)
static int entropy_write_seed_file( entropy_context *ctx, const char *path )
{
    int ret = POLARSSL_ERR_ENTROPY_FILE_IO_ERROR;
    FILE *f;
    unsigned char buf[ENTROPY_BLOCK_SIZE];

    if( ( f = fopen( path, "wb" ) ) == NULL )
        return( POLARSSL_ERR_ENTROPY_FILE_IO_ERROR );

    if( ( ret = entropy_func( ctx, buf, ENTROPY_BLOCK_SIZE ) ) != 0 )
        goto exit;

    if( fwrite( buf, 1, ENTROPY_BLOCK_SIZE, f ) != ENTROPY_BLOCK_SIZE )
    {
        ret = POLARSSL_ERR_ENTROPY_FILE_IO_ERROR;
        goto exit;
    }

    ret = 0;

exit:
    fclose( f );
    return( ret );
}

static int entropy_update_seed_file( entropy_context *ctx, const char *path )
{
    FILE *f;
    size_t n;
    unsigned char buf[ ENTROPY_MAX_SEED_SIZE ];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( POLARSSL_ERR_ENTROPY_FILE_IO_ERROR );

    fseek( f, 0, SEEK_END );
    n = (size_t) ftell( f );
    fseek( f, 0, SEEK_SET );

    if( n > ENTROPY_MAX_SEED_SIZE )
        n = ENTROPY_MAX_SEED_SIZE;

    if( fread( buf, 1, n, f ) != n )
    {
        fclose( f );
        return( POLARSSL_ERR_ENTROPY_FILE_IO_ERROR );
    }

    fclose( f );

    entropy_update_manual( ctx, buf, n );

    return( entropy_write_seed_file( ctx, path ) );
}
#endif /* POLARSSL_FS_IO */

#if defined(POLARSSL_SELF_TEST)

#if defined(POLARSSL_PLATFORM_C)
//#include "polarssl/platform.h"
#else
#include <stdio.h>
#define polarssl_printf     printf
#endif

/*
 * Dummy source function
 */
static int entropy_dummy_source( void *data, unsigned char *output,
                                 size_t len, size_t *olen )
{
    ((void) data);

    memset( output, 0x2a, len );
    *olen = len;

    return( 0 );
}

/*
 * The actual entropy quality is hard to test, but we can at least
 * test that the functions don't cause errors and write the correct
 * amount of data to buffers.
 */
static int entropy_self_test( int verbose )
{
    int ret = 0;
    entropy_context ctx;
    unsigned char buf[ENTROPY_BLOCK_SIZE] = { 0 };
    unsigned char acc[ENTROPY_BLOCK_SIZE] = { 0 };
    size_t i, j;

    if( verbose != 0 )
        polarssl_printf( "  ENTROPY test: " );

    entropy_init( &ctx );

    ret = entropy_add_source( &ctx, entropy_dummy_source, NULL, 16 );
    if( ret != 0 )
        goto cleanup;

    if( ( ret = entropy_gather( &ctx ) ) != 0 )
        goto cleanup;

    if( ( ret = entropy_update_manual( &ctx, buf, sizeof buf ) ) != 0 )
        goto cleanup;

    /*
     * To test that entropy_func writes correct number of bytes:
     * - use the whole buffer and rely on ASan to detect overruns
     * - collect entropy 8 times and OR the result in an accumulator:
     *   any byte should then be 0 with probably 2^(-64), so requiring
     *   each of the 32 or 64 bytes to be non-zero has a false failure rate
     *   of at most 2^(-58) which is acceptable.
     */
    for( i = 0; i < 8; i++ )
    {
        if( ( ret = entropy_func( &ctx, buf, sizeof( buf ) ) ) != 0 )
            goto cleanup;

        for( j = 0; j < sizeof( buf ); j++ )
            acc[j] |= buf[j];
    }

    for( j = 0; j < sizeof( buf ); j++ )
    {
        if( acc[j] == 0 )
        {
            ret = 1;
            goto cleanup;
        }
    }

cleanup:
    entropy_free( &ctx );

    if( verbose != 0 )
    {
        if( ret != 0 )
            polarssl_printf( "failed\n" );
        else
            polarssl_printf( "passed\n" );

        polarssl_printf( "\n" );
    }

    return( ret != 0 );
}
#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_ENTROPY_C */
/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_ENTROPY_C)

//#include "polarssl/entropy.h"
//#include "polarssl/entropy_poll.h"

#if defined(POLARSSL_TIMING_C)
//#include "polarssl/timing.h"
#endif
#if defined(POLARSSL_HAVEGE_C)
//#include "polarssl/havege.h"
#endif

#if !defined(POLARSSL_NO_PLATFORM_ENTROPY)
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0400
#endif
#define _WINSOCKAPI_
#include <windows.h>
#include <wincrypt.h>

int platform_entropy_poll( void *data, unsigned char *output, size_t len,
                           size_t *olen )
{
    HCRYPTPROV provider;
    ((void) data);
    *olen = 0;

    if( CryptAcquireContext( &provider, NULL, NULL,
                              PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) == FALSE )
    {
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );
    }

    if( CryptGenRandom( provider, (DWORD) len, output ) == FALSE )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

    CryptReleaseContext( provider, 0 );
    *olen = len;

    return( 0 );
}
#else /* _WIN32 && !EFIX64 && !EFI32 */

#include <stdio.h>

int platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen )
{
    FILE *file;
    size_t ret;
    ((void) data);

    *olen = 0;

    file = fopen( "/dev/urandom", "rb" );
    if( file == NULL )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

    ret = fread( output, 1, len, file );
    if( ret != len )
    {
        fclose( file );
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );
    }

    fclose( file );
    *olen = len;

    return( 0 );
}
#endif /* _WIN32 && !EFIX64 && !EFI32 */
#endif /* !POLARSSL_NO_PLATFORM_ENTROPY */

#if defined(POLARSSL_TIMING_C)
int hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    unsigned long timer = hardclock();
    ((void) data);
    *olen = 0;

    if( len < sizeof(unsigned long) )
        return( 0 );

    memcpy( output, &timer, sizeof(unsigned long) );
    *olen = sizeof(unsigned long);

    return( 0 );
}
#endif /* POLARSSL_TIMING_C */

#if defined(POLARSSL_HAVEGE_C)
int havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen )
{
    havege_state *hs = (havege_state *) data;
    *olen = 0;

    if( havege_random( hs, output, len ) != 0 )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

    *olen = len;

    return( 0 );
}
#endif /* POLARSSL_HAVEGE_C */

#endif /* POLARSSL_ENTROPY_C */
/**
 * \file md.c
 *
 * \brief Generic message digest wrapper for PolarSSL
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_MD_C)

//#include "polarssl/md.h"
//#include "polarssl/md_wrap.h"

#include <stdlib.h>

#if defined(_MSC_VER) && !defined strcasecmp && !defined(EFIX64) && \
    !defined(EFI32)
#define strcasecmp  _stricmp
#endif

/* Implementation that should never be optimized out by the compiler */
//static void polarssl_zeroize( void *v, size_t n ) {
//    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
//}

static const int supported_digests[] = {

#if defined(POLARSSL_SHA512_C)
        POLARSSL_MD_SHA512,
        POLARSSL_MD_SHA384,
#endif

#if defined(POLARSSL_SHA256_C)
        POLARSSL_MD_SHA256,
        POLARSSL_MD_SHA224,
#endif

#if defined(POLARSSL_SHA1_C)
        POLARSSL_MD_SHA1,
#endif

#if defined(POLARSSL_RIPEMD160_C)
        POLARSSL_MD_RIPEMD160,
#endif

#if defined(POLARSSL_MD5_C)
        POLARSSL_MD_MD5,
#endif

#if defined(POLARSSL_MD4_C)
        POLARSSL_MD_MD4,
#endif

#if defined(POLARSSL_MD2_C)
        POLARSSL_MD_MD2,
#endif

        POLARSSL_MD_NONE
};

const int *md_list( void )
{
    return( supported_digests );
}

#if 0
const md_info_t *md_info_from_string( const char *md_name )
{
    if( NULL == md_name )
        return( NULL );

    /* Get the appropriate digest information */
#if defined(POLARSSL_MD2_C)
    if( !strcasecmp( "MD2", md_name ) )
        return md_info_from_type( POLARSSL_MD_MD2 );
#endif
#if defined(POLARSSL_MD4_C)
    if( !strcasecmp( "MD4", md_name ) )
        return md_info_from_type( POLARSSL_MD_MD4 );
#endif
#if defined(POLARSSL_MD5_C)
    if( !strcasecmp( "MD5", md_name ) )
        return md_info_from_type( POLARSSL_MD_MD5 );
#endif
#if defined(POLARSSL_RIPEMD160_C)
    if( !strcasecmp( "RIPEMD160", md_name ) )
        return md_info_from_type( POLARSSL_MD_RIPEMD160 );
#endif
#if defined(POLARSSL_SHA1_C)
    if( !strcasecmp( "SHA1", md_name ) || !strcasecmp( "SHA", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA1 );
#endif
#if defined(POLARSSL_SHA256_C)
    if( !strcasecmp( "SHA224", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA224 );
    if( !strcasecmp( "SHA256", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA256 );
#endif
#if defined(POLARSSL_SHA512_C)
    if( !strcasecmp( "SHA384", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA384 );
    if( !strcasecmp( "SHA512", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA512 );
#endif
    return( NULL );
}
#endif

/*
const md_info_t *md_info_from_type( md_type_t md_type ) 
{
extern int printf(const char *format, ...);
   printf("running md_info_from_type.\n"); 
}
*/

const md_info_t *md_info_from_type(md_type_t md_type) { return NULL; }

#if 0
const md_info_t *md_info_from_type( md_type_t md_type )
{
    switch( md_type )
    {
#if defined(POLARSSL_MD2_C)
        case POLARSSL_MD_MD2:
            return( &md2_info );
#endif
#if defined(POLARSSL_MD4_C)
        case POLARSSL_MD_MD4:
            return( &md4_info );
#endif
#if defined(POLARSSL_MD5_C)
        case POLARSSL_MD_MD5:
            return( &md5_info );
#endif
#if defined(POLARSSL_RIPEMD160_C)
        case POLARSSL_MD_RIPEMD160:
            return( &ripemd160_info );
#endif
#if defined(POLARSSL_SHA1_C)
        case POLARSSL_MD_SHA1:
            return( &sha1_info );
#endif
#if defined(POLARSSL_SHA256_C)
        case POLARSSL_MD_SHA224:
            return( &sha224_info );
        case POLARSSL_MD_SHA256:
            return( &sha256_info );
#endif
#if defined(POLARSSL_SHA512_C)
        case POLARSSL_MD_SHA384:
            return( &sha384_info );
        case POLARSSL_MD_SHA512:
            return( &sha512_info );
#endif
        default:
            return( NULL );
    }
}
#endif

static void md_init( md_context_t *ctx )
{
    memset( ctx, 0, sizeof( md_context_t ) );
}

static void md_free( md_context_t *ctx )
{
    if( ctx == NULL )
        return;

    if( ctx->md_ctx )
        ctx->md_info->ctx_free_func( ctx->md_ctx );

    polarssl_zeroize( ctx, sizeof( md_context_t ) );
}

static int md_init_ctx( md_context_t *ctx, const md_info_t *md_info )
{
    if( md_info == NULL || ctx == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    memset( ctx, 0, sizeof( md_context_t ) );

    if( ( ctx->md_ctx = md_info->ctx_alloc_func() ) == NULL )
        return( POLARSSL_ERR_MD_ALLOC_FAILED );

    ctx->md_info = md_info;

    md_info->starts_func( ctx->md_ctx );

    return( 0 );
}

static int md_free_ctx( md_context_t *ctx )
{
    md_free( ctx );

    return( 0 );
}

static int md_starts( md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->starts_func( ctx->md_ctx );

    return( 0 );
}

static int md_update( md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->update_func( ctx->md_ctx, input, ilen );

    return( 0 );
}

static int md_finish( md_context_t *ctx, unsigned char *output )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->finish_func( ctx->md_ctx, output );

    return( 0 );
}

int md( const md_info_t *md_info, const unsigned char *input, size_t ilen,
            unsigned char *output )
{
    if( md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    md_info->digest_func( input, ilen, output );

    return( 0 );
}

static int md_file( const md_info_t *md_info, const char *path, unsigned char *output )
{
#if defined(POLARSSL_FS_IO)
    int ret;
#endif

    if( md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

#if defined(POLARSSL_FS_IO)
    ret = md_info->file_func( path, output );
    if( ret != 0 )
        return( POLARSSL_ERR_MD_FILE_IO_ERROR + ret );

    return( ret );
#else
    ((void) path);
    ((void) output);

    return( POLARSSL_ERR_MD_FEATURE_UNAVAILABLE );
#endif /* POLARSSL_FS_IO */
}

static int md_hmac_starts( md_context_t *ctx, const unsigned char *key, size_t keylen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->hmac_starts_func( ctx->md_ctx, key, keylen );

    return( 0 );
}

static int md_hmac_update( md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->hmac_update_func( ctx->md_ctx, input, ilen );

    return( 0 );
}

static int md_hmac_finish( md_context_t *ctx, unsigned char *output )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->hmac_finish_func( ctx->md_ctx, output );

    return( 0 );
}

static int md_hmac_reset( md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->hmac_reset_func( ctx->md_ctx );

    return( 0 );
}

static int md_hmac( const md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output )
{
    if( md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    md_info->hmac_func( key, keylen, input, ilen, output );

    return( 0 );
}

static int md_process( md_context_t *ctx, const unsigned char *data )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->process_func( ctx->md_ctx, data );

    return( 0 );
}

#endif /* POLARSSL_MD_C */
/*
 *  TCP networking functions
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_NET_C)

//#include "polarssl/net.h"

#if (defined(_WIN32) || defined(_WIN32_WCE)) && !defined(EFIX64) && !defined(EFI32)

#if defined(POLARSSL_HAVE_IPV6)
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
/* Enables getaddrinfo() & Co */
#define _WIN32_WINNT 0x0501
#include <ws2tcpip.h>
#endif

#include <winsock2.h>
#include <windows.h>

#if defined(_MSC_VER)
#if defined(_WIN32_WCE)
#pragma comment( lib, "ws2.lib" )
#else
#pragma comment( lib, "ws2_32.lib" )
#endif
#endif /* _MSC_VER */

/*
#define read(fd,buf,len)        recv(fd,(char*)buf,(int) len,0)
#define write(fd,buf,len)       send(fd,(char*)buf,(int) len,0)
#define close(fd)               closesocket(fd)
*/

static int wsa_init_done = 0;

#else /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(POLARSSL_HAVE_TIME)
#include <sys/time.h>
#endif
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) ||  \
    defined(__DragonFly__)
#include <sys/endian.h>
#elif defined(__APPLE__) || defined(HAVE_MACHINE_ENDIAN_H) ||   \
      defined(EFIX64) || defined(EFI32)
#include <machine/endian.h>
#elif defined(sun)
#include <sys/isa_defs.h>
#elif defined(_AIX) || defined(HAVE_ARPA_NAMESER_COMPAT_H)
#include <arpa/nameser_compat.h>
#else
#include <endian.h>
#endif

#endif /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

#include <stdlib.h>
#include <stdio.h>

#if defined(_MSC_VER) && !defined  snprintf && !defined(EFIX64) && !defined(EFI32)
#define  snprintf  _snprintf
#endif

#if defined(POLARSSL_HAVE_TIME)
#include <time.h>
#endif

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

/*
 * htons() is not always available.
 * By default go for LITTLE_ENDIAN variant. Otherwise hope for _BYTE_ORDER and
 * __BIG_ENDIAN to help determine endianness.
 */
#if defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) &&                   \
    __BYTE_ORDER == __BIG_ENDIAN
#define POLARSSL_HTONS(n) (n)
#define POLARSSL_HTONL(n) (n)
#else
#define POLARSSL_HTONS(n) ((((unsigned short)(n) & 0xFF      ) << 8 ) | \
                           (((unsigned short)(n) & 0xFF00    ) >> 8 ))
#define POLARSSL_HTONL(n) ((((unsigned long )(n) & 0xFF      ) << 24) | \
                           (((unsigned long )(n) & 0xFF00    ) << 8 ) | \
                           (((unsigned long )(n) & 0xFF0000  ) >> 8 ) | \
                           (((unsigned long )(n) & 0xFF000000) >> 24))
#endif

unsigned short net_htons( unsigned short n );
unsigned long  net_htonl( unsigned long  n );
#define net_htons(n) POLARSSL_HTONS(n)
#define net_htonl(n) POLARSSL_HTONL(n)

/*
 * Prepare for using the sockets interface
 */
static int net_prepare( void )
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
    WSADATA wsaData;

    if( wsa_init_done == 0 )
    {
        if( WSAStartup( MAKEWORD(2,0), &wsaData ) != 0 )
            return( POLARSSL_ERR_NET_SOCKET_FAILED );

        wsa_init_done = 1;
    }
#else
#if !defined(EFIX64) && !defined(EFI32)
    signal( SIGPIPE, SIG_IGN );
#endif
#endif
    return( 0 );
}

/*
 * Initiate a TCP connection with host:port
 */
static int net_connect( int *fd, const char *host, int port )
{
#if defined(POLARSSL_HAVE_IPV6)
    int ret;
    struct addrinfo hints, *addr_list, *cur;
    char port_str[6];

    if( ( ret = net_prepare() ) != 0 )
        return( ret );

    /* getaddrinfo expects port as a string */
    memset( port_str, 0, sizeof( port_str ) );
    snprintf( port_str, sizeof( port_str ), "%d", port );

    /* Do name resolution with both IPv6 and IPv4, but only TCP */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if( getaddrinfo( host, port_str, &hints, &addr_list ) != 0 )
        return( POLARSSL_ERR_NET_UNKNOWN_HOST );

    /* Try the sockaddrs until a connection succeeds */
    ret = POLARSSL_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
        *fd = (int) socket( cur->ai_family, cur->ai_socktype,
                            cur->ai_protocol );
        if( *fd < 0 )
        {
            ret = POLARSSL_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if( connect( *fd, cur->ai_addr, (int)cur->ai_addrlen ) == 0 )
        {
            ret = 0;
            break;
        }

        close( *fd );
        ret = POLARSSL_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo( addr_list );

    return( ret );

#else
    /* Legacy IPv4-only version */

    int ret;
    struct sockaddr_in server_addr;
    struct hostent *server_host;

    if( ( ret = net_prepare() ) != 0 )
        return( ret );

    if( ( server_host = gethostbyname( host ) ) == NULL )
        return( POLARSSL_ERR_NET_UNKNOWN_HOST );

    if( ( *fd = (int) socket( AF_INET, SOCK_STREAM, IPPROTO_IP ) ) < 0 )
        return( POLARSSL_ERR_NET_SOCKET_FAILED );

    memcpy( (void *) &server_addr.sin_addr,
            (void *) server_host->h_addr,
                     server_host->h_length );

    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = net_htons( port );

    if( connect( *fd, (struct sockaddr *) &server_addr,
                 sizeof( server_addr ) ) < 0 )
    {
        close( *fd );
        return( POLARSSL_ERR_NET_CONNECT_FAILED );
    }

    return( 0 );
#endif /* POLARSSL_HAVE_IPV6 */
}

/*
 * Create a listening socket on bind_ip:port
 */
static int net_bind( int *fd, const char *bind_ip, int port )
{
#if defined(POLARSSL_HAVE_IPV6)
    int n, ret;
    struct addrinfo hints, *addr_list, *cur;
    char port_str[6];

    if( ( ret = net_prepare() ) != 0 )
        return( ret );

    /* getaddrinfo expects port as a string */
    memset( port_str, 0, sizeof( port_str ) );
    snprintf( port_str, sizeof( port_str ), "%d", port );

    /* Bind to IPv6 and/or IPv4, but only in TCP */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if( bind_ip == NULL )
        hints.ai_flags = AI_PASSIVE;

    if( getaddrinfo( bind_ip, port_str, &hints, &addr_list ) != 0 )
        return( POLARSSL_ERR_NET_UNKNOWN_HOST );

    /* Try the sockaddrs until a binding succeeds */
    ret = POLARSSL_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
        *fd = (int) socket( cur->ai_family, cur->ai_socktype,
                            cur->ai_protocol );
        if( *fd < 0 )
        {
            ret = POLARSSL_ERR_NET_SOCKET_FAILED;
            continue;
        }

        n = 1;
        if( setsockopt( *fd, SOL_SOCKET, SO_REUSEADDR,
                        (const char *) &n, sizeof( n ) ) != 0 )
        {
            close( *fd );
            ret = POLARSSL_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if( ::bind( *fd, cur->ai_addr, (int)cur->ai_addrlen ) != 0 )
        {
            close( *fd );
            ret = POLARSSL_ERR_NET_BIND_FAILED;
            continue;
        }

        if( listen( *fd, POLARSSL_NET_LISTEN_BACKLOG ) != 0 )
        {
            close( *fd );
            ret = POLARSSL_ERR_NET_LISTEN_FAILED;
            continue;
        }

        /* I we ever get there, it's a success */
        ret = 0;
        break;
    }

    freeaddrinfo( addr_list );

    return( ret );
#else
    /* Legacy IPv4-only version */

    int ret, n, c[4];
    struct sockaddr_in server_addr;

    if( ( ret = net_prepare() ) != 0 )
        return( ret );

    if( ( *fd = (int) socket( AF_INET, SOCK_STREAM, IPPROTO_IP ) ) < 0 )
        return( POLARSSL_ERR_NET_SOCKET_FAILED );

    n = 1;
    setsockopt( *fd, SOL_SOCKET, SO_REUSEADDR,
                (const char *) &n, sizeof( n ) );

    server_addr.sin_addr.s_addr = net_htonl( INADDR_ANY );
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = net_htons( port );

    if( bind_ip != NULL )
    {
        memset( c, 0, sizeof( c ) );
        sscanf( bind_ip, "%d.%d.%d.%d", &c[0], &c[1], &c[2], &c[3] );

        for( n = 0; n < 4; n++ )
            if( c[n] < 0 || c[n] > 255 )
                break;

        if( n == 4 )
            server_addr.sin_addr.s_addr = net_htonl(
                ( (uint32_t) c[0] << 24 ) |
                ( (uint32_t) c[1] << 16 ) |
                ( (uint32_t) c[2] <<  8 ) |
                ( (uint32_t) c[3]       ) );
    }

    if( bind( *fd, (struct sockaddr *) &server_addr,
              sizeof( server_addr ) ) < 0 )
    {
        close( *fd );
        return( POLARSSL_ERR_NET_BIND_FAILED );
    }

    if( listen( *fd, POLARSSL_NET_LISTEN_BACKLOG ) != 0 )
    {
        close( *fd );
        return( POLARSSL_ERR_NET_LISTEN_FAILED );
    }

    return( 0 );
#endif /* POLARSSL_HAVE_IPV6 */
}

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 */
static int net_would_block( int fd )
{
    ((void) fd);
    return( WSAGetLastError() == WSAEWOULDBLOCK );
}
#else
/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 *
 * Note: on a blocking socket this function always returns 0!
 */
static int net_would_block( int fd )
{
    /*
     * Never return 'WOULD BLOCK' on a non-blocking socket
     */
    if( ( fcntl( fd, F_GETFL ) & O_NONBLOCK ) != O_NONBLOCK )
        return( 0 );

    switch( errno )
    {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return( 1 );
    }
    return( 0 );
}
#endif /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

/*
 * Accept a connection from a remote client
 */
static int net_accept( int bind_fd, int *client_fd, void *client_ip )
{
#if defined(POLARSSL_HAVE_IPV6)
    struct sockaddr_storage client_addr;
#else
    struct sockaddr_in client_addr;
#endif

#if defined(__socklen_t_defined) || defined(_SOCKLEN_T) ||  \
    defined(_SOCKLEN_T_DECLARED)
    socklen_t n = (socklen_t) sizeof( client_addr );
#else
    int n = (int) sizeof( client_addr );
#endif

    *client_fd = (int) accept( bind_fd, (struct sockaddr *)
                               &client_addr, &n );

    if( *client_fd < 0 )
    {
        if( net_would_block( bind_fd ) != 0 )
            return( POLARSSL_ERR_NET_WANT_READ );

        return( POLARSSL_ERR_NET_ACCEPT_FAILED );
    }

    if( client_ip != NULL )
    {
#if defined(POLARSSL_HAVE_IPV6)
        if( client_addr.ss_family == AF_INET )
        {
            struct sockaddr_in *addr4 = (struct sockaddr_in *) &client_addr;
            memcpy( client_ip, &addr4->sin_addr.s_addr,
                        sizeof( addr4->sin_addr.s_addr ) );
        }
        else
        {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &client_addr;
            memcpy( client_ip, &addr6->sin6_addr.s6_addr,
                        sizeof( addr6->sin6_addr.s6_addr ) );
        }
#else
        memcpy( client_ip, &client_addr.sin_addr.s_addr,
                    sizeof( client_addr.sin_addr.s_addr ) );
#endif /* POLARSSL_HAVE_IPV6 */
    }

    return( 0 );
}

/*
 * Set the socket blocking or non-blocking
 */
static int net_set_block( int fd )
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
    u_long n = 0;
    return( ioctlsocket( fd, FIONBIO, &n ) );
#else
    return( fcntl( fd, F_SETFL, fcntl( fd, F_GETFL ) & ~O_NONBLOCK ) );
#endif
}

static int net_set_nonblock( int fd )
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
    u_long n = 1;
    return( ioctlsocket( fd, FIONBIO, &n ) );
#else
    return( fcntl( fd, F_SETFL, fcntl( fd, F_GETFL ) | O_NONBLOCK ) );
#endif
}

#if defined(POLARSSL_HAVE_TIME)
/*
 * Portable usleep helper
 */
static void net_usleep( unsigned long usec )
{
    struct timeval tv;
    tv.tv_sec  = 0;
#if !defined(_WIN32) && ( defined(__unix__) || defined(__unix) || \
    ( defined(__APPLE__) && defined(__MACH__) ) )
    tv.tv_usec = (suseconds_t) usec;
#else
    tv.tv_usec = usec;
#endif
    select( 0, NULL, NULL, NULL, &tv );
}
#endif /* POLARSSL_HAVE_TIME */

/*
 * Read at most 'len' characters
 */
static int net_recv( void *ctx, unsigned char *buf, size_t len )
{
    int fd = *((int *) ctx);
    int ret = (int) read( fd, buf, (unsigned int)len );

    if( ret < 0 )
    {
        if( net_would_block( fd ) != 0 )
            return( POLARSSL_ERR_NET_WANT_READ );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( POLARSSL_ERR_NET_WANT_READ );
#endif

        return( POLARSSL_ERR_NET_RECV_FAILED );
    }

    return( ret );
}

/*
 * Write at most 'len' characters
 */
static int net_send( void *ctx, const unsigned char *buf, size_t len )
{
    int fd = *((int *) ctx);
    int ret = (int) write( fd, buf, (unsigned int)len );

    if( ret < 0 )
    {
        if( net_would_block( fd ) != 0 )
            return( POLARSSL_ERR_NET_WANT_WRITE );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( POLARSSL_ERR_NET_WANT_WRITE );
#endif

        return( POLARSSL_ERR_NET_SEND_FAILED );
    }

    return( ret );
}

/*
 * Gracefully close the connection
 */
static void net_close( int fd )
{
    shutdown( fd, 2 );
    close( fd );
}

#endif /* POLARSSL_NET_C */
/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_RSA_C)

//#include "polarssl/rsa.h"
//#include "polarssl/oid.h"

#if defined(POLARSSL_PKCS1_V21)
//#include "polarssl/md.h"
#endif

#include <stdlib.h>
#include <stdio.h>

#if defined(POLARSSL_PLATFORM_C)
//#include "polarssl/platform.h"
#else
#define polarssl_printf printf
#endif

/*
 * Initialize an RSA context
 */
static void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( rsa_context ) );

    rsa_set_padding( ctx, padding, hash_id );

#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_init( &ctx->mutex );
#endif
}

/*
 * Set padding for an existing RSA context
 */
static void rsa_set_padding( rsa_context *ctx, int padding, int hash_id )
{
    ctx->padding = padding;
    ctx->hash_id = hash_id;
}

#if defined(POLARSSL_GENPRIME)

/*
 * Generate an RSA keypair
 */
static int rsa_gen_key( rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
    int ret;
    mpi P1, Q1, H, G;

    if( f_rng == NULL || nbits < 128 || exponent < 3 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MPI_CHK( mpi_lset( &ctx->E, exponent ) );

    do
    {
        MPI_CHK( mpi_gen_prime( &ctx->P, ( nbits + 1 ) >> 1, 0,
                                f_rng, p_rng ) );

        MPI_CHK( mpi_gen_prime( &ctx->Q, ( nbits + 1 ) >> 1, 0,
                                f_rng, p_rng ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MPI_CHK( mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mpi_msb( &ctx->N ) != nbits )
            continue;

        MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
        MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MPI_CHK( mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;

cleanup:

    mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );

    if( ret != 0 )
    {
        rsa_free( ctx );
        return( POLARSSL_ERR_RSA_KEY_GEN_FAILED + ret );
    }

    return( 0 );
}

#endif /* POLARSSL_GENPRIME */

/*
 * Check a public RSA key
 */
static int rsa_check_pubkey( const rsa_context *ctx )
{
    if( !ctx->N.p || !ctx->E.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( ( ctx->N.p[0] & 1 ) == 0 ||
        ( ctx->E.p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->N ) < 128 ||
        mpi_msb( &ctx->N ) > POLARSSL_MPI_MAX_BITS )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->E ) < 2 ||
        mpi_cmp_mpi( &ctx->E, &ctx->N ) >= 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
static int rsa_check_privkey( const rsa_context *ctx )
{
    int ret;
    mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2, DP, DQ, QP;

    if( ( ret = rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    mpi_init( &PQ ); mpi_init( &DE ); mpi_init( &P1 ); mpi_init( &Q1 );
    mpi_init( &H  ); mpi_init( &I  ); mpi_init( &G  ); mpi_init( &G2 );
    mpi_init( &L1 ); mpi_init( &L2 ); mpi_init( &DP ); mpi_init( &DQ );
    mpi_init( &QP );

    MPI_CHK( mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MPI_CHK( mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    MPI_CHK( mpi_gcd( &G2, &P1, &Q1 ) );
    MPI_CHK( mpi_div_mpi( &L1, &L2, &H, &G2 ) );
    MPI_CHK( mpi_mod_mpi( &I, &DE, &L1  ) );

    MPI_CHK( mpi_mod_mpi( &DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &QP, &ctx->Q, &ctx->P ) );
    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mpi_cmp_mpi( &PQ, &ctx->N ) != 0 ||
        mpi_cmp_mpi( &DP, &ctx->DP ) != 0 ||
        mpi_cmp_mpi( &DQ, &ctx->DQ ) != 0 ||
        mpi_cmp_mpi( &QP, &ctx->QP ) != 0 ||
        mpi_cmp_int( &L2, 0 ) != 0 ||
        mpi_cmp_int( &I, 1 ) != 0 ||
        mpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = POLARSSL_ERR_RSA_KEY_CHECK_FAILED;
    }

cleanup:
    mpi_free( &PQ ); mpi_free( &DE ); mpi_free( &P1 ); mpi_free( &Q1 );
    mpi_free( &H  ); mpi_free( &I  ); mpi_free( &G  ); mpi_free( &G2 );
    mpi_free( &L1 ); mpi_free( &L2 ); mpi_free( &DP ); mpi_free( &DQ );
    mpi_free( &QP );

    if( ret == POLARSSL_ERR_RSA_KEY_CHECK_FAILED )
        return( ret );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED + ret );

    return( 0 );
}

/*
 * Do an RSA public key operation
 */
static int rsa_public( rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret;
    size_t olen;
    mpi T;

    mpi_init( &T );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    olen = ctx->len;
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PUBLIC_FAILED + ret );

    return( 0 );
}

#if !defined(POLARSSL_RSA_NO_CRT)
/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology—CRYPTO’96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding( rsa_context *ctx, mpi *Vi, mpi *Vf,
                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, count = 0;

#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_lock( &ctx->mutex );
#endif

    if( ctx->Vf.p != NULL )
    {
        /* We already have blinding values, just update them by squaring */
        MPI_CHK( mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &ctx->Vi ) );
        MPI_CHK( mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
        MPI_CHK( mpi_mul_mpi( &ctx->Vf, &ctx->Vf, &ctx->Vf ) );
        MPI_CHK( mpi_mod_mpi( &ctx->Vf, &ctx->Vf, &ctx->N ) );

        goto done;
    }

    /* Unblinding value: Vf = random number, invertible mod N */
    do {
        if( count++ > 10 )
            return( POLARSSL_ERR_RSA_RNG_FAILED );

        MPI_CHK( mpi_fill_random( &ctx->Vf, ctx->len - 1, f_rng, p_rng ) );
        MPI_CHK( mpi_gcd( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    } while( mpi_cmp_int( &ctx->Vi, 1 ) != 0 );

    /* Blinding value: Vi =  Vf^(-e) mod N */
    MPI_CHK( mpi_inv_mod( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    MPI_CHK( mpi_exp_mod( &ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN ) );

done:
    if( Vi != &ctx->Vi )
    {
        MPI_CHK( mpi_copy( Vi, &ctx->Vi ) );
        MPI_CHK( mpi_copy( Vf, &ctx->Vf ) );
    }

cleanup:
#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_unlock( &ctx->mutex );
#endif

    return( ret );
}
#endif /* !POLARSSL_RSA_NO_CRT */

/*
 * Do an RSA private key operation
 */
static int rsa_private( rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret;
    size_t olen;
    mpi T, T1, T2;
#if !defined(POLARSSL_RSA_NO_CRT)
    mpi *Vi, *Vf;

    /*
     * When using the Chinese Remainder Theorem, we use blinding values.
     * Without threading, we just read them directly from the context,
     * otherwise we make a local copy in order to reduce locking contention.
     */
#if defined(POLARSSL_THREADING_C)
    mpi Vi_copy, Vf_copy;

    mpi_init( &Vi_copy ); mpi_init( &Vf_copy );
    Vi = &Vi_copy;
    Vf = &Vf_copy;
#else
    Vi = &ctx->Vi;
    Vf = &ctx->Vf;
#endif
#endif /* !POLARSSL_RSA_NO_CRT */

    mpi_init( &T ); mpi_init( &T1 ); mpi_init( &T2 );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );
    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

#if defined(POLARSSL_RSA_NO_CRT)
    ((void) f_rng);
    ((void) p_rng);
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#else
    if( f_rng != NULL )
    {
        /*
         * Blinding
         * T = T * Vi mod N
         */
        MPI_CHK( rsa_prepare_blinding( ctx, Vi, Vf, f_rng, p_rng ) );
        MPI_CHK( mpi_mul_mpi( &T, &T, Vi ) );
        MPI_CHK( mpi_mod_mpi( &T, &T, &ctx->N ) );
    }

    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MPI_CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MPI_CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MPI_CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * T = T2 + T * Q
     */
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );

    if( f_rng != NULL )
    {
        /*
         * Unblind
         * T = T * Vf mod N
         */
        MPI_CHK( mpi_mul_mpi( &T, &T, Vf ) );
        MPI_CHK( mpi_mod_mpi( &T, &T, &ctx->N ) );
    }
#endif /* POLARSSL_RSA_NO_CRT */

    olen = ctx->len;
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:
    mpi_free( &T ); mpi_free( &T1 ); mpi_free( &T2 );
#if !defined(POLARSSL_RSA_NO_CRT) && defined(POLARSSL_THREADING_C)
    mpi_free( &Vi_copy ); mpi_free( &Vf_copy );
#endif

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PRIVATE_FAILED + ret );

    return( 0 );
}

#if defined(POLARSSL_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
 * \param md_ctx    message digest context to use
 */
static void mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src,
                      size_t slen, md_context_t *md_ctx )
{
    unsigned char mask[POLARSSL_MD_MAX_SIZE];
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;

    memset( mask, 0, POLARSSL_MD_MAX_SIZE );
    memset( counter, 0, 4 );

    hlen = md_ctx->md_info->size;

    // Generate and apply dbMask
    //
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;

        md_starts( md_ctx );
        md_update( md_ctx, src, slen );
        md_update( md_ctx, counter, 4 );
        md_finish( md_ctx, mask );

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }
}
#endif /* POLARSSL_PKCS1_V21 */

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
static int rsa_rsaes_oaep_encrypt( rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    size_t olen;
    int ret;
    unsigned char *p = output;
    unsigned int hlen;
    const md_info_t *md_info;
    md_context_t md_ctx;

    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V21 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    md_info = md_info_from_type( (md_type_t)ctx->hash_id );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;
    hlen = md_get_size( md_info );

    if( olen < ilen + 2 * hlen + 2 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    memset( output, 0, olen );

    *p++ = 0;

    // Generate a random octet string seed
    //
    if( ( ret = f_rng( p_rng, p, hlen ) ) != 0 )
        return( POLARSSL_ERR_RSA_RNG_FAILED + ret );

    p += hlen;

    // Construct DB
    //
    md( md_info, label, label_len, p );
    p += hlen;
    p += olen - 2 * hlen - 2 - ilen;
    *p++ = 1;
    memcpy( p, input, ilen );

    md_init( &md_ctx );
    md_init_ctx( &md_ctx, md_info );

    // maskedDB: Apply dbMask to DB
    //
    mgf_mask( output + hlen + 1, olen - hlen - 1, output + 1, hlen,
               &md_ctx );

    // maskedSeed: Apply seedMask to seed
    //
    mgf_mask( output + 1, hlen, output + hlen + 1, olen - hlen - 1,
               &md_ctx );

    md_free( &md_ctx );

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, f_rng, p_rng, output, output ) );
}
#endif /* POLARSSL_PKCS1_V21 */

#if defined(POLARSSL_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
static int rsa_rsaes_pkcs1_v15_encrypt( rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t nb_pad, olen;
    int ret;
    unsigned char *p = output;

    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    if( olen < ilen + 11 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    nb_pad = olen - 3 - ilen;

    *p++ = 0;
    if( mode == RSA_PUBLIC )
    {
        *p++ = RSA_CRYPT;

        while( nb_pad-- > 0 )
        {
            int rng_dl = 100;

            do {
                ret = f_rng( p_rng, p, 1 );
            } while( *p == 0 && --rng_dl && ret == 0 );

            // Check if RNG failed to generate data
            //
            if( rng_dl == 0 || ret != 0 )
                return( POLARSSL_ERR_RSA_RNG_FAILED + ret );

            p++;
        }
    }
    else
    {
        *p++ = RSA_SIGN;

        while( nb_pad-- > 0 )
            *p++ = 0xFF;
    }

    *p++ = 0;
    memcpy( p, input, ilen );

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, f_rng, p_rng, output, output ) );
}
#endif /* POLARSSL_PKCS1_V15 */

/*
 * Add the message padding, then do an RSA operation
 */
static int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    switch( ctx->padding )
    {
#if defined(POLARSSL_PKCS1_V15)
        case RSA_PKCS_V15:
            return rsa_rsaes_pkcs1_v15_encrypt( ctx, f_rng, p_rng, mode, ilen,
                                                input, output );
#endif

#if defined(POLARSSL_PKCS1_V21)
        case RSA_PKCS_V21:
            return rsa_rsaes_oaep_encrypt( ctx, f_rng, p_rng, mode, NULL, 0,
                                           ilen, input, output );
#endif

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
static int rsa_rsaes_oaep_decrypt( rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    int ret;
    size_t ilen, i, pad_len;
    unsigned char *p, bad, pad_done;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    unsigned char lhash[POLARSSL_MD_MAX_SIZE];
    unsigned int hlen;
    const md_info_t *md_info;
    md_context_t md_ctx;

    /*
     * Parameters sanity checks
     */
    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V21 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ilen = ctx->len;

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    md_info = md_info_from_type( (md_type_t)ctx->hash_id );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    /*
     * RSA operation
     */
    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        return( ret );

    /*
     * Unmask data and generate lHash
     */
    hlen = md_get_size( md_info );

    md_init( &md_ctx );
    md_init_ctx( &md_ctx, md_info );

    /* Generate lHash */
    md( md_info, label, label_len, lhash );

    /* seed: Apply seedMask to maskedSeed */
    mgf_mask( buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
               &md_ctx );

    /* DB: Apply dbMask to maskedDB */
    mgf_mask( buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
               &md_ctx );

    md_free( &md_ctx );

    /*
     * Check contents, in "constant-time"
     */
    p = buf;
    bad = 0;

    bad |= *p++; /* First byte must be 0 */

    p += hlen; /* Skip seed */

    /* Check lHash */
    for( i = 0; i < hlen; i++ )
        bad |= lhash[i] ^ *p++;

    /* Get zero-padding len, but always read till end of buffer
     * (minus one, for the 01 byte) */
    pad_len = 0;
    pad_done = 0;
    for( i = 0; i < ilen - 2 * hlen - 2; i++ )
    {
        pad_done |= p[i];
        pad_len += ( pad_done == 0 );
    }

    p += pad_len;
    bad |= *p++ ^ 0x01;

    /*
     * The only information "leaked" is whether the padding was correct or not
     * (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
     * the different error conditions.
     */
    if( bad != 0 )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    if( ilen - ( p - buf ) > output_max_len )
        return( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );

    *olen = ilen - (p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}
#endif /* POLARSSL_PKCS1_V21 */

#if defined(POLARSSL_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
static int rsa_rsaes_pkcs1_v15_decrypt( rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len)
{
    int ret;
    size_t ilen, pad_count = 0, i;
    unsigned char *p, bad, pad_done = 0;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];

    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ilen = ctx->len;

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        return( ret );

    p = buf;
    bad = 0;

    /*
     * Check and get padding len in "constant-time"
     */
    bad |= *p++; /* First byte must be 0 */

    /* This test does not depend on secret data */
    if( mode == RSA_PRIVATE )
    {
        bad |= *p++ ^ RSA_CRYPT;

        /* Get padding len, but always read till end of buffer
         * (minus one, for the 00 byte) */
        for( i = 0; i < ilen - 3; i++ )
        {
            pad_done |= ( p[i] == 0 );
            pad_count += ( pad_done == 0 );
        }

        p += pad_count;
        bad |= *p++; /* Must be zero */
    }
    else
    {
        bad |= *p++ ^ RSA_SIGN;

        /* Get padding len, but always read till end of buffer
         * (minus one, for the 00 byte) */
        for( i = 0; i < ilen - 3; i++ )
        {
            pad_done |= ( p[i] != 0xFF );
            pad_count += ( pad_done == 0 );
        }

        p += pad_count;
        bad |= *p++; /* Must be zero */
    }

    if( bad )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    if( ilen - ( p - buf ) > output_max_len )
        return( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );

    *olen = ilen - (p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}
#endif /* POLARSSL_PKCS1_V15 */

/*
 * Do an RSA operation, then remove the message padding
 */
static int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len)
{
    switch( ctx->padding )
    {
#if defined(POLARSSL_PKCS1_V15)
        case RSA_PKCS_V15:
            return rsa_rsaes_pkcs1_v15_decrypt( ctx, f_rng, p_rng, mode, olen,
                                                input, output, output_max_len );
#endif

#if defined(POLARSSL_PKCS1_V21)
        case RSA_PKCS_V21:
            return rsa_rsaes_oaep_decrypt( ctx, f_rng, p_rng, mode, NULL, 0,
                                           olen, input, output,
                                           output_max_len );
#endif

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
 */
static int rsa_rsassa_pss_sign( rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         int mode,
                         md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
    size_t olen;
    unsigned char *p = sig;
    unsigned char salt[POLARSSL_MD_MAX_SIZE];
    unsigned int slen, hlen, offset = 0;
    int ret;
    size_t msb;
    const md_info_t *md_info;
    md_context_t md_ctx;

    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V21 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    if( md_alg != POLARSSL_MD_NONE )
    {
        // Gather length of hash to sign
        //
        md_info = md_info_from_type( md_alg );
        if( md_info == NULL )
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

        hashlen = md_get_size( md_info );
    }

    md_info = md_info_from_type( (md_type_t)ctx->hash_id );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    hlen = md_get_size( md_info );
    slen = hlen;

    if( olen < hlen + slen + 2 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    memset( sig, 0, olen );

    // Generate salt of length slen
    //
    if( ( ret = f_rng( p_rng, salt, slen ) ) != 0 )
        return( POLARSSL_ERR_RSA_RNG_FAILED + ret );

    // Note: EMSA-PSS encoding is over the length of N - 1 bits
    //
    msb = mpi_msb( &ctx->N ) - 1;
    p += olen - hlen * 2 - 2;
    *p++ = 0x01;
    memcpy( p, salt, slen );
    p += slen;

    md_init( &md_ctx );
    md_init_ctx( &md_ctx, md_info );

    // Generate H = Hash( M' )
    //
    md_starts( &md_ctx );
    md_update( &md_ctx, p, 8 );
    md_update( &md_ctx, hash, hashlen );
    md_update( &md_ctx, salt, slen );
    md_finish( &md_ctx, p );

    // Compensate for boundary condition when applying mask
    //
    if( msb % 8 == 0 )
        offset = 1;

    // maskedDB: Apply dbMask to DB
    //
    mgf_mask( sig + offset, olen - hlen - 1 - offset, p, hlen, &md_ctx );

    md_free( &md_ctx );

    msb = mpi_msb( &ctx->N ) - 1;
    sig[0] &= 0xFF >> ( olen * 8 - msb );

    p += hlen;
    *p++ = 0xBC;

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, f_rng, p_rng, sig, sig ) );
}
#endif /* POLARSSL_PKCS1_V21 */


#undef POLARSSL_PKCS1_V15
#if defined(POLARSSL_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 */
/*
 * Do an RSA operation to sign the message digest
 */
static int rsa_rsassa_pkcs1_v15_sign( rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    size_t nb_pad, olen, oid_size = 0;
    unsigned char *p = sig;
    const char *oid = NULL;

    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;
    nb_pad = olen - 3;

    if( md_alg != POLARSSL_MD_NONE )
    {
        const md_info_t *md_info = md_info_from_type( md_alg );
        if( md_info == NULL )
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

        if( oid_get_oid_by_md( md_alg, &oid, &oid_size ) != 0 )
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

        nb_pad -= 10 + oid_size;

        hashlen = md_get_size( md_info );
    }

    nb_pad -= hashlen;

    if( ( nb_pad < 8 ) || ( nb_pad > olen ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    *p++ = 0;
    *p++ = RSA_SIGN;
    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    if( md_alg == POLARSSL_MD_NONE )
    {
        memcpy( p, hash, hashlen );
    }
    else
    {
        /*
         * DigestInfo ::= SEQUENCE {
         *   digestAlgorithm DigestAlgorithmIdentifier,
         *   digest Digest }
         *
         * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
         *
         * Digest ::= OCTET STRING
         */
        *p++ = ASN1_SEQUENCE | ASN1_CONSTRUCTED;
        *p++ = (unsigned char) ( 0x08 + oid_size + hashlen );
        *p++ = ASN1_SEQUENCE | ASN1_CONSTRUCTED;
        *p++ = (unsigned char) ( 0x04 + oid_size );
        *p++ = ASN1_OID;
        *p++ = oid_size & 0xFF;
        memcpy( p, oid, oid_size );
        p += oid_size;
        *p++ = ASN1_NULL;
        *p++ = 0x00;
        *p++ = ASN1_OCTET_STRING;
        *p++ = hashlen;
        memcpy( p, hash, hashlen );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, f_rng, p_rng, sig, sig ) );
}
#endif /* POLARSSL_PKCS1_V15 */

/*
 * Do an RSA operation to sign the message digest
 */
static int rsa_pkcs1_sign( rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    int mode,
                    md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    switch( ctx->padding )
    {
#if defined(POLARSSL_PKCS1_V15)
        case RSA_PKCS_V15:
            return rsa_rsassa_pkcs1_v15_sign( ctx, f_rng, p_rng, mode, md_alg,
                                              hashlen, hash, sig );
#endif

#if defined(POLARSSL_PKCS1_V21)
        case RSA_PKCS_V21:
            return rsa_rsassa_pss_sign( ctx, f_rng, p_rng, mode, md_alg,
                                        hashlen, hash, sig );
#endif

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
static int rsa_rsassa_pss_verify_ext( rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{
    int ret;
    size_t siglen;
    unsigned char *p;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    unsigned char result[POLARSSL_MD_MAX_SIZE];
    unsigned char zeros[8];
    unsigned int hlen;
    size_t slen, msb;
    const md_info_t *md_info;
    md_context_t md_ctx;

    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V21 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    siglen = ctx->len;

    if( siglen < 16 || siglen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, f_rng, p_rng, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( buf[siglen - 1] != 0xBC )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    if( md_alg != POLARSSL_MD_NONE )
    {
        // Gather length of hash to sign
        //
        md_info = md_info_from_type( md_alg );
        if( md_info == NULL )
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

        hashlen = md_get_size( md_info );
    }

    md_info = md_info_from_type( mgf1_hash_id );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    hlen = md_get_size( md_info );
    slen = siglen - hlen - 1; /* Currently length of salt + padding */

    memset( zeros, 0, 8 );

    // Note: EMSA-PSS verification is over the length of N - 1 bits
    //
    msb = mpi_msb( &ctx->N ) - 1;

    // Compensate for boundary condition when applying mask
    //
    if( msb % 8 == 0 )
    {
        p++;
        siglen -= 1;
    }
    if( buf[0] >> ( 8 - siglen * 8 + msb ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    md_init( &md_ctx );
    md_init_ctx( &md_ctx, md_info );

    mgf_mask( p, siglen - hlen - 1, p + siglen - hlen - 1, hlen, &md_ctx );

    buf[0] &= 0xFF >> ( siglen * 8 - msb );

    while( p < buf + siglen && *p == 0 )
        p++;

    if( p == buf + siglen ||
        *p++ != 0x01 )
    {
        md_free( &md_ctx );
        return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    /* Actual salt len */
    slen -= p - buf;

    if( expected_salt_len != RSA_SALT_LEN_ANY &&
        slen != (size_t) expected_salt_len )
    {
        md_free( &md_ctx );
        return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    // Generate H = Hash( M' )
    //
    md_starts( &md_ctx );
    md_update( &md_ctx, zeros, 8 );
    md_update( &md_ctx, hash, hashlen );
    md_update( &md_ctx, p, slen );
    md_finish( &md_ctx, result );

    md_free( &md_ctx );

    if( memcmp( p + slen, result, hlen ) == 0 )
        return( 0 );
    else
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );
}

/*
 * Simplified PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
static int rsa_rsassa_pss_verify( rsa_context *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           int mode,
                           md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig )
{
    md_type_t mgf1_hash_id = ( ctx->hash_id != POLARSSL_MD_NONE )
                             ? (md_type_t) ctx->hash_id
                             : md_alg;

    return( rsa_rsassa_pss_verify_ext( ctx, f_rng, p_rng, mode,
                                       md_alg, hashlen, hash,
                                       mgf1_hash_id, RSA_SALT_LEN_ANY,
                                       sig ) );

}
#endif /* POLARSSL_PKCS1_V21 */

#if defined(POLARSSL_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
 */
static int rsa_rsassa_pkcs1_v15_verify( rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode,
                                 md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig )
{
    int ret;
    size_t len, siglen, asn1_len;
    unsigned char *p, *end;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    md_type_t msg_md_alg;
    const md_info_t *md_info;
    asn1_buf oid;

    if( mode == RSA_PRIVATE && ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    siglen = ctx->len;

    if( siglen < 16 || siglen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, f_rng, p_rng, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( *p++ != 0 || *p++ != RSA_SIGN )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    while( *p != 0 )
    {
        if( p >= buf + siglen - 1 || *p != 0xFF )
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
        p++;
    }
    p++;

    len = siglen - ( p - buf );

    if( len == hashlen && md_alg == POLARSSL_MD_NONE )
    {
        if( memcmp( p, hash, hashlen ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    md_info = md_info_from_type( md_alg );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    hashlen = md_get_size( md_info );

    end = p + len;

    // Parse the ASN.1 structure inside the PKCS#1 v1.5 structure
    //
    if( ( ret = asn1_get_tag( &p, end, &asn1_len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( asn1_len + 2 != len )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( ( ret = asn1_get_tag( &p, end, &asn1_len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( asn1_len + 6 + hashlen != len )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( ( ret = asn1_get_tag( &p, end, &oid.len, ASN1_OID ) ) != 0 )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    oid.p = p;
    p += oid.len;

    if( oid_get_md_alg( &oid, &msg_md_alg ) != 0 )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( md_alg != msg_md_alg )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    /*
     * assume the algorithm parameters must be NULL
     */
    if( ( ret = asn1_get_tag( &p, end, &asn1_len, ASN1_NULL ) ) != 0 )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( ( ret = asn1_get_tag( &p, end, &asn1_len, ASN1_OCTET_STRING ) ) != 0 )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( asn1_len != hashlen )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( memcmp( p, hash, hashlen ) != 0 )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    p += hashlen;

    if( p != end )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    return( 0 );
}
#endif /* POLARSSL_PKCS1_V15 */

/*
 * Do an RSA operation and check the message digest
 */
static int rsa_pkcs1_verify( rsa_context *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng,
                      int mode,
                      md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig )
{
    switch( ctx->padding )
    {
#if defined(POLARSSL_PKCS1_V15)
        case RSA_PKCS_V15:
            return rsa_rsassa_pkcs1_v15_verify( ctx, f_rng, p_rng, mode, md_alg,
                                                hashlen, hash, sig );
#endif

#if defined(POLARSSL_PKCS1_V21)
        case RSA_PKCS_V21:
            return rsa_rsassa_pss_verify( ctx, f_rng, p_rng, mode, md_alg,
                                          hashlen, hash, sig );
#endif

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

/*
 * Copy the components of an RSA key
 */
static int rsa_copy( rsa_context *dst, const rsa_context *src )
{
    int ret;

    dst->ver = src->ver;
    dst->len = src->len;

    MPI_CHK( mpi_copy( &dst->N, &src->N ) );
    MPI_CHK( mpi_copy( &dst->E, &src->E ) );

    MPI_CHK( mpi_copy( &dst->D, &src->D ) );
    MPI_CHK( mpi_copy( &dst->P, &src->P ) );
    MPI_CHK( mpi_copy( &dst->Q, &src->Q ) );
    MPI_CHK( mpi_copy( &dst->DP, &src->DP ) );
    MPI_CHK( mpi_copy( &dst->DQ, &src->DQ ) );
    MPI_CHK( mpi_copy( &dst->QP, &src->QP ) );

    MPI_CHK( mpi_copy( &dst->RN, &src->RN ) );
    MPI_CHK( mpi_copy( &dst->RP, &src->RP ) );
    MPI_CHK( mpi_copy( &dst->RQ, &src->RQ ) );

#if !defined(POLARSSL_RSA_NO_CRT)
    MPI_CHK( mpi_copy( &dst->Vi, &src->Vi ) );
    MPI_CHK( mpi_copy( &dst->Vf, &src->Vf ) );
#endif

    dst->padding = src->padding;
    dst->hash_id = src->hash_id;

cleanup:
    if( ret != 0 )
        rsa_free( dst );

    return( ret );
}

/*
 * Free the components of an RSA key
 */
static void rsa_free( rsa_context *ctx )
{
#if !defined(POLARSSL_RSA_NO_CRT)
    mpi_free( &ctx->Vi ); mpi_free( &ctx->Vf );
#endif
    mpi_free( &ctx->RQ ); mpi_free( &ctx->RP ); mpi_free( &ctx->RN );
    mpi_free( &ctx->QP ); mpi_free( &ctx->DQ ); mpi_free( &ctx->DP );
    mpi_free( &ctx->Q  ); mpi_free( &ctx->P  ); mpi_free( &ctx->D );
    mpi_free( &ctx->E  ); mpi_free( &ctx->N  );

#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_free( &ctx->mutex );
#endif
}

#if defined(POLARSSL_SELF_TEST)

//#include "polarssl/sha1.h"

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

#if defined(POLARSSL_PKCS1_V15)
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}
#endif /* POLARSSL_PKCS1_V15 */

/*
 * Checkup routine
 */
static int rsa_self_test( int verbose )
{
    int ret = 0;
#if defined(POLARSSL_PKCS1_V15)
    size_t len;
    rsa_context rsa;
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];
#if defined(POLARSSL_SHA1_C)
    unsigned char sha1sum[20];
#endif

    rsa_init( &rsa, RSA_PKCS_V15, 0 );

    rsa.len = KEY_LEN;
    MPI_CHK( mpi_read_string( &rsa.N , 16, RSA_N  ) );
    MPI_CHK( mpi_read_string( &rsa.E , 16, RSA_E  ) );
    MPI_CHK( mpi_read_string( &rsa.D , 16, RSA_D  ) );
    MPI_CHK( mpi_read_string( &rsa.P , 16, RSA_P  ) );
    MPI_CHK( mpi_read_string( &rsa.Q , 16, RSA_Q  ) );
    MPI_CHK( mpi_read_string( &rsa.DP, 16, RSA_DP ) );
    MPI_CHK( mpi_read_string( &rsa.DQ, 16, RSA_DQ ) );
    MPI_CHK( mpi_read_string( &rsa.QP, 16, RSA_QP ) );

    if( verbose != 0 )
        polarssl_printf( "  RSA key validation: " );

    if( rsa_check_pubkey(  &rsa ) != 0 ||
        rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( rsa_pkcs1_encrypt( &rsa, myrand, NULL, RSA_PUBLIC, PT_LEN,
                           rsa_plaintext, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n  PKCS#1 decryption : " );

    if( rsa_pkcs1_decrypt( &rsa, myrand, NULL, RSA_PRIVATE, &len,
                           rsa_ciphertext, rsa_decrypted,
                           sizeof(rsa_decrypted) ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        return( 1 );
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        return( 1 );
    }

#if defined(POLARSSL_SHA1_C)
    if( verbose != 0 )
        polarssl_printf( "passed\n  PKCS#1 data sign  : " );

    sha1( rsa_plaintext, PT_LEN, sha1sum );

    if( rsa_pkcs1_sign( &rsa, myrand, NULL, RSA_PRIVATE, POLARSSL_MD_SHA1, 0,
                        sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n  PKCS#1 sig. verify: " );

    if( rsa_pkcs1_verify( &rsa, NULL, NULL, RSA_PUBLIC, POLARSSL_MD_SHA1, 0,
                          sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n\n" );
#endif /* POLARSSL_SHA1_C */

cleanup:
    rsa_free( &rsa );
#else /* POLARSSL_PKCS1_V15 */
    ((void) verbose);
#endif /* POLARSSL_PKCS1_V15 */
    return( ret );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_RSA_C */
/*
 *  FIPS-180-2 compliant SHA-384/512 implementation
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  The SHA-512 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_SHA512_C)

//#include "polarssl/sha512.h"

#if defined(POLARSSL_FS_IO) || defined(POLARSSL_SELF_TEST)
#include <stdio.h>
#endif

#if defined(POLARSSL_PLATFORM_C)
//#include "polarssl/platform.h"
#else
#define polarssl_printf printf
#endif

/* Implementation that should never be optimized out by the compiler */
//static void polarssl_zeroize( void *v, size_t n ) {
//    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
//}

#if !defined(POLARSSL_SHA512_ALT)

/*
 * 64-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i)    ] << 56 )       \
        | ( (uint64_t) (b)[(i) + 1] << 48 )       \
        | ( (uint64_t) (b)[(i) + 2] << 40 )       \
        | ( (uint64_t) (b)[(i) + 3] << 32 )       \
        | ( (uint64_t) (b)[(i) + 4] << 24 )       \
        | ( (uint64_t) (b)[(i) + 5] << 16 )       \
        | ( (uint64_t) (b)[(i) + 6] <<  8 )       \
        | ( (uint64_t) (b)[(i) + 7]       );      \
}
#endif /* GET_UINT64_BE */

#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 7] = (unsigned char) ( (n)       );       \
}
#endif /* PUT_UINT64_BE */

/*
 * Round constants
 */
static const uint64_t K[80] =
{
    UL64(0x428A2F98D728AE22),  UL64(0x7137449123EF65CD),
    UL64(0xB5C0FBCFEC4D3B2F),  UL64(0xE9B5DBA58189DBBC),
    UL64(0x3956C25BF348B538),  UL64(0x59F111F1B605D019),
    UL64(0x923F82A4AF194F9B),  UL64(0xAB1C5ED5DA6D8118),
    UL64(0xD807AA98A3030242),  UL64(0x12835B0145706FBE),
    UL64(0x243185BE4EE4B28C),  UL64(0x550C7DC3D5FFB4E2),
    UL64(0x72BE5D74F27B896F),  UL64(0x80DEB1FE3B1696B1),
    UL64(0x9BDC06A725C71235),  UL64(0xC19BF174CF692694),
    UL64(0xE49B69C19EF14AD2),  UL64(0xEFBE4786384F25E3),
    UL64(0x0FC19DC68B8CD5B5),  UL64(0x240CA1CC77AC9C65),
    UL64(0x2DE92C6F592B0275),  UL64(0x4A7484AA6EA6E483),
    UL64(0x5CB0A9DCBD41FBD4),  UL64(0x76F988DA831153B5),
    UL64(0x983E5152EE66DFAB),  UL64(0xA831C66D2DB43210),
    UL64(0xB00327C898FB213F),  UL64(0xBF597FC7BEEF0EE4),
    UL64(0xC6E00BF33DA88FC2),  UL64(0xD5A79147930AA725),
    UL64(0x06CA6351E003826F),  UL64(0x142929670A0E6E70),
    UL64(0x27B70A8546D22FFC),  UL64(0x2E1B21385C26C926),
    UL64(0x4D2C6DFC5AC42AED),  UL64(0x53380D139D95B3DF),
    UL64(0x650A73548BAF63DE),  UL64(0x766A0ABB3C77B2A8),
    UL64(0x81C2C92E47EDAEE6),  UL64(0x92722C851482353B),
    UL64(0xA2BFE8A14CF10364),  UL64(0xA81A664BBC423001),
    UL64(0xC24B8B70D0F89791),  UL64(0xC76C51A30654BE30),
    UL64(0xD192E819D6EF5218),  UL64(0xD69906245565A910),
    UL64(0xF40E35855771202A),  UL64(0x106AA07032BBD1B8),
    UL64(0x19A4C116B8D2D0C8),  UL64(0x1E376C085141AB53),
    UL64(0x2748774CDF8EEB99),  UL64(0x34B0BCB5E19B48A8),
    UL64(0x391C0CB3C5C95A63),  UL64(0x4ED8AA4AE3418ACB),
    UL64(0x5B9CCA4F7763E373),  UL64(0x682E6FF3D6B2B8A3),
    UL64(0x748F82EE5DEFB2FC),  UL64(0x78A5636F43172F60),
    UL64(0x84C87814A1F0AB72),  UL64(0x8CC702081A6439EC),
    UL64(0x90BEFFFA23631E28),  UL64(0xA4506CEBDE82BDE9),
    UL64(0xBEF9A3F7B2C67915),  UL64(0xC67178F2E372532B),
    UL64(0xCA273ECEEA26619C),  UL64(0xD186B8C721C0C207),
    UL64(0xEADA7DD6CDE0EB1E),  UL64(0xF57D4F7FEE6ED178),
    UL64(0x06F067AA72176FBA),  UL64(0x0A637DC5A2C898A6),
    UL64(0x113F9804BEF90DAE),  UL64(0x1B710B35131C471B),
    UL64(0x28DB77F523047D84),  UL64(0x32CAAB7B40C72493),
    UL64(0x3C9EBE0A15C9BEBC),  UL64(0x431D67C49C100D4C),
    UL64(0x4CC5D4BECB3E42B6),  UL64(0x597F299CFC657E2A),
    UL64(0x5FCB6FAB3AD6FAEC),  UL64(0x6C44198C4A475817)
};

static void sha512_init( sha512_context *ctx )
{
    memset( ctx, 0, sizeof( sha512_context ) );
}

static void sha512_free( sha512_context *ctx )
{
    if( ctx == NULL )
        return;

    polarssl_zeroize( ctx, sizeof( sha512_context ) );
}

/*
 * SHA-512 context setup
 */
static void sha512_starts( sha512_context *ctx, int is384 )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if( is384 == 0 )
    {
        /* SHA-512 */
        ctx->state[0] = UL64(0x6A09E667F3BCC908);
        ctx->state[1] = UL64(0xBB67AE8584CAA73B);
        ctx->state[2] = UL64(0x3C6EF372FE94F82B);
        ctx->state[3] = UL64(0xA54FF53A5F1D36F1);
        ctx->state[4] = UL64(0x510E527FADE682D1);
        ctx->state[5] = UL64(0x9B05688C2B3E6C1F);
        ctx->state[6] = UL64(0x1F83D9ABFB41BD6B);
        ctx->state[7] = UL64(0x5BE0CD19137E2179);
    }
    else
    {
        /* SHA-384 */
        ctx->state[0] = UL64(0xCBBB9D5DC1059ED8);
        ctx->state[1] = UL64(0x629A292A367CD507);
        ctx->state[2] = UL64(0x9159015A3070DD17);
        ctx->state[3] = UL64(0x152FECD8F70E5939);
        ctx->state[4] = UL64(0x67332667FFC00B31);
        ctx->state[5] = UL64(0x8EB44A8768581511);
        ctx->state[6] = UL64(0xDB0C2E0D64F98FA7);
        ctx->state[7] = UL64(0x47B5481DBEFA4FA4);
    }

    ctx->is384 = is384;
}

static void sha512_process( sha512_context *ctx, const unsigned char data[128] )
{
    int i;
    uint64_t temp1, temp2, W[80];
    uint64_t A, B, C, D, E, F, G, H;

#define  SHR(x,n) (x >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (64 - n)))

#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^  SHR(x, 7))
#define S1(x) (ROTR(x,19) ^ ROTR(x,61) ^  SHR(x, 6))

#define S2(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define S3(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

    for( i = 0; i < 16; i++ )
    {
        GET_UINT64_BE( W[i], data, i << 3 );
    }

    for( ; i < 80; i++ )
    {
        W[i] = S1(W[i -  2]) + W[i -  7] +
               S0(W[i - 15]) + W[i - 16];
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
    i = 0;

    do
    {
        P( A, B, C, D, E, F, G, H, W[i], K[i] ); i++;
        P( H, A, B, C, D, E, F, G, W[i], K[i] ); i++;
        P( G, H, A, B, C, D, E, F, W[i], K[i] ); i++;
        P( F, G, H, A, B, C, D, E, W[i], K[i] ); i++;
        P( E, F, G, H, A, B, C, D, W[i], K[i] ); i++;
        P( D, E, F, G, H, A, B, C, W[i], K[i] ); i++;
        P( C, D, E, F, G, H, A, B, W[i], K[i] ); i++;
        P( B, C, D, E, F, G, H, A, W[i], K[i] ); i++;
    }
    while( i < 80 );

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

/*
 * SHA-512 process buffer
 */
static void sha512_update( sha512_context *ctx, const unsigned char *input,
                    size_t ilen )
{
    size_t fill;
    unsigned int left;

    if( ilen == 0 )
        return;

    left = (unsigned int) (ctx->total[0] & 0x7F);
    fill = 128 - left;

    ctx->total[0] += (uint64_t) ilen;

    if( ctx->total[0] < (uint64_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        sha512_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 128 )
    {
        sha512_process( ctx, input );
        input += 128;
        ilen  -= 128;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );
}

static const unsigned char sha512_padding[128] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-512 final digest
 */
static void sha512_finish( sha512_context *ctx, unsigned char output[64] )
{
    size_t last, padn;
    uint64_t high, low;
    unsigned char msglen[16];

    high = ( ctx->total[0] >> 61 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT64_BE( high, msglen, 0 );
    PUT_UINT64_BE( low,  msglen, 8 );

    last = (size_t)( ctx->total[0] & 0x7F );
    padn = ( last < 112 ) ? ( 112 - last ) : ( 240 - last );

    sha512_update( ctx, sha512_padding, padn );
    sha512_update( ctx, msglen, 16 );

    PUT_UINT64_BE( ctx->state[0], output,  0 );
    PUT_UINT64_BE( ctx->state[1], output,  8 );
    PUT_UINT64_BE( ctx->state[2], output, 16 );
    PUT_UINT64_BE( ctx->state[3], output, 24 );
    PUT_UINT64_BE( ctx->state[4], output, 32 );
    PUT_UINT64_BE( ctx->state[5], output, 40 );

    if( ctx->is384 == 0 )
    {
        PUT_UINT64_BE( ctx->state[6], output, 48 );
        PUT_UINT64_BE( ctx->state[7], output, 56 );
    }
}

#endif /* !POLARSSL_SHA512_ALT */

/*
 * output = SHA-512( input buffer )
 */
static void sha512( const unsigned char *input, size_t ilen,
             unsigned char output[64], int is384 )
{
    sha512_context ctx;

    sha512_init( &ctx );
    sha512_starts( &ctx, is384 );
    sha512_update( &ctx, input, ilen );
    sha512_finish( &ctx, output );
    sha512_free( &ctx );
}

#if defined(POLARSSL_FS_IO)
/*
 * output = SHA-512( file contents )
 */
static int sha512_file( const char *path, unsigned char output[64], int is384 )
{
    FILE *f;
    size_t n;
    sha512_context ctx;
    unsigned char buf[1024];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( POLARSSL_ERR_SHA512_FILE_IO_ERROR );

    sha512_init( &ctx );
    sha512_starts( &ctx, is384 );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        sha512_update( &ctx, buf, n );

    sha512_finish( &ctx, output );
    sha512_free( &ctx );

    if( ferror( f ) != 0 )
    {
        fclose( f );
        return( POLARSSL_ERR_SHA512_FILE_IO_ERROR );
    }

    fclose( f );
    return( 0 );
}
#endif /* POLARSSL_FS_IO */

/*
 * SHA-512 HMAC context setup
 */
static void sha512_hmac_starts( sha512_context *ctx, const unsigned char *key,
                         size_t keylen, int is384 )
{
    size_t i;
    unsigned char sum[64];

    if( keylen > 128 )
    {
        sha512( key, keylen, sum, is384 );
        keylen = ( is384 ) ? 48 : 64;
        key = sum;
    }

    memset( ctx->ipad, 0x36, 128 );
    memset( ctx->opad, 0x5C, 128 );

    for( i = 0; i < keylen; i++ )
    {
        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
    }

    sha512_starts( ctx, is384 );
    sha512_update( ctx, ctx->ipad, 128 );

    polarssl_zeroize( sum, sizeof( sum ) );
}

/*
 * SHA-512 HMAC process buffer
 */
static void sha512_hmac_update( sha512_context  *ctx,
                         const unsigned char *input, size_t ilen )
{
    sha512_update( ctx, input, ilen );
}

/*
 * SHA-512 HMAC final digest
 */
static void sha512_hmac_finish( sha512_context *ctx, unsigned char output[64] )
{
    int is384, hlen;
    unsigned char tmpbuf[64];

    is384 = ctx->is384;
    hlen = ( is384 == 0 ) ? 64 : 48;

    sha512_finish( ctx, tmpbuf );
    sha512_starts( ctx, is384 );
    sha512_update( ctx, ctx->opad, 128 );
    sha512_update( ctx, tmpbuf, hlen );
    sha512_finish( ctx, output );

    polarssl_zeroize( tmpbuf, sizeof( tmpbuf ) );
}

/*
 * SHA-512 HMAC context reset
 */
static void sha512_hmac_reset( sha512_context *ctx )
{
    sha512_starts( ctx, ctx->is384 );
    sha512_update( ctx, ctx->ipad, 128 );
}

/*
 * output = HMAC-SHA-512( hmac key, input buffer )
 */
static void sha512_hmac( const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char output[64], int is384 )
{
    sha512_context ctx;

    sha512_init( &ctx );
    sha512_hmac_starts( &ctx, key, keylen, is384 );
    sha512_hmac_update( &ctx, input, ilen );
    sha512_hmac_finish( &ctx, output );
    sha512_free( &ctx );
}

#if defined(POLARSSL_SELF_TEST)

/*
 * FIPS-180-2 test vectors
 */
static unsigned char sha512_test_buf[3][113] =
{
    { "abc" },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" },
    { "" }
};

static const int sha512_test_buflen[3] =
{
    3, 112, 1000
};

static const unsigned char sha512_test_sum[6][64] =
{
    /*
     * SHA-384 test vectors
     */
    { 0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
      0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
      0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
      0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
      0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
      0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7 },
    { 0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8,
      0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B, 0x47,
      0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
      0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12,
      0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9,
      0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39 },
    { 0x9D, 0x0E, 0x18, 0x09, 0x71, 0x64, 0x74, 0xCB,
      0x08, 0x6E, 0x83, 0x4E, 0x31, 0x0A, 0x4A, 0x1C,
      0xED, 0x14, 0x9E, 0x9C, 0x00, 0xF2, 0x48, 0x52,
      0x79, 0x72, 0xCE, 0xC5, 0x70, 0x4C, 0x2A, 0x5B,
      0x07, 0xB8, 0xB3, 0xDC, 0x38, 0xEC, 0xC4, 0xEB,
      0xAE, 0x97, 0xDD, 0xD8, 0x7F, 0x3D, 0x89, 0x85 },

    /*
     * SHA-512 test vectors
     */
    { 0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
      0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
      0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
      0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
      0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
      0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
      0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
      0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F },
    { 0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
      0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
      0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
      0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
      0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
      0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
      0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
      0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09 },
    { 0xE7, 0x18, 0x48, 0x3D, 0x0C, 0xE7, 0x69, 0x64,
      0x4E, 0x2E, 0x42, 0xC7, 0xBC, 0x15, 0xB4, 0x63,
      0x8E, 0x1F, 0x98, 0xB1, 0x3B, 0x20, 0x44, 0x28,
      0x56, 0x32, 0xA8, 0x03, 0xAF, 0xA9, 0x73, 0xEB,
      0xDE, 0x0F, 0xF2, 0x44, 0x87, 0x7E, 0xA6, 0x0A,
      0x4C, 0xB0, 0x43, 0x2C, 0xE5, 0x77, 0xC3, 0x1B,
      0xEB, 0x00, 0x9C, 0x5C, 0x2C, 0x49, 0xAA, 0x2E,
      0x4E, 0xAD, 0xB2, 0x17, 0xAD, 0x8C, 0xC0, 0x9B }
};

/*
 * RFC 4231 test vectors
 */
static unsigned char sha512_hmac_test_key[7][26] =
{
    { "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
      "\x0B\x0B\x0B\x0B" },
    { "Jefe" },
    { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
      "\xAA\xAA\xAA\xAA" },
    { "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
      "\x11\x12\x13\x14\x15\x16\x17\x18\x19" },
    { "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
      "\x0C\x0C\x0C\x0C" },
    { "" }, /* 0xAA 131 times */
    { "" }
};

static const int sha512_hmac_test_keylen[7] =
{
    20, 4, 20, 25, 20, 131, 131
};

static unsigned char sha512_hmac_test_buf[7][153] =
{
    { "Hi There" },
    { "what do ya want for nothing?" },
    { "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD" },
    { "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD" },
    { "Test With Truncation" },
    { "Test Using Larger Than Block-Size Key - Hash Key First" },
    { "This is a test using a larger than block-size key "
      "and a larger than block-size data. The key needs to "
      "be hashed before being used by the HMAC algorithm." }
};

static const int sha512_hmac_test_buflen[7] =
{
    8, 28, 50, 50, 20, 54, 152
};

static const unsigned char sha512_hmac_test_sum[14][64] =
{
    /*
     * HMAC-SHA-384 test vectors
     */
    { 0xAF, 0xD0, 0x39, 0x44, 0xD8, 0x48, 0x95, 0x62,
      0x6B, 0x08, 0x25, 0xF4, 0xAB, 0x46, 0x90, 0x7F,
      0x15, 0xF9, 0xDA, 0xDB, 0xE4, 0x10, 0x1E, 0xC6,
      0x82, 0xAA, 0x03, 0x4C, 0x7C, 0xEB, 0xC5, 0x9C,
      0xFA, 0xEA, 0x9E, 0xA9, 0x07, 0x6E, 0xDE, 0x7F,
      0x4A, 0xF1, 0x52, 0xE8, 0xB2, 0xFA, 0x9C, 0xB6 },
    { 0xAF, 0x45, 0xD2, 0xE3, 0x76, 0x48, 0x40, 0x31,
      0x61, 0x7F, 0x78, 0xD2, 0xB5, 0x8A, 0x6B, 0x1B,
      0x9C, 0x7E, 0xF4, 0x64, 0xF5, 0xA0, 0x1B, 0x47,
      0xE4, 0x2E, 0xC3, 0x73, 0x63, 0x22, 0x44, 0x5E,
      0x8E, 0x22, 0x40, 0xCA, 0x5E, 0x69, 0xE2, 0xC7,
      0x8B, 0x32, 0x39, 0xEC, 0xFA, 0xB2, 0x16, 0x49 },
    { 0x88, 0x06, 0x26, 0x08, 0xD3, 0xE6, 0xAD, 0x8A,
      0x0A, 0xA2, 0xAC, 0xE0, 0x14, 0xC8, 0xA8, 0x6F,
      0x0A, 0xA6, 0x35, 0xD9, 0x47, 0xAC, 0x9F, 0xEB,
      0xE8, 0x3E, 0xF4, 0xE5, 0x59, 0x66, 0x14, 0x4B,
      0x2A, 0x5A, 0xB3, 0x9D, 0xC1, 0x38, 0x14, 0xB9,
      0x4E, 0x3A, 0xB6, 0xE1, 0x01, 0xA3, 0x4F, 0x27 },
    { 0x3E, 0x8A, 0x69, 0xB7, 0x78, 0x3C, 0x25, 0x85,
      0x19, 0x33, 0xAB, 0x62, 0x90, 0xAF, 0x6C, 0xA7,
      0x7A, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9C,
      0xC5, 0x57, 0x7C, 0x6E, 0x1F, 0x57, 0x3B, 0x4E,
      0x68, 0x01, 0xDD, 0x23, 0xC4, 0xA7, 0xD6, 0x79,
      0xCC, 0xF8, 0xA3, 0x86, 0xC6, 0x74, 0xCF, 0xFB },
    { 0x3A, 0xBF, 0x34, 0xC3, 0x50, 0x3B, 0x2A, 0x23,
      0xA4, 0x6E, 0xFC, 0x61, 0x9B, 0xAE, 0xF8, 0x97 },
    { 0x4E, 0xCE, 0x08, 0x44, 0x85, 0x81, 0x3E, 0x90,
      0x88, 0xD2, 0xC6, 0x3A, 0x04, 0x1B, 0xC5, 0xB4,
      0x4F, 0x9E, 0xF1, 0x01, 0x2A, 0x2B, 0x58, 0x8F,
      0x3C, 0xD1, 0x1F, 0x05, 0x03, 0x3A, 0xC4, 0xC6,
      0x0C, 0x2E, 0xF6, 0xAB, 0x40, 0x30, 0xFE, 0x82,
      0x96, 0x24, 0x8D, 0xF1, 0x63, 0xF4, 0x49, 0x52 },
    { 0x66, 0x17, 0x17, 0x8E, 0x94, 0x1F, 0x02, 0x0D,
      0x35, 0x1E, 0x2F, 0x25, 0x4E, 0x8F, 0xD3, 0x2C,
      0x60, 0x24, 0x20, 0xFE, 0xB0, 0xB8, 0xFB, 0x9A,
      0xDC, 0xCE, 0xBB, 0x82, 0x46, 0x1E, 0x99, 0xC5,
      0xA6, 0x78, 0xCC, 0x31, 0xE7, 0x99, 0x17, 0x6D,
      0x38, 0x60, 0xE6, 0x11, 0x0C, 0x46, 0x52, 0x3E },

    /*
     * HMAC-SHA-512 test vectors
     */
    { 0x87, 0xAA, 0x7C, 0xDE, 0xA5, 0xEF, 0x61, 0x9D,
      0x4F, 0xF0, 0xB4, 0x24, 0x1A, 0x1D, 0x6C, 0xB0,
      0x23, 0x79, 0xF4, 0xE2, 0xCE, 0x4E, 0xC2, 0x78,
      0x7A, 0xD0, 0xB3, 0x05, 0x45, 0xE1, 0x7C, 0xDE,
      0xDA, 0xA8, 0x33, 0xB7, 0xD6, 0xB8, 0xA7, 0x02,
      0x03, 0x8B, 0x27, 0x4E, 0xAE, 0xA3, 0xF4, 0xE4,
      0xBE, 0x9D, 0x91, 0x4E, 0xEB, 0x61, 0xF1, 0x70,
      0x2E, 0x69, 0x6C, 0x20, 0x3A, 0x12, 0x68, 0x54 },
    { 0x16, 0x4B, 0x7A, 0x7B, 0xFC, 0xF8, 0x19, 0xE2,
      0xE3, 0x95, 0xFB, 0xE7, 0x3B, 0x56, 0xE0, 0xA3,
      0x87, 0xBD, 0x64, 0x22, 0x2E, 0x83, 0x1F, 0xD6,
      0x10, 0x27, 0x0C, 0xD7, 0xEA, 0x25, 0x05, 0x54,
      0x97, 0x58, 0xBF, 0x75, 0xC0, 0x5A, 0x99, 0x4A,
      0x6D, 0x03, 0x4F, 0x65, 0xF8, 0xF0, 0xE6, 0xFD,
      0xCA, 0xEA, 0xB1, 0xA3, 0x4D, 0x4A, 0x6B, 0x4B,
      0x63, 0x6E, 0x07, 0x0A, 0x38, 0xBC, 0xE7, 0x37 },
    { 0xFA, 0x73, 0xB0, 0x08, 0x9D, 0x56, 0xA2, 0x84,
      0xEF, 0xB0, 0xF0, 0x75, 0x6C, 0x89, 0x0B, 0xE9,
      0xB1, 0xB5, 0xDB, 0xDD, 0x8E, 0xE8, 0x1A, 0x36,
      0x55, 0xF8, 0x3E, 0x33, 0xB2, 0x27, 0x9D, 0x39,
      0xBF, 0x3E, 0x84, 0x82, 0x79, 0xA7, 0x22, 0xC8,
      0x06, 0xB4, 0x85, 0xA4, 0x7E, 0x67, 0xC8, 0x07,
      0xB9, 0x46, 0xA3, 0x37, 0xBE, 0xE8, 0x94, 0x26,
      0x74, 0x27, 0x88, 0x59, 0xE1, 0x32, 0x92, 0xFB },
    { 0xB0, 0xBA, 0x46, 0x56, 0x37, 0x45, 0x8C, 0x69,
      0x90, 0xE5, 0xA8, 0xC5, 0xF6, 0x1D, 0x4A, 0xF7,
      0xE5, 0x76, 0xD9, 0x7F, 0xF9, 0x4B, 0x87, 0x2D,
      0xE7, 0x6F, 0x80, 0x50, 0x36, 0x1E, 0xE3, 0xDB,
      0xA9, 0x1C, 0xA5, 0xC1, 0x1A, 0xA2, 0x5E, 0xB4,
      0xD6, 0x79, 0x27, 0x5C, 0xC5, 0x78, 0x80, 0x63,
      0xA5, 0xF1, 0x97, 0x41, 0x12, 0x0C, 0x4F, 0x2D,
      0xE2, 0xAD, 0xEB, 0xEB, 0x10, 0xA2, 0x98, 0xDD },
    { 0x41, 0x5F, 0xAD, 0x62, 0x71, 0x58, 0x0A, 0x53,
      0x1D, 0x41, 0x79, 0xBC, 0x89, 0x1D, 0x87, 0xA6 },
    { 0x80, 0xB2, 0x42, 0x63, 0xC7, 0xC1, 0xA3, 0xEB,
      0xB7, 0x14, 0x93, 0xC1, 0xDD, 0x7B, 0xE8, 0xB4,
      0x9B, 0x46, 0xD1, 0xF4, 0x1B, 0x4A, 0xEE, 0xC1,
      0x12, 0x1B, 0x01, 0x37, 0x83, 0xF8, 0xF3, 0x52,
      0x6B, 0x56, 0xD0, 0x37, 0xE0, 0x5F, 0x25, 0x98,
      0xBD, 0x0F, 0xD2, 0x21, 0x5D, 0x6A, 0x1E, 0x52,
      0x95, 0xE6, 0x4F, 0x73, 0xF6, 0x3F, 0x0A, 0xEC,
      0x8B, 0x91, 0x5A, 0x98, 0x5D, 0x78, 0x65, 0x98 },
    { 0xE3, 0x7B, 0x6A, 0x77, 0x5D, 0xC8, 0x7D, 0xBA,
      0xA4, 0xDF, 0xA9, 0xF9, 0x6E, 0x5E, 0x3F, 0xFD,
      0xDE, 0xBD, 0x71, 0xF8, 0x86, 0x72, 0x89, 0x86,
      0x5D, 0xF5, 0xA3, 0x2D, 0x20, 0xCD, 0xC9, 0x44,
      0xB6, 0x02, 0x2C, 0xAC, 0x3C, 0x49, 0x82, 0xB1,
      0x0D, 0x5E, 0xEB, 0x55, 0xC3, 0xE4, 0xDE, 0x15,
      0x13, 0x46, 0x76, 0xFB, 0x6D, 0xE0, 0x44, 0x60,
      0x65, 0xC9, 0x74, 0x40, 0xFA, 0x8C, 0x6A, 0x58 }
};

/*
 * Checkup routine
 */
static int sha512_self_test( int verbose )
{
    int i, j, k, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sha512sum[64];
    sha512_context ctx;

    sha512_init( &ctx );

    for( i = 0; i < 6; i++ )
    {
        j = i % 3;
        k = i < 3;

        if( verbose != 0 )
            polarssl_printf( "  SHA-%d test #%d: ", 512 - k * 128, j + 1 );

        sha512_starts( &ctx, k );

        if( j == 2 )
        {
            memset( buf, 'a', buflen = 1000 );

            for( j = 0; j < 1000; j++ )
                sha512_update( &ctx, buf, buflen );
        }
        else
            sha512_update( &ctx, sha512_test_buf[j],
                                 sha512_test_buflen[j] );

        sha512_finish( &ctx, sha512sum );

        if( memcmp( sha512sum, sha512_test_sum[i], 64 - k * 16 ) != 0 )
        {
            if( verbose != 0 )
                polarssl_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            polarssl_printf( "passed\n" );
    }

    if( verbose != 0 )
        polarssl_printf( "\n" );

    for( i = 0; i < 14; i++ )
    {
        j = i % 7;
        k = i < 7;

        if( verbose != 0 )
            polarssl_printf( "  HMAC-SHA-%d test #%d: ", 512 - k * 128, j + 1 );

        if( j == 5 || j == 6 )
        {
            memset( buf, '\xAA', buflen = 131 );
            sha512_hmac_starts( &ctx, buf, buflen, k );
        }
        else
            sha512_hmac_starts( &ctx, sha512_hmac_test_key[j],
                                      sha512_hmac_test_keylen[j], k );

        sha512_hmac_update( &ctx, sha512_hmac_test_buf[j],
                                  sha512_hmac_test_buflen[j] );

        sha512_hmac_finish( &ctx, sha512sum );

        buflen = ( j == 4 ) ? 16 : 64 - k * 16;

        if( memcmp( sha512sum, sha512_hmac_test_sum[i], buflen ) != 0 )
        {
            if( verbose != 0 )
                polarssl_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            polarssl_printf( "passed\n" );
    }

    if( verbose != 0 )
        polarssl_printf( "\n" );

exit:
    sha512_free( &ctx );

    return( ret );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_SHA512_C */
/*
 *  Portable interface to the CPU cycle counter
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your soption) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
//#include "polarssl/config.h"
#else
//#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_SELF_TEST) && defined(POLARSSL_PLATFORM_C)
//#include "polarssl/platform.h"
#else
#include <stdio.h>
#define polarssl_printf     printf
#endif

#if defined(POLARSSL_TIMING_C) && !defined(POLARSSL_TIMING_ALT)

//#include "polarssl/timing.h"

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#include <windows.h>
#include <winbase.h>

struct _hr_time
{
    LARGE_INTEGER start;
};

#else

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>

struct _hr_time
{
    struct timeval start;
};

#endif /* _WIN32 && !EFIX64 && !EFI32 */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&  \
    ( defined(_MSC_VER) && defined(_M_IX86) ) || defined(__WATCOMC__)

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long tsc;
    __asm   rdtsc
    __asm   mov  [tsc], eax
    return( tsc );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          ( _MSC_VER && _M_IX86 ) || __WATCOMC__ */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__i386__)

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long lo, hi;
    asm volatile( "rdtsc" : "=a" (lo), "=d" (hi) );
    return( lo );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          __GNUC__ && __i386__ */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&  \
    defined(__GNUC__) && ( defined(__amd64__) || defined(__x86_64__) )

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long lo, hi;
    asm volatile( "rdtsc" : "=a" (lo), "=d" (hi) );
    return( lo | ( hi << 32 ) );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          __GNUC__ && ( __amd64__ || __x86_64__ ) */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&  \
    defined(__GNUC__) && ( defined(__powerpc__) || defined(__ppc__) )

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long tbl, tbu0, tbu1;

    do
    {
        asm volatile( "mftbu %0" : "=r" (tbu0) );
        asm volatile( "mftb  %0" : "=r" (tbl ) );
        asm volatile( "mftbu %0" : "=r" (tbu1) );
    }
    while( tbu0 != tbu1 );

    return( tbl );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          __GNUC__ && ( __powerpc__ || __ppc__ ) */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc64__)

#if defined(__OpenBSD__)
#warning OpenBSD does not allow access to tick register using software version instead
#else
#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long tick;
    asm volatile( "rdpr %%tick, %0;" : "=&r" (tick) );
    return( tick );
}
#endif /* __OpenBSD__ */
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          __GNUC__ && __sparc64__ */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc__) && !defined(__sparc64__)

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long tick;
    asm volatile( ".byte 0x83, 0x41, 0x00, 0x00" );
    asm volatile( "mov   %%g1, %0" : "=r" (tick) );
    return( tick );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          __GNUC__ && __sparc__ && !__sparc64__ */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__alpha__)

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long cc;
    asm volatile( "rpcc %0" : "=r" (cc) );
    return( cc & 0xFFFFFFFF );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          __GNUC__ && __alpha__ */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(POLARSSL_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__ia64__)

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    unsigned long itc;
    asm volatile( "mov %0 = ar.itc" : "=r" (itc) );
    return( itc );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && POLARSSL_HAVE_ASM &&
          __GNUC__ && __ia64__ */

#if !defined(POLARSSL_HAVE_HARDCLOCK) && defined(_MSC_VER) && \
    !defined(EFIX64) && !defined(EFI32)

#define POLARSSL_HAVE_HARDCLOCK

unsigned long hardclock( void )
{
    LARGE_INTEGER offset;

    QueryPerformanceCounter( &offset );

    return( (unsigned long)( offset.QuadPart ) );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK && _MSC_VER && !EFIX64 && !EFI32 */

#if !defined(POLARSSL_HAVE_HARDCLOCK)

#define POLARSSL_HAVE_HARDCLOCK

static int hardclock_init = 0;
static struct timeval tv_init;

unsigned long hardclock( void )
{
    struct timeval tv_cur;

    if( hardclock_init == 0 )
    {
        gettimeofday( &tv_init, NULL );
        hardclock_init = 1;
    }

    gettimeofday( &tv_cur, NULL );
    return( ( tv_cur.tv_sec  - tv_init.tv_sec  ) * 1000000
          + ( tv_cur.tv_usec - tv_init.tv_usec ) );
}
#endif /* !POLARSSL_HAVE_HARDCLOCK */

/*static volatile int alarmed = 0;*/

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

unsigned long get_timer( struct hr_time *val, int reset )
{
    unsigned long delta;
    LARGE_INTEGER offset, hfreq;
    struct _hr_time *t = (struct _hr_time *) val;

    QueryPerformanceCounter(  &offset );
    QueryPerformanceFrequency( &hfreq );

    delta = (unsigned long)( ( 1000 *
        ( offset.QuadPart - t->start.QuadPart ) ) /
           hfreq.QuadPart );

    if( reset )
        QueryPerformanceCounter( &t->start );

    return( delta );
}

DWORD WINAPI TimerProc( LPVOID uElapse )
{
    Sleep( (DWORD) uElapse );
    alarmed = 1;
    return( TRUE );
}

void set_alarm( int seconds )
{
    DWORD ThreadId;

    alarmed = 0;
    CloseHandle( CreateThread( NULL, 0, TimerProc,
        (LPVOID) ( seconds * 1000 ), 0, &ThreadId ) );
}

void m_sleep( int milliseconds )
{
    Sleep( milliseconds );
}

#else /* _WIN32 && !EFIX64 && !EFI32 */

unsigned long get_timer( struct hr_time *val, int reset )
{
    unsigned long delta;
    struct timeval offset;
    struct _hr_time *t = (struct _hr_time *) val;

    gettimeofday( &offset, NULL );

    if( reset )
    {
        t->start.tv_sec  = offset.tv_sec;
        t->start.tv_usec = offset.tv_usec;
        return( 0 );
    }

    delta = ( offset.tv_sec  - t->start.tv_sec  ) * 1000
          + ( offset.tv_usec - t->start.tv_usec ) / 1000;

    return( delta );
}

#if defined(INTEGRITY)
void m_sleep( int milliseconds )
{
    usleep( milliseconds * 1000 );
}

#else /* INTEGRITY */

static void sighandler( int signum )
{
    alarmed = 1;
    signal( signum, sighandler );
}

void set_alarm( int seconds )
{
    alarmed = 0;
    signal( SIGALRM, sighandler );
    alarm( seconds );
}

void m_sleep( int milliseconds )
{
    struct timeval tv;

    tv.tv_sec  = milliseconds / 1000;
    tv.tv_usec = ( milliseconds % 1000 ) * 1000;

    select( 0, NULL, NULL, NULL, &tv );
}
#endif /* INTEGRITY */

#endif /* _WIN32 && !EFIX64 && !EFI32 */

#if defined(POLARSSL_SELF_TEST)

/* To test net_usleep against our functions */
#if defined(POLARSSL_NET_C) && defined(POLARSSL_HAVE_TIME)
//#include "polarssl/net.h"
#endif

/*
 * Busy-waits for the given number of milliseconds.
 * Used for testing hardclock.
 */
static void busy_msleep( unsigned long msec )
{
    struct hr_time hires;
    unsigned long i = 0; /* for busy-waiting */
    volatile unsigned long j; /* to prevent optimisation */

    (void) get_timer( &hires, 1 );

    while( get_timer( &hires, 0 ) < msec )
        i++;

    j = i;
    (void) j;
}

/*
 * Checkup routine
 *
 * Warning: this is work in progress, some tests may not be reliable enough
 * yet! False positives may happen.
 */
int timing_self_test( int verbose )
{
    unsigned long cycles, ratio;
    unsigned long millisecs, secs;
    int hardfail;
    struct hr_time hires;

    if( verbose != 0 )
        polarssl_printf( "  TIMING tests note: will take some time!\n" );

    if( verbose != 0 )
        polarssl_printf( "  TIMING test #1 (m_sleep   / get_timer): " );

    for( secs = 1; secs <= 3; secs++ )
    {
        (void) get_timer( &hires, 1 );

        m_sleep( (int)( 500 * secs ) );

        millisecs = get_timer( &hires, 0 );

        if( millisecs < 450 * secs || millisecs > 550 * secs )
        {
            if( verbose != 0 )
                polarssl_printf( "failed\n" );

            return( 1 );
        }
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    if( verbose != 0 )
        polarssl_printf( "  TIMING test #2 (set_alarm / get_timer): " );

    for( secs = 1; secs <= 3; secs++ )
    {
        (void) get_timer( &hires, 1 );

        set_alarm( (int) secs );
        while( !alarmed )
            ;

        millisecs = get_timer( &hires, 0 );

        if( millisecs < 900 * secs || millisecs > 1100 * secs )
        {
            if( verbose != 0 )
                polarssl_printf( "failed\n" );

            return( 1 );
        }
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

    if( verbose != 0 )
        polarssl_printf( "  TIMING test #3 (hardclock / get_timer): " );

    /*
     * Allow one failure for possible counter wrapping.
     * On a 4Ghz 32-bit machine the cycle counter wraps about once per second;
     * since the whole test is about 10ms, it shouldn't happen twice in a row.
     */
    hardfail = 0;

hard_test:
    if( hardfail > 1 )
    {
        if( verbose != 0 )
            polarssl_printf( "failed\n" );

        return( 1 );
    }

    /* Get a reference ratio cycles/ms */
    millisecs = 1;
    cycles = hardclock();
    busy_msleep( millisecs );
    cycles = hardclock() - cycles;
    ratio = cycles / millisecs;

    /* Check that the ratio is mostly constant */
    for( millisecs = 2; millisecs <= 4; millisecs++ )
    {
        cycles = hardclock();
        busy_msleep( millisecs );
        cycles = hardclock() - cycles;

        /* Allow variation up to 20% */
        if( cycles / millisecs < ratio - ratio / 5 ||
            cycles / millisecs > ratio + ratio / 5 )
        {
            hardfail++;
            goto hard_test;
        }
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );

#if defined(POLARSSL_NET_C) && defined(POLARSSL_HAVE_TIME)
    if( verbose != 0 )
        polarssl_printf( "  TIMING test #4 (net_usleep/ get_timer): " );

    for( secs = 1; secs <= 3; secs++ )
    {
        (void) get_timer( &hires, 1 );

        net_usleep( 500000 * secs );

        millisecs = get_timer( &hires, 0 );

        if( millisecs < 450 * secs || millisecs > 550 * secs )
        {
            if( verbose != 0 )
                polarssl_printf( "failed\n" );

            return( 1 );
        }
    }

    if( verbose != 0 )
        polarssl_printf( "passed\n" );
#endif /* POLARSSL_NET_C */

    if( verbose != 0 )
        polarssl_printf( "\n" );

    return( 0 );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_TIMING_C && !POLARSSL_TIMING_ALT */

/**************************************************************************
 * 下面开始是封装好的函数接口的代码                                          
 ***************************************************************************/

#define RSA_INTERFACE_FOR_INTEGRATTION
#ifdef RSA_INTERFACE_FOR_INTEGRATTION
typedef struct{
	mpi N;
	mpi E;
} public_key;  // 公钥类型
typedef struct{
	mpi N;
	mpi E;
	mpi D;
	mpi P;
	mpi Q;
	mpi DP;
	mpi DQ;
	mpi QP;
}private_key;  // 私钥类型

static const int KEY_SIZE = 1024;
static const int EXPONENT = 65537;


/*
功能：
    将32位整数转成二进制形式，存到buf中。buf应该至少提供4字节的内存空间。
    整数的低字节填充到buf的低地址。
*/
static void uint32tob(uint32_t i, void *buf)
{
    unsigned char *p = (unsigned char*)buf;

    p[0] = (unsigned char)( i & 0xff );
    p[1] = (unsigned char)( (i >> 8) & 0xff );
    p[2] = (unsigned char)( (i >> 16) & 0xff );
    p[3] = (unsigned char)( (i >> 24) & 0xff );
}

static void btouint32(uint32_t *pi, const void *buf)
{
    const unsigned char * p = (unsigned char*)buf;
    uint32_t i = 0;

    i = i | p[0];
    i = (i << 8) | p[1];
    i = (i << 8) | p[2];
    i = (i << 8) | p[3];
    
    *pi = i;
}


/*
    定义该宏表示使用固定大小存储大整数（mpi类型），目前的约定是KEYSIZE/8，即折算成字节数的密钥大小；
    该宏定义影响encode_mpi_to_buffer()/decode_mpi_from_buffer()两个函数的行为。如果不定义该宏，
    即不使用固定大小来存储大整数，那么会在每个大整数存储区域之前增加32bit整数表示该大整数存储区域的
    大小。
*/
#define WRITE_MPI_USING_FIXED_SIZE  

static void encode_mpi_to_buffer(const mpi *X, void *buf, size_t *buflen)
{
    size_t len = 0;
    unsigned char *pbin = (unsigned char*)buf;
    

#ifdef  WRITE_MPI_USING_FIXED_SIZE  
    mpi_write_binary(X, (unsigned char*)buf, KEY_SIZE/8);
    *buflen = KEY_SIZE/8;
#else
    uint32_t size; // 大整数字节数
    size = (uint32_t)mpi_size(X);
    uint32tob(size, pbin + len);
    len += 4;
    mpi_write_binary(X, pbin + len, size);
    len += size;

    *buflen = len;
#endif
}

static void decode_mpi_from_buffer(mpi *X, const void * buf, size_t *usedlen)
{
    size_t len = 0;
    const unsigned char * pbin = (unsigned char *)buf;


    mpi_init(X);  // 写大整数的内存之前初始化

#ifdef WRITE_MPI_USING_FIXED_SIZE
    mpi_read_binary(X, (unsigned char *)buf, KEY_SIZE / 8);
    *usedlen = KEY_SIZE/8;
#else
    uint32_t size;   // 大整数字节数
    btouint32(&size, pbin+len);
    len += 4;

    mpi_read_binary(X, pbin + len, size);
    len += size;

    *usedlen = len;
#endif
}

/*
功能：将密钥转成一片整体的二进制内存存储区域
参数：
    key: 指向密钥数据结构的指针
    buf: 存放转换结果的内存区域指针
    mode: 是转公钥还是私钥。
        RSA_PUBLIC：公钥
        RSA_PRIVATE：私钥
返回值：
    成功返回0；出错返回非零值
*/
static void key2binary(void* key, void* buf, int *buf_len, int mode)
{
    size_t len = 0;
    unsigned char *pbin = (unsigned char *)buf;
    size_t i1 = 0; // 大整数字节数

    if (mode == RSA_PUBLIC)  // 转换公钥
    {
        public_key *pubk = (public_key*)key;
        
        
        encode_mpi_to_buffer(&pubk->N, pbin+len, &i1);
        len += i1;
      

        encode_mpi_to_buffer(&pubk->E, pbin+len, &i1);
        len += i1;

        *buf_len = (int)len;
    }
    else  // 否则视作是私钥
    {
        private_key *privk = (private_key*)key;

        encode_mpi_to_buffer(&privk->N, pbin + len, &i1);
        len += i1;

        encode_mpi_to_buffer(&privk->E, pbin + len, &i1);
        len += i1;

        encode_mpi_to_buffer(&privk->D, pbin + len, &i1);
        len += i1;

        encode_mpi_to_buffer(&privk->P, pbin + len, &i1);
        len += i1;

        encode_mpi_to_buffer(&privk->Q, pbin + len, &i1);
        len += i1;

        encode_mpi_to_buffer(&privk->DP, pbin + len, &i1);
        len += i1;

        encode_mpi_to_buffer(&privk->DQ, pbin + len, &i1);
        len += i1;

        encode_mpi_to_buffer(&privk->QP, pbin + len, &i1);
        len += i1;

        *buf_len = (int)len;
    }
}


static void binary2key(void* key, void* buf, int *used_len, int mode)
{
    size_t len = 0;
    const unsigned char *pbin = (unsigned char *)buf;
    size_t i1 = 0; // 大整数字节数

    if (mode == RSA_PUBLIC)  // 转换公钥
    {
        public_key *pubk = (public_key*)key;


        decode_mpi_from_buffer(&pubk->N, pbin + len, &i1);
        len += i1;


        decode_mpi_from_buffer(&pubk->E, pbin + len, &i1);
        len += i1;

        *used_len = (int)len;
    }
    else  // 否则视作是私钥
    {
        private_key *privk = (private_key*)key;

        decode_mpi_from_buffer(&privk->N, pbin + len, &i1);
        len += i1;

        decode_mpi_from_buffer(&privk->E, pbin + len, &i1);
        len += i1;

        decode_mpi_from_buffer(&privk->D, pbin + len, &i1);
        len += i1;

        decode_mpi_from_buffer(&privk->P, pbin + len, &i1);
        len += i1;

        decode_mpi_from_buffer(&privk->Q, pbin + len, &i1);
        len += i1;

        decode_mpi_from_buffer(&privk->DP, pbin + len, &i1);
        len += i1;

        decode_mpi_from_buffer(&privk->DQ, pbin + len, &i1);
        len += i1;

        decode_mpi_from_buffer(&privk->QP, pbin + len, &i1);
        len += i1;

        *used_len = (int)len;
    }
}


/**
功能: 生成一对RSA算法使用的公钥/密钥（KEYSIZE约定为1024，单位是bit）。调用者提供足够
      的内存空间存放密钥。
原理: 公钥实际上由2个大整数组成，私钥包括8个大整数；每个大整数的二进制位数不超过KEYSIZE，
      但约定按照KEYSIZE位存储，长度不足则再高位用0-bit进行填充；
      所以私钥的大小折算成字节数是KEYSIZE（8*KEYSIZE个bit），公钥的大小折算成字节数是
      KEYSIZE/4（2*KEYSIZE个bit）
参数:
	priv_buf:  存放所生成的私钥（以二进制的形式）；内存空间的大小至少是KEYSIZE个字节；
	priv_len:  私钥存储后实际所占内存长度；
	pub_buf:   存放所生成的公钥（以二进制的形式）；内存空间的大小至少是KEYSIZE/4个字节
	pub_len:   公钥所占内存区域长度
返回值:
	成功生成，返回0; 
	如果返回值非0，表示出错
*/
static int rsa_gen_keypair(void *priv_buf, int *priv_len, void *pub_buf, int *pub_len)
{
	int ret;
	rsa_context rsa;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	const char *pers = "rsa_genkey";


	entropy_init(&entropy);
	if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		//printf(" failed\n  ! ctr_drbg_init returned %d\n", ret);
		goto exit;
	}

	rsa_init(&rsa, RSA_PKCS_V15, 0);

	if ((ret = rsa_gen_key(&rsa, ctr_drbg_random, &ctr_drbg, KEY_SIZE,
		EXPONENT)) != 0)
	{
		//printf(" failed\n  ! rsa_gen_key returned %d\n\n", ret);
		goto exit;
	}

	/* set public key */
    public_key pubk;
	pubk.N = rsa.N;
	pubk.E = rsa.E;
    key2binary(&pubk, pub_buf, pub_len, RSA_PUBLIC);



	/* set private key */
    private_key privk;
	privk.N = rsa.N;
	privk.E = rsa.E;
	privk.D = rsa.D;
	privk.P = rsa.P;
	privk.Q = rsa.Q;
	privk.DP = rsa.DP;
	privk.DQ = rsa.DQ;
	privk.QP = rsa.QP;
    key2binary(&privk, priv_buf, priv_len, RSA_PRIVATE);
	

exit:

	rsa_free(&rsa);  // 大整数的内容存储区通过该函数释放
	ctr_drbg_free(&ctr_drbg);
	entropy_free(&entropy);

	return ret;

}

/*
功能：
    根据加密所用密钥和输入的明文长度估计密文的长度，以确定需要为输出
    缓冲区预留的空间大小。
原理：
    从密钥解出大整数N（RSA算法中的模），然后N的大小（字节数）即是密文（块）的长度；
    由密文块长度减去11可得最大明文块长度，之后从明文总的输入大小，得到明文分块的块数，
    以之乘以密文块的长度，即可出密文的总体长度。
参数：
    key:    存放密钥的内存区域
    plaintext_len:  明文长度
返回值：
    计算得到的密文总体长度。分配缓冲区时，可以这个为参考，适当增加一点（比如16字节）即可。
*/
int estimate_ciphertext_size(void *key, int plaintext_len)
{
    mpi N;
    size_t used_len = 0;

    int block_ciph_len = 0;  // 分块情况下每块密文的长度（字符数）
    int block_plain_len = 0; // 分块情况下每块明文的长度（字符数）

    int ciphertext_len = 0;
    
    decode_mpi_from_buffer(&N, key, &used_len);

    block_ciph_len = (int)mpi_size(&N);
    block_plain_len = block_ciph_len - 11;

    ciphertext_len = block_ciph_len * (plaintext_len / block_plain_len + ((plaintext_len%block_plain_len) ? 1 : 0));

    return ciphertext_len;

}

/*
功能：
    根据密钥，返回明文和密文的分块后的最大长度；
参数：
    key:  提供的密钥
    plaintext_max_block_size: 
          分块后明文的最大长度；
          传入一个整型指针，为NULL则表示不需要获取该长度；
    ciphertext_max_block_size: 
          一个明文块加密后密文的长度
          传入一个整型指针，为NULL则表示不需要获取该长度；
*/
void get_block_size_from_key(void *key, int *plaintext_max_block_size, int *ciphertext_max_block_size)
{
    int *pbs = plaintext_max_block_size;
    int *cbs = ciphertext_max_block_size;

    mpi N;
    size_t used_len = 0;

    decode_mpi_from_buffer(&N, key, &used_len);

    *cbs = (int)mpi_size(&N);
    *pbs = *cbs - 11;
}


/**
功能：
    将加解密所用的密钥设置到rsa_context中。
    rsa_context中大整数和len被设置。
*/
static void set_rsa_key(void *key, rsa_context * rsa, int mode)
{
    /* set key */
    if (mode == RSA_PUBLIC)
    {
        //public_key *pubk = key;
        public_key pubk;
        int len = 0;

        binary2key(&pubk, key, &len, RSA_PUBLIC);
        rsa->N = pubk.N;
        rsa->E = pubk.E;
    }
    else // 视作私钥
    {
        //private_key *privk = key;
        private_key privk;
        int len = 0;

        binary2key(&privk, key, &len, RSA_PRIVATE);

        rsa->N = privk.N;
        rsa->E = privk.E;
        rsa->D = privk.D;
        rsa->P = privk.P;
        rsa->Q = privk.Q;
        rsa->DP = privk.DP;
        rsa->DQ = privk.DQ;
        rsa->QP = privk.QP;
    } 

    rsa->len = (mpi_msb(&rsa->N) + 7) >> 3;
}

/*
功能：具体执行加密运算的函数
参数：
	mode: 表示加密进行的模式，即以公钥加密还是以私钥加密
	其他参数见下面调用它的包装函数。
返回值：
	成功返回0；
	出错返回非零值
*/
static int rsa_encrypt(void *key, int mode, const unsigned char *input, int input_len, unsigned char *output_buf, int *output_len)
{
	int ret = 1;
	rsa_context rsa;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	//size_t i;
	//unsigned char input[1024];
	//unsigned char buf[512];
	const char *pers = "rsa_encrypt";


    int block_inlen = 0;   // 分块加密
    int block_outlen = 0;
    int nblocks;  // 块的数目
    

    int i;
 


	entropy_init(&entropy);
	if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		//printf(" failed\n  ! ctr_drbg_init returned %d\n", ret);
		goto exit;
	}

	rsa_init(&rsa, RSA_PKCS_V15, 0);

	/* set key */
    set_rsa_key(key, &rsa, mode);


	//rsa.len = (mpi_msb(&rsa.N) + 7) >> 3; // 实际上就是mpi_size(&rsa.N);

    block_inlen = (int)rsa.len - 11; // 分块的大小
    block_outlen = (int)rsa.len;

    nblocks = input_len / block_inlen + ((input_len%block_inlen) ? 1 : 0);

    *output_len = 0;

  
    for (i = 0; i < nblocks; i++)
    {
        int in_len;

        in_len = block_inlen;
        if (i == nblocks - 1) in_len = input_len - block_inlen*i;

	    if ((ret = rsa_pkcs1_encrypt(&rsa, ctr_drbg_random, &ctr_drbg,
		    mode, in_len,
            input + block_inlen*i, output_buf+*output_len)) != 0)
	    {
		    //printf(" failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret);
		    goto exit;
	    }

        *output_len += (int)rsa.len;
    }

	ret = 0;


exit:
	ctr_drbg_free(&ctr_drbg);
	entropy_free(&entropy);

	return ret;
}

/*
功能：使用私钥执行RSA算法的加密。
     存储密文的缓冲区由调用者提供，其大小可以在加密之前调用estimate_ciphertext_size()函数从密钥和输入大小获得。
     缓冲区的大小是保证能容纳密文，并非表示密文必定就是这么大。
参数：
	priv_key:   用来加密的私钥
	input:      明文，即加密算法的输入
	input_len:  明文的大小
	output:     存放密文的缓冲区
	output_len: 加密后得到的密文的长度，也即存入缓冲区的长度
返回值：
	成功返回0；
	出错返回非零值
*/
static int rsa_encrypt_private(void *priv_key, const unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
	return rsa_encrypt(priv_key, RSA_PRIVATE, input, input_len, output, output_len);
}

/*
功能：使用公钥执行RSA算法的加密。
     存储密文的缓冲区由调用者提供，其大小可以在加密之前调用estimate_ciphertext_size()函数从密钥和输入大小获得。
     缓冲区的大小是保证能容纳密文，并非表示密文必定就是这么大。
参数：
	priv_key:   用来加密的公钥
	input:      明文，即加密算法的输入
	input_len:  明文的大小
	output:     存放密文的缓冲区
	output_len: 加密后得到的密文的长度，也即存入缓冲区的长度
返回值：
	成功返回0；
	出错返回非零值
*/
static int rsa_encrypt_public(void *pub_key, const unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
	return rsa_encrypt(pub_key, RSA_PUBLIC, input, input_len, output, output_len);
}



/*
功能：具体执行解密运算的函数
参数：
	mode: 表示解密进行的模式，即以公钥解密还是以私钥解密
	其他参数见下面调用它的包装函数。
返回值：
	成功返回0；
	出错返回非零值
*/
static int rsa_decrypt(void *key, int mode, const unsigned char *input, int input_len, unsigned char *output_buf, int *output_len)
{
	int ret = 1;
    int i;
    size_t block_outlen = 0;
	int nblocks = 0;

	rsa_context rsa;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	const char *pers = "rsa_decrypt";


	entropy_init(&entropy);
	if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		//printf(" failed\n  ! ctr_drbg_init returned %d\n", ret);
		goto exit;
	}

	rsa_init(&rsa, RSA_PKCS_V15, 0);

	/* set the key */
    set_rsa_key(key, &rsa, mode);


	//rsa.len = (mpi_msb(&rsa.N) + 7) >> 3;

	//if (input_len != rsa.len)
    if (input_len%rsa.len != 0) //密文长度都是rsa.len，所以应该是它的整数倍
	{
		goto exit;
	}

    nblocks = (int)(input_len / rsa.len);
    *output_len = 0;

#if 0
    {
        enum{ MAX_BLOCK_OUTPUT_SIZE = 1024 };
        unsigned char result[MAX_BLOCK_OUTPUT_SIZE];
        for (i = 0; i < nblocks; i++)
        {
	        if ((ret = rsa_pkcs1_decrypt(&rsa, ctr_drbg_random, &ctr_drbg,
		        mode, &block_outlen, input+rsa.len*i, result,
                MAX_BLOCK_OUTPUT_SIZE)) != 0)
	        {
		        //printf(" failed\n  ! rsa_pkcs1_decrypt returned %d\n\n", ret);
		        goto exit;
	        }

            memcpy(output_buf+(*output_len), result, block_outlen);
            *output_len += block_outlen;
        }
    }
#else
    // 似乎无需再声明一个result作为中间的缓冲；此段为改进版本。
        for (i = 0; i < nblocks; i++)
        {
	        if ((ret = rsa_pkcs1_decrypt(&rsa, ctr_drbg_random, &ctr_drbg,
		        mode, &block_outlen, input+rsa.len*i, output_buf+*output_len,
                KEY_SIZE/8)) != 0)
	        {
		        //printf(" failed\n  ! rsa_pkcs1_decrypt returned %d\n\n", ret);
		        goto exit;
	        }

            //memcpy(output_buf+(*output_len), result, block_outlen);
            *output_len += (int)block_outlen;
        }
#endif


    




	ret = 0;

exit:
	ctr_drbg_free(&ctr_drbg);
	entropy_free(&entropy);


	return(ret);
}


/*
功能： 使用私钥执行RSA算法的解密。
       存放输出的明文的缓冲区由调用者提供，可以分配与密文同样的大小。
参数：
    priv_key:    用来解密的私钥
    input:       密文
    input_len:   密文的大小
    output:      存放明文的缓冲区
    output_len:  解密后得到的明文的长度，即实际存入到缓冲区的长度
返回值：
    成功返回0；
    出错返回非零值
*/
static int rsa_decrypt_private(void *priv_key, const unsigned char *input, int input_len, unsigned char *output_buf, int *output_len)
{
	return rsa_decrypt(priv_key, RSA_PRIVATE, input, input_len, output_buf, output_len);
}

/*
功能: 使用公钥执行RSA算法的解密。
      存放明文的缓冲区由调用者提供，可以分配与密文同样的大小。
参数：
    priv_key:   用来解密的公钥
    input:      密文
    input_len:  密文的大小
    output:     存放明文的缓冲区
    output_len: 解密后得到的明文的长度，即实际存入到缓冲区的长度
返回值：
    成功返回0；
    出错返回非零值
*/
static int rsa_decrypt_public(void *pub_key, const unsigned char *input, int input_len, unsigned char *output_buf, int *output_len)
{
	return rsa_decrypt(pub_key, RSA_PUBLIC, input, input_len, output_buf, output_len);
}



/*
功能:密钥buf与字符串互相转换
说明:
1.(RSA目前固定为1024bit密钥长度.)
2.私钥pByteSKey固定为128*8=1024byte(1024bit*8),公钥pBytePKeyy固定为128*2=256byte(1024bit*2)
3.pszStringSKey固定为128*8*2+1=2049byte(最后一个字节是字符串结束符),字母小写,pszStringPKey固定为128*2*2+1=513byte
4.返回转换之后的字节数
*/
static int rsa_skey_byte2string(const void * pByteSKey,char * pszStringSKey)
{
	return XtBytesToString(pByteSKey,RSA_SKEY_SIZE,pszStringSKey,true);
}
static int rsa_pkey_byte2string(const void * pBytePKey,char * pszStringPKey)
{
	return XtBytesToString(pBytePKey,RSA_PKEY_SIZE,pszStringPKey,true);
}
static int rsa_skey_string2byte(const char * pszStringSKey,void * pByteSKey)
{
	return XtStringToBytes(pszStringSKey,pByteSKey);
}
static int rsa_pkey_string2byte(const char * pszStringPKey,void * pBytePKey)
{
	return XtStringToBytes(pszStringPKey,pBytePKey);
}
//----RSA对外接口begin--------------------------------------------------------------------------
/*
特殊说明:
1.RSA目前固定为1024bit密钥长度.
2.外部接口统一使用带结束符共257字节的字符串(最后字节是字符串结束符)
3.
*/
//!	外部接口要用的RSA参数
struct RSA_CONTEXT_FOR_API
{
	unsigned char abySKey[RSA_SKEY_SIZE];//!	字节表示的私钥
	unsigned char abyPKey[RSA_PKEY_SIZE];//!	字节表示的公钥
	char szSKey[RSA_STRING_SKEY_SIZE1];	//!	字符串表示的私钥
	char szPKey[RSA_STRING_PKEY_SIZE1];	//!	字符串表示的公钥
};

//!	产生RSA句柄
/*!
\return RSA句柄,就是RSA_CONTEXT_FOR_API的实例指针,后面调用都要有句柄
\remarks RSA句柄用完之后应该用rsa_destroy_handle()销毁
\sa rsa_destroy_handle()
*/
void * rsa_create_handle()
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)::malloc(sizeof(RSA_CONTEXT_FOR_API));
	memset(p,0,sizeof(*p));
	return p;
}

//!	销毁RSA句柄
/*!
\param pRSA:RSA句柄
\sa rsa_create_handle()
*/
static void rsa_destroy_handle(void * pRSA)
{
	if(pRSA)
	{
		::free(pRSA);
	}//if
}

//!	拷贝RSA句柄
/*!
\param pDstRSA:目标RSA句柄
\param pSrcRSA:源数据RSA句柄
*/
static void rsa_copy_handle(void * pDstRSA,const void* pSrcRSA)
{
	if(pDstRSA && pSrcRSA)
	{
		memcpy(pDstRSA,pSrcRSA,sizeof(RSA_CONTEXT_FOR_API));
	}//if
}
//!	产生公钥私钥
/*!
\return 0成功,-1失败
\param  pRSA:RSA句柄,不能为空
*/
static int rsa_create_key(void * pRSA)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;
	int priv_len	= 0;
	int pub_len		= 0;
	int ret = rsa_gen_keypair(p->abySKey, &priv_len, p->abyPKey, &pub_len);
	if(ret != 0)
	{
		return -1;
	}//if
	assert(priv_len == RSA_SKEY_SIZE && pub_len == RSA_PKEY_SIZE);

	rsa_skey_byte2string(p->abySKey,p->szSKey);
	rsa_pkey_byte2string(p->abyPKey,p->szPKey);

	return 0;
}

//!	设置公钥私钥
/*!
\return 0成功,-1失败
\param  pRSA:RSA句柄,不能为空
\param  pszSKey:私钥的十六进制字符串表示,一定是2048字符的十六进制字符串
\param  pszPKey:公钥的十六进制字符串表示,一定是512字符的十六进制字符串
*/
static int rsa_set_key(void * pRSA,const char * pszSKey,const char * pszPKey)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;

	if(pszSKey && strlen(pszSKey) != RSA_STRING_SKEY_SIZE)
	{
		return -1;
	}//if
	if(pszPKey && strlen(pszPKey) != RSA_STRING_PKEY_SIZE)
	{
		return -1;
	}//if

	if(pszSKey)
	{
		strcpy(p->szSKey,pszSKey);
		rsa_skey_string2byte(p->szSKey,p->abySKey);
	}//if
	if(pszPKey)
	{
		strcpy(p->szPKey,pszPKey);
		rsa_pkey_string2byte(p->szPKey,p->abyPKey);
	}//if

	return 0;
}


//!	取RSA的密钥
/*!
\return RSA的字符串密钥
\param  pRSA:RSA句柄,不能为空
*/
const char * rsa_get_skey(const void * pRSA)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;
	return p->szSKey;
}
const char * rsa_get_pkey(const void * pRSA)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;
	return p->szPKey;
}

//!	由输入的待转换数据预估输出的最大长度
/*!
\return 预估最大长度,失败则返回-1
\param  pRSA:RSA句柄,不能为空
\param nInputSize:输入大小
\remarks RSA句柄必须先初始化
*/
static int rsa_estimate_max_size(const void * pRSA,int nInputSize)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;

	int nMax	= estimate_ciphertext_size(p->szSKey[0] == 0?p->abyPKey:p->abySKey,nInputSize);
	return nMax>=nInputSize?nMax:nInputSize;
}


//!	加密解密
/*!
\return 输出长度,返回-1表示失败
\param  pRSA:RSA句柄,不能为空,且需要之前用rsa_set_key()初始化
\param pInput:输入缓冲区
\param pOutput:输出缓冲区,大小必须>=rsa_estimate_max_size(),否则崩溃
\remarks 
\sa rsa_set_key(),rsa_estimate_max_size()
*/
static int rsa_encrypt_by_skey(const void * pRSA,const void * pInput,int nInputSize,void * pOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;
	int nOutputSize = -1;
	int ret = rsa_encrypt_private(p->abySKey, (const unsigned char*)pInput, nInputSize, (unsigned char*)pOutput, &nOutputSize);

	return ret == 0?nOutputSize:-1;
}
static int rsa_encrypt_by_pkey(const void * pRSA,const void * pInput,int nInputSize,void * pOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;
	int nOutputSize = -1;
	int ret = rsa_encrypt_public(p->abyPKey, (const unsigned char*)pInput, nInputSize, (unsigned char*)pOutput, &nOutputSize);

	return ret == 0?nOutputSize:-1;
}
static int rsa_decrypt_by_skey(const void * pRSA,const void * pInput,int nInputSize,void * pOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;
	int nOutputSize = -1;
	int ret = rsa_decrypt_private(p->abySKey, (const unsigned char*)pInput, nInputSize, (unsigned char*)pOutput, &nOutputSize);

	return ret == 0?nOutputSize:-1;
}
static int rsa_decrypt_by_pkey(const void * pRSA,const void * pInput,int nInputSize,void * pOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;
	int nOutputSize = -1;
	int ret = rsa_decrypt_public(p->abyPKey, (const unsigned char*)pInput, nInputSize, (unsigned char*)pOutput, &nOutputSize);

	return ret == 0?nOutputSize:-1;
}
//!	按字符串对字符串加密解密
/*!
\return 输出长度,返回-1表示失败
\param  pRSA:RSA句柄,不能为空,且需要之前用rsa_set_key()初始化
\param pszInput:带有结束符的字符串
\param strOutput:输出字符串对象
\remarks 
两者都是字符串,encrypt时,待加密的内容是字符串,加密结果是字节串,将其十六进制字符串化,decrypt时,一定是
encrypt得到的十六进制字符串,首先会还原成字节串,再解密成原来的明文字符串.
如果不是严格遵照上述规定,乱用decrypt则可能出现问题.
*/
static int rsa_string_encrypt_by_skey(const void * pRSA,const char * pszInput,string& strOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;

	strOutput.clear();
	int nInputSize		= (int)strlen(pszInput);
	int nMaxSize		= rsa_estimate_max_size(p,nInputSize);
	if(nMaxSize <= 0)
	{
		return -1;
	}
	void * pOutput		= ::malloc(nMaxSize);
	int nOutputSize		= rsa_encrypt_by_skey(pRSA,pszInput,nInputSize,pOutput);

	if(nOutputSize > 0)
	{
		strOutput.resize(nOutputSize*2);
		XtBytesToString(pOutput,nOutputSize,(char*)strOutput.data(),true);
	}

	::free(pOutput);

	return nOutputSize>0?nOutputSize*2:-1;
}
static int rsa_string_encrypt_by_pkey(const void * pRSA,const char * pszInput,string& strOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;

	strOutput.clear();
	int nInputSize		= (int)strlen(pszInput);
	int nMaxSize		= rsa_estimate_max_size(p,nInputSize);
	if(nMaxSize <= 0)
	{
		return -1;
	}
	void * pOutput		= ::malloc(nMaxSize);
	int nOutputSize		= rsa_encrypt_by_pkey(pRSA,pszInput,nInputSize,pOutput);

	if(nOutputSize > 0)
	{
		strOutput.resize(nOutputSize*2);
		XtBytesToString(pOutput,nOutputSize,(char*)strOutput.data(),true);
	}

	::free(pOutput);

	return nOutputSize>0?nOutputSize*2:-1;
}
static int rsa_string_decrypt_by_skey(const void * pRSA,const char * pszInput,string& strOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;

	strOutput.clear();
	int nInputSize0		= (int)strlen(pszInput);
	void * pInput		= ::malloc(nInputSize0/2);
	int nInputSize		= XtStringToBytes(pszInput,pInput);

	int nMaxSize		= rsa_estimate_max_size(p,nInputSize);
	if(nMaxSize <= 0)
	{
		::free(pInput);
		return -1;
	}
	void * pOutput		= ::malloc(nMaxSize);
	int nOutputSize		= rsa_decrypt_by_skey(pRSA,pInput,nInputSize,pOutput);

	if(nOutputSize > 0)
	{
		strOutput.resize(nOutputSize);
		memcpy((char*)strOutput.data(),pOutput,nOutputSize);
	}

	::free(pInput);
	::free(pOutput);

	return nOutputSize>0?nOutputSize*2:-1;
}
static int rsa_string_decrypt_by_pkey(const void * pRSA,const char * pszInput,string& strOutput)
{
	assert(pRSA);
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)pRSA;

	strOutput.clear();
	int nInputSize0		= (int)strlen(pszInput);
	void * pInput		= ::malloc(nInputSize0/2);
	int nInputSize		= XtStringToBytes(pszInput,pInput);

	int nMaxSize		= rsa_estimate_max_size(p,nInputSize);
	if(nMaxSize <= 0)
	{
		::free(pInput);
		return -1;
	}
	void * pOutput		= ::malloc(nMaxSize);
	int nOutputSize		= rsa_decrypt_by_pkey(pRSA,pInput,nInputSize,pOutput);

	if(nOutputSize > 0)
	{
		strOutput.resize(nOutputSize);
		memcpy((char*)strOutput.data(),pOutput,nOutputSize);
	}

	::free(pInput);
	::free(pOutput);

	return nOutputSize>0?nOutputSize*2:-1;
}
//----RSA对外接口end--------------------------------------------------------------------------


#endif

static void EndFunction4RSA(){}
//end: RSA
//-----rsa end------------------------------------------------------------------------


//-----xtgame begin------------------------------------------------------------------------
//begin: xuetian encrypt/decrypt algorithms
static void BeginFunction4XT(){}
//为了加强破解难度，以免代码泄密时很容易理解，本文中的代码注释去掉了，具体规则参见另外的文档说明

//实现函数
//!	计算ipseed
bool XtGetIpseed16(unsigned char ipseed[16],unsigned int nIPv4)
{
	if(nIPv4 == 0)
	{
#ifdef WIN32
		char name[255];
		PHOSTENT hostinfo;
		if(::gethostname ( name, sizeof(name)) == 0)
		{
			if((hostinfo = ::gethostbyname(name)) != NULL)
			{
				nIPv4 = (unsigned int)::htonl(((struct in_addr *)hostinfo->h_addr)->s_addr);
			}
		}
#else
#ifdef LINUX
		int   sock;   
		sockaddr_in   sin;   
		ifreq   ifr;   
		sock	= ::socket(AF_INET,SOCK_DGRAM,0);   
		if(sock != -1)   
		{    
#define   ETH_NAME "eth0"
			::strncpy(ifr.ifr_name,ETH_NAME,IFNAMSIZ); 
			ifr.ifr_name[IFNAMSIZ-1]	= 0;   
			if(ioctl(sock,SIOCGIFADDR,&ifr) >= 0)   
			{   
				memcpy(&sin,&ifr.ifr_addr,sizeof(sin)); 
				nIPv4 = (unsigned int)::htonl(sin.sin_addr.s_addr);
			}   
		} 
#endif
#endif
	}
	XtMD5Encode16((const void*)&nIPv4,sizeof(nIPv4),ipseed);
	return true;
}
bool XtGetIpseed32(char ipseed[32],bool bLowerChar,unsigned int nIPv4)
{
	unsigned char pEncryBuf[16];
	bool bOK = XtGetIpseed16(pEncryBuf,nIPv4);
	if(bLowerChar)
	{
		sprintf(ipseed,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);
	}//if
	else
	{
		sprintf(ipseed,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);
	}

	return bOK;
}
bool XtGetIpseed33(char ipseed[33],bool bLowerChar,unsigned int nIPv4)
{
	bool bOK = XtGetIpseed32(ipseed,bLowerChar,nIPv4);
	ipseed[32] = 0;
	return bOK;
}
//!	hupdate.exe传递token给hclient.exe的加密规则,返回缓冲区有效长度，请保证返回缓冲区够大
int XtTokenToToken1(const char * szToken,char * szToken1,const char * szAllseed,const char szIpseed[33])
{
	int nLen1 = (int)::strlen(szAllseed);
	int nLen2 = nLen1 + 33;
	char * pszTemp = (char *)::malloc(nLen2);
	::strcpy(pszTemp,szAllseed);
	::strcat(pszTemp,szIpseed);
	char szKey[33];
	XtMD5EncodeToString33((const void*)pszTemp,nLen2-1,szKey,true);
	::free(pszTemp);

	AES_CONTEXT AES;
	XtAesSetKey(&AES,(const void*)szKey,32*8,false);

	int nTextLength = (int)::strlen(szToken);
	XtAesEncrypt(&AES,(const void*)szToken,nTextLength,(void*)szToken1);
	szToken1[nTextLength] = 0;

	return nTextLength;
}
int XtToken1ToToken(const char * szToken1,int nToken1ByteLength,char * szToken,const char * szAllseed,const char szIpseed[33])
{
	int nLen1 = (int)::strlen(szAllseed);
	int nLen2 = nLen1 + 33;
	char * pszTemp = (char *)::malloc(nLen2);
	::strcpy(pszTemp,szAllseed);
	::strcat(pszTemp,szIpseed);
	char szKey[33];
	XtMD5EncodeToString33((const void*)pszTemp,nLen2-1,szKey,true);
	::free(pszTemp);

	AES_CONTEXT AES;
	XtAesSetKey(&AES,(const void*)szKey,32*8,false);

	int nTextLength = nToken1ByteLength <= 0?(int)::strlen(szToken1):nToken1ByteLength;
	XtAesDecrypt(&AES,(const void*)szToken1,nTextLength,(void*)szToken);
	szToken[nTextLength] = 0;

	return nTextLength;
}
//!	hclient.exe传递token给haccess_srv.exe和hctrl_srv.exe的加密规则,返回缓冲区有效长度，请保证返回缓冲区够大
int XtTokenToToken2(const char * szToken,char * szToken2,const char * szAllseed,const char szSeed2[33])
{
	return XtTokenToToken1(szToken,szToken2,szAllseed,szSeed2);
}
int XtToken2ToToken(const char * szToken2,int nToken2ByteLength,char * szToken,const char * szAllseed,const char szSeed2[33])
{
	return XtToken1ToToken(szToken2,nToken2ByteLength,szToken,szAllseed,szSeed2);
}
//!	hclient.exe传递token给gupdate.exe和gclient.exe的加密规则
int XtTokenToToken3(const char * szToken,char * szToken3,const char * szAllseed,const char szSeed3[33],const char szIpseed[33])
{
	int nLen1 = (int)::strlen(szAllseed);
	int nLen2 = nLen1 + 32 + 33;
	char * pszTemp = (char *)::malloc(nLen2);
	::strcpy(pszTemp,szAllseed);
	::strcat(pszTemp,szSeed3);
	::strcat(pszTemp,szIpseed);
	char szKey[33];
	XtMD5EncodeToString33((const void*)pszTemp,nLen2-1,szKey,true);
	::free(pszTemp);

	AES_CONTEXT AES;
	XtAesSetKey(&AES,(const void*)szKey,32*8,false);

	int nTextLength = (int)::strlen(szToken);
	XtAesEncrypt(&AES,(const void*)szToken,nTextLength,(void*)szToken3);
	szToken3[nTextLength] = 0;

	return nTextLength;

}
int XtToken3ToToken(const char * szToken3,int nToken3ByteLength,char * szToken,const char * szAllseed,const char szSeed3[33],const char szIpseed[33])
{
	int nLen1 = (int)::strlen(szAllseed);
	int nLen2 = nLen1 + 32 + 33;
	char * pszTemp = (char *)::malloc(nLen2);
	::strcpy(pszTemp,szAllseed);
	::strcat(pszTemp,szSeed3);
	::strcat(pszTemp,szIpseed);
	char szKey[33];
	XtMD5EncodeToString33((const void*)pszTemp,nLen2-1,szKey,true);
	::free(pszTemp);

	AES_CONTEXT AES;
	XtAesSetKey(&AES,(const void*)szKey,32*8,false);

	int nTextLength = nToken3ByteLength <= 0?(int)::strlen(szToken3):nToken3ByteLength;
	XtAesDecrypt(&AES,(const void*)szToken3,nTextLength,(void*)szToken);
	szToken[nTextLength] = 0;

	return nTextLength;
}
//!	gclient.exe传递token给gaccess_srv.exe的加密规则
int XtTokenToToken4(const char * szToken,char * szToken4,const char * szAllseed,const char szSeed3[33])
{
	int nTextLength = (int)::strlen(szToken);

	int nLen1 = (int)::strlen(szAllseed);
	int nLen2 = nLen1 + 33 + nTextLength;
	char * pszTemp = (char *)::malloc(nLen2);
	::strcpy(pszTemp,szAllseed);
	::strcat(pszTemp,szSeed3);
	::strcat(pszTemp,szToken);
	char szKey[33];
	XtMD5EncodeToString33((const void*)pszTemp,nLen2-1,szKey,true);
	::free(pszTemp);

	AES_CONTEXT AES;
	XtAesSetKey(&AES,(const void*)szKey,32*8,false);

	//int nTextLength = (int)::strlen(szToken);
	XtAesEncrypt(&AES,(const void*)szToken,nTextLength,(void*)szToken4);
	szToken4[nTextLength] = 0;

	return nTextLength;
}
int XtToken4ToToken(const char * szToken4,int nToken4ByteLength,char * szToken,const char * szAllseed,const char szSeed3[33])
{
	int nOldTextLength = (int)::strlen(szToken);

	int nLen1 = (int)::strlen(szAllseed);
	int nLen2 = nLen1 + 33 + nOldTextLength;
	char * pszTemp = (char *)::malloc(nLen2);
	::strcpy(pszTemp,szAllseed);
	::strcat(pszTemp,szSeed3);
	::strcat(pszTemp,szToken);
	char szKey[33];
	XtMD5EncodeToString33((const void*)pszTemp,nLen2-1,szKey,true);
	::free(pszTemp);

	AES_CONTEXT AES;
	XtAesSetKey(&AES,(const void*)szKey,32*8,false);

	int nTextLength = nToken4ByteLength <= 0?(int)::strlen(szToken4):nToken4ByteLength;
	XtAesDecrypt(&AES,(const void*)szToken4,nTextLength,(void*)szToken);
	szToken[nTextLength] = 0;

	return nTextLength;
}

//!	hclient.exe传递sctoken给haccess_srv.exe和hctrl_srv.exe的加密规则
int XtMakeSctoken(char szSctoken[33],const char * szAllseed,const char szSeed2[33],const char * szToken2,int nToken2ByteLength)
{
	int nTextLength = nToken2ByteLength <= 0?(int)::strlen(szToken2):nToken2ByteLength;

	int nLen1 = (int)::strlen(szAllseed);
	int nLen2 = nLen1 + 33 + nTextLength;
	char * pszTemp = (char *)::malloc(nLen2);
	::strcpy(pszTemp,szAllseed);
	::strcat(pszTemp,szSeed2);
	::memcpy(pszTemp+nLen1 + 32,szToken2,nTextLength+1);
	XtMD5EncodeToString33((const void*)pszTemp,nLen2-1,szSctoken,true);
	::free(pszTemp);

	return 32;
}
//!	haccess_srv.exe产生的seed及其衍生seedN规则
bool XtMakeSeed0(char szSeed0[33])
{
	int i = 0;
	for(; i < 32; ++i)
	{
		szSeed0[i] = 1 + rand()%9 + '0';
	}//fori
	szSeed0[32] = 0;
	return true;
}
bool XtMakeSeed1(char szSeed1[33],const char szSeed0[33],const char * szAllseed)
{
	//（3）	把seed与allseed的每个单字节相加双字节相减且为0值时取1值得到的字节缓冲区作为输入，
	//计算得到32字符表示的MD5码，把该MD5码作为seed1；
	const unsigned char * pMin	= 0;
	const unsigned char * pMax	= 0;
	int nMin					= 0;
	int nMax					= 0;

	int nLen1					= (int)::strlen(szAllseed);
	if(32 <= nLen1)
	{
		nMin					= 32;
		nMax					= nLen1;
		pMin					= (const unsigned char *)szSeed0;
		pMax					= (const unsigned char *)szAllseed;
	}//if
	else
	{
		nMin					= nLen1;
		nMax					= 32;
		pMin					= (const unsigned char *)szAllseed;
		pMax					= (const unsigned char *)szSeed0;
	}

	unsigned char * pBuf		= (unsigned char *)::malloc(nMax+1);

	::memcpy(pBuf,pMax,nMax+1);
	int i = 1;
	for(; i < nMin; i += 2)
	{
		pBuf[i]					+= pMin[i];
	}//fori
	i = 0;
	for(; i < nMin; i += 2)
	{
		pBuf[i]					-= pMin[i];
	}//fori

	XtMD5EncodeToString33((const void*)pBuf,nMax,szSeed1,true);

	::free(pBuf);

	return true;
}
bool XtMakeSeed2(char szSeed2[33],const char szSeed1[33],const char * szAllseed)
{
	return XtMakeSeed1(szSeed2,szSeed1,szAllseed);
}
bool XtMakeSeed3(char szSeed3[33],const char szSeed2[33],const char * szAllseed)
{
	return XtMakeSeed1(szSeed3,szSeed2,szAllseed);
}
static void EndFunction4XT(){}
//end: xuetian encrypt/decrypt algorithms
//-----xtgame end------------------------------------------------------------------------

//-----other begin------------------------------------------------------------------------
//begin: other function
static void BeginFunction4Other(){}
static void EndFunction4Other(){}
//end: other function
//-----other end------------------------------------------------------------------------

//==============基本算法end========================================================================================
static void EndFunction4AllBase(){}
//=======new end===========================================================================================

XteSecIO::XteSecIO()
{
	m_pRSA	= rsa_create_handle();
	memset(&m_AES,0,sizeof(m_AES));
	init();
}

XteSecIO::~XteSecIO()
{
	free();

	if(m_pRSA)
	{
		rsa_destroy_handle(m_pRSA);
		m_pRSA	= NULL;
	}//if
}

XteSecIO::XteSecIO(const XteSecIO & src)
//:XteObject(src)
{
	init();
	set(src);
}

void XteSecIO::init()
{
	//	Need code here
	
}
void XteSecIO::free()
{
	//	need code here

}
void XteSecIO::operator=(const XteSecIO & src)
{
	set(src);
}
void XteSecIO::set(const XteSecIO & src)
{
	if(this == &src)
	{
		return;
	}//if
	free();
	if(src.m_pRSA)
	{
		if(!m_pRSA)
		{
			m_pRSA	= rsa_create_handle();
		}
		rsa_copy_handle(m_pRSA,src.m_pRSA);
	}//if
	m_AES		= src.m_AES;
}
//-------------------------------------------------------------------------
//	add other functions
//-------------------------------------------------------------------------
//!	设置加强型加密算法的加密种子
const void * XteSecIO::setKeySeed(const void * pKeySeedBuf,int nKeySeedBufLength)
{
	if(nKeySeedBufLength > 0)
	{
		const uint8_t * pBuf = (const uint8_t *)pKeySeedBuf;
		int i = 0;
		for(; i < g_nEncrySeedLength; ++i)
		{
			g_szEncrySeed[i] = (char)pBuf[i%nKeySeedBufLength];
		}//fori
	}
	return (const void *)g_szEncrySeed;
}
const char * XteSecIO::setKeySeedByString(const char * pszKeySeed)
{
	return (const char * )setKeySeed((const void *)pszKeySeed,(int)strlen(pszKeySeed));

}
//!	取当前加强型加密算法的加密种子指针
const void * XteSecIO::getKeySeedBuf()
{
	return (const void *)g_szEncrySeed;
}
//!	取当前加强型加密算法的加密种子长度
int XteSecIO::getKeySeedLength()
{
	return g_nEncrySeedLength;
}

//-----------------------------------------------------------------------------
	//网络数据包加密与解密
//-----------------------------------------------------------------------------
//!	网络数据包加密
bool XteSecIO::netPackEncode(uint8_t & nCheckCode,const void * pPlainBuf,int32_t nPlainLength,void * pEncryBuf,int32_t & nEncryLength,uint8_t nEncryType,XteSecIO * pSecIO)
{
	assert(pPlainBuf && pEncryBuf);
		
	//防止缓冲区溢出
	if(nPlainLength <= 0 || nPlainLength > XTE_MAX_BUF_LENGTH)
	{
		assert(0);
		return false;
	}//if

	//暂时总是认为缓冲区足够大
	nEncryLength = 999999999;

	//check code
	nCheckCode = 0;
	int i = 0;
	const uint8_t * p0	= ((const uint8_t *)pPlainBuf);
	for(;i < nPlainLength;i++)
	{
		nCheckCode += *p0++ * (i + 1);
	}//for i
		
	
	switch(nEncryType)
	{
	case ENCRYTYPE::NORMAL1://from check and left left-shift && right right-shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;

			//from check
			int nLeft			= nCheckCode % nPlainLength + 1;
			int nRight			= nPlainLength - nLeft;

			//right right-shift
			const uint8_t * p1	= ((const uint8_t *)pPlainBuf) + nLeft;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i

			//left left-shift
			const uint8_t * p3	= ((const uint8_t *)pPlainBuf);
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p3;
				XTLCMBYTE(*p2,(i%7 + 1));
				p3++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::NORMAL2://from check and left right-shift && right left-shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;
			
			//from check
			int nLeft			= nCheckCode % nPlainLength + 1;
			int nRight			= nPlainLength - nLeft;
			
			//right left-shift
			const uint8_t * p1	= ((const uint8_t *)pPlainBuf) + nLeft;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			//left right-shift
			const uint8_t * p3	= ((const uint8_t *)pPlainBuf);
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p3;
				XTRCMBYTE(*p2,(i%7 + 1));
				p3++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::NORMAL3://from check and left left-shift && right left-shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;
			
			//from check
			int nLeft			= nCheckCode % nPlainLength + 1;
			int nRight			= nPlainLength - nLeft;
			
			//right left-shift
			const uint8_t * p1	= ((const uint8_t *)pPlainBuf) + nLeft;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			//left left-shift
			const uint8_t * p3	= ((const uint8_t *)pPlainBuf);
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p3;
				XTLCMBYTE(*p2,(i%7 + 1));
				p3++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::NORMAL4://from check and left right-shift && right right-shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;
			
			//from check
			int nLeft			= nCheckCode % nPlainLength + 1;
			int nRight			= nPlainLength - nLeft;
			
			//right right-shift
			const uint8_t * p1	= ((const uint8_t *)pPlainBuf) + nLeft;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			//left right-shift
			const uint8_t * p3	= ((const uint8_t *)pPlainBuf);
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p3;
				XTRCMBYTE(*p2,(i%7 + 1));
				p3++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST1://from end && right shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;

			const uint8_t * p1	= ((const uint8_t *)pPlainBuf) + nPlainLength - 1;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nPlainLength;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1--;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST2://from begin && right shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;

			const uint8_t * p1	= (const uint8_t *)pPlainBuf;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nPlainLength;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST3://from end && left shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;

			const uint8_t * p1	= ((const uint8_t *)pPlainBuf) + nPlainLength - 1;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nPlainLength;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1--;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST4://from begin && left shift
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if
			
			nEncryLength = nPlainLength;

			const uint8_t * p1	= (const uint8_t *)pPlainBuf;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			for(i = 0;i < nPlainLength;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::ENHANCE1://move seed number bit to extend byte
	case ENCRYTYPE::ENHANCE2://
	case ENCRYTYPE::ENHANCE3://
	case ENCRYTYPE::ENHANCE4://
		{
			int32_t nE = getEncryLengthByPlainLength(nPlainLength,nEncryType);
			if(nEncryLength < nE)
			{
				return false;
			}//if

			nEncryLength = nE;

			int nSeedIndex = 0;

			//seed number
			const uint8_t * p1	= (const uint8_t *)pPlainBuf;
			uint8_t * p2			= (uint8_t *)pEncryBuf;
			const uint8_t * p3	= (const uint8_t *)g_szEncrySeed;
			for(i = 0;i < nPlainLength / 8;i++)
			{
				if(nSeedIndex + 8 >= g_nEncrySeedLength)
				{
					nSeedIndex = 0;
				}//if
				uint8_t * p8		= p2 + 8;
				*p8				= 0;
				int j = 0;
				for(;j < 8;j++)
				{
					switch(*(p3 + nSeedIndex++) % 8)
					{
					case 0://
						{
							*p8		|= (((0X80 & *p1) >> 7) << j);
							*p2++	= (0X7F & *p1);
							p1++;
							break;
						}
					case 1://
						{
							*p8		|= (((0X40 & *p1) >> 6) << j);
							*p2++	= (0XBF & *p1);
							p1++;
							break;
						}
					case 2://
						{
							*p8		|= (((0X20 & *p1) >> 5) << j);
							*p2++	= (0XDF & *p1);
							p1++;
							break;
						}
					case 3://
						{
							*p8		|= (((0X10 & *p1) >> 4) << j);
							*p2++	= (0XEF & *p1);
							p1++;
							break;
						}
					case 4://
						{
							*p8		|= (((0X08 & *p1) >> 3) << j);
							*p2++	= (0XF7 & *p1);
							p1++;
							break;
						}
					case 5://
						{
							*p8		|= (((0X04 & *p1) >> 2) << j);
							*p2++	= (0XFB & *p1);
							p1++;
							break;
						}
					case 6://
						{
							*p8		|= (((0X02 & *p1) >> 1) << j);
							*p2++	= (0XFD & *p1);
							p1++;
							break;
						}
					case 7://
						{
							*p8		|= (((0X01 & *p1) >> 0) << j);
							*p2++	= (0XFE & *p1);
							p1++;
							break;
						}
					default:
						{
							
							break;
						}
					}//switch
				}//for j
				p2++;
			}//for i

			i = 0;
			for(;i < nPlainLength % 8;i++)
			{
				*p2++	= *p1++;
			}//for i
			
			uint8_t nCC = 0;
			if(nEncryType == ENCRYTYPE::ENHANCE1)
			{
				return netPackEncode(nCC,pEncryBuf,nEncryLength,ENCRYTYPE::FAST1,pSecIO);
			}//if
			else if(nEncryType == ENCRYTYPE::ENHANCE2)
			{
				return netPackEncode(nCC,pEncryBuf,nEncryLength,ENCRYTYPE::FAST2,pSecIO);
			}//if
			else if(nEncryType == ENCRYTYPE::ENHANCE3)
			{
				return netPackEncode(nCC,pEncryBuf,nEncryLength,ENCRYTYPE::FAST3,pSecIO);
			}//if
			else //if(nEncryType == ENCRYTYPE::ENHANCE4)
			{
				return netPackEncode(nCC,pEncryBuf,nEncryLength,ENCRYTYPE::FAST4,pSecIO);
			}//if			
			
			break;
		}
	case ENCRYTYPE::SUPER1://AES ENCRYPT
		{
			if(nEncryLength < nPlainLength)
			{
				return false;
			}//if

			if(!pSecIO)
			{
				return false;
			}//if

			nEncryLength = nPlainLength;
			pSecIO->aesEncrypt(pPlainBuf,nPlainLength,pEncryBuf);

			break;
		}
	default:
		{
			return false;
			break;
		}
	}//switch	

	return true;
}
bool XteSecIO::netPackEncode(uint8_t & nCheckCode,void * pBuf,int32_t nLength,uint8_t nEncryType,XteSecIO * pSecIO)
{
	assert(pBuf);

	//特殊加密类型	
	if(nEncryType == ENCRYTYPE::FAST2 || nEncryType == ENCRYTYPE::FAST4)
	{
		return netPackEncode(nCheckCode,pBuf,nLength,pBuf,nLength,nEncryType,pSecIO);
	}//if

	//取得密文缓冲区
	uint8_t * pEncryBuf = new uint8_t[nLength];

	//无法取得密文缓冲区则只能处理特殊加密类型
	if(!pEncryBuf)
	{
		return false;
	}

	if(netPackEncode(nCheckCode,pBuf,nLength,pEncryBuf,nLength,nEncryType,pSecIO))
	{
		memcpy(pBuf,pEncryBuf,nLength);
		delete [] pEncryBuf;
		return true;
	}

	return false;
}
//!	网络数据包解密
bool XteSecIO::netPackDecode(uint8_t nCheckCode,const void * pEncryBuf,int32_t nEncryLength,void * pPlainBuf,int32_t & nPlainLength,uint8_t nEncryType,XteSecIO * pSecIO)
{
	assert(pPlainBuf && pEncryBuf);
	
	//防止缓冲区溢出
	if(nEncryLength <= 0 || nEncryLength > XTE_MAX_BUF_LENGTH)
	{
		assert(0);
		return false;
	}//if	
	
	//暂时总是认为缓冲区足够大
	nPlainLength = 99999999;

	int i = 0;
	switch(nEncryType)
	{
	case ENCRYTYPE::NORMAL1://from check and left left-shift && right right-shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;

			//from check
			int nLeft			= nCheckCode % nEncryLength + 1;
			int nRight			= nEncryLength - nLeft;

			//right right-shift
			const uint8_t * p1	= ((const uint8_t *)pEncryBuf);
			uint8_t * p2			= (uint8_t *)pPlainBuf + nLeft;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i

			//left left-shift
			p2			= (uint8_t *)pPlainBuf;
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::NORMAL2://from check and left right-shift && right left-shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;
			
			//from check
			int nLeft			= nCheckCode % nEncryLength + 1;
			int nRight			= nEncryLength - nLeft;
			
			//right left-shift
			const uint8_t * p1	= ((const uint8_t *)pEncryBuf);
			uint8_t * p2			= (uint8_t *)pPlainBuf + nLeft;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			//left right-shift
			p2			= (uint8_t *)pPlainBuf;
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::NORMAL3://from check and left left-shift && right left-shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;
			
			//from check
			int nLeft			= nCheckCode % nEncryLength + 1;
			int nRight			= nEncryLength - nLeft;
			
			//right left-shift
			const uint8_t * p1	= ((const uint8_t *)pEncryBuf);
			uint8_t * p2			= (uint8_t *)pPlainBuf + nLeft;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			//left left-shift
			p2			= (uint8_t *)pPlainBuf;
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::NORMAL4://from check and left right-shift && right right-shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;
			
			//from check
			int nLeft			= nCheckCode % nEncryLength + 1;
			int nRight			= nEncryLength - nLeft;
			
			//right right-shift
			const uint8_t * p1	= ((const uint8_t *)pEncryBuf);
			uint8_t * p2			= (uint8_t *)pPlainBuf + nLeft;
			for(i = 0;i < nRight;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			//left right-shift
			p2			= (uint8_t *)pPlainBuf;
			for(i = 0;i < nLeft;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST1://from end && right shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;

			const uint8_t * p1	= ((const uint8_t *)pEncryBuf);
			uint8_t * p2			= (uint8_t *)pPlainBuf + nEncryLength - 1;
			for(i = 0;i < nEncryLength;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2--;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST2://from begin && right shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;

			const uint8_t * p1	= (const uint8_t *)pEncryBuf;
			uint8_t * p2			= (uint8_t *)pPlainBuf;
			for(i = 0;i < nEncryLength;i++)
			{
				*p2 = *p1;
				XTLCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST3://from end && left shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;

			const uint8_t * p1	= ((const uint8_t *)pEncryBuf);
			uint8_t * p2			= (uint8_t *)pPlainBuf + nEncryLength - 1;
			for(i = 0;i < nEncryLength;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2--;
			}//for i
			
			break;
		}
	case ENCRYTYPE::FAST4://from begin && left shift
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if
			
			nPlainLength = nEncryLength;

			const uint8_t * p1	= (const uint8_t *)pEncryBuf;
			uint8_t * p2			= (uint8_t *)pPlainBuf;
			for(i = 0;i < nEncryLength;i++)
			{
				*p2 = *p1;
				XTRCMBYTE(*p2,(i%7 + 1));
				p1++;
				p2++;
			}//for i
			
			break;
		}
	case ENCRYTYPE::ENHANCE1://move seed number bit to extend byte
	case ENCRYTYPE::ENHANCE2://
	case ENCRYTYPE::ENHANCE3://
	case ENCRYTYPE::ENHANCE4://
		{
			//第一步按快速解密
			uint8_t * pBuf = NULL;
			if(nPlainLength < nEncryLength)
			{
				//取得明文临时缓冲区
				pBuf = new uint8_t[nEncryLength];
			}//if
			else
			{
				pBuf = (uint8_t *)pPlainBuf;
			}
				
			//无法取得明文缓冲区则失败
			if(!pBuf)
			{
				return false;
			}

			if(nEncryType == ENCRYTYPE::ENHANCE1)
			{
				netPackDecode(0,pEncryBuf,nEncryLength,pBuf,nEncryLength,ENCRYTYPE::FAST1,pSecIO);
			}//if
			else if(nEncryType == ENCRYTYPE::ENHANCE2)
			{
				netPackDecode(0,pEncryBuf,nEncryLength,pBuf,nEncryLength,ENCRYTYPE::FAST2,pSecIO);
			}//if
			else if(nEncryType == ENCRYTYPE::ENHANCE3)
			{
				netPackDecode(0,pEncryBuf,nEncryLength,pBuf,nEncryLength,ENCRYTYPE::FAST3,pSecIO);
			}//if
			else //if(nEncryType == ENCRYTYPE::ENHANCE4)
			{
				netPackDecode(0,pEncryBuf,nEncryLength,pBuf,nEncryLength,ENCRYTYPE::FAST4,pSecIO);
			}//if		

			//第二步按照bit还原
			int32_t nP = getPlainLengthByEncryLength(nEncryLength,nEncryType);
			if(nPlainLength < nP)
			{
				if(nPlainLength < nEncryLength)
				{
					delete pBuf;
				}
				return false;
			}//if

			nPlainLength = nP;

			int nSeedIndex = 0;

			//seed number
			const uint8_t * p1	= (const uint8_t *)pBuf;
			uint8_t * p2		= (uint8_t *)pPlainBuf;
			const uint8_t * p3	= (const uint8_t *)g_szEncrySeed;
			for(i = 0;i < nEncryLength / 9;i++)
			{
				if(nSeedIndex + 8 >= g_nEncrySeedLength)
				{
					nSeedIndex = 0;
				}//if
				const uint8_t * p8		= p1 + 8;
				int j = 0;
				for(;j < 8;j++)
				{
					switch(*(p3 + nSeedIndex++) % 8)
					{
					case 0://
						{
							*p2		= (0X7F & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x80;
							}//if
							p2++;
							p1++;
							break;
						}
					case 1://
						{
							*p2		= (0XBF & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x40;
							}//if
							p2++;
							p1++;
							break;
						}
					case 2://
						{
							*p2		= (0XDF & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x20;
							}//if
							p2++;
							p1++;
							break;
						}
					case 3://
						{
							*p2		= (0XEF & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x10;
							}//if
							p2++;
							p1++;
							break;
						}
					case 4://
						{
							*p2		= (0XF7 & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x08;
							}//if
							p2++;
							p1++;
							break;
						}
					case 5://
						{
							*p2		= (0XFB & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x04;
							}//if
							p2++;
							p1++;
							break;
						}
					case 6://
						{
							*p2		= (0XFD & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x02;
							}//if
							p2++;
							p1++;
							break;
						}
					case 7://
						{
							*p2		= (0XFE & *p1);
							if((*p8 >> j) & 0x01)
							{
								*p2	|= 0x01;
							}//if
							p2++;
							p1++;
							break;
						}
					default:
						{
							
							break;
						}
					}//switch
				}//for j

				p1++;
			}//for i

			i = 0;
			for(;i < nEncryLength % 9;i++)
			{
				*p2++	= *p1++;
			}//for i	


			if(nPlainLength < nEncryLength)
			{
				delete pBuf;
			}
			
			break;
		}
	case ENCRYTYPE::SUPER1://AES DECRYPT
		{
			if(nPlainLength < nEncryLength)
			{
				return false;
			}//if

			if(!pSecIO)
			{
				return false;
			}//if

			nPlainLength = nEncryLength;

			pSecIO->aesDecrypt(pEncryBuf,nEncryLength,pPlainBuf);

			break;
		}
	default:
		{
			return false;
			break;
		}
	}//switch

	//check code
	uint8_t nCheckCode1 = 0;
	const uint8_t * p0	= ((const uint8_t *)pPlainBuf);
	for(i = 0;i < nPlainLength;i++)
	{
		nCheckCode1 += *p0++ * (i + 1);
	}//for i
	
	return nCheckCode1 == nCheckCode;
}
bool XteSecIO::netPackDecode(uint8_t nCheckCode,void * pBuf,int32_t nLength,uint8_t nEncryType,XteSecIO * pSecIO)
{
	assert(pBuf);
		
	//特殊加密类型	
	if(nEncryType == ENCRYTYPE::FAST2 || nEncryType == ENCRYTYPE::FAST4)
	{
		return netPackDecode(nCheckCode,pBuf,nLength,pBuf,nLength,nEncryType,pSecIO);
	}//if
	
	//取得明文缓冲区
	uint8_t * pPlainBuf = new uint8_t[nLength];
	
	//无法取得明文缓冲区则只能处理特殊加密类型
	if(!pPlainBuf)
	{
		return false;
	}
	
	if(netPackDecode(nCheckCode,pPlainBuf,nLength,pBuf,nLength,nEncryType,pSecIO))
	{
		memcpy(pPlainBuf,pBuf,nLength);
		delete pPlainBuf;
		return true;
	}
	
	return false;
}

//!	判断一种加密类型是否为等长加密
bool XteSecIO::isEqualLengthEncryType(uint8_t nEncryType)
{
	switch(nEncryType)
	{
	case ENCRYTYPE::NORMAL1://
	case ENCRYTYPE::NORMAL2://
	case ENCRYTYPE::NORMAL3://
	case ENCRYTYPE::NORMAL4://
	case ENCRYTYPE::FAST1://
	case ENCRYTYPE::FAST2://
	case ENCRYTYPE::FAST3://
	case ENCRYTYPE::FAST4://
	case ENCRYTYPE::SUPER1://
		{
			return true;
			break;
		}
	case ENCRYTYPE::ENHANCE1://
	case ENCRYTYPE::ENHANCE2://
	case ENCRYTYPE::ENHANCE3://
	case ENCRYTYPE::ENHANCE4://
		{
			return false;
			break;
		}
	default:
		{
			return false;
			break;
		}
	}//switch

	return false;
}
//!	判断一种加密类型是否合理
bool XteSecIO::isEncryTypeOK(uint8_t nEncryType)
{
	switch(nEncryType)
	{
	case ENCRYTYPE::NORMAL1://
	case ENCRYTYPE::NORMAL2://
	case ENCRYTYPE::NORMAL3://
	case ENCRYTYPE::NORMAL4://
	case ENCRYTYPE::FAST1://
	case ENCRYTYPE::FAST2://
	case ENCRYTYPE::FAST3://
	case ENCRYTYPE::FAST4://
	case ENCRYTYPE::ENHANCE1://
	case ENCRYTYPE::ENHANCE2://
	case ENCRYTYPE::ENHANCE3://
	case ENCRYTYPE::ENHANCE4://
	case ENCRYTYPE::SUPER1://
		{
			return true;
			break;
		}
	default:
		{
			return false;
			break;
		}
	}//switch

	return false;
}
//!	随机给出一个数字，返回最为接近的加密类型
uint8_t XteSecIO::getEncryTypeByNumber(uint32_t dwNum)
{
	if(dwNum <= ENCRYTYPE::NORMAL1)
	{
		return ENCRYTYPE::NORMAL1;
	}//if
	else if(dwNum <= ENCRYTYPE::NORMAL2)
	{
		return ENCRYTYPE::NORMAL2;
	}//if
	else if(dwNum <= ENCRYTYPE::NORMAL3)
	{
		return ENCRYTYPE::NORMAL3;
	}//if
	else if(dwNum <= ENCRYTYPE::NORMAL4)
	{
		return ENCRYTYPE::NORMAL4;
	}//if
	else if(dwNum <= ENCRYTYPE::FAST1)
	{
		return ENCRYTYPE::FAST1;
	}//if
	else if(dwNum <= ENCRYTYPE::FAST2)
	{
		return ENCRYTYPE::FAST2;
	}//if
	else if(dwNum <= ENCRYTYPE::FAST3)
	{
		return ENCRYTYPE::FAST3;
	}//if
	else if(dwNum <= ENCRYTYPE::FAST4)
	{
		return ENCRYTYPE::FAST4;
	}//if
	else if(dwNum <= ENCRYTYPE::ENHANCE1)
	{
		return ENCRYTYPE::ENHANCE1;
	}//if
	else if(dwNum <= ENCRYTYPE::ENHANCE2)
	{
		return ENCRYTYPE::ENHANCE2;
	}//if
	else if(dwNum <= ENCRYTYPE::ENHANCE3)
	{
		return ENCRYTYPE::ENHANCE3;
	}//if
	else if(dwNum <= ENCRYTYPE::ENHANCE4)
	{
		return ENCRYTYPE::ENHANCE4;
	}
	else
	{
		return ENCRYTYPE::SUPER1;
	}
	
}

//!	由加密类型和明文长度求取密文长度
int32_t XteSecIO::getEncryLengthByPlainLength(int32_t nPlainLength,uint8_t nEncryType)
{
	switch(nEncryType)
	{
	case ENCRYTYPE::NORMAL1://
	case ENCRYTYPE::NORMAL2://
	case ENCRYTYPE::NORMAL3://
	case ENCRYTYPE::NORMAL4://
	case ENCRYTYPE::FAST1://
	case ENCRYTYPE::FAST2://
	case ENCRYTYPE::FAST3://
	case ENCRYTYPE::FAST4://
	case ENCRYTYPE::SUPER1://
		{
			return nPlainLength;
			break;
		}
	case ENCRYTYPE::ENHANCE1://
	case ENCRYTYPE::ENHANCE2://
	case ENCRYTYPE::ENHANCE3://
	case ENCRYTYPE::ENHANCE4://
		{
			return nPlainLength + nPlainLength / 8;
			break;
		}
	default:
		{
			return 0;
			break;
		}
	}//switch
	
	return 0;
}
//!	由加密类型和密文长度求取明文长度
int32_t XteSecIO::getPlainLengthByEncryLength(int32_t nEncryLength,uint8_t nEncryType)
{
	switch(nEncryType)
	{
	case ENCRYTYPE::NORMAL1://
	case ENCRYTYPE::NORMAL2://
	case ENCRYTYPE::NORMAL3://
	case ENCRYTYPE::NORMAL4://
	case ENCRYTYPE::FAST1://
	case ENCRYTYPE::FAST2://
	case ENCRYTYPE::FAST3://
	case ENCRYTYPE::FAST4://
	case ENCRYTYPE::SUPER1://
		{
			return nEncryLength;
			break;
		}
	case ENCRYTYPE::ENHANCE1://
	case ENCRYTYPE::ENHANCE2://
	case ENCRYTYPE::ENHANCE3://
	case ENCRYTYPE::ENHANCE4://
		{
			return  (nEncryLength / 9) * (int32_t)8 + nEncryLength % 9;
			break;
		}
	default:
		{
			return 0;
			break;
		}
	}//switch
	
	return 0;
}




//!	MD5加密(16位)
uint8_t* XteSecIO::MD5Encode16(const void * pPlainBuf,int32_t nPlainLength,uint8_t pEncryBuf[16])
{
	assert(pPlainBuf && nPlainLength >= 0);
//	static    MD5Context context;
//	MD5_Init(&context);
//	MD5_Update(&context,(unsigned char *)pPlainBuf,nPlainLength);
//	MD5_Final(&context,pEncryBuf);

	MD5_CTX context;
	MD5Init(&context);
	MD5Update(&context,(unsigned char *)pPlainBuf,nPlainLength);
	MD5Final(pEncryBuf,&context);
	return pEncryBuf;
}
char* XteSecIO::MD5EncodeToString32(const void * pPlainBuf,int32_t nPlainLength,char szEncryBuf[32],bool bLowerChar)
{
	uint8_t pEncryBuf[16];
	MD5Encode16(pPlainBuf,nPlainLength,pEncryBuf);
	if(bLowerChar)
	{
		sprintf(szEncryBuf,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);
	}//if
	else
	{
		sprintf(szEncryBuf,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);

	}
	return szEncryBuf;
}
char* XteSecIO::MD5EncodeToString33(const void * pPlainBuf,int32_t nPlainLength,char szEncryBuf[33],bool bLowerChar)
{
	MD5EncodeToString32(pPlainBuf,nPlainLength,szEncryBuf,bLowerChar);
	szEncryBuf[32] = '\0';
	return szEncryBuf;
}

bool		XteSecIO::MD5File16(const char * filename,uint8_t pEncryBuf[16])
{
	if(!MDFile(filename,pEncryBuf))
	{
		return false;
	}//if

	return true;
}
bool		XteSecIO::MD5FileToString32(const char * filename,char szEncryBuf[32],bool bLowerChar)
{
	uint8_t pEncryBuf[16];
	if(!MDFile(filename,pEncryBuf))
	{
		return false;
	}

	if(bLowerChar)
	{
		sprintf(szEncryBuf,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);
	}//if
	else
	{
		sprintf(szEncryBuf,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			pEncryBuf[0],pEncryBuf[1],pEncryBuf[2],pEncryBuf[3],pEncryBuf[4],pEncryBuf[5],pEncryBuf[6],pEncryBuf[7],
			pEncryBuf[8],pEncryBuf[9],pEncryBuf[10],pEncryBuf[11],pEncryBuf[12],pEncryBuf[13],pEncryBuf[14],pEncryBuf[15]);
		
	}
	return true;
}
bool		XteSecIO::MD5FileToString33(const char * filename,char szEncryBuf[33],bool bLowerChar)
{
	if(!MD5FileToString32(filename,szEncryBuf,bLowerChar))
	{
		return false;
	}//if
	szEncryBuf[32] = '\0';
	return true;
}
//-----------------------------------------------------------------------------


//--------------------------------------------------------------------------
//AES类接口
//!set aes key
int XteSecIO::aesSetKey(const void* pKey, int nKeyBitsLength,bool bConvertToMD5Key)
{
	return ::XtAesSetKey((AES_CONTEXT*)&m_AES,pKey,nKeyBitsLength,bConvertToMD5Key);
}
int XteSecIO::aesSetKeyByString(const char* pszKey,bool bConvertToMD5Key)
{
	return ::XtAesSetKeyByString((AES_CONTEXT*)&m_AES,pszKey,bConvertToMD5Key);
}
//!encrypt plaintext to ciphertext
void XteSecIO::aesEncrypt(const void* pPlainTextBuf, int nPlainTextLength,void* pCipherTextBuf)
{
	::XtAesEncrypt((const AES_CONTEXT*)&m_AES,pPlainTextBuf,nPlainTextLength,pCipherTextBuf);
}
int XteSecIO::aesEncryptString(const char* pszPlainTextBuf, char* pszCipherTextBuf)
{
	return ::XtAesEncryptString((const AES_CONTEXT*)&m_AES,pszPlainTextBuf,pszCipherTextBuf);
}
//!encrypt plaintext to ciphertext
void XteSecIO::aesDecrypt(const void* pCipherTextBuf, int nCipherTextLength,void* pPlainTextBuf)
{
	::XtAesDecrypt((const AES_CONTEXT*)&m_AES,pCipherTextBuf,nCipherTextLength,pPlainTextBuf);
}
int XteSecIO::aesDecryptString(const char* pszCipherTextBuf, char* pszPlainTextBuf,int nCipherTextBufLength)
{
	return ::XtAesDecryptString((const AES_CONTEXT*)&m_AES,pszCipherTextBuf,pszPlainTextBuf,nCipherTextBufLength);
}
//--------------------------------------------------------------------------

//------rsa begin---------------------------------------------------------------------------
//!	由指定密码产生rsa的自定义私钥和公钥
/*!
\return RSA加密参数,NULL表示失败
*/
void* XteSecIO::rsaCreateSPKey()
{
	if(!m_pRSA)
	{
		m_pRSA	= rsa_create_handle();
	}//if

	if(rsa_create_key(m_pRSA)==0)
	{
		return m_pRSA;
	}

	return NULL;
}
//!设置rsa密钥
int XteSecIO::rsaSetKeyByString(IN const char* pszSKey,IN const char* pszPKey)
{
	if(!m_pRSA)
	{
		m_pRSA	= rsa_create_handle();
	}//if
	return rsa_set_key(m_pRSA,pszSKey,pszPKey);
}
int XteSecIO::rsaSetKeyByBuf(IN const void* pSKey,IN int nSKeySize,IN const void* pPKey,IN int nPKeySize)
{
	if(!m_pRSA)
	{
		m_pRSA	= rsa_create_handle();
	}//if

	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;

	if(pSKey && nSKeySize != RSA_SKEY_SIZE)
	{
		return -1;
	}//if
	if(pPKey && nPKeySize != RSA_PKEY_SIZE)
	{
		return -1;
	}//if

	if(pSKey)
	{
		memcpy(p->abySKey,pSKey,nSKeySize);
		rsa_skey_byte2string(p->abySKey,p->szSKey);
	}//if
	if(pPKey)
	{
		memcpy(p->abyPKey,pPKey,nPKeySize);
		rsa_pkey_byte2string(p->abyPKey,p->szPKey);
	}//if

	return 0;

}

//!	取当前私钥(是自定义的字符串),返回长度为0的字符串表示还没有设置RSA密钥
string	XteSecIO::rsaGetSKey()const
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(p)
	{
		return string(p->szSKey);
	}//if
	return string("");
}
//!	取当前公钥(是自定义的字符串),返回长度为0的字符串表示还没有设置RSA密钥
string	XteSecIO::rsaGetPKey()const
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(p)
	{
		return string(p->szPKey);
	}//if
	return string("");
}
//!	取当前私钥字节内容(是通用的字节),返回NULL表示还没有设置RSA密钥
void*	XteSecIO::rsaGetSKeyBuf(OUT int * pnKeySize)const
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(p && p->szSKey[0])
	{
		if(pnKeySize)
		{
			*pnKeySize	= RSA_SKEY_SIZE;
		}//if
		return (void*)(p->abySKey);
	}//if

	if(pnKeySize)
	{
		*pnKeySize	= 0;
	}//if
	return NULL;
}
//!	取当前公钥字节内容(是通用的字节),返回NULL表示还没有设置RSA密钥
void*	XteSecIO::rsaGetPKeyBuf(OUT int * pnKeySize)const
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(p && p->szPKey[0])
	{
		if(pnKeySize)
		{
			*pnKeySize	= RSA_PKEY_SIZE;
		}//if
		return (void*)(p->abyPKey);
	}//if

	if(pnKeySize)
	{
		*pnKeySize	= 0;
	}//if
	return NULL;
}

//!encrypt plaintext to ciphertext
/*!
\return 密文实际长度,小于0表示失败,-1表示失败原因是rsaSetSKey()/rsaSetPKey()没有事先被调用,-2表示失败原因是密文buf长度不够
\param pPlainTextBuf:明文buf
\param nPlainTextLength:明文buf的长度
\param pCipherTextBuf:密文buf
\param nCipherTextBufLength:密文buf的最大长度,如果长度不足则会返回-2错误
\remarks
	建议用rsaEstimateMaxSize()先计算输出长度
*/
int XteSecIO::rsaSEncrypt(IN const void* pPlainTextBuf,IN int nPlainTextLength,OUT void* pCipherTextBuf,IN int nCipherTextBufLength)
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(!p || p->szSKey[0] == 0)
	{
		return -1;
	}//if

	int nOutputSize		= rsa_encrypt_by_skey(m_pRSA,pPlainTextBuf,nPlainTextLength,pCipherTextBuf);
	if(nOutputSize > 0 && nOutputSize <= nCipherTextBufLength)
	{
		return nOutputSize;
	}//if
	return -2;
}
int XteSecIO::rsaPEncrypt(IN const void* pPlainTextBuf,IN int nPlainTextLength,OUT void* pCipherTextBuf,IN int nCipherTextBufLength)
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(!p || p->szPKey[0] == 0)
	{
		return -1;
	}//if

	int nOutputSize		= rsa_encrypt_by_pkey(m_pRSA,pPlainTextBuf,nPlainTextLength,pCipherTextBuf);
	if(nOutputSize > 0 && nOutputSize <= nCipherTextBufLength)
	{
		return nOutputSize;
	}//if
	return -2;
}

//!encrypt plaintext to ciphertext
/*!
\return 明文实际长度,小于0表示失败,-1表示失败原因是rsaSetSKey()/rsaSetPKey()没有事先被调用,-2表示失败原因是明文buf长度不够,-3表示密文长度错误
\param pCipherTextBuf:密文buf
\param nCipherTextLength:密文buf的长度
\param pPlainTextBuf:明文buf
\param nPlainTextBufLength:明文buf的最大长度,如果长度不足则会返回-2错误
\remarks
	建议用rsaEstimateMaxSize()先计算输出长度
*/
int XteSecIO::rsaSDecrypt(IN const void* pCipherTextBuf,IN int nCipherTextLength,OUT void* pPlainTextBuf,IN int nPlainTextBufLength)
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(!p || p->szSKey[0] == 0)
	{
		return -1;
	}//if

	int nOutputSize		= rsa_decrypt_by_skey(m_pRSA,pCipherTextBuf,nCipherTextLength,pPlainTextBuf);
	if(nOutputSize > 0 && nOutputSize <= nPlainTextBufLength)
	{
		return nOutputSize;
	}//if
	return -2;
}
int XteSecIO::rsaPDecrypt(IN const void* pCipherTextBuf,IN int nCipherTextLength,OUT void* pPlainTextBuf,IN int nPlainTextBufLength)
{
	RSA_CONTEXT_FOR_API * p = (RSA_CONTEXT_FOR_API *)m_pRSA;
	if(!p || p->szPKey[0] == 0)
	{
		return -1;
	}//if

	int nOutputSize		= rsa_decrypt_by_pkey(m_pRSA,pCipherTextBuf,nCipherTextLength,pPlainTextBuf);
	if(nOutputSize > 0 && nOutputSize <= nPlainTextBufLength)
	{
		return nOutputSize;
	}//if
	return -2;
}

//!字符串之间的加密解密转换
/*!
\return 输出长度,返回-1表示失败
\param pszInput:带有结束符的字符串
\param strOutput:输出字符串对象
\remarks 
两者都是字符串,encrypt时,待加密的内容是字符串,加密结果是字节串,将其十六进制字符串化,decrypt时,一定是
encrypt得到的十六进制字符串,首先会还原成字节串,再解密成原来的明文字符串.
如果不是严格遵照上述规定,乱用decrypt则可能出现问题.
*/
int XteSecIO::rsaStringSEncrypt(const char * pszInput,string& strOutput)
{
	return rsa_string_encrypt_by_skey(m_pRSA,pszInput,strOutput);
}
int XteSecIO::rsaStringPEncrypt(const char * pszInput,string& strOutput)
{
	return rsa_string_encrypt_by_pkey(m_pRSA,pszInput,strOutput);
}
int XteSecIO::rsaStringSDecrypt(const char * pszInput,string& strOutput)
{
	return rsa_string_decrypt_by_skey(m_pRSA,pszInput,strOutput);
}
int XteSecIO::rsaStringPDecrypt(const char * pszInput,string& strOutput)
{
	return rsa_string_decrypt_by_pkey(m_pRSA,pszInput,strOutput);
}
//------rsa end-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//与游戏逻辑相关的一些加密算法，为了加强破解难度，以免代码泄密时很容易理解，本文中的代码注释去掉了，具体规则参见另外的文档说明
//!	计算ipseed
/*!
\return true为成功，false为失败
\param ipseed: 返回值ipseed，可以是16字节表示的MD5码或者32个字符表示的MD5码或者32个字符+1个结束符表示的字符串MD5码
\param bLowerChar: 是否需要把MD5码字符串以小写表示，false时则为大写
\param nIPv4: IPv4表示的标准互联网IP地址，为0表示由函数内部自动获取第一个IP地址
\remarks 
如果需要由函数内部自动获得IP地址，需要调用前初始化socket机制，否则无法获得IP地址。
目前只支持Windows和Linux系统获得IP地址。
*/
bool XteSecIO::gameGetIpseed16(unsigned char ipseed[16],unsigned int nIPv4)
{
	return ::XtGetIpseed16(ipseed,nIPv4);
}
bool XteSecIO::gameGetIpseed32(char ipseed[32],bool bLowerChar,unsigned int nIPv4)
{
	return ::XtGetIpseed32(ipseed,bLowerChar,nIPv4);
}
bool XteSecIO::gameGetIpseed33(char ipseed[33],bool bLowerChar,unsigned int nIPv4)
{
	return ::XtGetIpseed33(ipseed,bLowerChar,nIPv4);
}

//!	hupdate.exe传递token给hclient.exe的加密规则,返回缓冲区有效长度，请保证返回缓冲区够大
int XteSecIO::gameTokenToToken1(const char * szToken,char * szToken1,const char * szAllseed,const char szIpseed[33])
{
	return ::XtTokenToToken1(szToken,szToken1,szAllseed,szIpseed);
}
int XteSecIO::gameToken1ToToken(const char * szToken1,int nToken1ByteLength,char * szToken,const char * szAllseed,const char szIpseed[33])
{
	return ::XtToken1ToToken(szToken1,nToken1ByteLength,szToken,szAllseed,szIpseed);
}
//!	hclient.exe传递token给haccess_srv.exe和hctrl_srv.exe的加密规则,返回缓冲区有效长度，请保证返回缓冲区够大
int XteSecIO::gameTokenToToken2(const char * szToken,char * szToken2,const char * szAllseed,const char szSeed2[33])
{
	return ::XtTokenToToken2(szToken,szToken2,szAllseed,szSeed2);
}
int XteSecIO::gameToken2ToToken(const char * szToken2,int nToken2ByteLength,char * szToken,const char * szAllseed,const char szSeed2[33])
{
	return ::XtToken2ToToken(szToken2,nToken2ByteLength,szToken,szAllseed,szSeed2);
}
//!	hclient.exe传递token给gupdate.exe和gclient.exe的加密规则
int XteSecIO::gameTokenToToken3(const char * szToken,char * szToken3,const char * szAllseed,const char szSeed3[33],const char szIpseed[33])
{
	return ::XtTokenToToken3(szToken,szToken3,szAllseed,szSeed3,szIpseed);
}
int XteSecIO::gameToken3ToToken(const char * szToken3,int nToken3ByteLength,char * szToken,const char * szAllseed,const char szSeed3[33],const char szIpseed[33])
{
	return ::XtToken3ToToken(szToken3,nToken3ByteLength,szToken,szAllseed,szSeed3,szIpseed);
}
//!	gclient.exe传递token给gaccess_srv.exe的加密规则
int XteSecIO::gameTokenToToken4(const char * szToken,char * szToken4,const char * szAllseed,const char szSeed3[33])
{
	return ::XtTokenToToken4(szToken,szToken4,szAllseed,szSeed3);
}
int XteSecIO::gameToken4ToToken(const char * szToken4,int nToken4ByteLength,char * szToken,const char * szAllseed,const char szSeed3[33])
{
	return ::XtToken4ToToken(szToken4,nToken4ByteLength,szToken,szAllseed,szSeed3);
}

//!	hclient.exe传递sctoken给haccess_srv.exe和hctrl_srv.exe的加密规则
int XteSecIO::gameMakeSctoken(char szSctoken[33],const char * szAllseed,const char szSeed2[33],const char * szToken2,int nToken2ByteLength)
{
	return ::XtMakeSctoken(szSctoken,szAllseed,szSeed2,szToken2,nToken2ByteLength);
}

//!	haccess_srv.exe产生的seed及其衍生seedN规则
bool XteSecIO::gameMakeSeed0(char szSeed0[33])
{
	return ::XtMakeSeed0(szSeed0);
}
bool XteSecIO::gameMakeSeed1(char szSeed1[33],const char szSeed0[33],const char * szAllseed)
{
	return ::XtMakeSeed1(szSeed1,szSeed0,szAllseed);
}
bool XteSecIO::gameMakeSeed2(char szSeed2[33],const char szSeed1[33],const char * szAllseed)
{
	return ::XtMakeSeed2(szSeed2,szSeed1,szAllseed);
}
bool XteSecIO::gameMakeSeed3(char szSeed3[33],const char szSeed2[33],const char * szAllseed)
{
	return ::XtMakeSeed3(szSeed3,szSeed2,szAllseed);
}

//end: xuetian encrypt/decrypt algorithms
//-----------------------------------------------------------------------------

//other function
//!	将字节串转换为字符串
int XteSecIO::otherBytesToString(const void * pSrcBuf,int nSrcBufByteLength,char * szDestString,bool bLowerChar)
{
	return ::XtBytesToString(pSrcBuf,nSrcBufByteLength,szDestString,bLowerChar);
}
//!	将字符串转换为字节串
int XteSecIO::otherStringToBytes(const char * szSrcString,void * pDestBuf)
{
	return ::XtStringToBytes(szSrcString,pDestBuf);
}

//!	产生一个随机数
XTINT8	XteSecIO::otherRand8()
{
	if(RAND_MAX > 0x7FFF)
	{
		return (XTINT8)(otherRand32()%0x7F);
	}//if
	else
	{
		return (XTINT8)(otherRand16()%0x7F);
	}
}
XTINT16	XteSecIO::otherRand16()
{
	if(RAND_MAX > 0x7FFF)
	{
		return (XTINT16)(otherRand32()%0x7FFF);
	}//if
	else
	{
		int n1 = rand()%3;
		while(n1-- > 0)
		{
			rand();
		}//while
		return (XTINT16)rand();
	}
}
XTINT32	XteSecIO::otherRand32()
{
	int n1 = rand()%3;
	while(n1-- > 0)
	{
		rand();
	}//while

	if(RAND_MAX > 0x7FFF)
	{
		return (XTINT32)rand();
	}//if
	else
	{
		return (XTINT32)((rand() << 16) | rand());
	}
}
XTINT64	XteSecIO::otherRand64()
{
	XTINT32 n1	= otherRand32();
	XTUINT32 n2 = otherRandU32();
	return (((XTINT64)n1) << 32) | (XTINT64)n2;
}
XTUINT8	XteSecIO::otherRandU8()
{
	if(RAND_MAX > 0x7FFF)
	{
		return (XTUINT8)(otherRandU32()%0xFF);
	}//if
	else
	{
		return (XTUINT8)(otherRandU16()%0xFF);
	}
}
XTUINT16	XteSecIO::otherRandU16()
{
	if(RAND_MAX > 0x7FFF)
	{
		return (XTUINT16)(otherRandU32()%0xFFFF);
	}//if
	else
	{
		int n1 = rand()%3;
		while(n1-- > 0)
		{
			rand();
		}//while
		return (XTUINT16)(rand()+rand());
	}
}
XTUINT32	XteSecIO::otherRandU32()
{
	int n1 = rand()%3;
	while(n1-- > 0)
	{
		rand();
	}//while

	if(RAND_MAX > 0x7FFF)
	{
		return (XTUINT32)(rand()+rand());
	}//if
	else
	{
		return (XTUINT32)(rand() << 20 | rand() << 10 | rand());
	}
}
XTUINT64	XteSecIO::otherRandU64()
{
	XTUINT32 n1	= otherRandU32();
	XTUINT32 n2 = otherRandU32();
	return (((XTUINT64)n1) << 32) | (XTUINT64)n2;
}
float	XteSecIO::otherRandFloat()
{
	return (float)((((double)otherRandU32())-2147483648.0)/2147483648.0);
}

//!	产生随机字符串:全部为数字,全部为字母,数字字母混合
int XteSecIO::otherRandNumberString(OUT char * pszResult,IN int nValideSize)
{
	int i = 0;
	for(; i < nValideSize; ++i)
	{
		pszResult[i]	= '0'+(char)(otherRand32()%('9'-'0'+1));
	}//fori
	pszResult[i]	= 0;
	return nValideSize;
}
int XteSecIO::otherRandLetterString(OUT char * pszResult,IN int nValideSize,IN int nUpperLowerCaseFlag)
{
	if(nUpperLowerCaseFlag == 0)
	{//仅小写
		int i = 0;
		for(; i < nValideSize; ++i)
		{
			pszResult[i]	= 'a'+(char)(otherRand32()%('z'-'a'+1));
		}//fori
	}//if
	else if(nUpperLowerCaseFlag == 1)
	{//仅大写
		int i = 0;
		for(; i < nValideSize; ++i)
		{
			pszResult[i]	= 'A'+(char)(otherRand32()%('Z'-'A'+1));
		}//fori
	}//if
	else
	{//随机大小写
		int i = 0;
		for(; i < nValideSize; ++i)
		{
			if(rand()%2 == 0)
			{
				pszResult[i]	= 'a'+(char)(otherRand32()%('z'-'a'+1));
			}//if
			else
			{
				pszResult[i]	= 'A'+(char)(otherRand32()%('Z'-'A'+1));
			}
		}//fori
	}
	
	pszResult[nValideSize]	= 0;
	return nValideSize;
}
int XteSecIO::otherRandNumberLetterString(OUT char * pszResult,IN int nValideSize,IN int nUpperLowerCaseFlag)
{
	if(nUpperLowerCaseFlag == 0)
	{//仅小写
		int i = 0;
		for(; i < nValideSize; ++i)
		{
			if(rand()%2 == 0)
			{
				pszResult[i]	= 'a'+(char)(otherRand32()%('z'-'a'+1));
			}//if
			else
			{
				pszResult[i]	= '0'+(char)(otherRand32()%('9'-'0'+1));
			}
		}//fori
	}//if
	else if(nUpperLowerCaseFlag == 1)
	{//仅大写
		int i = 0;
		for(; i < nValideSize; ++i)
		{
			if(rand()%2 == 0)
			{
				pszResult[i]	= 'A'+(char)(otherRand32()%('Z'-'A'+1));
			}//if
			else
			{
				pszResult[i]	= '0'+(char)(otherRand32()%10);
			}
		}//fori
	}//if
	else
	{//随机大小写
		int i = 0;
		for(; i < nValideSize; ++i)
		{
			int n = rand()%3;
			if(n == 0)
			{
				pszResult[i]	= 'a'+(char)(otherRand32()%('z'-'a'+1));
			}//if
			else if(n == 1)
			{
				pszResult[i]	= 'A'+(char)(otherRand32()%('Z'-'A'+1));
			}//if
			else
			{
				pszResult[i]	= '0'+(char)(otherRand32()%('9'-'0'+1));
			}
		}//fori
	}

	pszResult[nValideSize]	= 0;
	return nValideSize;
}

//!	产生随机字符串:先产生N个字节数字,再将每个字节转换为16进制字母
int XteSecIO::otherRandBufHexString(OUT char * pszResult,IN int nBufByteSize,IN int nUpperLowerCaseFlag)
{
	char * p				= pszResult;
	int j					= 0;
	int i = 0;
	for(; i < nBufByteSize; ++i)
	{
		XTUINT8 n8			= otherRandU8();

		XTUINT8 n81			= n8 >> 4;
		if(n81 <= 9)
		{
			p[j]			= '0'+n81;	
		}//if
		else
		{
			if(nUpperLowerCaseFlag == 0)
			{
				p[j]		= 'a'+n81-10;
			}//if
			else if(nUpperLowerCaseFlag == 1)
			{
				p[j]		= 'A'+n81-10;
			}//if
			else
			{
				if(rand()%2 == 0)
				{
					p[j]	= 'a'+n81-10;
				}//if
				else
				{
					p[j]	= 'A'+n81-10;
				}
			}
		}
		j++;
		
		n81					= n8 & 0x0F;
		if(n81 <= 9)
		{
			p[j]			= '0'+n81;	
		}//if
		else
		{
			if(nUpperLowerCaseFlag == 0)
			{
				p[j]		= 'a'+n81-10;
			}//if
			else if(nUpperLowerCaseFlag == 1)
			{
				p[j]		= 'A'+n81-10;
			}//if
			else
			{
				if(rand()%2 == 0)
				{
					p[j]	= 'a'+n81-10;
				}//if
				else
				{
					p[j]	= 'A'+n81-10;
				}
			}
		}
		j++;
	}//fori

	p[j]					= 0;
	return j;
}	
//!	产生随机buf:每个字节都是随机数字
int XteSecIO::otherRandBuf(OUT void * pBuf,IN int nBufSize)
{
	XTUINT8 * p = (XTUINT8 *)pBuf;
	int i = 0;
	for(; i < nBufSize; ++i)
	{
		*p = otherRandU8();
	}//fori
	return nBufSize;
}
//-----------------------------------------------------------------------------
