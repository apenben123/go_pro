//-------------------------------------------------------------*-C++-*---------
//	版本号 1.0
//-----------------------------------------------------------------------------
//	文件名: ext_sec_io.h
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
//	成学文		20150127		增加rsa非对称密钥算法
//-----------------------------------------------------------------------------

#ifndef _XTESECIO_H_FILE_
#define _XTESECIO_H_FILE_

//#include "mod_ext/mod_ext.h"
#include "stdafx.h"
#include "XtMacros.h"
#include "iostream"
#include "fstream"

#if (defined WIN32) || (defined WIN64)
typedef char_t XTINT8;
typedef int16_t XTINT16;
typedef int32_t XTINT32;
typedef int64_t XTINT64;
typedef uchar_t XTUINT8;
typedef uint16_t XTUINT16;
typedef uint32_t XTUINT32;
typedef uint64_t XTUINT64;
#endif

using namespace std;
//-----------------------------------------------------------------------------
//! 安全读写类
//-----------------------------------------------------------------------------
/*!
0.该类包括了文件加密读写/网络数据包加解密/基本加解密算法等功能.
1.通过该类的read()/write()函数来实现加密文件读写操作.
2.通过该类的netPackEncode()/netPackDecode()函数来实现网络数据包加解密操作.
3.通过该类的aesEncrypt()/aesDecrypt()函数来实现aes算法加解密操作.
4.通过该类的MD5EncodeToString33()/MD5FileToString33()函数来实现对缓冲区和文件计算MD5.
5.通过该类的otherBytesToString()/otherStringToBytes()函数来实现缓冲区与字符串之间的互相转换.
*/
//-----------------------------------------------------------------------------
class XteSecIO
{
public:
	//!	加密类型
	struct ENCRYTYPE
	{
		enum
		{
			//-------------------------------------------------------------------------
			BEGIN					= 1,

			//基本加密类型
			NORMAL_BEGIN			= BEGIN,
			//!	普通1
			NORMAL1					= NORMAL_BEGIN+0,
			//!	普通2
			NORMAL2					= NORMAL_BEGIN+1,
			//!	普通3
			NORMAL3					= NORMAL_BEGIN+2,
			//!	普通4
			NORMAL4					= NORMAL_BEGIN+3,
			NORMAL_END				= NORMAL4,
			NORMAL_COUNT			= NORMAL_END - NORMAL_BEGIN + 1,

			FAST_BEGIN				= NORMAL_END + 1,
			//!	快速1
			FAST1					= FAST_BEGIN+0,
			//!	快速2
			FAST2					= FAST_BEGIN+1,
			//!	快速3
			FAST3					= FAST_BEGIN+2,
			//!	快速4
			FAST4					= FAST_BEGIN+3,
			FAST_END				= FAST4,	
			FAST_COUNT				= FAST_END - FAST_BEGIN + 1,

			ENHANCE_BEGIN			= FAST_END + 1,
			//!	增强1(采用动态密码自定义算法)
			ENHANCE1				= ENHANCE_BEGIN+0,
			//!	增强2
			ENHANCE2				= ENHANCE_BEGIN+1,			
			//!	增强3
			ENHANCE3				= ENHANCE_BEGIN+2,
			//!	增强4
			ENHANCE4				= ENHANCE_BEGIN+3,
			ENHANCE_END				= ENHANCE4,
			ENHANCE_COUNT			= ENHANCE_END - ENHANCE_BEGIN + 1,

			SUPER_BEGIN				= ENHANCE_END + 1,
			//!	超级增强1(采用动态密码AES算法)
			SUPER1					= SUPER_BEGIN+0,
			SUPER_END				= 4,
			SUPER_COUNT				= SUPER_END - SUPER_BEGIN + 1,

			END						= ENHANCE_END,
			COUNT					= END - BEGIN + 1,
			//-------------------------------------------------------------------------

			//-------------------------------------------------------------------------
			//以下是一些数据包的建议类型
			//!	客户端向服务端发送的登录数据包
			LOGIN					= SUPER1,
			//!	客户端向服务端发送的普通数据包
			CTOS					= NORMAL1,
			
			//!	服务端向客户端发送的普通数据包
			STOC					= NORMAL1,

			//!	目录服务端向客户端发送数据包
			DIRSRVTOC				= STOC,

			//!	接入服务端向客户端发送数据包
			ACESSSRVTOC				= STOC,
			//!	接入服务端向登录服务器发送数据包
			ACESSSRVTOACCOUNTSRV	= FAST1,
			//!	接入服务端向主逻辑服务器发送数据包
			ACESSSRVTOMAINSRV		= FAST1,
			//!	接入服务端向辅助逻辑服务器发送数据包
			ACESSSRVTOAUXSRV		= FAST1,
			//!	接入服务端向目录服务器发送数据包
			ACESSSRVTODIRSRV		= FAST1,

			//!	web服务器向帐号数据库服务器发送数据包
			WEBSRVTODBSRV			= ENHANCE1,

			//!	登录服务器向帐号数据库服务器发送数据包
			ACCOUNTSRVTODBSRV		= ENHANCE1,

			//!	帐号数据库服务器向登录服务器发送数据包
			DBSRVTOACCOUNTSRV		= ENHANCE1,
			//!	帐号数据库服务器向web服务器发送数据包
			DBSRVTOWEBSRV			= ENHANCE1,

			//!	主服务器向接入服务器发送数据包
			MAINSRVTOACCESSSRV		= STOC,
			//!	主服务器向辅助服务器发送数据包
			MAINSRVTOAUXSRV			= FAST2,
			//!	主服务器向聊天服务器发送数据包
			MAINSRVTOCHATSRV		= FAST2,
			//!	主服务器向数据库路由服务器发送数据包
			MAINSRVTODBRSRV			= FAST2,

			//!	辅助服务器向接入服务器发送数据包
			AUXSRVTOACCESSSRV		= STOC,
			//!	辅助服务器向主服务器发送数据包
			AUXSRVTOMAINSRV			= FAST2,
			//!	辅助服务器向数据库路由服务器发送数据包
			AUXSRVTODBRSRV			= FAST2,

			//!	聊天服务器向接入服务器发送数据包
			CHATSRVTOACCESSSRV		= STOC,
			//!	聊天服务器向主服务器发送数据包
			CHATSRVTOMAINSRV		= FAST2,
			//!	聊天服务器向数据库路由服务器发送数据包
			CHATSRVTODBRSRV			= FAST2,

			//!	数据库路由服务器向主服务器发送数据包
			DBRSRVTOMAINSRV			= FAST2,
			//!	数据库路由服务器向辅助服务器发送数据包
			DBRSRVTOAUXSRV			= FAST2,
			//!	数据库路由服务器向聊天服务器发送数据包
			DBRSRVTOCHATSRV			= FAST2,
			//!	数据库路由服务器向数据库服务器发送数据包
			DBRSRVTODBSRV			= FAST2,

			//!	数据库服务器向数据库路由服务器发送数据包
			DBSRVTODBRSRV			= FAST2,
			//-------------------------------------------------------------------------

		};
	};
public:
	//-------------------构造与析构--------------------------------------------
public:
	//!	构造与析构
	/*!
	\param const XteSecIO & src:被拷贝的对象，注意此处不会拷贝对象的锁定次数
	\sa operator=()
	\sa set()
	*/
	XteSecIO();
	XteSecIO(const XteSecIO & src);
	virtual ~XteSecIO();

	//---------------------初始化与释放内存------------------------------------
private:
	//!	初始化本对象，建议每个类都设计初始化函数，在构造时首先调用init()函数
	/*!
	\sa free()
	*/
	void init();
public:
	//!
	//!	释放内存，建议每个类都设计内存释放函数，在析构时调用free()函数
	/*!
	\sa init()
	*/
	virtual void free();
	//-------------------一般操作----------------------------------------------
public:
	//!	复制操作符重载，即拷贝一个对象的内容到本对象
	/*!
	\param const XteSecIO & src:被拷贝的对象，注意此处不会拷贝对象的锁定次数。
	\remarks 一般的派生类需要重载。
	\sa set()
	*/
	virtual void operator=(const XteSecIO & src);

	//!	拷贝一个对象的内容到本对象
	/*!
	\param const XteSecIO & src:被拷贝的对象，注意此处不会拷贝对象的锁定次数。
	\remarks 一般的派生类需要重载。
	\sa operator=()
	*/
	virtual void set(const XteSecIO & src);
	//-------------------------------------------------------------------------

	//------自定义加密算法begin-------------------------------------------------------------------
public:
	//!	设置加强型加密算法的加密种子
	/*!
	\return 返回实际设置的加密种子指针,如果加密种子原始数据为字符串,则返回值也一定为字符串
	\param pKeySeedBuf:加密种子原始指针,建议总是设置字符串作为种子,这样比较方便跟踪种子,但字符串不是必须的
	\param nKeySeedBufLength:pKeySeedBuf缓冲区长度,必须小于等于pKeySeedBuf实际长度
	\param pszKeySeed:以'\0'结束的加密种子原始字符串
	\remarks 
	建议总是设置字符串作为种子,这样比较方便跟踪种子,但字符串不是必须的.
	一般的,无须调用本函数,就可以调用增强型加密算法. 只有特殊控制的情况下
	才需要调用本函数设定特殊的加密种子.若需要变更加密种子,建议先调用getKeySeedBuf()
	和getKeySeedLength()获得原有加密种子,保存下来,特殊控制完成之后,调用setKeySeed()
	恢复到原来的种子,否则,数据的交换性会大大降低,很容易导致文件读写出错.
	*/
	static const void * setKeySeed(const void * pKeySeedBuf,int nKeySeedBufLength);
	static const char * setKeySeedByString(const char * pszKeySeed);
	//!	取当前加强型加密算法的加密种子指针
	static const void * getKeySeedBuf();
	//!	取当前加强型加密算法的加密种子长度
	static int getKeySeedLength();
private:
//-----------------------------------------------------------------------------
	//网络数据包加密与解密
//-----------------------------------------------------------------------------
public:
	//!	网络数据包加密
	/*!
	\return 成功返回true，失败返回false
	\param nCheckCode:加密之后返回的校验码
	\param pPlainBuf:明文缓冲区，不得为空
	\param nPlainLength:明文缓冲区长度
	\param pEncryBuf:密文缓冲区，预先分配好，足够密文使用，否则加密会失败，不得为空
	\param nEncryLength:密文缓冲区长度，传入的是密文缓冲的可用最大长度，传出时是密文的真正长度
	\param nEncryType:加密类型
	\param pBuf:明文和密文缓冲区是同一个缓冲区，且长度总是相等，如果使用的加密类型不是等长度的将失败，不得为空
	\param nLength:明文和密文缓冲区的长度
	\param pSecIO:AES加密参数设置的本类对象实例,当nEncryType == ENCRYTYPE::SUPER1时,pSecIO必须不为空
	\remarks 
	1.加密类型不对或者密文缓冲区不够长则失败，其它情况都应该成功；\n
	2.明文和密文都是一个缓冲区要求加密类型为非增强类型，且不支持多线程。
	\sa ENCRYTYPE netPackDecode()
	*/
	static bool netPackEncode(uint8_t & nCheckCode,const void * pPlainBuf,int32_t nPlainLength,void * pEncryBuf,int32_t & nEncryLength,uint8_t nEncryType = ENCRYTYPE::NORMAL1,XteSecIO * pSecIO = NULL);
	static bool netPackEncode(uint8_t & nCheckCode,void * pBuf,int32_t nLength,uint8_t nEncryType = ENCRYTYPE::NORMAL1,XteSecIO * pSecIO = NULL);

	//!	网络数据包解密
	/*!
	\return 成功返回true，失败返回false
	\param nCheckCode:传入封包时返回的校验码
	\param pPlainBuf:明文缓冲区，预先分配好，足够明文使用，否则解密会失败，不得为空
	\param nPlainLength:明文缓冲区长度，传入的是明文缓冲的可用最大长度，传出时是明文的真正长度
	\param pEncryBuf:密文缓冲区，不得为空
	\param nEncryLength:密文缓冲区长度
	\param nEncryType:加密类型，必须保持封包一致
	\param pBuf:明文和密文缓冲区是同一个缓冲区，且长度总是相等，如果使用的加密类型不是等长度的将失败，不得为空
	\param nLength:明文和密文缓冲区的长度
	\param pSecIO:AES加密参数设置的本类对象实例,当nEncryType == ENCRYTYPE::SUPER1时,pSecIO必须不为空
	\remarks 
	1.加密类型不对、名文缓冲区不够长、校验码不对则失败，其它情况都应该成功；\n
	2.明文和密文都是一个缓冲区要求加密类型为非增强类型，且不支持多线程。
	\sa ENCRYTYPE netPackEncode()
	*/
	static bool netPackDecode(uint8_t nCheckCode,const void * pEncryBuf,int32_t nEncryLength,void * pPlainBuf,int32_t & nPlainLength,uint8_t nEncryType,XteSecIO * pSecIO = NULL);
	static bool netPackDecode(uint8_t nCheckCode,void * pBuf,int32_t nLength,uint8_t nEncryType,XteSecIO * pSecIO = NULL);

	//!	判断一种加密类型是否为等长加密
	static bool isEqualLengthEncryType(uint8_t nEncryType);
	//!	判断一种加密类型是否合理
	static bool isEncryTypeOK(uint8_t nEncryType);
	//!	随机给出一个数字，返回最为接近的加密类型
	static uint8_t getEncryTypeByNumber(uint32_t dwNum);
	//!	由加密类型和明文长度求取密文长度
	static int32_t getEncryLengthByPlainLength(int32_t nPlainLength,uint8_t nEncryType);
	//!	由加密类型和密文长度求取明文长度
	static int32_t getPlainLengthByEncryLength(int32_t nEncryLength,uint8_t nEncryType);
	//------自定义加密算法end-------------------------------------------------------------------

	//------md5 begin---------------------------------------------------------------------------
public:
	//!	计算MD5码(16BYTE)
	/*!
	\return 密文指针,失败返回false
	\param pPlainBuf:明文缓冲区,不得为空
	\param nPlainLength:明文长度,不得小于0,如果明文缓冲区是字符串的话,本值应该
	是字符串的普通长度,即不包括字符串结束符在内的长度
	\param pEncryBuf:密文缓冲区,一定是16个字节,不能保证最后一个字节是0
	\param szEncryBuf:密文缓冲区,一定是32个字符,即MD5 16个字节的16进制的字符串
	表示szEncryBuf的每个字符串都是0~F,szEncryBuf[31]并不是结束符'\0',所以,szEncryBuf
	本身不是一个完整的字符串,如果该字符串长度大于等于33,则可以把szEncryBuf[32]置为
	字符串结束符'\0',这样szEncryBuf就是完整的字符串了.
	\param bLowerChar:字符串是否小写
	\param filename:文件名
	\remarks 
	1.MD5的加密结果是以16个字节串描述的,提供字符串密文结果是为了方便字符串操作
	的程序使用,但是,16个字节的16进制字符串描述是32个0~F字符,所以szEncryBuf[32]
	的字符串结束符'\0'是靠调用的代码自己控制的,而szEncryBuf[33]会自动在最后一个
	字符设置为字符串结束符'\0',从而得到完整的字符串
	*/
	static uint8_t*	MD5Encode16(const void * pPlainBuf,int32_t nPlainLength,uint8_t pEncryBuf[16]);
	static char*	MD5EncodeToString32(const void * pPlainBuf,int32_t nPlainLength,char szEncryBuf[32],bool bLowerChar = true);
	static char*	MD5EncodeToString33(const void * pPlainBuf,int32_t nPlainLength,char szEncryBuf[33],bool bLowerChar = true);

	static bool		MD5File16(const char * filename,uint8_t pEncryBuf[16]);
	static bool		MD5FileToString32(const char * filename,char szEncryBuf[32],bool bLowerChar = true);
	static bool		MD5FileToString33(const char * filename,char szEncryBuf[33],bool bLowerChar = true);
	//------md5 end-----------------------------------------------------------------------------

	//------aes begin---------------------------------------------------------------------------
	//AES加密
private:
	//!	定义一个与AES加密参数结构体(AES_CONTEXT)完全一样的结构体
	struct AES_DADA
	{
		//aes key length: 4*4bytes(128bits) or 6*4bytes(192bits) or 8*4bytes(256bits)
		uint32_t  aes_key_4bytes_len;
		//aes encrypt key
		uint32_t  aes_e_key[64];
		//aes decrypt key
		uint32_t  aes_d_key[64];
	};
	//!	当前类对象保存的AES加密参数
	AES_DADA m_AES;
public:
	//!set aes key
	/*!
	1.aes key must be 4*4bytes(128bits) or 6*4bytes(192bits) or 8*4bytes(256bits)
	2.if the pKey/pszKey is not 4/6/8bytes, it will convert to nearest big length, e.g if (int32_t)strlen(pszKey)=20, then it will convert to 6*4bytes=192bits key
	3.return the real key bits length, e.g aesSetKey("01234567890123456789"), return 192.
	4.must aesSetKey() before call aesEncrypt() and aesDecrypt()
	5.pszKey is null terminated
	*/
	int aesSetKey(const void* pKey, int nKeyBitsLength,bool bConvertToMD5Key = false);
	int aesSetKeyByString(const char* pszKey,bool bConvertToMD5Key = false);

	//!encrypt plaintext to ciphertext
	/*!
	1.aesEncryptString return the ciphertext length. Usually, it is not equal to (int32_t)strlen(pszCipherTextBuf).
	2.pCipherTextBuf's buffer length must >= pPlainTextBuf's buffer length (nPlainTextLength), because the plaintext's length is equal to the ciphertext's length
	3.pszPlainTextBuf and pszCipherTextBuf are null terminated
	4.note: It is not safe to use aesEncryptString()/aesDecryptString() with default parameters,
	besause aesEncryptString() return pszCipherTextBuf maybe not a null-terminated string buffer,
	pszPlainTextBuf's all bytes maybe not-0 but the last bytes, but its cipher buffer maybe some 
	0 bytes somewhere. So, recommand safely code like:
	...
	int nCipherTextBufLength	= aesEncryptString(pszPlainTextBuf,pszCipherTextBuf);
	...
	int nPlainTextBufLength		= aesDecryptString(pszCipherTextBuf,pszPlainTextBuf,nCipherTextBufLength);
	...
	*/
	void aesEncrypt(const void* pPlainTextBuf, int nPlainTextLength,void* pCipherTextBuf);
	int aesEncryptString(const char* pszPlainTextBuf, char* pszCipherTextBuf);

	//!encrypt plaintext to ciphertext
	/*!
	1.aesDecryptString return the plaintext length.
	2.pPlainTextBuf's buffer length must >= pCipherTextBuf's buffer length (nCipherTextLength), because the plaintext's length is equal to the ciphertext's length
	3.pszPlainTextBuf and pszCipherTextBuf are null terminated
	4.note: It is not safe to use aesEncryptString()/aesDecryptString() with default parameters,
	besause aesEncryptString() return pszCipherTextBuf maybe not a null-terminated string buffer,
	pszPlainTextBuf's all bytes maybe not-0 but the last bytes, but its cipher buffer maybe some 
	0 bytes somewhere. So, recommand safely code like:
	...
	int nCipherTextBufLength	= aesEncryptString(pszPlainTextBuf,pszCipherTextBuf);
	...
	int nPlainTextBufLength		= aesDecryptString(pszCipherTextBuf,pszPlainTextBuf,nCipherTextBufLength);
	...
	*/
	void aesDecrypt(const void* pCipherTextBuf, int nCipherTextLength,void* pPlainTextBuf);
	int aesDecryptString(const char* pszCipherTextBuf, char* pszPlainTextBuf,int nCipherTextBufLength);
	//------aes end-----------------------------------------------------------------------------


	//------rsa begin---------------------------------------------------------------------------
public:
	//!	当前类对象保存的RSA加密参数
	void * m_pRSA;
public:
	//!	由指定密码产生rsa的自定义私钥和公钥
	/*!
	\return RSA加密参数,NULL表示失败
	*/
	void* rsaCreateSPKey();

	//!设置rsa密钥
	/*!
	\return 0表示设置成功,否则是错误码,-1表示失败
	\param pszSKey:自定义的私钥字符串,必须由rsaGenSPKey产生而来的
	\param pszPKey:自定义的公钥字符串,必须由rsaGenSPKey产生而来的
	\param pSKey:通用的私钥字节
	\param nSKeySize:通用的私钥字节数
	\param pPKey:通用的公钥字节
	\param nPKeySize:通用的公钥字节数
	\remarks
	调用rsaSEncrypt()/rsaSDecrypt()之前必须rsaSetSKey()成功才能成功
	自定义的密钥一定是字符串形式,目前是采用1024bit(128Byte)作为大整数长度,而原始私钥采用8个大整数,
	钥采用2个大整数,故原始的私钥是1024字节,公钥是256字节,但是,为了使用方便,我们会将字节数据转换为
	十六进制的字符串,即字符串私钥是2048字符加上1个字符串结束符,字符串公钥是512字符加上1个字符串结束符,
	故所有对内私钥是1024字节,对内公钥是256字节,对外私钥是2048字符串,对外公钥是512字符串.
	*/
	int rsaSetKeyByString(IN const char* pszSKey,IN const char* pszPKey);
	int rsaSetKeyByBuf(IN const void* pSKey,IN int nSKeySize,IN const void* pPKey,IN int nPKeySize);

	//!	取当前私钥(是自定义的字符串),返回长度为0的字符串表示还没有设置RSA密钥
	string	rsaGetSKey()const;
	//!	取当前公钥(是自定义的字符串),返回长度为0的字符串表示还没有设置RSA密钥
	string	rsaGetPKey()const;
	//!	取当前私钥字节内容(是通用的字节),返回NULL表示还没有设置RSA密钥
	void*	rsaGetSKeyBuf(OUT int * pnKeySize=0)const;
	//!	取当前公钥字节内容(是通用的字节),返回NULL表示还没有设置RSA密钥
	void*	rsaGetPKeyBuf(OUT int * pnKeySize=0)const;

	//!	根据输入数据长度预估rsa加密解密的最大长度(字节长度,不是转换字符串长度,转换字符串长度应该翻倍再加1字节结束符)
	/*!
	\return 预估rsa加密加密之后的最大长度(字节长度,不是转换字符串长度,转换字符串长度应该翻倍再加1字节结束符)
	\param nInputDataSize:输入数据长度
	\remarks 
	这个长度可能比实际长度要大很多,但可以用这个函数预先分配足够大的内存来存放输出数据
	*/
	int		rsaEstimateMaxSize(int nInputDataSize)const;

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
	int rsaSEncrypt(IN const void* pPlainTextBuf,IN int nPlainTextLength,OUT void* pCipherTextBuf,IN int nCipherTextBufLength);
	int rsaPEncrypt(IN const void* pPlainTextBuf,IN int nPlainTextLength,OUT void* pCipherTextBuf,IN int nCipherTextBufLength);

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
	int rsaSDecrypt(IN const void* pCipherTextBuf,IN int nCipherTextLength,OUT void* pPlainTextBuf,IN int nPlainTextBufLength);
	int rsaPDecrypt(IN const void* pCipherTextBuf,IN int nCipherTextLength,OUT void* pPlainTextBuf,IN int nPlainTextBufLength);
	
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
	int rsaStringSEncrypt(const char * pszInput,string& strOutput);
	int rsaStringPEncrypt(const char * pszInput,string& strOutput);
	int rsaStringSDecrypt(const char * pszInput,string& strOutput);
	int rsaStringPDecrypt(const char * pszInput,string& strOutput);
	//------rsa end-----------------------------------------------------------------------------

	//------xtgame encrypt/decrypt begin---------------------------------------------------------------------------
	//与游戏逻辑相关的一些加密算法，为了加强破解难度，以免代码泄密时很容易理解，本文中的代码注释去掉了，具体规则参见另外的文档说明
public:
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
	static bool gameGetIpseed16(unsigned char ipseed[16],unsigned int nIPv4 = 0);
	static bool gameGetIpseed32(char ipseed[32],bool bLowerChar = true,unsigned int nIPv4 = 0);
	static bool gameGetIpseed33(char ipseed[33],bool bLowerChar = true,unsigned int nIPv4 = 0);

	//!	hupdate.exe传递token给hclient.exe的加密规则,返回缓冲区有效长度，请保证返回缓冲区够大
	static int gameTokenToToken1(const char * szToken,char * szToken1,const char * szAllseed,const char szIpseed[33]);
	static int gameToken1ToToken(const char * szToken1,int nToken1ByteLength,char * szToken,const char * szAllseed,const char szIpseed[33]);
	//!	hclient.exe传递token给haccess_srv.exe和hctrl_srv.exe的加密规则,返回缓冲区有效长度，请保证返回缓冲区够大
	static int gameTokenToToken2(const char * szToken,char * szToken2,const char * szAllseed,const char szSeed2[33]);
	static int gameToken2ToToken(const char * szToken2,int nToken2ByteLength,char * szToken,const char * szAllseed,const char szSeed2[33]);
	//!	hclient.exe传递token给gupdate.exe和gclient.exe的加密规则
	static int gameTokenToToken3(const char * szToken,char * szToken3,const char * szAllseed,const char szSeed3[33],const char szIpseed[33]);
	static int gameToken3ToToken(const char * szToken3,int nToken3ByteLength,char * szToken,const char * szAllseed,const char szSeed3[33],const char szIpseed[33]);
	//!	gclient.exe传递token给gaccess_srv.exe的加密规则
	static int gameTokenToToken4(const char * szToken,char * szToken4,const char * szAllseed,const char szSeed3[33]);
	static int gameToken4ToToken(const char * szToken4,int nToken4ByteLength,char * szToken,const char * szAllseed,const char szSeed3[33]);

	//!	hclient.exe传递sctoken给haccess_srv.exe和hctrl_srv.exe的加密规则
	static int gameMakeSctoken(char szSctoken[33],const char * szAllseed,const char szSeed2[33],const char * szToken2,int nToken2ByteLength);

	//!	haccess_srv.exe产生的seed及其衍生seedN规则
	static bool gameMakeSeed0(char szSeed0[33]);
	static bool gameMakeSeed1(char szSeed1[33],const char szSeed0[33],const char * szAllseed);
	static bool gameMakeSeed2(char szSeed2[33],const char szSeed1[33],const char * szAllseed);
	static bool gameMakeSeed3(char szSeed3[33],const char szSeed2[33],const char * szAllseed);

	//------xtgame encrypt/decrypt end---------------------------------------------------------------------------

//-----other begin------------------------------------------------------------------------
	//other function
public:
	//!	将字节串转换为字符串
	/*!
	\return 字符串字符数量（不包括结束符）
	\param pSrcBuf:源字节缓冲区
	\param nSrcBufByteLength:源字节缓冲区的以字节为单位的长度
	\param szDestString:目标字符串，缓冲区长度必须大于等于2*nSrcBufByteLength+1，其中szDestString[2*nSrcBufByteLength]=='\0'
	\param bLowerChar:返回的字符串是否转换为小写，false则为大写
	*/
	static int otherBytesToString(const void * pSrcBuf,int nSrcBufByteLength,char * szDestString,bool bLowerChar = true);
	//!	将字符串转换为字节串
	/*!
	\return 字节串有效长度，一般为(int32_t)strlen(szSrcString)/2
	\param szSrcString:源字符串缓冲区，里面通过(int32_t)strlen(szSrcString)来确定长度，最后的结束符不转换为字节串数值
	\param pDestBuf:目标字节串缓冲区，缓冲区长度必须大于等于(int32_t)strlen(szSrcString)/2
	\remarks
	源字符串缓冲区必须是由XtBytesToString转换而来或者其它明确途径转换而来的长度
	为双数且每个字符都是一个16进制字符的字符串，否则转换没有意义
	*/
	static int otherStringToBytes(const char * szSrcString,void * pDestBuf);

	//!	产生一个随机数
	/*!
	\return 0~2^8,0~2^16,0~2^32,0~2^64之间的整数,otherRandFloat()返回[-1.0,+1.0]之间的小数
	\remarks 
	1.因为担心os的随机数被人破解,这是自定义的随机数函数,借助系统rand()函数,但重新组合了.
	2.效率比系统rand函数低.
	3.调用之前请确保srand()被调用过,即保证rand()函数是可用的.
	*/
	static XTINT8	otherRand8();
	static XTINT16	otherRand16();
	static XTINT32	otherRand32();
	static XTINT64	otherRand64();
	static XTUINT8	otherRandU8();
	static XTUINT16	otherRandU16();
	static XTUINT32	otherRandU32();
	static XTUINT64	otherRandU64();
	static float	otherRandFloat();

	//!	产生随机字符串:全部为数字,全部为字母,数字字母混合
	/*!
	\return 随机字符串的字节(字符)数,不包括字符串结束符NULL,一定是nValideSize
	\param pszResult:随机字符串结果,以NULL结束
	\param nValideSize:pszResult的有效长度,即字符串结束符NULL字节之前的长度,即pszResult的字节数减一
	\param nUpperLowerCaseFlag:字母大小写控制,0:仅小写;1仅大写,2随机大小写
	*/
	static int otherRandNumberString(OUT char * pszResult,IN int nValideSize);
	static int otherRandLetterString(OUT char * pszResult,IN int nValideSize,IN int nUpperLowerCaseFlag = 0);
	static int otherRandNumberLetterString(OUT char * pszResult,IN int nValideSize,IN int nUpperLowerCaseFlag = 0);

	//!	产生随机字符串:先产生N个字节数字,再将每个字节转换为16进制字母
	/*!
	\return 随机字符串的字节(字符)数,不包括字符串结束符NULL,一定是nBufByteSize*2
	\param pszResult:随机字符串结果,以NULL结束
	\param nBufByteSize:需要产生的字节数量,而pszResult的长度必须>=nBufByteSize*2+1
	\param nUpperLowerCaseFlag:字母大小写控制,0:仅小写;1仅大写,2随机大小写
	*/
	static int otherRandBufHexString(OUT char * pszResult,IN int nBufByteSize,IN int nUpperLowerCaseFlag = 0);
	
	//!	产生随机buf:每个字节都是随机数字
	/*!
	\return 随机字节数,不包括字符串结束符NULL,一定是nBufSize
	\param pBuf:随机字节串结果,没有结束符
	\param nBufSize:需要产生的字节数量,也即pBuf的长度
	*/
	static int otherRandBuf(OUT void * pBuf,IN int nBufSize);
//------other end-----------------------------------------------------------------------
};

//-------------------------------------------------------------------------
//	Added by cxw,2007:2:8. 加密算法测试
//-------------------------------------------------------------------------
#if 0
void main()
{
	//all argorithms test
	int i = 0;
	for(;i < 25;i++)
	{
		TRACE(_T("----------------------%i begin---------------------------------\n"),i);

		//get encry type
		uint8_t nEncryType = XteSecIO::getEncryTypeByNumber(i);
		TRACE(_T("nEncryType=0X%02X\n"),nEncryType);

		TRACE(_T("XteSecIO::isEncryTypeOK()=%d\n"),XteSecIO::isEncryTypeOK(nEncryType)?1:0);
		TRACE(_T("XteSecIO::isEqualLengthEncryType()=%d\n"),XteSecIO::isEqualLengthEncryType(nEncryType)?1:0);

		//create plain buffer
		uint8_t pPlainBuf[200];
		int nPlainLength = 100;
		int j = 0;
		srand(time(NULL));
		TRACE(_T("pPlainBuf=0X"));
		for(;j < 100;j++)
		{
			pPlainBuf[j] = rand() % 256;
			TRACE(_T("%02X "),pPlainBuf[j]);
		}//for j
		TRACE(_T("\n"));
		
		//create encry buffer
		uint8_t pEncryBuf[200];
		int nEncryLength = 200;

		//encode
		uint8_t nCheckCode = 0;
		if(!XteSecIO::netPackEncode(nCheckCode,pPlainBuf,nPlainLength,pEncryBuf,nEncryLength,nEncryType))
		{
			TRACE(_T("XteSecIO::netPackEncode(nCheckCode,pPlainBuf,nPlainLength,pEncryBuf,nEncryLength,nEncryType) failed\n"));
			continue;
		}//if

		TRACE(_T("------------------------------\n"));
		TRACE(_T("result for XteSecIO::netPackEncode(nCheckCode,pPlainBuf,nPlainLength,pEncryBuf,nEncryLength,nEncryType):\n"));
		TRACE(_T("nEncryType=0X%02X\n"),nEncryType);
		TRACE(_T("nCheckCode=0X%02X\n"),nCheckCode);
		TRACE(_T("nPlainLength=%d\n"),nPlainLength);
		TRACE(_T("nEncryLength=%d\n"),nEncryLength);
		
		TRACE(_T("pPlainBuf=0X"));
		for(j = 0;j < nPlainLength;j++)
		{
			TRACE(_T("%02X "),pPlainBuf[j]);
		}//for j
		TRACE(_T("\n"));

		TRACE(_T("pEncryBuf=0X"));
		for(j = 0;j < nEncryLength;j++)
		{
			TRACE(_T("%02X "),pEncryBuf[j]);
		}//for j
		TRACE(_T("\n"));
		TRACE(_T("------------------------------\n"));

		//decode
		memset(pPlainBuf,0,nPlainLength);
		if(!XteSecIO::netPackDecode(nCheckCode,pEncryBuf,nEncryLength,pPlainBuf,nPlainLength,nEncryType))
		{
			TRACE(_T("XteSecIO::netPackDecode(nCheckCode,pEncryBuf,nEncryLength,pPlainBuf,nPlainLength,nEncryType) failed\n"));
			continue;
		}//if

		TRACE(_T("------------------------------\n"));
		TRACE(_T("result for XteSecIO::netPackDecode(nCheckCode,pPlainBuf,nPlainLength,pEncryBuf,nEncryLength,nEncryType):\n"));
		TRACE(_T("nEncryType=0X%02X\n"),nEncryType);
		TRACE(_T("nCheckCode=0X%02X\n"),nCheckCode);
		TRACE(_T("nPlainLength=%d\n"),nPlainLength);
		TRACE(_T("nEncryLength=%d\n"),nEncryLength);
		
		TRACE(_T("pPlainBuf=0X"));
		for(j = 0;j < nPlainLength;j++)
		{
			TRACE(_T("%02X "),pPlainBuf[j]);
		}//for j
		TRACE(_T("\n"));

		TRACE(_T("pEncryBuf=0X"));
		for(j = 0;j < nEncryLength;j++)
		{
			TRACE(_T("%02X "),pEncryBuf[j]);
		}//for j
		TRACE(_T("\n"));
		TRACE(_T("------------------------------\n"));

		//encode
		nCheckCode = 0;
		memcpy(pEncryBuf,pPlainBuf,nPlainLength);
		nEncryLength = nPlainLength;
		if(!XteSecIO::netPackEncode(nCheckCode,pEncryBuf,nEncryLength,nEncryType))
		{
			TRACE(_T("XteSecIO::netPackEncode(nCheckCode,pEncryBuf,nEncryLength,nEncryType) failed\n"));
			continue;
		}//if

		TRACE(_T("------------------------------\n"));
		TRACE(_T("result for XteSecIO::netPackEncode(nCheckCode,pEncryBuf,nEncryLength,nEncryType):\n"));
		TRACE(_T("nEncryType=0X%02X\n"),nEncryType);
		TRACE(_T("nCheckCode=0X%02X\n"),nCheckCode);
		TRACE(_T("nPlainLength=%d\n"),nPlainLength);
		TRACE(_T("nEncryLength=%d\n"),nEncryLength);
		
		TRACE(_T("pPlainBuf=0X"));
		for(j = 0;j < nPlainLength;j++)
		{
			TRACE(_T("%02X "),pPlainBuf[j]);
		}//for j
		TRACE(_T("\n"));

		TRACE(_T("pEncryBuf=0X"));
		for(j = 0;j < nEncryLength;j++)
		{
			TRACE(_T("%02X "),pEncryBuf[j]);
		}//for j
		TRACE(_T("\n"));
		TRACE(_T("------------------------------\n"));

		//decode
		memcpy(pPlainBuf,pEncryBuf,nEncryLength);
		if(!XteSecIO::netPackDecode(nCheckCode,pPlainBuf,nPlainLength,nEncryType))
		{
			TRACE(_T("XteSecIO::netPackDecode(nCheckCode,pPlainBuf,nPlainLength,nEncryType) failed\n"));
			continue;
		}//if
		
		TRACE(_T("------------------------------\n"));
		TRACE(_T("result for XteSecIO::netPackDecode(nCheckCode,pPlainBuf,nPlainLength,nEncryType):\n"));
		TRACE(_T("nEncryType=0X%02X\n"),nEncryType);
		TRACE(_T("nCheckCode=0X%02X\n"),nCheckCode);
		TRACE(_T("nPlainLength=%d\n"),nPlainLength);
		TRACE(_T("nEncryLength=%d\n"),nEncryLength);
		
		TRACE(_T("pPlainBuf=0X"));
		for(j = 0;j < nPlainLength;j++)
		{
			TRACE(_T("%02X "),pPlainBuf[j]);
		}//for j
		TRACE(_T("\n"));

		TRACE(_T("pEncryBuf=0X"));
		for(j = 0;j < nEncryLength;j++)
		{
			TRACE(_T("%02X "),pEncryBuf[j]);
		}//for j
		TRACE(_T("\n"));
		TRACE(_T("------------------------------\n"));


		TRACE(_T("----------------------%i end---------------------------------\n"),i);
		
	}//for i

	//time test
	{
		//create plain buffer
		uint8_t pPlainBuf[200];
		int nPlainLength = 100;
		int j = 0;
		srand(time(NULL));
		TRACE(_T("pPlainBuf=0X"));
		for(;j < 100;j++)
		{
			pPlainBuf[j] = rand() % 256;
			TRACE(_T("%02X "),pPlainBuf[j]);
		}//for j
		TRACE(_T("\n"));
		
		//create encry buffer
		uint8_t pEncryBuf[200];
		int nEncryLength = 200;
		
		//encode
		uint8_t nCheckCode = 0;

		int i = 0;
		for(;i < 24;i++)
		{
			uint8_t nEncryType = (uint8_t)i;
			if(!XteSecIO::isEncryTypeOK(nEncryType))
			{
				continue;
			}//if

			DWORD dwT0 = ::GetTickCount();
			int j = 0;
			for(;j < 10000;j++)
			{
				nEncryLength = 200;
				if(!XteSecIO::netPackEncode(nCheckCode,pPlainBuf,nPlainLength,pEncryBuf,nEncryLength,nEncryType))
				{
					TRACE(_T("XteSecIO::netPackEncode(nCheckCode,pPlainBuf,nPlainLength,pEncryBuf,nEncryLength,nEncryType) failed\n"));
					continue;
				}//if
				if(!XteSecIO::netPackDecode(nCheckCode,pEncryBuf,nEncryLength,pPlainBuf,nPlainLength,nEncryType))
				{
					TRACE(_T("XteSecIO::netPackDecode(nCheckCode,pEncryBuf,nEncryLength,pPlainBuf,nPlainLength,nEncryType) failed\n"));
					continue;
				}//if
			}//for j
			DWORD dwT1 = ::GetTickCount();

			CString str;
			str.Format(_T("i=%d,nEncryType=%d, two buffers encode/decode 10000 times toltal time=%dms\n"),i,nEncryType,dwT1 - dwT0);
//			AfxMessageBox(str);
			TRACE(str);
			

			dwT0 = ::GetTickCount();
			j = 0;
			for(;j < 10000;j++)
			{
				nEncryLength = 200;
				if(!XteSecIO::netPackEncode(nCheckCode,pPlainBuf,nPlainLength,nEncryType))
				{
//					TRACE(_T("XteSecIO::netPackEncode(nCheckCode,pPlainBuf,nPlainLength,pEncryBuf,nEncryLength,nEncryType) failed\n"));
					continue;
				}//if
				if(!XteSecIO::netPackDecode(nCheckCode,pPlainBuf,nPlainLength,nEncryType))
				{
//					TRACE(_T("XteSecIO::netPackDecode(nCheckCode,pEncryBuf,nEncryLength,pPlainBuf,nPlainLength,nEncryType) failed\n"));
					continue;
				}//if
			}//for j
			dwT1 = ::GetTickCount();


			TRACE(_T("i=%d,nEncryType=%d, one buffers encode/decode 10000 times toltal time=%dms\n"),i,nEncryType,dwT1 - dwT0);
		}//for i
	}

	//MD5 TEST
	if(1)
	{
		uint8_t abyResult[16];

		char szStr[10][100] = 
		{
			"",
			"0",
			"0123456789",
			"a",
			"abcdefghijklmnopqrstuvwxyz",
			"Abcdefghijklmnopqrstuvwxyz",
			"w-900.ibm.com/cn/servers/eserver/produc ",
			"源代码 来源:技术资料中心 发布会员:新书城收集整理 发布时间:2006-7-",
			"having the form [ – ]d.dddd e [sign]ddd where ",
			"源代码 站点:爱心种子小博士 关键字:的MD5加密算法源代码 的MD5加",
		};

		int i = 0;
		for(;i < 10;i++)
		{
			TRACE("\nplaintext%d=",i);
			TRACE(szStr[i]);

			int nLength = sizeof(szStr[i]);
			memset(abyResult,0,16);
			XteSecIO::MD5Encode16(szStr[i],nLength,abyResult);
			TRACE("\nmd5result%d=0X",i);
			int j = 0;
			for(;j < 16;j++)
			{
				TRACE("%02X ",abyResult[j]);
			}//for j

			memset(abyResult,0,16);
			XteSecIO::MD5EncodeToString16(szStr[i],nLength,(char*)abyResult);
			TRACE("\nmd5 string result%d=%s",i,abyResult);
		}//for i
	}

	//test aes
	if(1)
	{
		XteSecIO sio;
		sio.aesSetKeyByString("mypwd123456");
		string strData0		= "测试数据ABC";
		string strData1;
		strData1.resize(strData0.size());
		sio.aesEncryptString(strData0.data(),(char*)strData1.data());
		string strData2;
		strData2.resize(strData1.size());
		sio.aesDecryptString(strData1.data(),(char*)strData2.data(),(int)strData1.size());
		assert(strData2 == strData0);
	}//if

	//test rsa
	if(1)
	{
		XteSecIO sio;
		sio.rsaCreateSPKey();
		string strSKey		= sio.rsaGetSKey();
		string strPKey		= sio.rsaGetPKey();
		int nSKeyLen = 0,nPKeyLen = 0;
		void * pSKey		= sio.rsaGetSKeyBuf(&nSKeyLen);
		void * pPKey		= sio.rsaGetPKeyBuf(&nPKeyLen);
		void * pSKey1		= malloc(nSKeyLen);
		void * pPKey1		= malloc(nPKeyLen);
		memcpy(pSKey1,pSKey,nSKeyLen);
		memcpy(pPKey1,pPKey,nPKeyLen);
		string strData0		= "测试数据ABC";
		sio.rsaSetKeyByString(strSKey.data(),strPKey.data());
		string strSKey2		= sio.rsaGetSKey();
		string strPKey2		= sio.rsaGetPKey();
		int nSKeyLen2 = 0,nPKeyLen2 = 0;
		void * pSKey20		= sio.rsaGetSKeyBuf(&nSKeyLen2);
		void * pPKey20		= sio.rsaGetPKeyBuf(&nPKeyLen2);
		void * pSKey2		= malloc(nSKeyLen2);
		void * pPKey2		= malloc(nPKeyLen2);
		memcpy(pSKey2,pSKey20,nSKeyLen2);
		memcpy(pPKey2,pPKey20,nPKeyLen2);
		assert(nSKeyLen2 == nSKeyLen && nPKeyLen2 == nPKeyLen && memcmp(pSKey2,pSKey1,nSKeyLen2) == 0 && memcmp(pPKey2,pPKey1,nPKeyLen2) == 0 && strSKey2 == strSKey && strPKey2 == strPKey);
		free(pSKey1);free(pPKey1);free(pSKey2);free(pPKey2);
		string strData1;
		sio.rsaStringSEncrypt(strData0.data(),strData1);
		string strData2;
		sio.rsaStringPDecrypt(strData1.data(),strData2);
		assert(strData2 == strData0);
		string strData3;
		sio.rsaStringPEncrypt(strData0.data(),strData3);
		string strData4;
		sio.rsaStringSDecrypt(strData3.data(),strData4);
		assert(strData4 == strData0);
	}//if
}
#endif//#if 0
//-------------------------------------------------------------------------
#endif //#ifndef _XTESECIO_H_FILE_
