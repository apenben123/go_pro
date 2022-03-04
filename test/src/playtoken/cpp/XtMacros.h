//-------------------------------------------------------------*-C++-*---------
//	版本号 1.0
//-----------------------------------------------------------------------------
//	文件名: XtMacros.h
//-----------------------------------------------------------------------------
//	版权所有 (C) 2004-2010，金的团队和雪天公司各自独立享有版权。
//	保留所有版权，未经授权，任何单位和个人不得擅自复制、使用本成果。
//-----------------------------------------------------------------------------
//	金的开发组、雪天公司: 
//	
//	修改人员			修改日期			修改内容
//
//	成学文			1999.10			初步设计
//	成学文			2000.02			第一次修订
//	成学文			2000.08			第二次修订
//	成学文			2001.02			第三次修订
//	成学文			2001.08			第四次修订
//	成学文			2002.08			第五次修订
//	成学文			2003.08			第六次修订
//	成学文			2004.02			标准化版本
//	成学文			2009.02			移植到雪天公司
//	成学文			2012.06			移植到homed(本来是不需要的,但是为了方便移植其它代码,就把这个文件移植过来了)
//-----------------------------------------------------------------------------
//	包括本模块最基本的宏定义和类型定义。
//-----------------------------------------------------------------------------

#if defined(WIN32) || defined (WIN64)
#pragma once
#endif

#ifndef _XTMACROS_H_FILE_
#define _XTMACROS_H_FILE_

#if !defined(WIN32) && !defined (WIN64)

#ifndef LINUX
#define LINUX
#endif

#ifndef LINUX64
#define LINUX64
#endif

#ifndef XTLINUX
#define XTLINUX
#endif

#ifndef LINUX_SERVER
#define LINUX_SERVER
#endif


#endif 

//-----------------------------------------------------------------------------
//	去掉一些警告	
#pragma warning(disable:4786)//warning C4786: std::vector: identifier was truncated to '255' characters in the debug information
#pragma warning(disable:4251)//warning C4251: 'CLASS_TEST::m_structs' : class 'std::vector<_Ty>' needs to have dll-interface to be used by clients of class ‘CLASS_TEST’
#pragma warning(disable:4275)//warning C4275: non dll-interface class 'Tsu::pt_Symbol' used as base for dll-interface class 'Dyn::dsel_ModelObject'
#pragma warning(disable:4103)//warning C4103: 'd:\vss\code\ltvc2008\base\include\xtstl\stl\_cprolog.h' : alignment changed after including header, may be due to missing #pragma pack(pop)
#pragma warning(disable:4018)//warning C4018: '<' : signed/unsigned mismatch
#pragma warning(disable:4717)//warning C4717: recursive on all control paths, function will cause runtime stack overflow
#pragma warning(disable:4353)//warning C4353: nonstandard extension used: constant 0 as function expression.  Use '__noop' function intrinsic instead
#pragma warning(disable:4996)//warning C4996: 'sprintf': This function or variable may be unsafe. Consider using sprintf_s instead. To disable deprecation, use _CRT_SECURE_NO_WARNINGS.
//-----------------------------------------------------------------------------

//!	遇到编译器不支持的代码时,是否立即终止编译(正式发布时应该由工程设置指定比较好)
#define XT_STOP_WHEN_OS_NOT_SUPPORT
//-----------------------------------------------------------------------------

//	c标准库
//#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <assert.h>

//	标准STL 
#include <cmath>
#include <algorithm> 
#include <deque>
#include <fstream>
#include <functional>
#include <iterator> 
#include <list>
#include <map>
#include <memory>
#include <numeric>
#include <queue>
#include <set>
#include <stack>  
#include <utility>
#include <vector>  
#include <string>
#include <sstream>
#ifndef WIN32
#include <ext/hash_map>
#include <ext/hash_set>
#else
#include <hash_map>
#include <hash_set>
#endif

using namespace std;
#ifdef LINUX
using   namespace   __gnu_cxx;//需要引入 
#endif


#if 0//def WIN32
using namespace stdext;
#endif


#ifdef WIN32
#include <tchar.h>
#endif//#ifdef WIN32
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//!	cpu定义
//	X86 CUP
#define XT_CUP_X86				0x00000001

#define XT_CUP_TYPE				XT_CUP_X86
//-----------------------------------------------------------------------------
//!	编译器定义（操作系统定义）
//	Windows 32bit(Windows 9x,WinNT ,Win2000,Windows XP,Windows CE,Windows ME),Windows 64bit,Linux 32bit,Linux 64bit
#if defined(WIN32) || defined (_WIN32) || defined (_W32)
	#define XTWIN32
#endif //#if defined(WIN32) || defined (_WIN32) || defined (_W32)

#if defined(WIN64) || defined (_WIN64) || defined (_W64)
	#define XTWIN64
#endif //#if defined(WIN64) || defined (_WIN64) || defined (_W64)

#if defined(LINUX) || defined (LINUX32) || defined (_LINUX) || defined (_LINUX32)
	#define XTLINUX32
#endif //#if defined(LINUX) || defined (LINUX32) || defined (_LINUX) || defined (_LINUX32)

#if defined (LINUX64) || defined (_LINUX64)
	#define XTLINUX64
#endif //#if defined (LINUX64) || defined (_LINUX64)

//!	Windows
#if defined(XTWIN32) || defined (XTWIN64)
	#ifndef XTWINDOWS
		#define XTWINDOWS
	#endif
#endif //#if defined(XTWIN32) || defined (XTWIN64)

//!	Linux
#if defined(XTLINUX32) || defined(XTLINUX64)
	#ifndef XTLINUX
		#define XTLINUX
	#endif
#endif //#if defined(LINUX)
//-----------------------------------------------------------------------------
//!	字节顺序定义
//	小端
#define XT_LITTLE_ENDIAN				0x00000001
//	大端
#define XT_BIG_ENDIAN					0x00000010

#if XT_CUP_TYPE==XT_CUP_X86//||XT_CUP_TYPE==XT_CUP_X86
#define XT_BYTE_ORDER					XT_LITTLE_ENDIAN
#else
#define XT_BYTE_ORDER					XT_BIG_ENDIAN
#endif

//-----------------------------------------------------------------------------
//!	操作系统位数定义
#if defined(XTWIN64) || defined(XTLINUX64)
	#define XTOSBIT_64
#elif defined(XTWIN32) || defined(XTLINUX32)
	#define XTOSBIT_32
#endif

#if defined(XTOSBIT_8)
	#define XT_OS_BIT						8
#elif defined(XTOSBIT_16)
	#define XT_OS_BIT						16
#elif defined(XTOSBIT_32)
	#define XT_OS_BIT						32
#elif defined(XTOSBIT_64)
	#define XT_OS_BIT						64
#else
	#define XT_OS_BIT						32
#endif//#ifdef XTOSBIT_64
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//!	UINCODE定义
#if defined(UNICODE) || defined(_UNICODE)
	#define XTUNICODE
	#ifdef WIN32
		#pragma message("UNICODE/_UNICODE/XTUNICODE is defined")
	#else
		#warning("UNICODE/_UNICODE/XTUNICODE is defined")
	#endif//#ifdef WIN32
#else
	#ifdef WIN32
		//#pragma message("UNICODE/_UNICODE/XTUNICODE is not defined")
	#else
		//#warning("UNICODE/_UNICODE/XTUNICODE is not defined")
	#endif//#ifdef WIN32
	
#endif//#if defined(UNICODE) || defined(_UNICODE)
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	基本数据类型定义

//#define XT_USE_HIGH_PRECISION
//!	基本类型精度控制
#ifdef XT_USE_HIGH_PRECISION
	typedef int								XtInt;
	typedef unsigned long					XtUInt;
	typedef double							XtFloat;
#else	
	typedef int								XtInt;
	typedef unsigned int					XtUInt;
	typedef float							XtFloat;
#endif	//#ifdef XT_USE_HIGH_PRECISION

	
//!	TCHAR定义	
#ifdef XTUNICODE
	typedef unsigned short					XTTCHAR;
	typedef unsigned short					XTUTCHAR;
#else
	typedef char							XTTCHAR;
	typedef unsigned char					XTUTCHAR;
#endif//#ifdef XTUNICODE
	
//!	不带精度的基本类型
typedef bool								XtBool;
typedef char								XtChar;
typedef unsigned char						XtUChar;
typedef short								XTSHORT;
typedef unsigned short						XtUShort;
typedef long								XtLong;
typedef unsigned long						XtULong;
typedef double								XtDouble;
typedef void*								XtAny;

//!	大写基本类型
typedef int									XTBOOL;
typedef unsigned char						XTBYTE;
typedef unsigned short						XTWORD;
typedef unsigned int						XTDWORD;

typedef XtChar								XTCHAR;
typedef XTSHORT								XTSHORT;
typedef XtInt								XTINT;
typedef XtLong								XTLONG;
typedef XtFloat								XTFLOAT;
typedef XtDouble							XTDOUBLE;

typedef XtUChar								XTUCHAR;
typedef XtUShort							XTUSHORT;
typedef XtUInt								XTUINT;
typedef XtULong								XTULONG;

typedef void*								XTPOSITION;
typedef void*								XTHANDLE;

typedef void*								XTLPVOID;
typedef void*								LPXTVOID;
typedef unsigned							XTUNSIGNED;
   
typedef XTHANDLE							XTHGLOBAL;
typedef XTUINT								XTWPARAM;
typedef XTLONG								XTLPARAM;
typedef XTLONG								XTLRESULT;

//!	整型定义
typedef char								XTINT8;
typedef short								XTINT16;
typedef int									XTINT32;

#ifdef XTWIN32
typedef __int64								XTINT64;
#elif defined(XTLINUX)
#include <stdint.h>
typedef int64_t								XTINT64;
#endif//

typedef unsigned char						XTUINT8;
typedef unsigned short						XTUINT16;
typedef unsigned int						XTUINT32;

#ifdef XTWIN32
typedef unsigned __int64					XTUINT64;
#elif defined(XTLINUX)
#include <stdint.h>
typedef  uint64_t							XTUINT64;
#endif//

typedef XTINT8								XTI8;
typedef XTINT16								XTI16;
typedef XTINT32								XTI32;
typedef XTINT64								XTI64;	
typedef XTUINT8								XTU8;
typedef XTUINT16							XTU16;
typedef XTUINT32							XTU32;
typedef XTUINT64							XTU64;	

//!	指针转换成整型
#if XT_OS_BIT==8
	typedef XTUINT8							XTPTRTYPE;
#elif XT_OS_BIT==16
	typedef XTUINT16						XTPTRTYPE;
#elif XT_OS_BIT==32
	typedef XTUINT32						XTPTRTYPE;
#elif XT_OS_BIT==64
	typedef XTUINT64						XTPTRTYPE;
#else
	typedef XTUINT32						XTPTRTYPE;
#endif

typedef XTPTRTYPE							XTPT;

//!	宽字节串
typedef unsigned short						XTWCHAR;
//typedef wchar_t								XTWCHAR;


//!	与字符串相关的几个定义
//-------------------------------------
//	UNICODE
typedef XTWCHAR			*LPXTWCHAR,	*PXTWCHAR,	*LPXTWCH,	*PXTWCH,	*LPXTWSTR,	*PXTWSTR,	*XTNWPSTR;
typedef const XTWCHAR	*LPXTCWCHAR,*PXTCWCHAR,	*LPXTCWCH,	*PXTCWCH,	*LPXTCWSTR, *PXTCWSTR,	*XTCNWPSTR;
//-------------------------------------
//	ASCII
typedef XTCHAR			*LPXTCHAR,	*PXTCHAR,	*LPXTCH,	*PXTCH,		*LPXTSTR,	*PXTSTR,	*XTNPSTR;
typedef const XTCHAR	*LPXTCCHAR,	*PXTCCHAR,	*LPXTCCH,	*PXTCCH,	*LPXTCSTR,	*PXTCSTR,	*XTCNPSTR;
//-------------------------------------
//	TCHAR
typedef XTTCHAR			*LPXTTCHAR,	*PXTTCHAR,	*LPXTTCH,	*PXTTCH,	*LPXTTSTR,	*PXTTSTR,	*XTNTPSTR;
typedef const XTTCHAR	*LPXTCTCHAR,*PXTCTCHAR,	*LPXTCTCH,	*PXTCTCH,	*LPXTCTSTR, *PXTCTSTR,	*XTCNTPSTR;
//-------------------------------------

//!	小写常量
#define XtFalse								false
#define XtTrue								true

//!	大写常量
#define XTTRUE								1
#define XTFALSE								0
#define XTNULL								0

//!	回调函数
#define XTPASCAL							__stdcall
#define XTCALLBACK							__stdcall


//!	长短指针
#define Xtfar 
#define Xtnear
#define XTFAR								Xtfar
#define XTNEAR								Xtnear

//!	坐标精度控制
#ifdef XT_USE_HIGH_PRECISION
	typedef double							XtPos;		//!<图形系统坐标类型
	typedef double							XtDim;		//!<图形系统长度类型，必须与坐标类型一致
	typedef float							XtTPa;		//!<图形系统坐标变换矩阵参数类型
#else	
	typedef int								XtPos;		//!<图形系统坐标类型
	typedef int								XtDim;		//!<图形系统长度类型，必须与坐标类型一致
	typedef float							XtTPa;		//!<图形系统坐标变换矩阵参数类型
#endif	//#ifdef XT_USE_HIGH_PRECISION

//-----------------------------------------------------------------------------
//!	对象属性描述字段类型定义
	
#ifdef XT_USE_HIGH_PRECISION	
	//!	ID
	typedef XTINT64								XTID;
	//!	超大ID
	typedef XTINT64								XTHUGEID;
	
	//!	索引
	typedef XTINT64								XTINDEX;
	//!	超大索引
	typedef XTINT64								XTHUGEINDEX;
	
	//!	大小
	typedef XTINT64								XTCOUNT;
	
	//!	数值
	typedef XTINT64								XTVALUE;
	//!	超大数值
	typedef XTINT64								XTHUGEVALUE;
	//!	大数值
	typedef XTINT32								XTBIGVALUE;
	//!	小数值
	typedef XTINT16								XTLITTLEVALUE;
	//!	超小数值
	typedef XTINT8								XTTINYVALUE;
	
	//!	百分数
	typedef double								XTPERCENT;
	//!	大值百分数
	typedef double								XTBIGPERCENT;
	//!	小值百分数
	typedef float								XTTINYPERCENT;
	
	//!	标志
	typedef XTINT64								XTSIGN;
	//!	超大标志
	typedef XTINT64								XTHUGESIGN;
	//!	超小标志
	typedef XTUINT8								XTTINYSIGN;
	
	//!	类型
	typedef XTINT64								XTTYPE;
	//!	超大类型
	typedef XTINT64								XTHUGETYPE;
	//!	大类型
	typedef XTUINT32							XTBIGTYPE;
	//!	小类型
	typedef XTUINT16							XTLITTLETYPE;
	//!	超小类型
	typedef XTUINT8								XTTINYTYPE;
#else	
	//!	ID,最多40亿,注意节约使用
	typedef XTUINT32							XTID;
	//!	超大ID
	typedef XTINT64								XTHUGEID;

	//!	索引
	typedef XTINT32								XTINDEX;
	//!	超大索引
	typedef XTINT64								XTHUGEINDEX;

	//!	大小
	typedef XTINT32								XTCOUNT;

	//!	数值
	typedef XTINT32								XTVALUE;
	//!	超大数值
	typedef XTINT64								XTHUGEVALUE;
	//!	大数值
	typedef XTINT32								XTBIGVALUE;
	//!	小数值
	typedef XTINT16								XTLITTLEVALUE;
	//!	超小数值
	typedef XTINT8								XTTINYVALUE;

	//!	百分数
	typedef XTINT32								XTPERCENT;
	//!	大值百分数
	typedef XTINT32								XTBIGPERCENT;
	//!	小值百分数
	typedef XTINT8								XTTINYPERCENT;


	//!	标志
	typedef XTDWORD								XTSIGN;
	//!	超大标志
	typedef XTINT64								XTHUGESIGN;
	//!	超小标志
	typedef XTUINT8								XTTINYSIGN;

	//!	类型
	typedef XTDWORD								XTTYPE;
	//!	超大类型
	typedef XTINT64								XTHUGETYPE;
	//!	大类型
	typedef XTUINT32							XTBIGTYPE;
	//!	小类型
	typedef XTUINT16							XTLITTLETYPE;
	//!	超小类型
	typedef XTUINT8								XTTINYTYPE;

#endif	//#ifdef XT_USE_HIGH_PRECISION

//! 时间类型非常特殊
#if defined(XT_USE_HIGH_PRECISION) || (XT_OS_BIT==64)
	//!	一般时间
	typedef XTINT64								XTTIME;
	//!	超大时间
	typedef XTINT64								XTHUGETIME;
	//!	毫秒为单位的时间
	typedef XTINT64								XTMSTIME;
	//!	超大毫秒为单位的时间
	typedef XTINT64								XTHUGEMSTIME;
	//!	秒为单位的时间
	typedef XTINT64								XTSTIME;
	//!	超大秒为单位的时间
	typedef XTINT64								XTHUGESTIME;
#else
	//!	一般时间,注意表示范围
	typedef XTINT32								XTTIME;
	//!	超大时间
	typedef XTINT64								XTHUGETIME;
	//!	毫秒为单位的时间,只能表示49/2天
	typedef XTINT32								XTMSTIME;
	//!	超大毫秒为单位的时间
	typedef XTINT64								XTHUGEMSTIME;
	//!	秒为单位的时间,只能表示136/2年
	typedef XTINT32								XTSTIME;
	//!	超大秒为单位的时间
	typedef XTINT64								XTHUGESTIME;
#endif//
//-----------------------------------------------------------------------------

//!	字符串的UNICODE与ASCII兼容
#ifndef XTTCHAR_RELATION_DEFINED

	//!	TCHAR 的相关定义
	#define XTTCHAR_RELATION_DEFINED

	//!	ASCII转为UNICODE
	#define XTDBTEXT(x)							L ## x
	//!	ASCII转为ASCII
	#define XTTEXT(x)							x

	#ifdef XTUNICODE
		#ifndef __T
			#define __T							XTDBTEXT
		#endif//#ifndef __T
		#ifndef _T
			#define _T							XTDBTEXT
		#endif//#ifndef _T
	#else
		#ifndef __T
			#define __T							XTTEXT
		#endif//#ifndef __T
		#ifndef _T
			#define _T							XTTEXT
		#endif//#ifndef _T
	#endif//#ifdef XTUNICODE

	#define XTTCHAR_ARG			XTTCHAR
	#define XTWCHAR_ARG			XTWCHAR
	#define XTCHAR_ARG			char
	#define XTDOUBLE_ARG		double

	#define XTFORCE_ANSI		0x10000
	#define XTFORCE_UNICODE		0x20000
	#define XTFORCE_INT64		0x40000

#endif//#ifndef XTTCHAR_RELATION_DEFINED
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//!	与游戏相关的一些类型定义
//!	经验值
//typedef XTCOUNT								XTEXP;
typedef double								XTEXP;
//!	金钱
typedef XTCOUNT								XTMONEY;
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	基本宏定义

//!	未知量
#define XT_UNKNOWN   						-1  
//-----------------------------------------------------------------------------
//!	两个字节组合成一个字,a为低字节,b为高字节
#define XTMAKEWORD(a,b)						((XTWORD)(((XTBYTE)(a)) | ((XTWORD) ((XTBYTE)(b))) << 8))
//!	两个字组合成一个双字,a为低字,b为高字
#define XTMAKELONG(a,b)						((XTLONG)(((XTWORD)(a)) | ((XTDWORD)((XTWORD)(b))) << 16))
#define XTMAKEDWORD(a,b)					((XTDWORD)(((XTWORD)(a))| ((XTDWORD)((XTWORD)(b))) << 16))
//!	取一个双字的低字
#define XTLOWORD(l)							((XTWORD)(l))
//!	取一个双字的高字
#define XTHIWORD(l)							((XTWORD)(((XTDWORD)(l) >> 16) & 0xFFFF))
//!	取一个字的低字节
#define XTLOBYTE(w)							((XTBYTE)(w))
//!	取一个字的高字节
#define XTHIBYTE(w)							((XTBYTE)(((XTWORD)(w) >> 8) & 0xFF))
//!	取一个双字右边的第1个字节,dw应该为双字
#define XTGETDWORDBYTE1(dw)					XTLOBYTE(XTLOWORD(dw))
//!	取一个双字右边的第2个字节,dw应该为双字
#define XTGETDWORDBYTE2(dw)					XTHIBYTE(XTLOWORD(dw))
//!	取一个双字右边的第3个字节,dw应该为双字
#define XTGETDWORDBYTE3(dw)					XTLOBYTE(XTHIWORD(dw))
//!	取一个双字右边的第4个字节,dw应该为双字
#define XTGETDWORDBYTE4(dw)					XTHIBYTE(XTHIWORD(dw))
//-----------------------------------------------------------------------------
//!	检查a中是否含有b,a,b一般为XTBYTE/short/int/long/XTWORD/XTDWORD等整型类型
#define XTHAS(a,b)							(((a) & (b))?true:false)
//!	往a中加入b
#define XTADD(a,b)							((a) |= (b))
//!	从a中删除b
#define XTREMOVE(a,b)						((a) &= ~(b))
//!	把a设置为b
#define XTSET(a,b)							((a) = (b))
//!	把a第b位设置为0,b的大小以逻辑位为准,即右边是低位
#define XTBITSET0(a,b)						((a) &= ~(1 << (b)))
//!	把a第b位设置为1,b的大小以逻辑位为准,即右边是低位
#define XTBITSET1(a,b)						((a) |= (1 << (b)))
//!	把a第b位设置为0,b的大小以逻辑位为准,即右边是低位
#define XTBIT0SET0(a)						((a) &= 0XFFFFFFFE)
#define XTBIT1SET0(a)						((a) &= 0XFFFFFFFD)
#define XTBIT2SET0(a)						((a) &= 0XFFFFFFFB)
#define XTBIT3SET0(a)						((a) &= 0XFFFFFFF7)
#define XTBIT4SET0(a)						((a) &= 0XFFFFFFEF)
#define XTBIT5SET0(a)						((a) &= 0XFFFFFFDF)
#define XTBIT6SET0(a)						((a) &= 0XFFFFFFBF)
#define XTBIT7SET0(a)						((a) &= 0XFFFFFF7F)
#define XTBIT8SET0(a)						((a) &= 0XFFFFFEFF)
#define XTBIT9SET0(a)						((a) &= 0XFFFFFDFF)
#define XTBIT10SET0(a)						((a) &= 0XFFFFFBFF)
#define XTBIT11SET0(a)						((a) &= 0XFFFFF7FF)
#define XTBIT12SET0(a)						((a) &= 0XFFFFEFFF)
#define XTBIT13SET0(a)						((a) &= 0XFFFFDFFF)
#define XTBIT14SET0(a)						((a) &= 0XFFFFBFFF)
#define XTBIT15SET0(a)						((a) &= 0XFFFF7FFF)
#define XTBIT16SET0(a)						((a) &= 0XFFFEFFFF)
#define XTBIT17SET0(a)						((a) &= 0XFFFDFFFF)
#define XTBIT18SET0(a)						((a) &= 0XFFFBFFFF)
#define XTBIT19SET0(a)						((a) &= 0XFFF7FFFF)
#define XTBIT20SET0(a)						((a) &= 0XFFEFFFFF)
#define XTBIT21SET0(a)						((a) &= 0XFFDFFFFF)
#define XTBIT22SET0(a)						((a) &= 0XFFBFFFFF)
#define XTBIT23SET0(a)						((a) &= 0XFF7FFFFF)
#define XTBIT24SET0(a)						((a) &= 0XFEFFFFFF)
#define XTBIT25SET0(a)						((a) &= 0XFDFFFFFF)
#define XTBIT26SET0(a)						((a) &= 0XFBFFFFFF)
#define XTBIT27SET0(a)						((a) &= 0XF7FFFFFF)
#define XTBIT28SET0(a)						((a) &= 0XEFFFFFFF)
#define XTBIT29SET0(a)						((a) &= 0XDFFFFFFF)
#define XTBIT30SET0(a)						((a) &= 0XBFFFFFFF)
#define XTBIT31SET0(a)						((a) &= 0X7FFFFFFF)
//!	把a第b位设置为1,b的大小以逻辑位为准,即右边是低位
#define XTBIT0SET1(a)						((a) |= 0X00000001)
#define XTBIT1SET1(a)						((a) |= 0X00000002)
#define XTBIT2SET1(a)						((a) |= 0X00000004)
#define XTBIT3SET1(a)						((a) |= 0X00000008)
#define XTBIT4SET1(a)						((a) |= 0X00000010)
#define XTBIT5SET1(a)						((a) |= 0X00000020)
#define XTBIT6SET1(a)						((a) |= 0X00000040)
#define XTBIT7SET1(a)						((a) |= 0X00000080)
#define XTBIT8SET1(a)						((a) |= 0X00000100)
#define XTBIT9SET1(a)						((a) |= 0X00000200)
#define XTBIT10SET1(a)						((a) |= 0X00000400)
#define XTBIT11SET1(a)						((a) |= 0X00000800)
#define XTBIT12SET1(a)						((a) |= 0X00001000)
#define XTBIT13SET1(a)						((a) |= 0X00002000)
#define XTBIT14SET1(a)						((a) |= 0X00004000)
#define XTBIT15SET1(a)						((a) |= 0X00008000)
#define XTBIT16SET1(a)						((a) |= 0X00010000)
#define XTBIT17SET1(a)						((a) |= 0X00020000)
#define XTBIT18SET1(a)						((a) |= 0X00040000)
#define XTBIT19SET1(a)						((a) |= 0X00080000)
#define XTBIT20SET1(a)						((a) |= 0X00100000)
#define XTBIT21SET1(a)						((a) |= 0X00200000)
#define XTBIT22SET1(a)						((a) |= 0X00400000)
#define XTBIT23SET1(a)						((a) |= 0X00800000)
#define XTBIT24SET1(a)						((a) |= 0X01000000)
#define XTBIT25SET1(a)						((a) |= 0X02000000)
#define XTBIT26SET1(a)						((a) |= 0X04000000)
#define XTBIT27SET1(a)						((a) |= 0X08000000)
#define XTBIT28SET1(a)						((a) |= 0X10000000)
#define XTBIT29SET1(a)						((a) |= 0X20000000)
#define XTBIT30SET1(a)						((a) |= 0X40000000)
#define XTBIT31SET1(a)						((a) |= 0X80000000)

//!	把a第b位设置为0,b的大小以逻辑位为准,即右边是低位
#define XTBYTEBIT0SET0(a)					((a) &= 0XFE)
#define XTBYTEBIT1SET0(a)					((a) &= 0XFD)
#define XTBYTEBIT2SET0(a)					((a) &= 0XFB)
#define XTBYTEBIT3SET0(a)					((a) &= 0XF7)
#define XTBYTEBIT4SET0(a)					((a) &= 0XEF)
#define XTBYTEBIT5SET0(a)					((a) &= 0XDF)
#define XTBYTEBIT6SET0(a)					((a) &= 0XBF)
#define XTBYTEBIT7SET0(a)					((a) &= 0X7F)

#define XTWORDBIT0SET0(a)					((a) &= 0XFFFE)
#define XTWORDBIT1SET0(a)					((a) &= 0XFFFD)
#define XTWORDBIT2SET0(a)					((a) &= 0XFFFB)
#define XTWORDBIT3SET0(a)					((a) &= 0XFFF7)
#define XTWORDBIT4SET0(a)					((a) &= 0XFFEF)
#define XTWORDBIT5SET0(a)					((a) &= 0XFFDF)
#define XTWORDBIT6SET0(a)					((a) &= 0XFFBF)
#define XTWORDBIT7SET0(a)					((a) &= 0XFF7F)
#define XTWORDBIT8SET0(a)					((a) &= 0XFEFF)
#define XTWORDBIT9SET0(a)					((a) &= 0XFDFF)
#define XTWORDBIT10SET0(a)					((a) &= 0XFBFF)
#define XTWORDBIT11SET0(a)					((a) &= 0XF7FF)
#define XTWORDBIT12SET0(a)					((a) &= 0XEFFF)
#define XTWORDBIT13SET0(a)					((a) &= 0XDFFF)
#define XTWORDBIT14SET0(a)					((a) &= 0XBFFF)
#define XTWORDBIT15SET0(a)					((a) &= 0X7FFF)

#define XTDWORDBIT0SET0(a)					((a) &= 0XFFFFFFFE)
#define XTDWORDBIT1SET0(a)					((a) &= 0XFFFFFFFD)
#define XTDWORDBIT2SET0(a)					((a) &= 0XFFFFFFFB)
#define XTDWORDBIT3SET0(a)					((a) &= 0XFFFFFFF7)
#define XTDWORDBIT4SET0(a)					((a) &= 0XFFFFFFEF)
#define XTDWORDBIT5SET0(a)					((a) &= 0XFFFFFFDF)
#define XTDWORDBIT6SET0(a)					((a) &= 0XFFFFFFBF)
#define XTDWORDBIT7SET0(a)					((a) &= 0XFFFFFF7F)
#define XTDWORDBIT8SET0(a)					((a) &= 0XFFFFFEFF)
#define XTDWORDBIT9SET0(a)					((a) &= 0XFFFFFDFF)
#define XTDWORDBIT10SET0(a)					((a) &= 0XFFFFFBFF)
#define XTDWORDBIT11SET0(a)					((a) &= 0XFFFFF7FF)
#define XTDWORDBIT12SET0(a)					((a) &= 0XFFFFEFFF)
#define XTDWORDBIT13SET0(a)					((a) &= 0XFFFFDFFF)
#define XTDWORDBIT14SET0(a)					((a) &= 0XFFFFBFFF)
#define XTDWORDBIT15SET0(a)					((a) &= 0XFFFF7FFF)
#define XTDWORDBIT16SET0(a)					((a) &= 0XFFFEFFFF)
#define XTDWORDBIT17SET0(a)					((a) &= 0XFFFDFFFF)
#define XTDWORDBIT18SET0(a)					((a) &= 0XFFFBFFFF)
#define XTDWORDBIT19SET0(a)					((a) &= 0XFFF7FFFF)
#define XTDWORDBIT20SET0(a)					((a) &= 0XFFEFFFFF)
#define XTDWORDBIT21SET0(a)					((a) &= 0XFFDFFFFF)
#define XTDWORDBIT22SET0(a)					((a) &= 0XFFBFFFFF)
#define XTDWORDBIT23SET0(a)					((a) &= 0XFF7FFFFF)
#define XTDWORDBIT24SET0(a)					((a) &= 0XFEFFFFFF)
#define XTDWORDBIT25SET0(a)					((a) &= 0XFDFFFFFF)
#define XTDWORDBIT26SET0(a)					((a) &= 0XFBFFFFFF)
#define XTDWORDBIT27SET0(a)					((a) &= 0XF7FFFFFF)
#define XTDWORDBIT28SET0(a)					((a) &= 0XEFFFFFFF)
#define XTDWORDBIT29SET0(a)					((a) &= 0XDFFFFFFF)
#define XTDWORDBIT30SET0(a)					((a) &= 0XBFFFFFFF)
#define XTDWORDBIT31SET0(a)					((a) &= 0X7FFFFFFF)
//!	把a第b位设置为1,b的大小以逻辑位为准,即右边是低位
#define XTBYTEBIT0SET1(a)					((a) |= 0X01)
#define XTBYTEBIT1SET1(a)					((a) |= 0X02)
#define XTBYTEBIT2SET1(a)					((a) |= 0X04)
#define XTBYTEBIT3SET1(a)					((a) |= 0X08)
#define XTBYTEBIT4SET1(a)					((a) |= 0X10)
#define XTBYTEBIT5SET1(a)					((a) |= 0X20)
#define XTBYTEBIT6SET1(a)					((a) |= 0X40)
#define XTBYTEBIT7SET1(a)					((a) |= 0X80)

#define XTWORDBIT0SET1(a)					((a) |= 0X0001)
#define XTWORDBIT1SET1(a)					((a) |= 0X0002)
#define XTWORDBIT2SET1(a)					((a) |= 0X0004)
#define XTWORDBIT3SET1(a)					((a) |= 0X0008)
#define XTWORDBIT4SET1(a)					((a) |= 0X0010)
#define XTWORDBIT5SET1(a)					((a) |= 0X0020)
#define XTWORDBIT6SET1(a)					((a) |= 0X0040)
#define XTWORDBIT7SET1(a)					((a) |= 0X0080)
#define XTWORDBIT8SET1(a)					((a) |= 0X0100)
#define XTWORDBIT9SET1(a)					((a) |= 0X0200)
#define XTWORDBIT10SET1(a)					((a) |= 0X0400)
#define XTWORDBIT11SET1(a)					((a) |= 0X0800)
#define XTWORDBIT12SET1(a)					((a) |= 0X1000)
#define XTWORDBIT13SET1(a)					((a) |= 0X2000)
#define XTWORDBIT14SET1(a)					((a) |= 0X4000)
#define XTWORDBIT15SET1(a)					((a) |= 0X8000)

#define XTDWORDBIT0SET1(a)					((a) |= 0X00000001)
#define XTDWORDBIT1SET1(a)					((a) |= 0X00000002)
#define XTDWORDBIT2SET1(a)					((a) |= 0X00000004)
#define XTDWORDBIT3SET1(a)					((a) |= 0X00000008)
#define XTDWORDBIT4SET1(a)					((a) |= 0X00000010)
#define XTDWORDBIT5SET1(a)					((a) |= 0X00000020)
#define XTDWORDBIT6SET1(a)					((a) |= 0X00000040)
#define XTDWORDBIT7SET1(a)					((a) |= 0X00000080)
#define XTDWORDBIT8SET1(a)					((a) |= 0X00000100)
#define XTDWORDBIT9SET1(a)					((a) |= 0X00000200)
#define XTDWORDBIT10SET1(a)					((a) |= 0X00000400)
#define XTDWORDBIT11SET1(a)					((a) |= 0X00000800)
#define XTDWORDBIT12SET1(a)					((a) |= 0X00001000)
#define XTDWORDBIT13SET1(a)					((a) |= 0X00002000)
#define XTDWORDBIT14SET1(a)					((a) |= 0X00004000)
#define XTDWORDBIT15SET1(a)					((a) |= 0X00008000)
#define XTDWORDBIT16SET1(a)					((a) |= 0X00010000)
#define XTDWORDBIT17SET1(a)					((a) |= 0X00020000)
#define XTDWORDBIT18SET1(a)					((a) |= 0X00040000)
#define XTDWORDBIT19SET1(a)					((a) |= 0X00080000)
#define XTDWORDBIT20SET1(a)					((a) |= 0X00100000)
#define XTDWORDBIT21SET1(a)					((a) |= 0X00200000)
#define XTDWORDBIT22SET1(a)					((a) |= 0X00400000)
#define XTDWORDBIT23SET1(a)					((a) |= 0X00800000)
#define XTDWORDBIT24SET1(a)					((a) |= 0X01000000)
#define XTDWORDBIT25SET1(a)					((a) |= 0X02000000)
#define XTDWORDBIT26SET1(a)					((a) |= 0X04000000)
#define XTDWORDBIT27SET1(a)					((a) |= 0X08000000)
#define XTDWORDBIT28SET1(a)					((a) |= 0X10000000)
#define XTDWORDBIT29SET1(a)					((a) |= 0X20000000)
#define XTDWORDBIT30SET1(a)					((a) |= 0X40000000)
#define XTDWORDBIT31SET1(a)					((a) |= 0X80000000)
//-----------------------------------------------------------------------------
//!	误差控制
#define XT_EXCEPT							1.0E-10 
//!	极小误差
#define XT_MIN_EXCEPT						1.0E-30 
//!	极大误差
#define XT_MAX_EXCEPT						1.0E-03 
//!	浮点计算的一般误差
#define XT_FLOAT_EXCEPT						1.0E-06 
//-----------------------------------------------------------------------------
//!	浮点近似等于吗,即理论上相等的浮点由于浮点误差的存在而必须用此函数比较
/*!
\remarks 对于没有经过计算的浮点(如读取文件的浮点)的比较建议采用0方案;对于经过简单
计算的浮点(如一般的加减乘除运算)的比较建议采用1方案;对于经过复杂运算的浮点(如直线
求交等)的比较建议采用2方案;
*/
#define XTFLOATEQUAL0(f1,f2)				(fabs((double)(f1) - (f2)) < XT_MIN_EXCEPT)
#define XTFLOATEQUAL1(f1,f2)				(fabs((double)(f1) - (f2)) < XT_EXCEPT)
#define XTFLOATEQUAL2(f1,f2)				(fabs((double)(f1) - (f2)) < XT_FLOAT_EXCEPT)
#define XTFLOATEQUAL3(f1,f2)				(fabs((double)(f1) - (f2)) < XT_MAX_EXCEPT)
//!	浮点近似大于等于吗,即理论上大于等于的浮点由于浮点误差的存在而必须用此函数比较
#define XTFLOATBIGGER0(f1,f2)				(((f1) - (f2)) > -XT_MIN_EXCEPT)
#define XTFLOATBIGGER1(f1,f2)				(((f1) - (f2)) > -XT_EXCEPT)
#define XTFLOATBIGGER2(f1,f2)				(((f1) - (f2)) > -XT_FLOAT_EXCEPT)
#define XTFLOATBIGGER3(f1,f2)				(((f1) - (f2)) > -XT_MAX_EXCEPT)
//! 浮点近似小于等于吗,即理论上小于等于的浮点由于浮点误差的存在而必须用此函数比较
#define XTFLOATLESS0(f1,f2)					(((f1) - (f2)) < XT_MIN_EXCEPT)
#define XTFLOATLESS1(f1,f2)					(((f1) - (f2)) < XT_EXCEPT)
#define XTFLOATLESS2(f1,f2)					(((f1) - (f2)) < XT_FLOAT_EXCEPT)
#define XTFLOATLESS3(f1,f2)					(((f1) - (f2)) < XT_MAX_EXCEPT)
//!	浮点近似为0
#define XTFLOATISZERO0(f)					(fabs((double)(f)) < XT_MIN_EXCEPT)
#define XTFLOATISZERO1(f)					(fabs((double)(f)) < XT_EXCEPT)
#define XTFLOATISZERO2(f)					(fabs((double)(f)) < XT_FLOAT_EXCEPT)
#define XTFLOATISZERO3(f)					(fabs((double)(f)) < XT_MAX_EXCEPT)
//-----------------------------------------------------------------------------
//!	常用的误差
#define XT_E01								1.0E-01 
#define XT_E02								1.0E-02 
#define XT_E03								1.0E-03 
#define XT_E04								1.0E-04 
#define XT_E05								1.0E-05 
#define XT_E06								1.0E-06 
#define XT_E07								1.0E-07 
#define XT_E08								1.0E-08 
#define XT_E09								1.0E-09 
#define XT_E10								1.0E-10 
#define XT_E11								1.0E-11 
#define XT_E12								1.0E-12 
#define XT_E13								1.0E-13 
#define XT_E14								1.0E-14 
#define XT_E15								1.0E-15 
#define XT_BIGE01							1 
#define XT_BIGE02							2
#define XT_BIGE03							3
#define XT_BIGE04							4 
#define XT_BIGE05							5 
#define XT_BIGE06							6 
#define XT_BIGE07							7 
#define XT_BIGE08							8 
#define XT_BIGE09							9 
#define XT_BIGE10							10 
#define XT_BIGE11							1.0E+1 
#define XT_BIGE12							1.0E+2 
#define XT_BIGE13							1.0E+3 
#define XT_BIGE14							1.0E+4 
#define XT_BIGE15							1.0E+5
//-----------------------------------------------------------------------------
//!	无穷
#define	XT_INT_MAX			 				2000000000		//!<无穷大
#define	XT_INT_MIN							-2000000000		//!<无穷小
#define	XT_MAX			 					XT_INT_MAX		//!<无穷大
#define	XT_MIN								XT_INT_MIN		//!<无穷小
#define	XT_FLOAT_MAX						1.0E+30F		//!<无穷大
#define	XT_FLOAT_MIN						-1.0E+30F		//!<无穷小
//-----------------------------------------------------------------------------
//!	本库支持的最大串长度
#define	XT_MAX_STR_LENGTH					1024 * 100
//!	最大路径
#define XT_MAX_PATH							1024
//!	文件名最大长度
#define XT_FILE_NAME_MAX_LENGTH				XT_MAX_PATH
//-----------------------------------------------------------------------------
//!	由于有些编译器不支持max和min，自己定义
#ifndef xtmax
	#define xtmax(a,b)						(((a) > (b)) ? (a) : (b))
#endif//#ifndef xtmax

#ifndef xtmin
	#define xtmin(a,b)						(((a) < (b)) ? (a) : (b))
#endif//#ifndef xtmin

//!	由于有些编译器不支持abs，自己定义
#ifndef xtabs
	#define xtabs(a)						(((a) > 0) ? (a) : -(a))
#endif//#ifndef xtabs

//!	交换a b两个变量的值
#define XT_SWAP(a,b,tmp) tmp = a; a = b; b = tmp
//!	0 1->1 0,eg.0X1234->0X3412
#define XT_SWAP2BYTES(a) {XTBYTE * p = (XTBYTE *)(a);XTBYTE tmp;XT_SWAP(p[0],p[1],tmp);}
//!	0 1 2 3->3 2 1 0,eg.0X12345678->0X78563412
#define XT_SWAP4BYTES(a) {XTBYTE * p = (XTBYTE *)(a);XTBYTE tmp;XT_SWAP(p[0],p[3],tmp);XT_SWAP(p[1],p[2],tmp);}
//!	0 1 2 3 4 5 6 7->7 6 5 4 3 2 1 0,eg.0X1234567890ABCDEF->0XEFCDAB9078563412
#define XT_SWAP8BYTES(a) {XTBYTE * p = (XTBYTE *)(a);XTBYTE tmp;XT_SWAP(p[0],p[7],tmp);XT_SWAP(p[1],p[6],tmp);XT_SWAP(p[2],p[5],tmp);XT_SWAP(p[3],p[4],tmp);}


//!	windows的rand()函数只能产生0~0x7fff数字，linux的rand()函数可以产生0~0x7fffffff，所以，需要产生大于0x7fff的随机数字时，需要使用本定义
#if (defined XT_SERVER || defined SERVER || defined LINUX_SERVER)
	#define xtbigrand()						rand()
#else
	#define xtbigrand()						(rand()*rand()+rand())
#endif//#ifdef XT_SERVER
#define XTBIGRAND							xtbigrand
#define xtrand01							(rand()%10001/10000.0)
#define XTRAND01							xtrand01

//!	一个字节a循环右移b位
#define XTRCMBYTE(a,b)	(a) = ((a) >> (b) | (a) <<  (8 - (b)))
//!	一个字节a循环左移b位
#define XTLCMBYTE(a,b)	(a) = ((a) << (b) | (a) >>  (8 - (b)))
//-----------------------------------------------------------------------------
//!	圆周率定义
#define XT_PI								3.1415926535897932384626433832795
//! 自然对数的底
#define XT_E								2.718282
//!	弧度转换为角度
#define XTRADTOANGLE(rad)					((rad)		* 180.0 / XT_PI)
//!	角度转换为弧度
#define XTANGLETORAD(angle)					((angle)	* XT_PI / 180.0  )

//!	大小写字母的值差
#define XTLOWERUPPERDIS						32
//!	判断一个字符是否为数字('0'~'9')((ch)必须为GBK或UTF8字符)
#define XTISDIG(ch)							(!((ch) < '0' || (ch) > '9'))
//!	判断一个字符是否为字母('A'~'Z' || 'a'~'z')((ch)必须为GBK或UTF8字符)
#define XTISALPHA(ch)						(!((ch) < 'A' || ((ch) > 'z') || ((ch) > 'Z' && (ch) < 'a')))
//!	判断一个字符是否为字母('A'~'Z')
#define XTISATOZ(ch)						(!((ch) < 'A' || (ch) > 'Z'))
//!	判断一个字符是否为字母('a'~'z')
#define XTISaTOz(ch)						(!((ch) < 'a' || (ch) > 'z'))
//!	一个字符是否是不可见字符' ' '\r' '\n' '\t' '\b'
#define XTISINVISIBLE(ch)					((ch) == ' ' || (ch) == '\r' || (ch) == '\n' || (ch) == '\t' || (ch) == '\b')
//!	一个字符是否是空格之外的不可见字符'\r' '\n' '\t' '\b'
#define XTISINVISIBLENOSPACE(ch)			((ch) == '\r' || (ch) == '\n' || (ch) == '\t' || (ch) == '\b')
//!	判断一个字符是否为中文((ch)必须为GBK或UTF8字符)
#define XTISCHINESE(ch)						((ch) < 0 || (ch) > 127)
//!	判断一个字符是否为英文(非中文)((ch)必须为GBK或UTF8字符)
#define XTISENGLISH(ch)						(!XTISCHINESE(ch))
//!	变为大写字母((ch)必须为GBK或UTF8字符)
#define XTMAKEUPPER(ch)						(XTISaTOz(ch)?((ch)-XTLOWERUPPERDIS):(ch))
//!	变为小写字母((ch)必须为GBK或UTF8字符)
#define XTMAKELOWER(ch)						(XTISATOZ(ch)?((ch)+XTLOWERUPPERDIS):ch)
//!	不区分大小写的字母是否相等((ch1),(ch2)必须为GBK或UTF8字符)
#define XTISEQUALNOCASE(ch1,ch2)			(((ch1) == (ch2)) || (XTISALPHA((ch1)) && XTISALPHA((ch2)) && abs((ch1) - (ch2)) == XTLOWERUPPERDIS))
//!	不区分大小写的字母是否相等(ch1,ch2)必须为GBK或UTF8 ('A'~'Z' || 'a'~'z')字母)
#define XTISEQUALNOCASE1(ch1,ch2)			(((ch1) == (ch2)) || (abs((ch1) - (ch2)) == XTLOWERUPPERDIS))
//-----------------------------------------------------------------------------
//	文件缓冲区的大小
//!	文件缓冲区的最小值
#define XT_FILEBUF_MIN						1024
//!	文件缓冲区的最大值
#define XT_FILEBUF_MAX						32768
//!	文件缓冲区的一般值
#define XT_FILEBUF_NORMAL					4096
//!	标准化缓冲区大小
#define XTCHECKFILEBUFLENGTH(f)				((int)(xtmin(xtmin(XT_FILEBUF_MAX,f),xtmax(XT_FILEBUF_MIN,f))))					
//-----------------------------------------------------------------------------
//!	虚函数和内联函数的声明字重新定义(由于WINDOWS CE有些时候支持虚函数和内联函数出错)
#define XTVIRTUAL							virtual
#define XTINLINE							inline
//!	对于服务器端程序来说,尽可能少使用虚函数
#if (defined XT_SERVER || defined SERVER || defined LINUX_SERVER)
	#define XTCVIRTUAL							
	#define XTCINLINE						
#else
	#define XTCVIRTUAL						virtual
	#define XTCINLINE						inline
#endif//#ifdef XT_SERVER
//------------------------------------------------------------------------------
//!	数据存取大小单位换算(必须是整数,浮点数则点XTF)
#define XTPBTOB(s)							((s)<<50)
#define XTPBTOKB(s)							((s)<<40)
#define XTPBTOMB(s)							((s)<<30)
#define XTPBTOGB(s)							((s)<<20)
#define XTPBTOTB(s)							((s)<<10)

#define XTTBTOB(s)							((s)<<40)
#define XTTBTOKB(s)							((s)<<30)
#define XTTBTOMB(s)							((s)<<20)
#define XTTBTOGB(s)							((s)<<10)
#define XTTBTOPB(s)							((s)>>10)

#define XTGBTOB(s)							((s)<<30)
#define XTGBTOKB(s)							((s)<<20)
#define XTGBTOMB(s)							((s)<<10)
#define XTGBTOTB(s)							((s)>>10)
#define XTGBTOPB(s)							((s)>>20)

#define XTMBTOB(s)							((s)<<20)
#define XTMBTOKB(s)							((s)<<10)
#define XTMBTOGB(s)							((s)>>10)
#define XTMBTOTB(s)							((s)>>20)
#define XTMBTOPB(s)							((s)>>30)

#define XTKBTOB(s)							((s)<<10)
#define XTKBTOMB(s)							((s)>>10)
#define XTKBTOGB(s)							((s)>>20)
#define XTKBTOTB(s)							((s)>>30)
#define XTKBTOPB(s)							((s)>>40)

#define XTBTOKB(s)							((s)>>10)
#define XTBTOMB(s)							((s)>>20)
#define XTBTOGB(s)							((s)>>30)
#define XTBTOTB(s)							((s)>>40)
#define XTBTOPB(s)							((s)>>50)

#define XTLLPBTOB(s)						(((XTINT64)(s))<<50)
#define XTLLPBTOKB(s)						(((XTINT64)(s))<<40)
#define XTLLPBTOMB(s)						(((XTINT64)(s))<<30)
#define XTLLPBTOGB(s)						(((XTINT64)(s))<<20)
#define XTLLPBTOTB(s)						(((XTINT64)(s))<<10)

#define XTLLTBTOB(s)						(((XTINT64)(s))<<40)
#define XTLLTBTOKB(s)						(((XTINT64)(s))<<30)
#define XTLLTBTOMB(s)						(((XTINT64)(s))<<20)
#define XTLLTBTOGB(s)						(((XTINT64)(s))<<10)
#define XTLLTBTOPB(s)						(((XTINT64)(s))>>10)

#define XTLLGBTOB(s)						(((XTINT64)(s))<<30)
#define XTLLGBTOKB(s)						(((XTINT64)(s))<<20)
#define XTLLGBTOMB(s)						(((XTINT64)(s))<<10)
#define XTLLGBTOTB(s)						(((XTINT64)(s))>>10)
#define XTLLGBTOPB(s)						(((XTINT64)(s))>>20)

#define XTLLMBTOB(s)						(((XTINT64)(s))<<20)
#define XTLLMBTOKB(s)						(((XTINT64)(s))<<10)
#define XTLLMBTOGB(s)						(((XTINT64)(s))>>10)
#define XTLLMBTOTB(s)						(((XTINT64)(s))>>20)
#define XTLLMBTOPB(s)						(((XTINT64)(s))>>30)

#define XTLLKBTOB(s)						(((XTINT64)(s))<<10)
#define XTLLKBTOMB(s)						(((XTINT64)(s))>>10)
#define XTLLKBTOGB(s)						(((XTINT64)(s))>>20)
#define XTLLKBTOTB(s)						(((XTINT64)(s))>>30)
#define XTLLKBTOPB(s)						(((XTINT64)(s))>>40)



#define XTFPBTOB(s)							((s)*1024.0*1024*1024*1024*1024)
#define XTFPBTOKB(s)						((s)*1024.0*1024*1024*1024)
#define XTFPBTOMB(s)						((s)*1024.0*1024*1024)
#define XTFPBTOGB(s)						((s)*1024.0*1024)
#define XTFPBTOTB(s)						((s)*1024.0)

#define XTFTBTOB(s)							((s)*1024.0*1024*1024*1024)
#define XTFTBTOKB(s)						((s)*1024.0*1024*1024)
#define XTFTBTOMB(s)						((s)*1024.0*1024)
#define XTFTBTOGB(s)						((s)*1024.0)
#define XTFTBTOPB(s)						((s)/1024)

#define XTFGBTOB(s)							((s)*1024.0*1024*1024)
#define XTFGBTOKB(s)						((s)*1024.0*1024)
#define XTFGBTOMB(s)						((s)*1024.0)
#define XTFGBTOTB(s)						((s)/1024)
#define XTFGBTOPB(s)						((s)/1024/1024)

#define XTFMBTOB(s)							((s)*1024.0*1024)
#define XTFMBTOKB(s)						((s)*1024.0)
#define XTFMBTOGB(s)						((s)/1024)
#define XTFMBTOTB(s)						((s)/1024/1024)
#define XTFMBTOPB(s)						((s)/1024/1024/1024)

#define XTFKBTOB(s)							((s)*1024.0)
#define XTFKBTOMB(s)						((s)/1024)
#define XTFKBTOGB(s)						((s)/1024/1024)
#define XTFKBTOTB(s)						((s)/1024/1024/1024)
#define XTFKBTOPB(s)						((s)/1024/1024/1024/1024)

#define XTFBTOKB(s)							((s)/1024)
#define XTFBTOMB(s)							((s)/1024/1024)
#define XTFBTOGB(s)							((s)/1024/1024/1024)
#define XTFBTOTB(s)							((s)/1024/1024/1024/1024)
#define XTFBTOPB(s)							((s)/1024/1024/1024/1024/1024)
//------------------------------------------------------------------------------
//! 英寸与mm的转换
#define XTINCHTOMM(inch)	((inch) * 25.4f)
//! mm与英寸的转换
#define XTMMTOINCH(mm)		((mm) / 25.4f)

//!	目录分隔符
#ifdef XTWINDOWS
	#define XT_PATH_SEPARATOR		'\\'
#else
	#define XT_PATH_SEPARATOR		'/'
#endif
//-----------------------------------------------------------------------------
//	类似MFC的定义

//!	调试控制
#ifdef XTWIN32
	#if defined(_DEBUG) || defined(DEBUG)
		#define	XTDEBUG
	#endif//#if defined(_DEBUG)
#endif//#ifdef XTWIN32

//!	所有提示尽可能弹出对话框
//#define XT_POP_ALL_MSG

#ifndef XT_EMPTY_FUNCTION
#define XT_EMPTY_FUNCTION
inline void XtEmptyFunc(...){}
#endif

//!	断言设计
#if defined(XTDEBUG)
	//assert
	#ifdef ASSERT
		#define XTASSERT(f)					ASSERT(f)
		#define XTVERIFY(f)					VERIFY(f)
	#else
		#define XTASSERT(f)					assert(f)
		#define XTVERIFY(f)					((void)(f))
	#endif//#ifdef ASSERT	
	
	//trace
	#ifdef TRACE
		#define XTTRACE						TRACE
		#define XTTRACE0(f)					TRACE(f)
		#define XTTRACE1(f,f1)				TRACE(f,f1)
		#define XTTRACE2(f,f1,f2)			TRACE(f,f1,f2)
		#define XTTRACE3(f,f1,f2,f3)		TRACE(f,f1,f2,f3)
		#define XTTRACE4(f,f1,f2,f3,f4)		TRACE(f,f1,f2,f3,f4)
	#else 
		#define XTTRACE						XtEmptyFunc
		#define XTTRACE0(f)					((void)(0))
		#define XTTRACE1(f,f1)				((void)(0))
		#define XTTRACE2(f,f1,f2)			((void)(0))
		#define XTTRACE3(f,f1,f2,f3)		((void)(0))
		#define XTTRACE4(f,f1,f2,f3,f4)		((void)(0))
	#endif//#ifdef TRACE

	//debug line(the line code will compile only in debug version)
	#define XTDEBUGLINE(f)					((void)(f))

	//trace file name and line number
	#ifdef DEBUG_NEW
		#define XTTRACEFILELINE(f)			XTTRACE(_T("%s,%s(%d)"),f,__FILE__,__LINE__)
		#define XTTRACEFILELINE0()			XTTRACE(_T("%s(%d)"),__FILE__,__LINE__)
	#else 
		#define XTTRACEFILELINE(f)			((void)(0))
		#define XTTRACEFILELINE0()			((void)(0))
	#endif//#ifdef DEBUG_NEW

	//debug messagebox
	#ifdef XTWINDOWS 
		#ifdef XT_POP_ALL_MSG
			#define XtDebugMsgBox(f,f1)					XTTRACE0(f);AfxMessageBox(f,f1)
			#define XtDebugMsgOKBox(f)					XTTRACE0(f);AfxMessageBox(f,MB_OK)
			#define XtDebugMsgOKCANCELBox(f)			XTTRACE0(f);AfxMessageBox(f,MB_OKCANCEL)
			#define XtDebugMsgABORTRETRYIGNOREBox(f)	XTTRACE0(f);AfxMessageBox(f,MB_ABORTRETRYIGNORE)
			#define XtDebugMsgYESNOCANCELBox(f)			XTTRACE0(f);AfxMessageBox(f,MB_YESNOCANCEL)
			#define XtDebugMsgYESNOBox(f)				XTTRACE0(f);AfxMessageBox(f,MB_YESNO)
			#define XtDebugMsgRETRYCANCELBox(f)			XTTRACE0(f);AfxMessageBox(f,MB_RETRYCANCEL)
			#define XtDebugMsgCANCELTRYCONTINUEBox(f)	XTTRACE0(f);AfxMessageBox(f,MB_CANCELTRYCONTINUE)
		#else
			#define XtDebugMsgBox(f,f1)					XTTRACE0(f)
			#define XtDebugMsgOKBox(f)					XTTRACE0(f)
			#define XtDebugMsgOKCANCELBox(f)			XTTRACE0(f)
			#define XtDebugMsgABORTRETRYIGNOREBox(f)	XTTRACE0(f)
			#define XtDebugMsgYESNOCANCELBox(f)			XTTRACE0(f)
			#define XtDebugMsgYESNOBox(f)				XTTRACE0(f)
			#define XtDebugMsgRETRYCANCELBox(f)			XTTRACE0(f)
			#define XtDebugMsgCANCELTRYCONTINUEBox(f)	XTTRACE0(f)
		#endif//#ifdef XT_POP_ALL_MSG
	#else
		#define XtDebugMsgBox(f,f1)						XTTRACE0(f)
		#define XtDebugMsgOKBox(f)						XTTRACE0(f)
		#define XtDebugMsgOKCANCELBox(f)				XTTRACE0(f)
		#define XtDebugMsgABORTRETRYIGNOREBox(f)		XTTRACE0(f)
		#define XtDebugMsgYESNOCANCELBox(f)				XTTRACE0(f)
		#define XtDebugMsgYESNOBox(f)					XTTRACE0(f)
		#define XtDebugMsgRETRYCANCELBox(f)				XTTRACE0(f)
		#define XtDebugMsgCANCELTRYCONTINUEBox(f)		XTTRACE0(f)
	#endif
#else  // #if defined(XTDEBUG)
	#define XTASSERT(f)							((void)(0))
	#define XTVERIFY(f)							((void)(f))
	#define XTTRACE								XtEmptyFunc
	#define XTTRACE0(f)							((void)(0))
	#define XTTRACE1(f,f1)						((void)(0))
	#define XTTRACE2(f,f1,f2)					((void)(0))
	#define XTTRACE3(f,f1,f2,f3)				((void)(0))
	#define XTTRACE4(f,f1,f2,f3,f4)				((void)(0))
	#define XTDEBUGLINE(f)						((void)(0))
	#define XTTRACEFILELINE(f)					((void)(0))
	#define XTTRACEFILELINE0()					((void)(0))
	#define XtDebugMsgBox(f,f1)					((void)(0))
	#define XtDebugMsgOKBox(f)					((void)(0))
	#define XtDebugMsgOKCANCELBox(f)			((void)(0))
	#define XtDebugMsgABORTRETRYIGNOREBox(f)	((void)(0))
	#define XtDebugMsgYESNOCANCELBox(f)			((void)(0))
	#define XtDebugMsgYESNOBox(f)				((void)(0))
	#define XtDebugMsgRETRYCANCELBox(f)			((void)(0))
	#define XtDebugMsgCANCELTRYCONTINUEBox(f)	((void)(0))
#endif // #if defined(XTDEBUG)

//!	替换标准C++的try-catch,对于难以确定到底要不要try-catch的代码,一律采用自定义的，如果一定需要try-catch的代码，还是直接使用
#ifndef XT_NO_USE_TRY
	#define XTTRY								try
	#define XTCATCH(f)							catch(f)
	#define XTBEGINTRY							try{
	#define XTMIDCATCH(f)						}catch(f){
	#define XTENDTRY							}
#else
	#define XTTRY								if(1)
	#define XTCATCH(f)							if(0)
	#define XTBEGINTRY							if(1){
	#define XTMIDCATCH(f)						}if(0){
	#define XTENDTRY							}
#endif// #ifndef XT_NO_USE_TRY


//--------------------------------------------------------------------------
//	Added by chengxuewen, 2011:6:9,为了提高代码可读性,经常需要知晓一个形参是否是(1)传入赋值参数(2)传出赋值参照(3)传入传出均赋值参数
#ifdef IN
	#undef IN
#endif
#ifdef OUT
	#undef OUT
#endif
#ifdef INOUT
	#undef INOUT
#endif
//!	这是一个仅仅传入的参数
#define IN
//!	这是一个仅仅传出的参数
#define OUT
//!	这是一个既需要传入又需要传出的参数
#define INOUT
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
//	Added by chengxuewen, 2012:10:26,字符串作为hash_map的key时,可能需要制定哈希函数

//!	string哈希函数
struct hash_string
{
	//!	(key为string)这是基本哈希函数
	size_t operator()(const string& str) const
	{
		unsigned long __h = 0;
		for (size_t i = 0 ; i < str.size() ; i ++)
			__h = 5*__h + str[i];
		return size_t(__h);
	}
	//!	(key为string)这是判断str1<str2函数(vc2010的hash_map使用,vc的hash_map元素在桶里面是从小到大排序的,查找时,首先把要查找的v1即str2与桶里的v2即str1比较,若返回true==(v2<v1)则继续,返回false==(v2<v1)则可能找到再比较,若返回true==(v1<v2)则代表v1!=v2[(!(v2<v1) && (v1<v2))=>v1!=v2],返回false=(v1<v2)则代表v1==v2[(!(v2<v1) && !(v1<v2))=>v1==v2])
	bool operator()(const string& str1,const string& str2) const
	{
		return str1 < str2;
	}
	enum
	{	// parameters for hash table(仅仅为了兼容VC2010的hash_map)
		bucket_size = 1	// 0 < bucket_size
	};
};
//!	string相等比较函数
struct hash_equal_string
{
	//!	(key为string)相等比较函数
	bool operator()(const string& str1,const string& str2)const
	{
		return str1 == str2;
	}
};
//!	char*哈希函数
struct hash_char
{
	//!	(key为char*)这是基本哈希函数
	size_t operator()(const char * str) const
	{
		unsigned long __h = 0;
		for (size_t i = 0 ; *str != 0; i ++)
			__h = 5*__h + *str++;
		return size_t(__h);
	}
	//!	(key为char*)这是判断str1<str2函数(vc2010的hash_map使用,vc的hash_map元素在桶里面是从小到大排序的,查找时,首先把要查找的v1即str2与桶里的v2即str1比较,若返回true==(v2<v1)则继续,返回false==(v2<v1)则可能找到再比较,若返回true==(v1<v2)则代表v1!=v2[(!(v2<v1) && (v1<v2))=>v1!=v2],返回false=(v1<v2)则代表v1==v2[(!(v2<v1) && !(v1<v2))=>v1==v2])
	bool operator()(const char* str1,const char* str2) const
	{
		return strcmp(str1,str2) < 0;
	}
	enum
	{	// parameters for hash table(仅仅为了兼容VC2010的hash_map)
		bucket_size = 1	// 0 < bucket_size
	};
};
//!	char*相等比较函数
struct hash_equal_char
{
	//!	(key为char*)相等比较函数(gcc的hash_map相等比较函数)
	bool operator()(const char* str1,const char* str2)const
	{
		return strcmp(str1,str2) == 0;
	}
};

//!	有的人喜欢反过来用名称
typedef hash_string				string_hash;
typedef hash_equal_string		string_hash_equal;
typedef hash_char				char_hash;
typedef hash_equal_char			char_hash_equal;

#ifdef WIN32//这是vc2010的hash_map的定义格式
//hash_map
template<class _key_type, class _value_type, 
class _hash_func = hash_compare<_key_type, less<_key_type> >, 
class _Alloc = allocator<pair<const _key_type, _value_type> > >
class hash_map0	: public hash_map< _key_type, _value_type, _hash_func, _Alloc>
{
};
template<class _key_type, class _value_type>
class hash_map_string : public hash_map< _key_type, _value_type, hash_string, allocator<pair<const _key_type, _value_type> > >
{
};
template<class _value_type>
class hash_map_string0 : public hash_map< string, _value_type, hash_string, allocator<pair<const string, _value_type> > >
{
};
template<class _key_type, class _value_type>
class hash_map_char : public hash_map< _key_type, _value_type, hash_char, allocator<pair<const _key_type, _value_type> > >
{
};
template<class _value_type>
class hash_map_char0 : public hash_map< const char*, _value_type, hash_char, allocator<pair<const char*, _value_type> > >
{
};
//hash_set
template<class _key_type, 
class _hash_func = hash_compare<_key_type, less<_key_type> >, 
class _Alloc = allocator<const _key_type> >
class hash_set0	: public hash_set< _key_type, _hash_func, _Alloc>
{
};
template<class _key_type>
class hash_set_string : public hash_set< _key_type, hash_string, allocator<const _key_type> >
{
};
class hash_set_string0 : public hash_set< string, hash_string, allocator<const string> >
{
};
template<class _key_type>
class hash_set_char : public hash_set< _key_type, hash_char, allocator<const _key_type> >
{
};
class hash_set_char0 : public hash_set< const char*, hash_char, allocator<const char*> >
{
};
#else//这是gcc的hash_map的定义格式
//hash_map
template<class _key_type, class _value_type, 
class _hash_func = __gnu_cxx::hash<_key_type>,
class _equal_key = equal_to<_key_type>, 
class _Alloc = allocator<_value_type> >
class hash_map0	: public hash_map< _key_type, _value_type, _hash_func, _equal_key, _Alloc>
{
};
template<class _key_type, class _value_type>
class hash_map_string : public hash_map< _key_type, _value_type, hash_string, hash_equal_string, allocator<_value_type> >
{
};
template<class _value_type>
class hash_map_string0 : public hash_map< string, _value_type, hash_string, hash_equal_string, allocator<_value_type> >
{
};
template<class _key_type, class _value_type>
class hash_map_char : public hash_map< _key_type, _value_type, hash_char, hash_equal_char, allocator<_value_type> >
{
};
template<class _value_type>
class hash_map_char0 : public hash_map< const char*, _value_type, hash_char, hash_equal_char, allocator<_value_type> >
{
};
//hash_set
template<class _key_type, 
class _hash_func = __gnu_cxx::hash<_key_type>,
class _equal_key = equal_to<_key_type>, 
class _Alloc = allocator<_key_type> >
class hash_set0	: public hash_set< _key_type, _hash_func, _equal_key, _Alloc>
{
};
template<class _key_type>
class hash_set_string : public hash_set< _key_type, hash_string, hash_equal_string, allocator<_key_type> >
{
};
class hash_set_string0 : public hash_set< string, hash_string, hash_equal_string, allocator<string> >
{
};
template<class _key_type>
class hash_set_char : public hash_set< _key_type, hash_char, hash_equal_char, allocator<_key_type> >
{
};
class hash_set_char0 : public hash_set< const char*, hash_char, hash_equal_char, allocator<const char*> >
{
};
#endif

//一般string为key的hash_map总是如下定义的:(这样就在vc2010和gcc中都可以编译通过)
//hash_map<string,my_value_type,hash_string> myHashmap;
//而上述简化之后,string为key的hash_map和hash_set都很简单了
//hash_map_string<string,my_value_type> myHashmap;
//hash_set_string<string> mySet;
//hash_map_string0<my_value_type> myHashmap;
//hash_set_string0 mySet;
//--------------------------------------------------------------------------


//------------------------------------------------------------------------------
//!	为了方便编译,本模块动态库控制与其它模块不同,特放置在本处
#ifdef WIN32
#ifndef XT_IMAGE_DLL
#ifdef  XT_USE_IMAGE_LIB
#define		XT_IMAGE_DLL									//!<使用静态库
#else 
#ifdef XT_USE_IMAGE_DLL
#define XT_IMAGE_DLL		__declspec(dllexport)		//!<导出动态库
#else 
#define XT_IMAGE_DLL		__declspec(dllimport)		//!<导入动态库
#endif//#ifdef GWINB_USE_DLL
#endif//#ifdef  GWINB_USE_LIB
#endif//#ifndef GWINB_DLL
#else
#ifndef XT_IMAGE_DLL
#define XT_IMAGE_DLL
#endif
#endif
//------------------------------------------------------------------------------
//!	图片通道控制标志
typedef struct tagXTZALPHAFLAG
{
	enum
	{
		//!	表示没有通道
		NOALPHA					= 0x00000001,
		//!	表示通道数据是压缩的
		COMPRESSED				= 0x00000002,
		//!	表示通道中含有实物
		HASSOLID				= 0x00000004,
		//!	表示通道中含有阴影
		HASSHADOW				= 0x00000008,
		//!	表示通道中含有特殊通道
		HASSPECIAL				= 0x00000010,
		//!	表示特殊通道是半透明
		SPECIALISTRANSLUCENT	= 0x00000020,
		//!	表示特殊通道是头发
		SPECIALISHAIR			= 0x00000040,
		//!	表示含有自定义Nbit通道(N=1~8)
		HASNBITALPHA			= 0x00000100,
		//!	表示含有8bit通道
		HAS8BITALPHA			= 0x00000200,
		//!	表示1bit通道
		ALPHA1BIT				= 0x00010000,
		//!	表示2bit通道
		ALPHA2BIT				= 0x00020000,
		//!	表示3bit通道
		ALPHA3BIT				= 0x00040000,
		//!	表示4bit通道(暂时为默认)
		ALPHA4BIT				= 0x00080000,
		//!	表示5bit通道
		ALPHA5BIT				= 0x00100000,
		//!	表示6bit通道
		ALPHA6BIT				= 0x00200000,
		//!	表示7bit通道
		ALPHA7BIT				= 0x00400000,
		//!	表示8bit通道
		ALPHA8BIT				= 0x00800000,
		//!	默认Nbit通道
		ALPHADEFAULTBIT			= ALPHA4BIT,
		//!	Nbit通道掩码
		ALPHANBITMASK			= 0x00FF0000,

		//!	默认的
		DEFAULT					= HASSOLID | HASSHADOW | ALPHADEFAULTBIT,
	};
}XTZALPHAFLAG;

//!	4bit自定义通道与8bit正常通道的换算因子
#define XTZ_ALPHA_4TO8_MULTI	25

//!图片类型
typedef struct tagXTOMPICTYPE
{
	enum
	{
		//!未知的
		UNKNOWN				= 0,
		//---------------------------------------------------------------------
		//!BMP
		BMP					= 1,
		//!GIF
		GIF					= 2,
		//!JPG
		JPG					= 3,
		//!PNG
		PNG					= 4,
		//!MNG
		MNG					= 5,
		//!ICO
		ICO					= 6,
		//!TIF
		TIF					= 7,
		//!TGA
		TGA					= 8,
		//!PCX
		PCX					= 9,
		//!WBMP
		WBMP				= 10,
		//!WMF
		WMF					= 11,
		//!J2K
		J2K					= 12,
		//!JBG
		JBG					= 13,
		//!JP2
		JP2					= 14,
		//!JPC
		JPC					= 15,
		//!PGX
		PGX					= 16,
		//!PNM
		PNM					= 17,
		//!RAS
		RAS					= 18,
		//!	自定义图片格式
		XT565BMP			= 19,			
	};
}XTOMPICTYPE;

//!	默认的图片格式
#define XTOM_DEFAULT_PICTYPE	XTOMPICTYPE::JPG

//------------------------------------------------------------------------------
//!	COLOREF
typedef XTDWORD								XTCOLOREF;

//!	取颜色的RGB值，总是返回XTBYTE
#define XTGETRVALUE(clrRGB)					((XTBYTE)(clrRGB))
#define XTGETGVALUE(clrRGB)					((XTBYTE)((clrRGB)>>8))
#define XTGETBVALUE(clrRGB)					((XTBYTE)((clrRGB)>>16))
#define XTGETRVALUE565(clrRGB)				((XTBYTE)(((clrRGB)>>8)&0xf8))
#define XTGETGVALUE565(clrRGB)				((XTBYTE)(((clrRGB)>>3)&0xfc))
#define XTGETBVALUE565(clrRGB)				((XTBYTE)(((clrRGB)<<3)&0xf8))
#define XTGETRVALUE0555(clrRGB)				((XTBYTE)(((clrRGB)>>7)&0xf8))
#define XTGETGVALUE0555(clrRGB)				((XTBYTE)(((clrRGB)>>2)&0xf8))
#define XTGETBVALUE0555(clrRGB)				((XTBYTE)(((clrRGB)<<3)&0xf8))

//! XTRGBTOBGR
#define XTRGBTOBGR(clrRGB)					((XTCOLORREF)(((XTBYTE)(XTGETBVALUE(clrRGB))|((XTWORD)((XTBYTE)(XTGETGVALUE(clrRGB)))<<8))|(((XTDWORD)(XTBYTE)(XTGETRVALUE(clrRGB)))<<16)))
//!	RGB
#define XTRGB(r,g,b)						((XTCOLORREF)(((XTBYTE)(r)|((XTWORD)((XTBYTE)(g))<<8))|(((XTDWORD)(XTBYTE)(b))<<16)))
//!	RGB565
#define XTRGB565(r,g,b)						(((XTWORD)((r)&0xf8))<<8|((XTWORD)((g)&0xfc))<<3|((XTWORD)((b)&0xf8))>>3)
//!	RGB0555
#define XTRGB0555(r,g,b)					(((XTWORD)((r)&0xf8))<<7|((XTWORD)((g)&0xf8))<<2|((XTWORD)((b)&0xf8))>>3)

//!	16BIT颜色与32bit颜色的互相转换
#define XT32TO565(clrRGB)					XTRGB565(XTGETRVALUE(clrRGB),XTGETGVALUE(clrRGB),XTGETBVALUE(clrRGB))
#define XT32TO0555(clrRGB)					XTRGB0555(XTGETRVALUE(clrRGB),XTGETGVALUE(clrRGB),XTGETBVALUE(clrRGB))
#define XT565TO32(clrRGB)					XTRGB(XTGETRVALUE565(clrRGB),XTGETGVALUE565(clrRGB),XTGETBVALUE565(clrRGB))
#define XT0555TO32(clrRGB)					XTRGB(XTGETRVALUE0555(clrRGB),XTGETGVALUE0555(clrRGB),XTGETBVALUE0555(clrRGB))

//! 图片关键色, 32位色, 即windows RGB
#define XTG_COLOR_KEY_R						255
#define XTG_COLOR_KEY_G						0
#define XTG_COLOR_KEY_B						255
#define XTG_COLOR_KEY						XTRGB(255,0,255)
#define XTG_UI_COLOR_KEY					0

//! 图片关键色, 16位色
#define XTG_COLOR_KEY565					XTRGB565(XTG_COLOR_KEY_R,XTG_COLOR_KEY_G,XTG_COLOR_KEY_B)
#define XTG_COLOR_KEY0555					XTRGB0555(XTG_COLOR_KEY_R,XTG_COLOR_KEY_G,XTG_COLOR_KEY_B)

//! 替换图片关键色, 32位色, 即windows RGB
#define XTG_REPLACE_COLOR_KEY_R				247
#define XTG_REPLACE_COLOR_KEY_G				0
#define XTG_REPLACE_COLOR_KEY_B				255
#define XTG_REPLACE_COLOR_KEY				XTRGB(XTG_REPLACE_COLOR_KEY_R,XTG_REPLACE_COLOR_KEY_G,XTG_REPLACE_COLOR_KEY_B)

//! 替换图片关键色, 16位色
#define XTG_REPLACE_COLOR_KEY565			XTRGB565(XTG_REPLACE_COLOR_KEY_R,XTG_REPLACE_COLOR_KEY_G,XTG_REPLACE_COLOR_KEY_B)
#define XTG_REPLACE_COLOR_KEY0555			XTRGB0555(XTG_REPLACE_COLOR_KEY_R,XTG_REPLACE_COLOR_KEY_G,XTG_REPLACE_COLOR_KEY_B)

//!	16BIT颜色与32bit颜色的误差	
#define XTG_COLOR_E_R565					0X07
#define XTG_COLOR_E_G565					0X03
#define XTG_COLOR_E_B565					0X07
#define XTG_COLOR_E_R0555					0X07
#define XTG_COLOR_E_G0555					0X07
#define XTG_COLOR_E_B0555					0X07

//!	是否为关键色
#define XTGISCOLORKEYRGB(r,g,b)				(XTG_COLOR_KEY == XTRGB(r,g,b))
#define XTGISCOLORKEY(clrRGB)				(XTG_COLOR_KEY == clrRGB)
#define XTGISCOLORKEYRGBTO565(r,g,b)		(XTG_COLOR_KEY565 == XTRGB565(r,g,b))
#define XTGISCOLORKEYTO565(clrRGB)			(XTG_COLOR_KEY565 == XT32TO565(clrRGB))
#define XTGISCOLORKEY565TO565(clrRGB)		(XTG_COLOR_KEY565 == clrRGB)
#define XTGISCOLORKEYRGBTO0555(r,g,b)		(XTG_COLOR_KEY0555 == XTRGB0555(r,g,b))
#define XTGISCOLORKEYTO0555(clrRGB)			(XTG_COLOR_KEY565 == XT32TO0555(clrRGB))
#define XTGISCOLORKEY0555TO0555(clrRGB)		(XTG_COLOR_KEY0555 == clrRGB)

//!	与windows对应的RGBQUAD
typedef struct tagXTRGBQUAD 
{
	tagXTRGBQUAD(XTBYTE r,XTBYTE g,XTBYTE b,XTBYTE a)
		:rgbBlue(b),rgbGreen(g),rgbRed(r),rgbReserved(a)
	{
	}
	XTBYTE    rgbBlue;
	XTBYTE    rgbGreen;
	XTBYTE    rgbRed;
	XTBYTE    rgbReserved;
}XTRGBQUAD;
const XTRGBQUAD XTG_COLOR_TRANSPARENT	=	XTRGBQUAD(XTG_COLOR_KEY_R,XTG_COLOR_KEY_G,XTG_COLOR_KEY_B,0);

//! 裁减图片对象的图像时周围Alpha值为多少以下(包含该值)时将裁去(0--255;完全透明到完全不透明)
#define XTG_CUT_IMAGE_ALPHA				   12

//!	地图格子宽(象素为单位)
#define XTG_GRID_W							32
//!	地图格子高(象素为单位)
#define XTG_GRID_H							32
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//!	对象锁定代码,对象构造函数应该resetLock(),拷贝对象之后也应该resetLock();(多线程多CPU不大安全)
#define OBJ_LOCK_CODE \
atomic_t m_nLockC;\
void resetclock()\
{\
	vdl_atomic_set(&m_nLockC,0);\
}\
i32 clock()\
{\
	return (i32)vdl_atomic_inc_and_fetch(&m_nLockC);\
}\
void cunlock()\
{\
	if(vdl_atomic_dec_and_fetch(&m_nLockC) == 0)\
	{\
		delete this;\
	}\
}\
i32 getclock()const\
{\
	return (i32)vdl_atomic_get((atomic_t *)&m_nLockC);\
}

//!	激活对象代码,对象构造函数应该active()
#define OBJ_ACTIVE_CODE \
time_t m_tLastActive;\
void active(time_t tCur = 0)\
{\
	if(tCur == 0)\
	{\
		tCur = time(NULL);\
	}\
	m_tLastActive = tCur;\
}\
time_t getActiveTimespan(time_t tCur = 0)const\
{\
	if(tCur == 0)\
	{\
		tCur = time(NULL);\
	}\
	return tCur - m_tLastActive;\
}
//------------------------------------------------------------------------------

#endif//#ifndef _XTMACROS_H_FILE_
