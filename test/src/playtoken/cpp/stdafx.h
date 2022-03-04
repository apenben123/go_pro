#ifndef __STDAFX_H__
#define __STDAFX_H__

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>

/* WIN32 */
#if (defined _W64 || defined WIN32)
	//#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers

#ifndef _WIN32_WINNT
//----beg----------------------------------------------------------------------
//	Modified by chengxuewen,2018:9:20,定义太低的windows版本号会导致很多代码无法编译了
//#define _WIN32_WINNT 0x0501
#define _WIN32_WINNT 0x0601
//----end----------------------------------------------------------------------
#endif
	#include <conio.h>
	#include <Winsock2.h>
	#include <ws2tcpip.h>
	#include <io.h>
	#include <Iphlpapi.h>

	#pragma comment( lib, "Ws2_32.lib" )
	#pragma comment( lib, "Iphlpapi.lib" )

	typedef unsigned char bool_t;
	typedef unsigned char uint8_t;
	typedef unsigned char uchar_t;
	typedef char char_t;
	typedef unsigned int uint32_t;
	typedef unsigned short uint16_t;
	typedef unsigned __int64 uint64_t;
	typedef short int16_t;
	typedef int int32_t;
	typedef __int64 int64_t;

	#define IS_MULTICAST_IP(ip) ( 0xE0<=(ip&0xFF) && (ip&0xFF)<0xF0 )
	#define strtoll _strtoi64
	#define strtoull _strtoui64
	#ifndef inline
	#define inline __inline
	#endif

#else
	/* LINUX */
	#include <unistd.h> 
	#ifndef __USE_GNU
	#define __USE_GNU 
	#endif
	#include <sched.h> 
	#include <pthread.h>
	#include <semaphore.h>
	#include <inttypes.h>
	#include <signal.h>
	#include <fcntl.h>
	#include <getopt.h>
	#include <termios.h>
	#include <netdb.h>
	#include <stdint.h>
	#include <arpa/inet.h>
		
	#include <netinet/in.h>
	#include <netinet/ip.h>
	#include <netinet/udp.h>
	#include <netinet/tcp.h>
	
	#include <net/if.h> 
	#include <net/if_arp.h> 
		
	#include <sys/socket.h>
	#include <sys/stat.h>
	#include <sys/ioctl.h>
	#include <sys/param.h> 
	#include <sys/types.h>
	#include <sys/timeb.h>
	#include <sys/time.h>
	#include <sys/reboot.h>
	#include <sys/mount.h>
	#include <sys/mman.h>	
	#include <sys/wait.h>
	#include <dlfcn.h>
	#include <linux/reboot.h>
	#include <linux/if_ether.h>
	#include <linux/if_packet.h>
	#include <linux/fb.h>
	#include <linux/ethtool.h>
	#include <linux/sockios.h>
	#include <linux/prctl.h>	
	#include <dirent.h>

	#define IS_MULTICAST_IP(ip) ( 0xE0<=(ip&0xFF) && (ip&0xFF)<0xF0 )	
	typedef unsigned char bool_t;
	typedef unsigned char uchar_t;
	typedef char char_t;
	//typedef int64_t SOCKET;
	typedef unsigned int SOCKET;
	#define INVALID_SOCKET -1
#endif

#ifndef __cplusplus
	#ifndef bool
	#define bool uint8_t
	#endif	

	#ifndef true
	#define true 1
	#endif	

	#ifndef false
	#define false 0
	#endif 
#endif /* __cplusplus */

	//--------------------------------------------------------------------------
	//	Added by chengxuewen, 2013:3:25,基本类型写法更加简单,而且一看就是自己定义而不是IDE定义的
#ifndef DEFINED_SIMPLE_TYPE
#define DEFINED_SIMPLE_TYPE
	typedef char		int8;
	typedef uint8_t		uint8;
	typedef int16_t		int16;
	typedef uint16_t	uint16;
	typedef int32_t		int32;
	typedef uint32_t	uint32;
	typedef int64_t		int64;
	typedef uint64_t	uint64;

	typedef int8		i8;
	typedef uint8		u8;
	typedef int16		i16;
	typedef uint16		u16;
	typedef int32		i32;
	typedef uint32		u32;
	typedef int64		i64;
	typedef uint64		u64;
#endif//#ifndef DEFINED_SIMPLE_TYPE
	//--------------------------------------------------------------------------

	//-----------------------------------------------------------------------------
	//!	本模块的动态库或静态库编译开关
#if (defined _W64 || defined WIN32)
	#ifndef XT_VDL_DLL
		#if (defined XT_BUILD_VDL_LIB || defined XT_USE_VDL_LIB)
			#define		XT_VDL_DLL										//!<指明要使用静态库
		#else 
			#ifdef XT_BUILD_VDL_DLL
				#define XT_VDL_DLL			__declspec(dllexport)		//!<指明要导出动态库
			#elif defined XT_USE_VDL_DLL
				#define XT_VDL_DLL			__declspec(dllimport)		//!<指明要导入动态库
			#else 
				#define XT_VDL_DLL										//!<默认使用静态库
			#endif
		#endif
	#endif
#else
	#ifndef XT_VDL_DLL
		#define XT_VDL_DLL												//!<非windows一律没有特殊控制
	#endif
#endif
	//-----------------------------------------------------------------------------
	
	//-----------------------------------HOMED 版本定义------------------------------------
	//#define HOMED_VERSION 1   //1.0的版本号
	#define HOMED_VERSION 2 //2.0的版本号
	
	#define HOMED_VERSION_1 (HOMED_VERSION==1)
	#define HOMED_VERSION_2 (HOMED_VERSION==2)
	//-----------------------------------HOMED 版本定义------------------------------------

	//-----------------------------------业务ID定义------------------------------------
	/**媒资资产相关*/
	typedef int64_t         ASSET_ID;           //全局资产ID
	typedef int64_t         ASSET_RELEVANCE_ID; // homed媒资关联的宁夏媒资ID

	typedef int64_t         PRG_ID;             // 节目ID
	typedef int64_t         CHL_ID;             // 频道ID
	typedef uint32_t		CHL_NUM;			// 频道号
	typedef int64_t         SERIES_ID;          // 点播剧集ID
	typedef int64_t         VIDEO_ID;           // 点播单集ID
	typedef int64_t         APP_ID;             // 应用ID
	typedef int64_t         EVENT_ID;           // EPG ID
	typedef int64_t         MUSIC_ID;           // 音乐ID
	typedef int64_t         SINGER_ID;          // 歌手ID
	typedef int64_t         ALBUM_ID;           // 专辑ID
	typedef int64_t         NEWS_ID;            // 新闻ID
	typedef int64_t         MONITOR_ID;         // 监控ID
	typedef int64_t         MOSAIC_ID;          // 马赛克ID
	typedef int64_t			MOSAIC_SET_ID;		// 马赛克setID
	typedef int64_t         DUPLICATE_ID;       // 聚合ID
	typedef int64_t         STAR_ID;            // 明星百科ID
	typedef int64_t         SHOP_ID;            // 电商店铺ID
	typedef int64_t         PROMO_ID;           // 电商活动ID
	typedef int64_t         PRODUCT_ID;         // 电商产品ID
	typedef int64_t         TOURISM_ROUTE_ID;   // 旅游线路ID
	typedef int64_t         TOURISM_TICKET_ID;  // 旅游票务ID
	typedef int64_t         TOURISM_HOTEL_ID;   // 旅游酒店ID
	typedef int64_t         SUBJECT_ID;         // 专题ID
	typedef int64_t         LIVE_ROOM_ID;       // 直播间ID
	typedef int64_t         PLAYLIST_ID;        // 播单ID
	typedef int64_t			PACKAGE_GROUP_ID;	// 套餐产品包ID
	typedef int64_t			PACKAGE_ID;			// 套餐ID
	typedef int64_t			PRICE_ID;			// 价格ID
	typedef int64_t			GROUP_ID;			// 用户组、频道组、监控组，各种组的ID

	/**媒资信息相关*/    
	typedef int32_t         YEAR_ID;            // 年代
	typedef uint32_t        ACTOR_ID;           // 演员
	typedef uint32_t        DIRECTOR_ID;        // 导演
	typedef int32_t         AGE_ID;             // 年龄
	typedef int32_t         HEAT_VALUE;         // 热度值
	
	/**栏目相关*/                                  
	typedef int64_t			PLB_ID;             // 栏目ID
	typedef uint32_t		TREE_ID;            // treeid
	typedef PLB_ID			MODULE_ID;          // 模块id
	typedef uint32_t		STRATEGY_ID;        // 策略id
	
	/**分类相关*/                                  
	typedef int32_t         TYPE_ID;            // type ID
	typedef int32_t         CONTENTTYPE_ID;     // contenttype ID
	typedef int32_t         SUBTYPE_ID;         // subtype ID
	typedef int32_t         TAG_ID;             // 媒资标签 ID

	typedef uint32_t		USER_LABEL_ID;		//用户标签ID
	
	/**平台相关*/	                               
	typedef int32_t         PLATFORM_ID;        // 平台 ID
	typedef int32_t         SERVER_ID;        // 平台 ID
	
	/**套餐相关*/
	typedef int64_t         BUY_ID;             // 购买ID
    typedef int64_t         USER_ID;            // 用户ID
	
	/**账号相关*/
	typedef	USER_ID		    INTDA;			    // DA使用数据类型
	typedef	int64_t			INTMEMBER;		    // member_id使用数据类型
	typedef	int64_t			INTHOME;		    // home_id使用数据类型
	typedef	int64_t			INTADDRESS;		    // address_id使用数据类型
	typedef	int64_t			INTDEVICE;		    // device_id使用数据类型
	typedef	uint64_t		INTPAYMENT;		    // payment_id使用数据类型
	typedef	int64_t			INTICON;		    // icon_id使用数据类型
	typedef int64_t			INTCOUNTRY;		    // country_id使用的数据类型
	typedef int64_t			INTPROVINCE;	    // province_id使用的数据类型
	typedef int64_t			INTCITY;		    // city_id使用的数据类型
	typedef int64_t			INTAREA;		    // area_id使用的数据类型
	typedef INTAREA			AREA_ID;			// 区域
	typedef int64_t			INTTOWN;		    // town_id使用的数据类型
	typedef int64_t			INTVILLAGE;		    // village_id使用的数据类型
	typedef uint64_t		INTPARENTCODE;		// parent_region_id使用的数据类型
	typedef uint64_t		INTVIRTUALCODE;		// virtual_region_id使用的数据类型
	typedef uint32_t		INTRIGHT;		    // right_id使用的数据类型
    typedef uint32_t        INTDATARIGHT;       // dataright_id使用的数据类型
	typedef uint32_t		INTSYSTEM;		    // system_id使用的数据类型
	typedef uint32_t		INTDEPARTMENT;	    // department_id使用的数据类型
	typedef uint32_t		INTJOB;			    // job_id使用的数据类型
	typedef uint64_t		INTID;			    // 一些序列号使用的数据类型
	typedef uint32_t		INTRIGHTPACK;	    // 权限包id
	typedef int64_t			INTUSERGROUP;	    // 用户组 ID
	typedef uint32_t		INTROLE;		    // 用户角色
	typedef int64_t			INTEQUIPMENT;		// 库存设备ID
    typedef int64_t         INTPORTALGROUP;     // portal组 ID

	typedef	LIVE_ROOM_ID	INTROOM;			// roomid使用数据类型
	typedef INTDA			INTROOMADMIN;		// room admin 使用数据类型
	typedef uint32_t		INTBLACKLISTID;		// blacklist id 使用数据类型
	typedef INTDA			INTANCHOR;			// anchor使用数据类型	
	typedef INTDA			TARGETID;			//类型ID，取值来源用户ID，家庭ID，设备ID	
	typedef int64_t			TOKENID;			// TOKEN ID使用的数据类型

    /**内容提供商相关*/
	typedef int32_t         INT_PROVIDER_ID;    //内容提供商ID 数值型

	/**EPG自动校正相关*/
	typedef uint32_t        EPG_SAMPLE_ID;      //样本id
	typedef uint32_t        EPG_RULE_ID;        //样本规则id
	typedef uint32_t        STATICLOGO_ID;      //静态logoid
	typedef uint32_t        SERIES_SAMPLE_ID;   //节目查重样本id
	typedef uint32_t        MSG_ID;             //消息id

	/**后台业务平台相关*/	
	typedef uint32_t        SYSTEM_ID;          //后台业务系统id
	
	/**搜索筛选相关*/	
	typedef uint32_t        SEARCH_FILTER_ID;   //搜索筛选id
	
	typedef int64_t         TASK_ID;        //任务ID
	//-----------------------------------业务ID定义------------------------------------

#endif /* __STDAFX_H__ */

