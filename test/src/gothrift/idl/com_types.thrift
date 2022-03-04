# 例子 - thrift接口描述文件
#
# 编写这个文件是为了教会你如何写thrift接口描述文件。
# 第一个你应该掌握的知识点就是.thrift文件
# 支持shell的注释方式，那就是用#符号。
 
/**
* 我们首先来复习一下thrift的常用数据类型，如下所示：
*
* bool 布尔型，1个字节
* byte 有符号整数，1个字节
* i16 有符号16位整型
* i32 有符号32位整型
* i64 有符号64位整型
* double 64位浮点数值
* string 字符串类型
* binary 二进制数据类型（字节数组）
* list 单类型有序列表，允许有重复元素
* set 单类型无需集合，不允许有重复元素
* map&lt;t1,t2&gt; Map型（key:value）
*
* 你发现了么，.thrift文件还支持C语言的多行注释形式。
*/
 
// 不卖关子了，其实我们还支持C语言的单行注释形式呢 ^_^
 
/**
* .thrift文件可以引用其他.thrift文件，这样就可以方便地把一些公共结构和服务囊括进来。
* 在引用其他.thrift文件时，既可以直接引用当前文件夹下的文件，也可以引用其他路径下的
* 文件，但后者需要在thrift编译工具编译时加上-I选项来设定路径。
*
* 如果希望访问被包含的.thrift文件中的内容，则需要使用.thrift文件的文件名作为前缀，
* 比如shared.SharedObject。我们在本例中引用了文件shared.thrift。
*/
 
/**
* Thrift支持对.thrift文件中的类型设定namespace，这样可以有效避免名字冲突。
* 这种机制在C++中也叫做namespace，而在Java中叫做Package。
* thrift支持针对不同的语言设置不同的namespace，比如下面的例子。
* thrift会在生成不同语言代码时，进行相应的设置。
*/

#cpp_include "vdl/stdadf.h"

namespace cpp rpc

//-----------------------------------业务ID定义------------------------------------
/**媒资资产相关*/
typedef i64         ASSET_ID;           //全局资产ID
typedef i64         ASSET_RELEVANCE_ID; // homed媒资关联的宁夏媒资ID

typedef i64         PRG_ID;             // 节目ID
typedef i64         CHL_ID;             // 频道ID
typedef i32         CHL_NUM;            // 频道号
typedef i64         SERIES_ID;          // 点播剧集ID
typedef i64         VIDEO_ID;           // 点播单集ID
typedef i64         APP_ID;             // 应用ID
typedef i64         EVENT_ID;           // EPG ID
typedef i64         MUSIC_ID;           // 音乐ID
typedef i64         SINGER_ID;          // 歌手ID
typedef i64         ALBUM_ID;           // 专辑ID
typedef i64         NEWS_ID;            // 新闻ID
typedef i64         MONITOR_ID;         // 监控ID
typedef i64         MOSAIC_ID;          // 马赛克ID
typedef i64         MOSAIC_SET_ID;      // 马赛克setID
typedef i64         DUPLICATE_ID;       // 聚合ID
typedef i64         STAR_ID;            // 明星百科ID
typedef i64         SHOP_ID;            // 电商店铺ID
typedef i64         PROMO_ID;           // 电商活动ID
typedef i64         PRODUCT_ID;         // 电商产品ID
typedef i64         TOURISM_ROUTE_ID;   // 旅游线路ID
typedef i64         TOURISM_TICKET_ID;  // 旅游票务ID
typedef i64         TOURISM_HOTEL_ID;   // 旅游酒店ID
typedef i64         SUBJECT_ID;         // 专题ID
typedef i64         LIVE_ROOM_ID;       // 直播间ID
typedef i64         PLAYLIST_ID;        // 播单ID
typedef i64         PACKAGE_GROUP_ID;   // 套餐产品包ID
typedef i64         PACKAGE_ID;         // 套餐ID
typedef i64         PRICE_ID;           // 价格ID
typedef i64         GROUP_ID;           // 用户组、频道组、监控组，各种组的ID

/**媒资信息相关*/    
typedef i32         YEAR_ID;            // 年代
typedef i32         ACTOR_ID;           // 演员
typedef i32         DIRECTOR_ID;        // 导演
typedef i32         AGE_ID;             // 年龄
typedef i32         HEAT_VALUE;         // 热度值

/**栏目相关*/                                  
typedef i64         PLB_ID;             // 栏目ID
typedef i32         TREE_ID;            // treeid
typedef PLB_ID      MODULE_ID;          // 模块id
typedef i32         STRATEGY_ID;        // 策略id

/**分类相关*/                                  
typedef i32         TYPE_ID;            // type ID
typedef i32         CONTENTTYPE_ID;     // contenttype ID
typedef i32         SUBTYPE_ID;         // subtype ID
typedef i32         TAG_ID;             // 媒资标签 ID

typedef i64         USER_LABEL_ID;      //用户标签ID

/**平台相关*/                                  
typedef i32         PLATFORM_ID;        // 平台 ID
typedef i32         SERVER_ID;          // 平台 ID

/**套餐相关*/
typedef i64         BUY_ID;             // 购买ID
typedef i64         USER_ID;            // 用户ID

/**账号相关*/
typedef USER_ID     INTDA;              // DA使用数据类型
typedef i64         INTMEMBER;          // member_id使用数据类型
typedef i64         INTHOME;            // home_id使用数据类型
typedef i64         INTADDRESS;         // address_id使用数据类型
typedef i64         INTDEVICE;          // device_id使用数据类型
typedef i64         INTPAYMENT;         // payment_id使用数据类型
typedef i64         INTICON;            // icon_id使用数据类型
typedef i64         INTCOUNTRY;         // country_id使用的数据类型
typedef i64         INTPROVINCE;        // province_id使用的数据类型
typedef i64         INTCITY;            // city_id使用的数据类型
typedef i64         INTAREA;            // area_id使用的数据类型
typedef INTAREA     AREA_ID;            // 区域
typedef i64         INTTOWN;            // town_id使用的数据类型
typedef i64         INTVILLAGE;         // village_id使用的数据类型
typedef i64         INTPARENTCODE;      // parent_region_id使用的数据类型
typedef i64         INTVIRTUALCODE;     // virtual_region_id使用的数据类型
typedef i64         INTRIGHT;           // right_id使用的数据类型
typedef i64         INTDATARIGHT;       // dataright_id使用的数据类型
typedef i64         INTSYSTEM;          // system_id使用的数据类型
typedef i64         INTDEPARTMENT;      // department_id使用的数据类型
typedef i64         INTJOB;             // job_id使用的数据类型
typedef i64         INTID;              // 一些序列号使用的数据类型
typedef i64         INTRIGHTPACK;       // 权限包id
typedef i64         INTUSERGROUP;       // 用户组 ID
typedef i64         INTROLE;            // 用户角色
typedef i64         INTEQUIPMENT;       // 库存设备ID
typedef i64         INTPORTALGROUP;     // portal组 ID
typedef i64         INTPORTALID;        //portal的id类型
typedef i64         INTPORTALPAGEID;    //portal page的id类型
typedef i64         INTPORTALMETHODID;  //portal method的id类型
typedef i64         INTPORTALCELLID;    //portal cell的id类型
typedef i64         INTTHEMEID;         //theme的id类型


typedef LIVE_ROOM_ID    INTROOM;            // roomid使用数据类型
typedef INTDA           INTROOMADMIN;       // room admin 使用数据类型
typedef i64             INTBLACKLISTID;     // blacklist id 使用数据类型
typedef INTDA           INTANCHOR;          // anchor使用数据类型 
typedef INTDA           TARGETID;           //类型ID，取值来源用户ID，家庭ID，设备ID   

/**内容提供商相关*/
typedef i32             INT_PROVIDER_ID;    //内容提供商ID 数值型

/**EPG自动校正相关*/
typedef i32             EPG_SAMPLE_ID;      //样本id
typedef i32             EPG_RULE_ID;        //样本规则id
typedef i32             STATICLOGO_ID;      //静态logoid
typedef i32             SERIES_SAMPLE_ID;   //节目查重样本id
typedef i32             MSG_ID;             //消息id

/**后台业务平台相关*/   
typedef i32             SYSTEM_ID;          //后台业务系统id

/**搜索筛选相关*/ 
typedef i32             SEARCH_FILTER_ID;   //搜索筛选id

typedef i64             TASK_ID;            //任务ID
typedef i16             STRATEGY_TYPE;      //策略类型
typedef i32             PTASK_ID;
typedef i64             RECORD_ID;
//-----------------------------------业务ID定义------------------------------------

// struct Test{
//     //! 子命令
//     1:required  PRG_ID    cSubcmdID,
// }

struct ReqHead{
    //! 子命令
    1:required  i8    cSubcmdID,
    //! 请求方的服务ID
    2:required  i32   nSrvID,
    //! 调用序列号
    3:required  i64   nSN,
}

struct RespHead{
    //! 子命令
    1:required  i8    cSubcmdID,
    //! 请求方的服务ID
    2:required  i32   nSrvID,
    //! 调用序列号
    3:required  i64   nSN,
}

/*
 zipkin公共头部
*/
struct ZipkinHeader 
{
    1:required string  X_B3_TraceId,
    2:required string  X_B3_SpanId,
    3:required string  X_B3_ParentSpanId,
    4:required bool    X_B3_Sampled = true,
    5:required string  X_B3_Flags
}

/*
 opentracing rpc调用链传递上下文的结构体
*/
typedef ZipkinHeader OtRpcCtx;

/*
 私有协议和thrift混合序列化时用到
 与私有协议的头部完全保持一致，字段、顺序全一致
*/
struct BtfHead{
    1:required   i16   m_wVersion,
    2:required   i32   m_nCmdID,
    3:required   i8    m_cSubcmdID,
    4:required   i64   m_nUserID,  //! 这个有歧义，实际是指进程服务ID
    5:required   i64   m_nSN,
    6:required   i8    m_cEncryptType,
    7:required   i64   m_nContext1,
    8:required   i64   m_nContext2,
    9:required   i64   m_nContext3,
    10:required  i64   m_nContext4,
}
