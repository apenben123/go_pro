include "com_types.thrift"
include "iuct_types.thrift"

namespace cpp rpc

/* 通用接口支持的操作枚举 */
enum EUserCenterOption {
	E_ADD_PROGRAM_PRAISE			= 1,	//添加用户点踩点赞
	E_DEL_PROGRAM_PRAISE			= 2,	//添删除户点踩点赞
	E_ADD_USER_SCORE				= 11,	//添加用户评分
	E_ADD_USER_SUBSCRIBE			= 21,	//添加用户订阅
	E_DEL_USER_SUBSCRIBE			= 22,	//删除用户订阅
	E_ADD_USER_SETTING				= 31,	//添加用户设置
	E_GET_USER_SETTING				= 32,	//获取用户设置
	E_CHECK_USER_SETTING_PROFILE	= 33,	//判断用户个性化开关是否开启
	E_ADD_USER_RESOURCE				= 41,	//添加用户资源投放
	E_GET_USER_RESOURCE				= 42,	//获取用户资源投放信息
	E_GET_RESOURCE					= 43,	//获取资源投放信息
	E_ADD_USER_PROFILE				= 51,	//添加用户画像(测试接口)
	E_ADD_USER_LOCK					= 61,	//添加或修改加锁密码
	E_DEL_USER_LOCK					= 62,	//删除加锁密码
	E_GET_USER_LOCK					= 63,	//获取加锁密码
	E_DEL_COMMENT					= 71,	//删除用户评论
	E_ADD_COMMENT_PRAISE			= 81,	//添加评论点踩点赞
	E_DEL_COMMENT_PRAISE			= 82,	//删除评论点踩点赞
	E_GET_COMMENT_PRAISE			= 83,	//获取评论点踩点赞次数
	E_DEL_USER_ALL_SHARES			= 91,	//删除用户自己分享的全部内容
	E_ADD_SEARCH_HISTORY			= 101,	//添加搜索历史
	E_DEL_SEARCH_HISTORY			= 102,	//删除搜索历史
	E_ADD_VOTE						= 111,	//添加投票
}

//返回基本数据结构
struct IuctRespBase {
	1: required i32                         nRetCode;	//结果: 0表示成功,其他值异常
	2: required string                      strRetMsg;	//结果消息
	3: optional i64                         nOutId1;	//预留整型数据
	4: optional i64                         nOutId2;	//预留整型数据
}

//请求个人中心数据结构
struct UserCenterReq {
	1: required com_types.PRG_ID            nPid;		//节目id
	2: optional com_types.USER_ID           nUid;		//用户id
	3: optional i64                         tUpdateTime;//操作时间
	4: optional i64                         nInId1;		//预留整型数据
	5: optional i64                         nInId2;		//预留整型数据
	6: optional string                      strInData1;	//预留字符串数据
	7: optional string                      strInData2;	//预留字符串数据
}

//请求个人中心数据结构
struct UserCenterUserReq {
	1: required com_types.USER_ID           nUid;		// 用户id
	2: optional i64                         nInId1;		// 预留整型数据
	3: optional i64                         nInId2;		// 预留整型数据
	4: optional i64                         nInId3;		// 预留整型数据
	5: optional string                      strInData1;	// 预留字符串数据
}

//请求个人中心数据结构 （低频接口统一函数使用）
struct UserCenterCommReq {
	1: required EUserCenterOption           eOption;	//操作选项
	2: required UserCenterUserReq           stParam;	//操作参数
}

/* 通用模块 */
struct MultiIntReq {
	1: required list<com_types.PRG_ID>      vecPids;
	2: required i64                         nUid;
	3: optional i32                         nFunction;
	4: optional list<com_types.SERIES_ID>   vecSids;
}

struct MultiIntResp {
	1: required IuctRespBase                stRetComm;
	2: required list<i32>                   vecIntRets1;
	3: optional list<i32>                   vecIntRets2;
}

struct MultiBigIntResp {
	1: required IuctRespBase                stRetComm;
	2: required list<i64>                   vecBigIntRets1;
	3: optional list<i64>                   vecBigIntRets2;
}

struct MultiBoolResp {
	1: required IuctRespBase                stRetComm;
	2: required list<bool>                  vecbRets;
}

struct MultiStrReq {
	1: required set<string>                 setStr;
	2: required i64                         nUid;
}

/* 1. 历史模块 */
struct HistoryReq {
	1: required com_types.PRG_ID            nPid;
	2: required com_types.USER_ID           nUid;
	3: required com_types.SERIES_ID         nSid;
	4: required string                      strSp;
}

struct HistoryResp {
	1: required IuctRespBase                stRetComm;
	2: required i32                         nOffSet;
	3: required i64                         tTimeStamp;
	4: optional com_types.PRG_ID            nPid;
}

struct HistoryListReq {
	1: required com_types.USER_ID           nUid;
	2: required set<i32>                    setTypes;
	3: required string                      strSp;
	4: required bool                        bGetAll = false;
	5: optional list<com_types.USER_ID>     vecUid;
}

struct HistoryListResp {
	1: required IuctRespBase                  stRetComm;
	2: required list<iuct_types.USER_HISTORY> vecHistorys;
	3: required list<com_types.PRG_ID>        vecIds;
}

struct UserSeriesProHisListResp {
	1: required IuctRespBase                  stRetComm;
	2: required com_types.PRG_ID              nLastHitPid;
	3: required i32                           nOffSet;
	4: required map<com_types.PRG_ID, i32>    mapPidHis;
}

struct UserSerirsHisListResp {
	1: required IuctRespBase                  stRetComm;
	2: required map<com_types.SERIES_ID, i32>   mapSidHis;
}


/* 3&4. 收藏/关注/追剧/预约模块 */
struct MultiFavoriteReq {
	1: required i64                         nUid;
	2: required list<com_types.PRG_ID>      vecPids;
	3: required i64                         tTimeStamp;
	4: optional list<com_types.SERIES_ID>   vecSids;
	5: optional i32                         nFunction;
}

struct IsFavsResp {
	1: required IuctRespBase                 stRetComm;
	2: required iuct_types.ISFAVORITE        stIsFavs;
}

struct MultiIsFavsResp {
	1: required IuctRespBase                 stRetComm;
	2: required list<iuct_types.ISFAVORITE>  vecIsFavs;
}

struct FavoriteListReq {
	1: required i64                         nUid;
	2: required set<i32>                    setTypes;
	3: required i32                         nFunction;
}

struct FavoriteListResp {
	1: required IuctRespBase                  stRetComm;
	2: required list<iuct_types.USER_FAVORITE> vecFavorite;
	3: required list<com_types.PRG_ID>        vecIds;
}


/* 5. 通知模块（收藏/关注/追剧/预约模块衍生） */
struct ProgramUpdateReq {
	1: required list<iuct_types.SERIESUPDATE> vecUpdate;
}


/* 6. 点击量模块 */
struct UserHitsReq {
	2: required com_types.USER_ID           nUid;
	1: required com_types.PRG_ID            nPid;
	3: required com_types.SERIES_ID         nSid;
	4: required i32                         nDeviceType;
}

struct MultiHitsReq {
	1: required list<com_types.PRG_ID>        vecPids;
	2: optional list<list<com_types.PRG_ID> > vecDistinctPids;
	3: optional i32                         nDeviceType;
	4: optional i32                         ePeriod;
}

struct MultiHitsResp {
	1: required IuctRespBase                stRetComm;
	2: required list<i32>                   vecHitsNums;
	3: required list<i64>                   vecPids;
}


/* 7. 点踩点赞模块 */
struct MultiPraiseResp {
	1: required IuctRespBase                stRetComm;
	2: required list<i32>                   vecPraiseNums;
	3: required list<i32>                   vecDegradeNums;
}


/* 9. 节目综合信息模块 */
struct DemandResp {
	1: required IuctRespBase                stRetComm;
	2: required iuct_types.PROGRAM_DEMAND   stDemand;
}

struct MultipleDemandReq {
	1: required list<i64>                   vecPids;
	2: required list<i64>                   vecSids;
	3: optional i32                         nDeviceType;
	4: optional i32                         ePeriod;
}

struct MultipleDemandResp {
	1: required IuctRespBase                      stRetComm;
	2: required list<iuct_types.PROGRAM_DEMAND>   vecDemands;
}


/* 11. 用户设置模块 */
struct UserColumnReq {
	1: required i64                         nUid;
	2: required list<com_types.USER_LABEL_ID> vecLabels;
}

struct UserColumnResp {
	1: required IuctRespBase                  stRetComm;
	2: required map<com_types.PLB_ID, iuct_types.ColumnSetting> mapColumnData;
}


/* 16. 用户回看节目预定模块 */
struct OrderReq {
	1: required iuct_types.USER_ORDER stOrder;
	2: optional i32                   nIsCover;
}

struct MultiIsOrderReq {
	1: required i64                         nUid;
	2: required list<iuct_types.ORDER>      vecOrder;
}

struct OrderListResp {
	1: required IuctRespBase                stRetComm;
	2: required i32                         nTotal;
	3: required list<iuct_types.USER_ORDER> vecOrder;
}


/* 17. 用户分享模块 */
struct ShareAddReq {
	1: required iuct_types.SHARE_INFO       stShare;
	2: required i32                         nPlatForm;
}

struct ShareListResp {
	1: required IuctRespBase                      stRetComm;
	2: required list<iuct_types.SHARE_INFO>      vecShares;
}


/* 18. 用户评论模块 */
struct CommentListResp {
	1: required IuctRespBase                      stRetComm;
	2: required list<iuct_types.USER_COMMENT_INFO>      vecComments;
	3: required list<iuct_types.USER_COMMENT_INFO>      vecRefComments;
}


/* 21. 排行榜模块 */
struct ProgramRankInfoResp {
	1: required IuctRespBase               stRetComm;
	2: required list<iuct_types.RankInfo>  vecInfo;	//节目在排行榜中的信息
}

struct RankListReq {
	1: required i32  eRankType;
	2: required i32  eOp;
	3: required i32  nType;
	4: required i32  nContentType;
	5: required i32  nSubType;
	6: required i32  ePeriod;
}

struct RankListResp {
	1: required IuctRespBase                 stRetComm;
	2: required list<iuct_types.RankItem>    vecRank;
}


/* 22. 用户搜索历史模块 */
struct SearchHistoryListResp {
	1: required IuctRespBase                  stRetComm;
	2: required list<iuct_types.USER_SEARCH_HISTORY> vecSearchHistorys;
}

/**************************************************
	请求删除用户数据数据结构
	nUid			用户id
	vecIds			历史id列表
**************************************************/
struct DelIdsReq {
	1: required i64                         nUid;
	2: required list<i64>                   vecIds;
}


/* 24. 猜你喜欢模块 */
struct GuessSubjResp{
	1: required IuctRespBase               stRetComm;
	2: required list<iuct_types.GuessSubjSingle> vecSubjects;
}

/**************************************************
	请求用户节目数据结构
	nPid			节目id
	nUid			用户id
	nSid			节目剧集id
	nDeviceType		设备类型
	bFavs			获取是否收藏
	bPraise			获取是否点踩点赞
	bHistory		获取历史
	bUserScore		获取用户对节目的评分
	strSp			节目提供商, 获取历史时必填
	ePeriod			获取周期 0 所有; 1 今天; 2 昨天
**************************************************/
struct UserProgramReq {
	1: required i64                         nPid;
	2: required i64                         nUid;
	3: required i64                         nSid;
	4: optional i32                         nDeviceType;
	5: optional bool                        bFavs;
	6: optional bool                        bPraise;
	7: optional bool                        bHistory;
	8: optional bool                        bUserScore;
	9: optional string                      strSp;
	10: optional i32                        ePeriod;
}

/**************************************************
	返回用户节目数据结构
	stRetComm			返回基本数据结构
	stDemand			节目综合数据
	stIsFavs			是否收藏&关注&追剧&预约
	nPraiseStatus		是否点踩点赞
	nLastHitsId			剧集中上次观看的频道
	nOffSet				剧集中上次观看频道的具体位置
**************************************************/
struct UserProgramResp {
	1: required IuctRespBase                  stRetComm;
	2: required iuct_types.USER_PROGRAM       stPro;
}

/**************************************************
	请求批量用户节目数据结构
	vecPids			节目id列表
	vecSids			节目剧集id列表
	nUid			用户id
	nDeviceType		设备类型
	bFavs			获取是否收藏
	bPraise			获取是否点踩点赞
	bHistory		获取历史
	bUserScore		获取用户对节目的评分
	vecSp			节目提供商, 获取历史时必填
	ePeriod			获取周期 0 所有; 1 今天; 2 昨天
**************************************************/
struct MultiUserProgramReq {
	1: required list<i64>                   vecPids;
	2: required list<i64>                   vecSids;
	3: required i64                         nUid;
	4: optional i32                         nDeviceType;
	5: optional bool                        bFavs;
	6: optional bool                        bPraise;
	7: optional bool                        bHistory;
	8: optional bool                        bUserScore;
	9: optional list<string>                vecSp;
	10: optional i32                        ePeriod;
}

/**************************************************
	返回用户节目数据结构
	stRetComm			返回基本数据结构
	stDemand			节目综合数据
	stIsFavs			是否收藏&关注&追剧&预约
	nPraiseStatus		是否点踩点赞
	nLastHitsId			剧集中上次观看的频道
	nOffSet				剧集中上次观看频道的具体位置
**************************************************/
struct MultiUserProgramResp {
	1: required IuctRespBase                  stRetComm;
	2: required list<iuct_types.USER_PROGRAM> vecPro;
}


// iuct rpc 服务接口
service iuct_thrift_service 
{
	/* thrift服务监控API */
	i32 monitorqueryprocessstatus();

	/* 0. 个人中心模块通用接口（部分低频接口的统一rpc接口） 
		eOption 取值列表
		 1: 添加用户点踩点赞			- program_praise
		 2: 添删除户点踩点赞			- program_praise
		11: 添加用户评分				- user_score
		12: 删除用户评分				- user_score
		21: 添加用户订阅				- user_subscribe
		22: 删除用户订阅				- user_subscribe
		31: 添加用户设置				- user_setting
		32: 删除用户设置				- user_setting
		41: 添加用户资源投放			- user_resource
		51: 添加用户画像(测试接口)		- user_profile 
		61: 添加用户设置或修改加锁密码	- user_lock
		62: 删除用户设置或修改加锁密码	- user_lock
	*/
	IuctRespBase rpc_do_user_center_comm_request(1:UserCenterCommReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 1. 历史模块 */
	//增加历史
	IuctRespBase rpc_do_add_user_history_request(1:iuct_types.USER_HISTORY req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//删除历史
	IuctRespBase rpc_do_del_user_history_request(1:iuct_types.USER_HISTORY req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户历史
	HistoryResp rpc_do_get_user_history_request(1:HistoryReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户历史列表
	HistoryListResp rpc_do_get_user_history_list_request(1:HistoryListReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户剧集中上一个点击的节目
	HistoryResp rpc_do_get_user_last_program_by_seriesid(1:UserCenterReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户剧集中上一个点击的节目以及每个节目的点击历史	
	UserSeriesProHisListResp rpc_do_get_user_program_list_by_seriesid(1:UserCenterReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户剧集历史（猜你在追的剧集功能使用）
	UserSerirsHisListResp rpc_do_get_user_series_history(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 2. 关机频道模块（历史模块衍生） */
	//获取关机频道号
	IuctRespBase rpc_do_get_user_watching_channel_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 3&4. 收藏/关注/追剧/预约模块 */
	//添加用户收藏/关注/追剧/预约
	IuctRespBase rpc_do_add_user_favorite_request(1:iuct_types.USER_FAVORITE req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//删除用户收藏/关注/追剧/预约
	IuctRespBase rpc_do_del_user_favorite_request(1:iuct_types.USER_FAVORITE req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量添加用户收藏（个人频道排序上传时批量增加/取消收藏频道时使用）
	IuctRespBase rpc_do_add_multiple_user_favorite_request(1:MultiFavoriteReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量删除用户收藏（个人频道排序上传时批量增加/取消收藏频道时使用）
	IuctRespBase rpc_do_del_multiple_user_favorite_request(1:MultiFavoriteReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//判断用户是否收藏(单内容判断,只判断收藏/关注/追剧/预约)
	IuctRespBase rpc_do_check_is_favorite_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量判断用户否收藏(单内容判断,只判断收藏/关注/追剧/预约)
	MultiBoolResp rpc_do_multiple_check_is_favorite_request(1:MultiIntReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//判断用户是否收藏(多内容判断,同时判断收藏&关注&追剧&预约)
	IsFavsResp rpc_do_check_is_favs_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量判断用户是否收藏(多内容判断,同时判断收藏&追剧&预约)
	MultiIsFavsResp rpc_do_multiple_check_is_favs_request(1:MultiIntReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户收藏/关注/追剧/预约列表
	FavoriteListResp rpc_do_get_user_favorite_list_request(1:FavoriteListReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 5. 通知模块（收藏/关注/追剧/预约模块衍生） */
	//通知用户节目更新
	IuctRespBase rpc_do_notify_user_program_update_request(1:ProgramUpdateReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 6. 点击量模块 */
	//节目点击量上报
	IuctRespBase rpc_do_program_enter_request(1:UserHitsReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//退出节目
	IuctRespBase rpc_do_program_exit_request(1:UserHitsReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取节目点击数
	IuctRespBase rpc_do_get_program_hits_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量获取节目点击数
	MultiHitsResp rpc_do_multiple_get_program_hits_request(1:MultiHitsReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 7. 点踩点赞模块 */
	//判断用户是否点踩点赞请求
	IuctRespBase rpc_do_check_is_praise_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量判断用户是否点踩点赞请求
	MultiIntResp rpc_do_multiple_check_is_praise_request(1:MultiIntReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取节目点踩点赞数
	IuctRespBase rpc_do_get_pid_praise_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量获取节目点踩点赞数
	MultiPraiseResp rpc_do_multiple_get_pids_praise_request(1:MultiIntReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 8. 评分模块 */

	/* 9. 节目综合信息模块 */
	//获取节目综合信息
	DemandResp rpc_do_get_program_demand_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量获取节目综合信息
	MultipleDemandResp rpc_do_get_multiple_program_demand_request(1:MultipleDemandReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 10. 用户订阅模块 */
	//获取用户订阅列表 (订阅和收藏使用的同一个结构体)
	FavoriteListResp rpc_do_get_user_subscribe_list_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 11. 用户设置模块 */
	//获取用户个性化栏目列表
	UserColumnResp rpc_do_get_user_column_list_request(1:UserColumnReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 12. 常看频道模块 */
	//获取用户常看频道列表
	MultiBigIntResp rpc_do_get_user_often_watch_channel_list_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 13. 用户资源投放模块 */

	/* 14. 用户画像模块 */
	//获取用户最爱观看的栏目和剧集
	MultiBigIntResp rpc_do_get_user_interest_column_and_series_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户最感兴趣媒资
	MultiIntResp rpc_do_get_user_interest_medias_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 15. 用户设置或修改加锁密码模块 */
	
	/* 16. 用户回看节目预定模块 */
	//添加预定
	IuctRespBase rpc_do_add_user_order_request(1:OrderReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//取消预定
	IuctRespBase rpc_do_del_user_order_request(1:OrderReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户预约未来epg
	IuctRespBase rpc_do_check_is_order_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量获取用户预约未来epg
	MultiIntResp rpc_do_check_multiple_is_order_request(1:MultiIsOrderReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取预约列表
	OrderListResp rpc_do_get_user_order_list_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 17. 用户分享模块 */
	//添加一条分享记录
	IuctRespBase rpc_do_add_share_request(1:ShareAddReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//批量删除分享记录
	IuctRespBase rpc_do_multiple_del_share_request(1:MultiStrReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户的分享列表
	ShareListResp rpc_do_get_user_share_list_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取媒资分享次数
	IuctRespBase rpc_do_get_program_share_times_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 18. 用户评论模块 */
	//添加用户评论
	IuctRespBase rpc_do_add_comment_request(1:iuct_types.USER_COMMENT_INFO req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取节目评论列表，返回节目评论总数
	CommentListResp rpc_do_get_program_comment_list_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//根据评论ID获取所有引用评论信息
	CommentListResp rpc_do_get_comment_list_by_commentid_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 19. 用户评论点踩点赞模块 */
	//批量获取评论ID的踩赞次数
	MultiPraiseResp rpc_do_multiple_get_comments_praise_request(1:MultiStrReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

	/* 20. 用户投票模块 */

	/* 21. 排行榜模块 */
	//获取排行榜
	RankListResp rpc_do_get_rank_list(1:RankListReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取节目在排行榜中的信息
	ProgramRankInfoResp rpc_do_get_program_rank_info(1:com_types.PRG_ID nPid, 2:com_types.ZipkinHeader ot_rpc_ctx);

	/* 22. 用户搜索历史模块 */
	//获取用户搜索历史
	SearchHistoryListResp rpc_do_get_user_search_history_request(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),


	/* 23. 用户弹幕模块 */

	
	/* 24. 猜你喜欢模块 */
	//获取用户指定contenttype下喜欢的所有专题
	MultiBigIntResp rpc_do_get_user_all_subject(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户指定contenttype下喜欢的所有专题以及节目（翻页）
	GuessSubjResp rpc_do_get_user_all_subject_and_program(1:UserCenterUserReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//获取用户指定contentype下的指定专题的节目信息（翻页）
	MultiBigIntResp rpc_do_get_user_subject_program(1:UserCenterReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),


	//rpc处理获取用户节目数据
	UserProgramResp rpc_do_get_user_program_info_request(1:UserProgramReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),
	//rpc处理批量获取用户节目数据
	MultiUserProgramResp rpc_do_get_multiple_user_program_info_request(1:MultiUserProgramReq req, 2:com_types.ZipkinHeader ot_rpc_ctx),

}
