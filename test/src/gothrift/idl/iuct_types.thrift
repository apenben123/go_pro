include "com_types.thrift"
include "rdspkg_base.thrift"

namespace cpp rpc

/**************************************************
	用户评分数据结构
	i64			评分id
	userID			用户DA
	dataID			节目id
	score			评分
	timestamp		生成时间
	updateTime		修改时间
**************************************************/
struct USER_SCORE {
	1: required i64 nId;
	2: required com_types.INTDA userID;
	3: required com_types.PRG_ID dataID;
	4: required i32 score;
	5: required i64 timestamp;
	6: required i64 updateTime;
}

/**************************************************
	用户收藏/关注/追剧数据结构
	i64			收藏/关注/追剧id
	unUserId		用户DA
	unFavoriteId		节目id
	unFunction		操作类型(0:收藏,1:关注,2:追剧)
	timestamp		生成时间
	updateTime		修改时间
**************************************************/
struct USER_FAVORITE {
	1: required i64 nId;
	2: required com_types.INTDA unUserId;
	3: required com_types.PRG_ID unFavoriteId;
	4: required i32 unFunction;
	5: required i64 timestamp;
	6: required i64 updateTime;
}

/**************************************************
	用户设置数据结构
	unDataId		设置类型
	unUserId		用户DA
	unDataValue		设置数据
	updateTime		修改时间
**************************************************/
struct USER_SETTING {
	1: required i32 unDataId;
	2: required com_types.INTDA unUserId;
	3: required string unDataValue;
	4: required i64 updateTime;
}

/**************************************************
	用户画像数据结构
	nDA			用户DA
	nTypeId			画像类型(按天/月/季度/年生成用户画像)
	strData			用户画像数据
	updateTime		生成时间
**************************************************/
struct USER_PROFILE
{
	1: required com_types.INTDA nDA;
	2: required i16 nTypeId;
	3: required string strData;
	4: required i64 updateTime;
}

/**************************************************
	用户设置数据结构
	program_id		节目id
	hits			点击次数
	updateTime		更新时间
**************************************************/
struct PROGRAM_HITS
{
	1: required com_types.PRG_ID program_id;
	2: required i32 hits;
	4: required i64 updateTime;
}

/**************************************************
	用户关机频道数据结构
	nId			关机频道id
	userID			点击次数
	deviceTypeID		设备类型(机顶盒,手机,pad)
	channelID		频道id
	last_time		时间
	updateTime		更新时间
**************************************************/
struct WATCHING_CHANNEL
{
	1: required i64 nId;
	2: required com_types.INTDA userID;
	3: required i32 deviceTypeID;
	4: required com_types.CHL_ID channelID;
	5: required i64 last_time;
	6: required i64 updateTime;
}

/**************************************************
	用户点击数据结构
	nId			用户点击id
	nPid			点击次数
**************************************************/
struct HITS_SIMPLE
{
	1: required i64 nId;
	2: required com_types.PRG_ID nPid;
}

/**************************************************
	用户点击redis存储数据结构
	sHits			用户点击剧集中的单集列表
	nLastHitPid		上次点击节目id
	tLastHitTime		上次点击时间
**************************************************/
struct USER_HITS_RDS
{
	1: required set<HITS_SIMPLE> sHits;
	2: required com_types.PRG_ID nLastHitPid;
	3: required i64 tLastHitTime;
}

/**************************************************
	用户历史redis存储数据结构
	nPid			节目或应用ID
	nSid			节目剧集id, 没有剧集id的就取值和节目id一致
	nOffset			用户观看时长
	tTimestamp		观看时间
	strSp			服务提供商
**************************************************/
struct HISTORY_RDS
{
	1: required com_types.PRG_ID nPid;
	2: required com_types.SERIES_ID nSid;
	3: required i32 nOffset;
	4: required i64 tTimestamp;
	5: required string strSp;
}

/**************************************************
	用户历史数据结构
	nId			历史数据id
	userID			用户ID
	nPid			节目或应用ID
	nSid			节目剧集id, 没有剧集id的就取值和节目id一致
	nOffset			用户观看时长
	tTimestamp		观看时间
	strSp			服务提供商
**************************************************/
struct USER_HISTORY
{
	1: required i64 nId;
	2: required com_types.INTDA userID;
	3: required com_types.PRG_ID dataID;
	4: required com_types.SERIES_ID nSid;
	5: required i32 offset;
	6: required i64 timestamp;
	7: required string strSp;
}

/**************************************************
	用户踩赞数据结构
	nId			踩赞id
	commentID		评论ID
	userID			用户ID
	my_praise_record	用户点踩点赞记录-1：没有点踩点赞 0：点踩 1：点赞
**************************************************/
struct USER_PRAISE_INFO
{
	1: required i64 nId;
	2: required string commentID;
	3: required com_types.INTDA userID;
	4: required i32 my_praise_record;
}

/**************************************************
	用户踩赞redis存储数据结构
	bPraise			是否是点赞
	nTime			操作时间
**************************************************/
struct USER_PRAISE_RDS
{
	1: required bool bPraise;
	2: required i64 nTime;
}

/**************************************************
	用户评论数据结构
	commentID		评论ID
	programID		节目ID
	userID			用户ID
	refCommentID		回复的评论ID
	commentTime		评论时间
	praise			评论被赞的次数
	degrade			评论被踩的次数
	commentSource		评论来源
	nReplyNum		评论回复条数
	content			评论内容
**************************************************/
struct USER_COMMENT_INFO
{
	1: required i64 commentID;
	2: required com_types.PRG_ID programID;
	3: required com_types.INTDA userID;
	4: required i64 refCommentID;
	5: required i64 commentTime;
	6: required i32 praise;
	7: required i32 degrade;
	8: required i32 commentSource;
	9: required i32 nReplyNum;
	10: required string content;
}

/**************************************************
	节目统计数据结构
	nPid			节目ID
	nCommentNum		评论数ID
	nTotalScore		节目总评分
	nScoreTimes		节目评分次数
	nFavoriteNum		节目收藏/关注次数(收藏明星叫关注)
	nBigenwatchNum		剧集追剧次数
	nReserveNum		剧集预约次数
	nPraiseNum		节目点赞数
	nDegradeNum		节目点踩数
	nHits			节目点击数
**************************************************/
struct PROGRAM_DEMAND
{
	1: required com_types.PRG_ID nPid;
	2: required i32 nCommentNum;
	3: required i32 nTotalScore;
	4: required i32 nScoreTimes;
	5: required i32 nFavoriteNum;
	6: required i32 nBigenwatchNum;
	7: required i32 nReserveNum;
	8: required i32 nPraiseNum;
	9: required i32 nDegradeNum;
	10: required i32 nHits;
}

/**************************************************
	是否收藏数据结构
	bIsFavorite		是否收藏
	bIsBigenWatch	是否追剧
	bIsReserve		是否预约
**************************************************/
struct ISFAVORITE
{
	1: required bool bIsFavorite;
	2: required bool bIsBigenWatch;
	3: required bool bIsReserve;
}

/**************************************************
	用户节目整合数据结构
	stDemand			节目综合数据
	stIsFavs			是否收藏&关注&追剧&预约
	nPraiseStatus		是否点踩点赞
	nLastHitId			剧集中上次观看的频道
	nOffSet				剧集中上次观看频道的具体位置
	nLastHitTime		剧集中上次观看频道时间
	nUserScore			用户对节目的评分
**************************************************/
struct USER_PROGRAM {
	1: required PROGRAM_DEMAND                stDemand;
	2: required ISFAVORITE                    stIsFavs;
	3: required i32                           nPraiseStatus = -1;
	4: required i64                           nLastHitId;
	5: required i32                           nOffSet;
	6: required i64                           nLastHitTime;
	7: required i32                           nUserScore;
}

/**************************************************
	用户个性化栏目排序数据结构
	nIdx				用户个性化栏目排序idx
	bIsLock				栏目是否被锁住
**************************************************/
struct ColumnSetting {
	1: required i16                           nIdx;
	2: required bool                          bIsLock;
}

/**************************************************
	分享数据结构
	strShareId			每条分享记录的唯一标识
	1、分享id格式	: FX+设备类型+用户id后四位+当前时间+用户id前四位
	2、当前时间格式	: MM(分钟) DD(日) HH(小时) YY(年) SS(秒) MM(月)
	nUserId				分享者用户id
	nTargetType			分享对象的id类型：1.个人；2.家庭组；3.homed好友群
	setTargetId			分享对象id
	nAssetType			分享内容的类型，与homed资产id对应，取值参照业务标准类型定义
	strAssetId			分享内容的homed资产id
	strReason			分享的原因
	tShareTime			分享的时间
	strShareInfo		第三方应用信息

**************************************************/
struct SHARE_INFO {
	1: required string                        strShareId;
	2: required com_types.INTDA               nUserId;
	3: required i32                           nTargetType;
	4: required set<i64>                      setTargetId;
	5: required i32                           nAssetType;
	6: required string                        strAssetId;
	7: required string                        strReason;
	8: required i64                           tShareTime;
	9: required string                        strShareInfo;
}

/**************************************************
	用户加锁数据结构
	nUserId				用户id
	nId					id可以为频道id、应用id、业务的分类id
	strPwd				加锁密码
**************************************************/
struct USER_LOCK {
	1: required com_types.INTDA               nUserId;
	2: required i64                           nId;
	3: required string                        strPwd;
}

/**************************************************
	用户预定数据结构
	userID				用户id
	channelID			频道id
	eventID				节目id
	timestamp			预定时间
	starttime			节目开始时间
	endtime				节目结束时间
	eventName			节目名
	updateTime			redis 数据更新时间戳
**************************************************/
struct USER_ORDER {
	1: required com_types.INTDA               userID;
	2: required com_types.CHL_ID              channelID;
	3: required com_types.PRG_ID              eventID;
	4: required i64                           timestamp;
	5: required i64                           starttime;
	6: required i64                           endtime;
	7: required string                        eventName;
	8: required i64                           updateTime;
}

/**************************************************
	预定数据结构
	channelID			频道id
	eventID				节目id
	timestamp			预定时间
**************************************************/
struct ORDER {
	1: required com_types.CHL_ID              channelID;
	2: required com_types.PRG_ID              eventID;
	3: required i64                           timestamp;
}

/**************************************************
	关注的明星剧集更新通知数据结构
	nStarId				明星id
	strStarName			明星名
**************************************************/
struct STARUPDATE {
	1: required com_types.STAR_ID             nStarId;
	2: required string                        strStarName;
}

/**************************************************
	剧集更新通知数据结构
	nType				更新类型,1: 追剧更新,2: 预约上新
	nSeriesId			剧集id
	strSeriesName		剧集名
	strNewIdx			更新集数索引(第几集)
	tUpdateTime			更新时间(上线时间)
	vecStarInfo			剧集关联的明星信息
	nContentType		剧集内容类型
	strContentTypeName	剧集内容类型中文名
**************************************************/
struct SERIESUPDATE {
	1: required i16                           nType;
	2: required com_types.PRG_ID              nSeriesId;
	3: required string                        strSeriesName;
	4: required string                        strNewIdx;
	5: required i64                           tUpdateTime;
	6: required list<STARUPDATE>              vecStarInfo;
	7: required i32                           nContentType;
	8: required string                        strContentTypeName;
}

/**************************************************
	用户资源投放数据结构
	nId					投放记录数据id
	nViewTimes			曝光次数
	nClickTimes			点击次数
**************************************************/
struct USER_RESOURCE_SAMPLE {
	1: required i64                          nId;
	2: required i32                          nViewTimes;
	3: required i32                          nClickTimes;
}

/**************************************************
	用户投票数据结构
	nId					投票id
	nUserId				用户id
	nVotingId			投票活动id
	nDataId				被投票的媒资id
	nVoteNum			投票次数
	tUpdateTime			最近一次投票时间
**************************************************/
struct USER_VOTE {
	1: required i64                          nId;
	2: required com_types.INTDA              nUserId;
	3: required i64                          nVotingId;
	4: required com_types.PRG_ID             nDataId;
	5: required i32                          nVoteNum;
	6: required i64                          tUpdateTime;
}

/**************************************************
	用户搜索历史数据结构
	nId					搜索历史id
	nUid				用户id
	nPid				节目id
	strSearchName		搜索名字
	tTimestamp			搜索时间
**************************************************/
struct USER_SEARCH_HISTORY {
	1: required i64 nId;
	2: required com_types.INTDA nUid;
	3: required com_types.PRG_ID nPid;
	4: required string strSearchName;
	5: required i64 tTimestamp;
}

/* 21. 排行榜模块 */
struct RankInfo {
	1: required i32		eRankType;	//! 排行榜分类（type，contenttype...）
	2: required i32		eOp;		//! 排行榜操作类型（点击，点赞...）
	3: required i32		ePeriod;	//! 排行榜周期（总榜，今日榜，昨日榜）
	4: required i32		nFirstIdx;	//! 当eRankType=E_RANK_TYPE_CONTENTTYPE时，该值为contenttype的值，eRankType值为E_RANK_TYPE_CONTENTTYPE时，该值为type的值
	5: required i32		nSecondIdx;	//! 单层排行榜无该值；eRankType=E_RANK_TYPE_SUBTYPE时，该值为subtype的值，eRankType=E_RANK_TYPE_CONTENTTYPE或者E_RANK_SUBTYPE时，该值为contenttype的值
	6: required i32		nRanking;	//! 排行榜排名（在排行榜中第几位）
}

struct RankItem {
	1: required com_types.PRG_ID	nPid;
	2: required i32					nNum;
}

/* 24. 猜你喜欢模块 */
struct GuessSubjSingle{
	1: required com_types.SUBJECT_ID  nSubjId;
	2: required string                strValue;
}

/**************************************************
			下面是redis广播相关结构体
**************************************************/
/**************************************************
	redis广播消息公共字段
	nLength				总长度(序列化之后的长度)
	nCmdID				命令ID
	nSubCmdID			子命令ID
	nSendSrvTypeID		是哪个SrvTypeID发出的消息
**************************************************/

struct RDSPKG_USER_RESOURCE {
	1:required i32                          nLength,
	2:required i32                          nCmdID = rdspkg_base.XtEnumRedisCmdID.IUCT_SYN_USER_RESOURCE_INFO,
	3:required i32                          nSubCmdID,
	4:required i32                          nSendSrvTypeID,

	5:required com_types.INTDA              nUserId;
	6:required i64                          nResourceId;
	7:required USER_RESOURCE_SAMPLE         stUSample;
}

struct RDSPKG_LOOP_HITS_PROGRAMS {
	1:required i32                          nLength,
	2:required i32                          nCmdID = rdspkg_base.XtEnumRedisCmdID.IUCT_SYN_LOOP_HITS_PROGRAMS,
	3:required i32                          nSubCmdID,
	4:required i32                          nSendSrvTypeID,

	5:required list<i64>                    vecHitsPids;
	6:required list<i64>                    vecPraisePids;
}