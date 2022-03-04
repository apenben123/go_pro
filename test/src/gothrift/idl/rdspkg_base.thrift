namespace cpp rpc

/*
 原netp_struct_base.h对应的结构体
*/

/*
 redis消息的结构体
 redis消息-结构体头,所有redis消息结构体由本结构体派生

struct RDSPKG_HEADER{
    //! 总长度(序列化之后的长度)
    1:required  i32     nLength,
    //! 命令ID
    2:required  i32     nCmdID,
    //! 子命令ID
    3:required  i32     nSubCmdID,
    //! 是哪个SrvTypeID发出的消息
    4:required  i32     nSendSrvTypeID,
}
*/

//-------------------------nCmdID定义 start--------------------------
 
enum XtEnumRedisCmdID {
    SYN_LITTLE_MSG                      = 1,
    //! 同步用户在线状态
    SYN_USER_STATUS                     = 10,
    //! 同步用户剩余消息数量
    SYN_USER_MSG_COUNT                  = 20,
    //! 同步引导信息
    SYN_USER_DIR                        = 30,

	//! 同步系统设置信息
	SYN_SYSTEM_SETTING_DATA             = 40,
    
    SYN_ACCOUNT_CREATE                  = 100,
    SYN_ACCOUNT_DEL                     = 101,
    SYN_ACCOUNT_STYLE_CREATE            = 102,
    SYN_ACCOUNT_STYLE_DEL               = 103,
    SYN_ACCOUNT_ICON_UPDATE             = 104,
    //! 同步账号头像删除                
    SYN_ACCOUNT_ICON_DEL                = 105,
    //! 同步成员创建信息                
    SYN_MEMBER_CREATE                   = 110,
    //! 同步删除成员信息                
    SYN_MEMBER_DEL                      = 111,
    //! 同步成员帐号创建信息            
    SYN_MEMBER_ACCOUNT_CREATE           = 120,
    //! 同步删除成员账号信息            
    SYN_MEMBER_ACCOUNT_DEL              = 121,
    //! 同步boss账号创建信息            
    SYN_DA_BOSS_CREATE                  = 122,
    //! 同步分组portal路由信息          
    SYN_GROUP_PORTAL_INFO               = 125,
    //! 同步家庭创建信息                
    SYN_HOME_CREATE                     = 130,
    //! 同步删除家庭信息                
    SYN_HOME_DEL                        = 131,
    //! 同步家庭成员创建信息            
    SYN_HOME_MEMBER_CREATE              = 140,
    //! 同步删除家庭成员信息            
    SYN_HOME_MEMBER_DEL                 = 141,
    //! 同步地址创建信息                
    SYN_ADDRESS_CREATE                  = 150,
    //! 同步家庭地址创建信息            
    SYN_HOME_ADDRESS_CREATE             = 160,
    //! 同步角色信息                    
    SYN_ROLE_INFO                       = 165,
    //! 同步设备创建信息                
    SYN_DEVICE_CREATE                   = 170,
    //! 同步删除device_account信息
    SYN_DEVICE_ACCOUNT_DEL              = 175,
    //! 同步地址设备创建信息            
    SYN_ADDRESS_DEVICE_CREATE           = 180,
    //! 同步portal分组信息              
    SYN_PORTAL_GROUP_INFO               = 181,
    //! 同步portal model信息            
    SYN_PORTAL_MODEL_INFO               = 182,
    //! 同步用户组protal组关联信息       
    SYN_USER_PORTAL_LINK                = 183,
    //! 同步目标-theme信息       
    SYN_TARGET_THEME_DATA               = 184,
    //! 同步图标创建信息                
    SYN_ICON_CREATE                     = 190,
    //! 同步资产定义信息                
    SYN_ASSET_INFO                      = 191,
    //! 同步用户标签信息                
    SYN_USER_LABEL_INFO                 = 192,
    //! 同步用户第三方绑定              
    SYN_USER_THIRD_AUTH                 = 193,
    //! 同步订单信息
    SYN_BUSINESS_RECORD                 = 194,
    //! 同步权限信息                    
    SYN_RIGHT_INFO                      = 195,
    //! 同步后台用户信息                
    SYN_OPERATOR_MGR_INFO               = 196,
    //! 同步计费信息                    
    SYN_CHARGE_SYS_INFO                 = 197,
    //! 同步终端账号token信息           
    SYN_ACCOUNT_TOKEN_MGR_INFO          = 198,
    //! 同步终端用户分组                
    SYN_USER_GROUP_INFO                 = 199,
    SYN_APP_DATA                        = 220,
    SYN_APP_EDU_DATA                    = 231,
    SYN_CHANNEL_STORE                   = 300,
    SYN_VIDEO_INFO                      = 310,
    SYN_VIDEO_EXTERN_INFO               = 320, 
    DTVS_SYN_CHANNEL_PROGRAM_INFO       = 330,
    DTVS_SYN_CHANNEL_HIS_PROGRAM_INFO   = 340,
    
    DTVS_SYN_USER_SCORE_INFO            = 350,

    SYN_PROGRAM_PROMOTION_INFO          = 360,
    SYN_PROGRAM_PROMOTION               = 361,
                                        
    SYN_WEATHER_INFO                    = 370,
    SYN_BARRAGE_INFO                    = 371,
    
    SYN_VIDEO_SERIES_ID_INFO            = 380,
    SYN_VIDEO_SERIES_ID_EXTERN_INFO     = 390,
    
    SYN_EVENT_SERIES_ID_INFO            = 400,
    SYN_EVENT_SERIES_ID_EXTERN_INFO     = 410,
    DTVS_SYN_EVENT_SERIES_BASIC_INFO    = 411,
    SYN_PROGRAM_COMPOSITE_INFO          = 420,
    DTVS_SYN_PROGRAM_DEMAND_INFO        = 430,
    DTVS_SYN_PROGRAM_RANK_INFO          = 431,
    DTVS_SYN_CHANNEL_SHOW_RULE          = 440,
    DTVS_SYN_CORE_MARK_INFO             = 450,

    DTVS_SYN_USER_FAVORITE_INFO         = 460,
    DTVS_SYN_USER_SETTING_INFO          = 470,
    DTVS_SYN_WATCHING_CHANNEL_INFO      = 480,
    DTVS_SYN_USER_HISTORY_INFO          = 490,
    DTVS_SYN_USER_SEARCH_HISTORY_INFO   = 492,
    DTVS_SYN_USER_HITS_INFO             = 495,
    DTVS_SYN_USER_LOCK_INFO             = 500,

    DTVS_SYN_USER_CHANNEL_PERSONAL      = 510,
    DTVS_SYN_PROGRAM_GROUP_INFO         = 520,
    DTVS_SYN_PROGRAM_PACKAGE_INFO       = 530,
    DTVS_SYN_PROGRAM_PRICE_INFO         = 540,

    SYN_MUSIC_STORE                     = 550,
    DTVS_SYN_USER_ORDER_INFO            = 560,
    DTVS_SYN_CHANNEL_GROUP_INFO         = 570,
    DTVS_SYN_CHANNEL_GROUP_DESC         = 580,
                                        
    SYN_SEARCH_HOT_KEY_INFO             = 590,
    DTVS_SYN_USER_PRAISE_INFO           = 600,
    DTVS_SYN_USER_COMMENT_INFO          = 605,
    DTVS_SYN_LABEL_CHANGE_INFO          = 610,
    DTVS_SYN_MONITOR_STORE              = 620,
    DTVS_SYN_MONITOR_GROUP_STORE        = 630,
    DTVS_SYN_MONITOR_GROUP_INFO         = 640,
    DTVS_SYN_COLUMN_INFO                = 650,
    DTVS_SYN_COLUMN_PROGRAM             = 660,
    DTVS_SYN_COLUMN_PROGRAM_LIST        = 661,
    DTVS_SYN_MOSAIC_CHANNEL_INFO        = 670,
    DTVS_SYN_PROGRAM_GROUP_MAP_INFO     = 680,
    DTVS_SYN_COLUMN_RIGHT_INFO          = 690,

    DTVS_SYN_PROGRAM_HITS_INFO          = 700,
    DTVS_SYN_USER_LOCAL_CHANNEL         = 710,
    SYN_BUSINESS_PARTNER                = 720,
    DTVS_SYNC_RECORD_CHANNEL_INFO       = 730,
    DTVS_SYNC_RECORD_SERVER_INFO        = 731,
    SYN_SENSITIVE_WORD_INFO             = 740,
    SYN_POLYPHONE_DATA                  = 741,
    DTVS_SYN_PROGRAM_RECORD             = 750, //dtvs redis同步节目录制到slave
    SYN_STAR_INFO                       = 760,
    SYN_BAIKE_RELATION                  = 761,
    
    DTVS_SYN_DUPLICATE_PROGRAM          = 770,
    SYN_VIDEO_SERIES_EDUCATION_INFO     = 780,
    SYN_VIDEO_SERIES_MUSIC_INFO         = 790,
    DTVS_SYN_STREAM_DATA_INFO           = 825,
    SYN_TOURISM_ROUTE_INFO              = 800,
    SYN_TOURISM_TICKET_INFO             = 810,
    SYN_QAM_AREACODE_INFO               = 820,
                                        
    DTVS_SYN_SUBJECT_INFO               = 830,
    DTVS_SYN_SUBJECT_PROGRAM            = 831,
    DTVS_SYN_PLAYLIST_INFO              = 832,
    DTVS_SYN_PLAYLIST_PROGRAM           = 833,
    DTVS_SYN_CHANNEL_LIMIT_INFO         = 840,
                                        
    SYN_MEDIA_TYPE_INFO                 = 850,
    SYN_FILTER_INFO                     = 870,
    DTVS_SYN_LIVE_ROOM_INFO             = 880,
    DTVS_SYN_LIVE_PROGRAM_INFO          = 885,
    ILOG_SYN_LIVE_SESSION               = 886,
    SYN_TEMPLATE_INFO                   = 890,
    DTVS_SYN_FILLPAD_INFO               = 895, //dtvs redis同步通用插播垫播信息到slave
                                        
    SYN_CONFIG_TAG_INFO                 = 900,
    SYN_USER_LABEL_MGR                  = 901,
    SYN_MEDIA_LABEL_INFO                = 902,
    SYN_PUBLIC_RESOURCE_INFO            = 903,
    SYN_VIDEO_SPORT_INFO                = 904,//体育播放器信息
    DTVS_SYN_USER_PROFILE_INFO          = 905, //!< 用户画像数据同步
    SYN_VIDEO_SERIES_EXTEND_INFO        = 906,//点播剧集扩展信息
    SYN_VIDEO_STREAM_INFO               = 908,//点播视频流编码信息
    SYN_HOME_TYPE_INFO                  = 909,
    SYN_SERIES_VIDEO_INDEX              = 910, //单条点播剧集和单集的索引关系
    SYN_MEDIA_TAGTYPE_INFO_MGR		= 911,//标签类型同步
    SYN_MEDIA_VISIBLE_INFO_MGR          = 912,//媒资可见规则
    SYN_PROGRAM_REFERENCE_INFO          = 913, //点播引用信息
    SYN_SERIES_VIDEO_INDEX_MULTI        = 914, //多条点播剧集和单集的索引关系
    DTVS_SYN_SUBJECT_SCHEDULE           = 915,//专题排期数据
      
    SYN_VIDEO_SERIES_SPEC_INFO          = 920, // 点播剧集个性化数据同步
    SYN_VIDEO_SERIES_INDEX_SPEC_INFO    = 921, // 点播发布单集所属的剧集索引个性化数据同步
    
    SYN_T_ACCOUNT_LOGIN_HISTORY         = 1000,      
    SYN_WEBSOCKET_MSG                   = 1001,
    SYN_WEBSOCKET_CONNECT_STATUS        = 1010,  
    ILOGMASTER_SYN_SAVE_AV_FILE	        = 2011,
    ILOGMASTER_SYN_SAVE_AV_SUBFILE      = 2012,      
    ILOGMASTER_SYN_BLACK_CHANNEL        = 2013,
    ILOGMASTER_SYN_SAVE_TRANSMIT_FILE	= 2014,
    SYN_PROCESS_INFO                    = 2015,
    SYS_ACTIVE_SERVER_INFO              = 2016,
    TSG_SYN_movie                       = 2020,
    TSG_SYN_poster_preview_dir          = 2021,
    TSG_SYN_poster_preview_file         = 2022,
    //! imsgs消息命令定义               
    SYN_TEMP_GROUP                      = 2100
    SYN_LAST_GROUP                      = 2101
                                        
    // edtv同步数据使用                 
    SYN_EDTV_TEMPLATE_DATA              = 2102,
    SYN_EDTV_INTERACTION_DATA           = 2103,
    SYN_EDTV_RELATION_DATA              = 2104,
    SYN_EDTV_FEEDBACK_DATA              = 2105, 
                                        
    SYN_MSGS_NOTICE_COUNT_DATA          = 2150,
    SYN_MSGS_NOTICE_TABLE_DATA          = 2151,
    SYN_MSGS_NOTICE_TYPE_DATA           = 2152,
    SYN_SUBSCRIBER_LASTEST_MSGS         = 2153,

    SYN_COMMON_SEARCH                   = 2201,
    SYN_SHARE_INFO                      = 2202,
    SYN_USER_PLAYLIST_INFO              = 2203,
    SYN_USER_PLAYLIST_PROGRAM_INFO      = 2204,
    SYN_SERVER_STATUS                   = 2205,
    SYN_SHOPPING_INFO                   = 2207,
    SYN_AD_POLICY                       = 2208,
    SYN_TROLLEY_INFO                    = 2209,
    SYN_USER_UPLOAD_RECORD              = 2220, //!< 用户上报记录
    // 转码参数模板信息同步             
    SYN_TRANSCODE_TEMPLATE_INFO         = 2221,
                                        
    //信息统计相关 begin                
    SYN_PLAYC_INFO                      = 2222,
    SYN_OLUSER_INFO                     = 2223,
    SYN_PRO_STATISTICS_INFO             = 2224,
                                        
    SYN_HLSSTAT_INFO                    = 2225,
    SYN_HLSVP_INFO                      = 2226,
    
    // 剧集id和明星id信息同步
    SYN_SERIES_STAR_ID_MAP              = 2228,
    // 转码控制信息
    SYN_TRANSCODE_CONTROL_INFO          = 2230,
    SYN_AD_STRATEGY                     = 2231,
    // 热词信息更新
    SYN_HOT_WORD_UPATE                  = 2240,
    
    // 同步私有服务信息
    SYN_ONE_BINARY_SRV                  = 2320,

    // 同步RPC服务信息
    SYN_ONE_RPC_SRV                     = 2321,

    //个人空间信息同步
    SYN_CLOUD_INFO                      = 2500,
    SYN_IAIPROXY_INFO                   = 2501,
    //! 用户订阅
    IUCT_SYN_USER_SUBSCRIBE_INFO        = 2505,
    //! 用户资源投放记录
    IUCT_SYN_USER_RESOURCE_INFO         = 2510,
    //! 用户投票
    IUCT_SYN_USER_VOTE_INFO             = 2511,
    //! 周期内被点击节目
    IUCT_SYN_LOOP_HITS_PROGRAMS         = 2512,
    //! 用户策略分组通知
    IUGS_SYN_GROUP_NOTIFY               = 2520,
    
    //! 推荐系统
    // 模型校验
    SYN_RECOMMEND_VERIFY_MODEL_INFO    	= 2530,
    /* 由于先前私有协议和thrift两种结构体共用同一种消息类型,
    ** 私有协议进行thrift改造后解码会死机，需要对该种情况扩展消息类型
    */
    THRIFT_SYN_CHANNEL_STORE            = 3000,
}
//-------------------------nCmdID定义 end-----------------------------

//-------------------------nSubCmdID定义 start------------------------
enum EComSubcmd
{
    SYN_ADD  = 0,
    SYN_DEL  = 1,
    SYN_MOD  = 2,
    SYN_CMD  = 3
}

typedef EComSubcmd SynDtvsAppInfoSubcmd;
typedef EComSubcmd SyncDtvsSearchHotKey;
typedef EComSubcmd SynDtvsStarInfoSubcmd;
typedef EComSubcmd SynILogPlayCInfoSubcmd;
typedef EComSubcmd SynILogOLUserInfoSubcmd;
typedef EComSubcmd SynILogProStatInfoSubcmd;
typedef EComSubcmd SynDtvsChannelLimitSubcmd;
typedef EComSubcmd SyncDtvsWeatherInfoSubcmd;
typedef EComSubcmd SyncDtvsSensitiveWordInfoSubcmd;
typedef EComSubcmd SynDtvsPublicResourceInfoSubcmd;
typedef EComSubcmd SynDtvsMediaLabelInfoSubcmd;
typedef EComSubcmd SynDtvsMediaTagTypeInfoSubcmd;
typedef EComSubcmd SynDtvsUserLabelInfoSubcmd;
typedef EComSubcmd SynDtvsMediaTypeInfoSubcmd;
typedef EComSubcmd SynDtvsPartnerInfoSubcmd;
typedef EComSubcmd SynDtvsFilterInfoSubcmd;
typedef EComSubcmd SynDtvsConfigTagInfoSubcmd;
typedef EComSubcmd SynDtvsHomeTypeInfoSubcmd;
typedef EComSubcmd SynILogHLSStatInfoSubcmd;
typedef EComSubcmd SynILogHLSVPInfoSubcmd;
typedef EComSubcmd SyncDtvsProgramCompositeSubcmd;
typedef EComSubcmd SynTrolleySubcmd;
typedef EComSubcmd SynDtvsMediaVisibleRuleSubcmd;
typedef EComSubcmd SynDtvsSystemSettingSubcmd;
typedef EComSubcmd SynDtvsVideoInfoSubcmd;
typedef EComSubcmd SynDtvsChannelShowRuleSubcmd;
typedef EComSubcmd SyncDtvsSubjectProgramSubcmd;
typedef EComSubcmd SyncDtvsSubjectScheduleSubcmd;

enum SyncIaiproxySubcmd
{
    SYNC_AIPROXY_SUBJECT_ADD    = 1, # 增加专题
    SYNC_AIPROXY_VIDEO_ADD      = 2  # 增加视频
}

enum SynIlogAdPolicySubcmd
{
    SYN_ADD    = 0,
    SYN_DEL    = 1,
    SYN_MOD    = 2,
    SYN_COUNT  = 3
}

enum SynDtvsShoppingSubcmd {
    SYN_SHOPPING_PROVIDER_ADD = 0,
    SYN_SHOPPING_PROVIDER_DEL = 1,
    SYN_SHOPPING_PROVIDER_MOD = 2,
    SYN_SHOPPING_SHOP_ADD = 3,
    SYN_SHOPPING_SHOP_DEL = 4,
    SYN_SHOPPING_SHOP_MOD = 5,
    SYN_SHOPPING_PROMO_ADD = 6,
    SYN_SHOPPING_PROMO_DEL = 7,
    SYN_SHOPPING_PROMO_MOD = 8,
    SYN_SHOPPING_PRODUCT_ADD = 9,
    SYN_SHOPPING_PRODUCT_DEL = 10,
    SYN_SHOPPING_PRODUCT_MOD = 11,
    SYN_SHOPPING_OTHER_PRODUCT_ADD = 12,
    SYN_SHOPPING_OTHER_PRODUCT_DEL = 13,
    SYN_SHOPPING_OTHER_PRODUCT_MOD = 14,
    SYN_SHOPPING_MAIN_PRODUCT_ADD = 15,
    SYN_SHOPPING_MAIN_PRODUCT_DEL = 16,
    SYN_SHOPPING_MAIN_PRODUCT_MOD = 17,
    SYN_SHOPPING_COMMENT_ADD = 18,
    SYN_SHOPPING_COMMENT_DEL = 19,
    SYN_SHOPPING_COMMENT_MOD = 20,
    SYN_SHOPPING_CATEGORY_ADD = 21,
    SYN_SHOPPING_CATEGORY_DEL = 22,
    SYN_SHOPPING_CATEGORY_MOD = 23,
    SYN_SHOPPING_PROMO_CATEGORY_ADD = 24,
    SYN_SHOPPING_PROMO_CATEGORY_DEL = 25,
    SYN_SHOPPING_PROMO_CATEGORY_MOD = 26
}

enum SynDtvsSeriesIdInfoSubcmd{
	EVENT_SERIES_OP_EX_ADD = 1,//添加
	EVENT_SERIES_OP_EX_DEL,
	EVENT_SERIES_OP_EX_MOD,
	EVENT_SERIES_OP_STATUS_EX_MOD,
	EVENT_SERIES_OP_ADD,
	EVENT_SERIES_OP_DEL,
	EVENT_SERIES_OP_PIC_DEL
}

enum SyncDtvsProgramPromotionInfoSubcmd{
    SYN_PROGRAM_PROMOTION_ADD		= 0,
	SYN_PROGRAM_PROMOTION_MOD		= 1,
	SYN_PROGRAM_PROMOTION_DEL		= 2,
	SYN_SUBMIT_PROGRAM_PROMOTION	= 3,
	SYN_RELEASE_PROGRAM_PROMOTION	= 4,
	SYN_PROMOTION_PROPERTY_MOD	= 5
}

enum SyncRecommendVerifyModelSubcmd{
    SYN_RECOMMEND_RELEASE   	= 0,	
    SYN_RECOMMEND_DEL		= 1
}

enum SyncDtvsMusicStoreInfoSubcmd{
	SYN_MUSIC_INFO_ADD		= 0,
	SYN_MUSIC_INFO_DEL,
	SYN_MUSIC_INFO_MOD,
	SYN_MUSIC_INFO_STATUS_MOD,
	SYN_MUSIC_SINGER_INFO_ADD = 5,
	SYN_MUSIC_SINGER_INFO_MOD,
	SYN_MUSIC_SINGER_INFO_DEL,
	SYN_MUSIC_ALBUM_INFO_ADD  = 10,
	SYN_MUSIC_ALBUM_INFO_DEL,
	SYN_MUSIC_ALBUM_INFO_MOD,
	SYN_MUSIC_ALBUM_INFO_STATUS_MOD,
	SYN_MUSIC_POSTER_ADD     = 15,
	SYN_MUSIC_POSTER_DEL,
}

enum SynLittleMsgSubcmd
{
    //! ilogmaster启动通知
    ILOGMASTER_START       = 3,

    //! news
    SYN_NEWS_ADD           = 390,
    SYN_NEWS_DEL           = 391,
    SYN_COLUMN_ADD         = 392,
    SYN_COLUMN_DEL         = 393,
}

enum  XtTsgMsgCategory
{
	//! 有黑边信息标志
	TSG_BLACK_INFO									= 1,
	//! 有海报信息标志
	TSG_POSTER_INFO									= 2,
	//! 有黑边和海报信息标志
	TSG_BLACK_AND_POSTER_INFO						= 3,
	//! 缩略图目录标志
	TSG_VIDEO_THUMBNAIL_DIR_INFO					= 4,
	//! 电影海报的请求
	TSG_MOVIE_POSTER_REQUEST						= 5,
	//! 电影海报的回应
	TSG_MOVIE_POSTER_RESPONSE						= 6,
	//! (新存储方式)标准海报
	TSG_STANDARD_POSTER_INFO						= 7,
	//! (新存储方式)非标准海报
	TSG_NONSTANDARD_POSTER_INFO						= 8,
	//! (新存储方式)缩略图文件标准
	TSG_THUMBNAIL_PKG_INFO							= 9,
	//! (新存储方式)电影海报的回应
	TSG_NEW_MOVIE_POSTER_RESPONSE					= 10,
	
	//! TS文件的索引文件生成请求
	TSG_IDX_REQUEST									= 20,
	//! TS文件的索引文件生成回应
	TSG_IDX_RESPONSE								= 21,
	
	//! 海报单独生成请求
	TSG_GEN_POSTER_REQUEST							= 30,
	//! 海报单独生成回应
	TSG_GEN_POSTER_RESPONSE							= 31,
	//! 缩略图单独生成请求
	TSG_GEN_THUMBNAIL_REQUEST						= 32,
	//! 缩略图单独生成回应
	TSG_GEN_THUMBNAIL_RESPONSE						= 33,
	//! idx文件单独生成请求
	TSG_GEN_IDX_REQUEST								= 34,
	//! idx文件单独生成回应
	TSG_GEN_IDX_RESPONSE							= 35,
	//! 生成海报，缩略图，idx文件请求
	TSG_GEN_POSTER_THUMBNAIL_IDX_REQUEST			= 36,
	//! 生成生成海报，缩略图，idx文件回应
	TSG_GEN_POSTER_THUMBNAIL_IDX_RESPONSE			= 37,
	//! 汇报状态信息请求
	TSG_REPORT_VIDEO_STATUS_REQUEST					= 38,
	//! 汇报状态信息回复
	TSG_REPORT_VIDEO_STATUS_RESPONSE				= 39,
	//! 通知删除任务
	TSG_NOTIFY_DELETE_TASK_REQUEST					= 40,
	//! 通知删除任务回复
	TSG_NOTIFY_DELETE_TASK_RESPONSE					= 41,
	//! 生成海报，缩略图，idx文件进度报告请求
	TSG_POSTER_THUMBNAIL_IDX_PROGRESS_REQUEST		= 42,
	//! 生成海报，缩略图，idx文件进度报告回复
	TSG_POSTER_THUMBNAIL_IDX_PROGRESS_RESPONSE		= 43,
	//! 重新生成录流缩略图请求
	TSG_REGEN_RECORD_THUMBNAIL_REQUEST				= 44,
	//! 重新生成录流缩略图回复
	TSG_REGEN_RECORD_THUMBNAIL_RESPONSE				= 45,
	//! 重新生成录流下缩略图进度报告请求
	TSG_REGEN_RECORD_THUMBNAIL_PROGRESS_REQUEST		= 46,
	//! 重新生成录流下缩略图进度报告回复
	TSG_REGEN_RECORD_THUMBNAIL_PROGRESS_RESPONSE		= 47,
	//! 提取电影文件从录流文件请求
	TSG_EXTRACT_MOVIE_FILE_FROM_RECORD_TS_REQUEST		= 48,
	//!	提取电影文件从录流文件回复
	TSG_EXTRACT_MOVIE_FILE_FROM_RECORD_TS_RESPONSE		= 49,
	//! 提取电影文件从录流文件进度报告请求
	TSG_EXTRACT_MOVIE_FILE_FROM_RECORD_TS_PROGRESS_REQUEST	= 50,
	//! 提取电影文件从录流文件进度报告回复
	TSG_EXTRACT_MOVIE_FILE_FROM_RECORD_TS_PROGRESS_RESPONSE	= 51,
	//! 转录流节目海报尺寸请求
	TSG_TRANS_RECORD_POSTER_SIZE_REQUEST = 52,
	//! 转录流节目海报尺寸回复
	TSG_TRANS_RECORD_POSTER_SIZE_RESPONSE = 53,
	//! 转海报尺寸进度报告请求
	TSG_TRANS_RECORD_POSTER_SIZE_PROGRESS_REQUEST		= 54,
	//! 转海报尺寸进度报告回复
	TSG_TRANS_RECORD_POSTER_SIZE_PROGRESS_RESPONSE		= 55,
	//! 重新生成电影的海报或seek图请求
	TSG_REGEN_MOVIE_THUMBNAIL_OR_POSTER_REQUEST = 56,
	//! 重新生成电影的海报或seek图回复
	TSG_REGEN_MOVIE_THUMBNAIL_OR_POSTER_RESPONSE = 57,
	//! 重新生成电影的海报或seek图进度报告请求
	TSG_REGEN_MOVIE_THUMBNAIL_OR_POSTER_PROGRESS_REQUEST = 58,
	//! 重新生成电影的海报或seek图进度回复
	TSG_REGEN_MOVIE_THUMBNAIL_OR_POSTER_PROGRESS_RESPONSE = 59,
	//! 生成多个文件的扩展信息的请求
	TSG_GEN_MUTLI_FILE_EXTERN_INFO_REQUEST			= 60,
	//! 生成多个文件的扩展信息的回应
	TSG_GEN_MUTLI_FILE_EXTERN_INFO_RESPONSE			= 61,
	//! 提取电影文件从电影文件请求
	TSG_EXTRACT_MOVIE_FILE_FROM_MOVIE_REQUEST		= 62,
	//!	提取电影文件从电影文件回复
	TSG_EXTRACT_MOVIE_FILE_FROM_MOVIE_RESPONSE		= 63,
	//! 提取电影文件从电影文件进度报告请求
	TSG_EXTRACT_MOVIE_FILE_FROM_MOVIE_PROGRESS_REQUEST	= 64,
	//! 提取电影文件从电影文件进度报告回复
	TSG_EXTRACT_MOVIE_FILE_FROM_MOVIE_PROGRESS_RESPONSE	= 65,
	//! 回看导入流并生成seek图请求
	TSG_IMPORT_LOOKBACK_STREAM_REQUEST = 66,
	//! 回看导入流并生成seek图回复
	TSG_IMPORT_LOOKBACK_STREAM_RESPONSE = 67,
	//! 补充生成多个文件的扩展信息的请求
	TSG_SUPPLEMENT_MUTLI_FILE_EXTERN_INFO_REQUEST			= 68,
	//! 补充生成多个文件的扩展信息的回应
	TSG_SUPPLEMENT_MUTLI_FILE_EXTERN_INFO_RESPONSE			= 69,
	//! 升级样本信息的请求
	TSG_UPDATE_SAMPLE_INFO_REQUEST			= 70,
	//! 升级样本信息的的回应
	TSG_UPDATE_SAMPLE_INFO_RESPONSE			= 71,
	//! 广告检测的请求
	TSG_PROGRAM_DETECT_INFO_REQUEST			= 72,
	//! 广告检测的的回应
	TSG_PROGRAM_DETECT_INFO_RESPONSE			= 73,
	//! 恢复total idx的请求
	TSG_RECOVER_TS_TOTAL_IDX_REQUEST        = 74,
	//! 恢复total idx的回复
	TSG_RECOVER_TS_TOTAL_IDX_RESPONSE       = 75,
	//! tsg节目检测控制
	TSG_PROGDETECT_CONTROL_INFO_REQUST = 76,
	//! 回看节目替换请求
	TSG_REPLACE_LOOKBACK_STREAM_REQUEST = 77,
	//! 回看节目替换回复
	TSG_REPLACE_LOOKBACK_STREAM_RESPONSE = 78,
	//! 删除任务请求
	TSG_DELETE_TASK_REQUEST = 79,
	//! 删除任务回复
	TSG_DELETE_TASK_RESPONSE = 80,
	//! 更新tsidx到redis请求
	TSG_UPDATE_TSIDX_TO_REDIS_REQUEST = 81,
	//! 更新tsidx到redis回复
	TSG_UPDATE_TSIDX_TO_REDIS_RESPONSE = 82,
	//! 任务查询请求
	TSG_QUERY_TASK_REQUEST = 83,
	//! 任务查询回复
	TSG_QUERY_TASK_RESPONSE = 84,
	// tsg任务数报告请求
	TSG_TASK_COUNT_REPORT_REQUEST = 85,
	// tsg任务数报告回复
	TSG_TASK_COUNT_REPORT_RESPONSE = 86,
	// 生成回看index请求
	TSG_REGEN_RECORD_CDN_INDEX_REQUEST = 87,
	//生成回看index回复
	TSG_REGEN_RECORD_CDN_INDEX_RESPONSE = 88,
	// 生成流信息请求
	TSG_REGEN_STREAM_INFO_REQUEST = 89,
	// 生成流信息回复
	TSG_REGEN_STREAM_INFO_RESPONSE = 90,
	// tsg生成TopN文件
	TSG_GEN_TOPN_FILE_REQUEST = 91,
	// 将生产完成的视频ID发送到dtvs
	TSG_TOPN_FINISH_REQUEST = 92,
	//! 样本特征提取请求
	TSG_SAMPLE_EXTRACT_REQUEST = 93,
	//! 样本特征提取回复
	TSG_SAMPLE_EXTRACT_RESPONSE = 94,
	//! 样本特征版本更新请求
	TSG_SAMPLE_UPDATE_REQUEST = 95,
	//! 样本特征版本更新回复
	TSG_SAMPLE_UPDATE_RESPONSE = 96,
	// 节目提取海报接口请求
	TSG_EXTRACT_EVENT_POSTER_REQUEST = 97,
	// 节目提取海报接口回复
	TSG_EXTRACT_EVENT_POSTER_RESPONSE = 98,
	// 电影提取海报接口请求
	TSG_EXTRACT_MOVIE_POSTER_REQUEST = 99,
	// 电影提取海报接口回复
	TSG_EXTRACT_MOVIE_POSTER_RESPONSE = 100,
	// 拆条任务获取seek图请求
	TSG_EXTRACT_FRAME_SEEK_REQUEST = 101,
	// 拆条任务获取seek图回复
	TSG_EXTRACT_FRAME_SEEK_RESPONSE = 102,
}

enum XtDtvsRecordChannelInfoMsgCategory
{
	//! 增加录流频道请求
	DTVS_ADD_RECORD_CHANNEL_REQUEST			= 1,
	//! 增加录流频道回复
	DTVS_ADD_RECORD_CHANNEL_RESPONSE		= 2,
	//! 删除录流频道请求
	DTVS_DELETE_RECORD_CHANNEL_REQUEST		= 3,
	//! 删除录流频道回复
	DTVS_DELETE_RECORD_CHANNEL_RESPONSE		= 4,
	//! 更改服务器工作模式请求
	DTVS_MOD_SERVER_WORK_FLAG_REQUEST		= 5,
	//! 更改服务器工作模式回复
	DTVS_MOD_SERVER_WORK_FLAG_RESPONSE		= 6,
	//! 重启服务器请求
	DTVS_RESTART_SERVER_REQUEST				= 7,
	//! 重启服务器回复
	DTVS_RESTART_SERVER_RESPONSE			= 8,
	//! 询问服务器是否重启完成请求
	DTVS_IS_RESTART_SERVER_FINISH_REQUEST	= 9,
	//! 询问服务器是否重启完成回复
	DTVS_IS_RESTART_SERVER_FINISH_RESPONSE	= 10,
	//! 更新数据因为某台tsg替换主tsg录流请求
	DTVS_UPDATE_DATA_FOR_BAK_SERVER_REPLACE_MASTER_SERVER_REQUEST	= 11,
	//! 更新数据因为某台tsg替换主tsg录流回复
	DTVS_UPDATE_DATA_FOR_BAK_SERVER_REPLACE_MASTER_SERVER_RESPONSE	= 12,
	//! 生成台标海报录流频道请求
	DTVS_CREATE_CHANNELLOGO_REQUEST			= 13,
	//! 生成台标海报录流频道请求回复
	DTVS_CREATE_CHANNELLOGO_RESPONSE		= 14,
}

enum XtHotBakServerMsgCategory
{
	//! 报告死掉的录流服务器请求
	REPORT_DEAD_RECORD_SERVER_REQUEST	= 1,
	//! 报告死掉的录流服务器回复
	REPORT_DEAD_RECORD_SERVER_RESPONSE	= 2,
}

enum XtLiveRoomMsgCategory
{
    //! 开播请求
    LIVE_START_LIVE_REQUEST  = 1,
    //! 开播回复
    LIVE_START_LIVE_RESPONSE = 2,
    //! 停播请求
    LIVE_STOP_LIVE_REQUEST   = 3,
    //! 停播回复
    LIVE_STOP_LIVE_RESPONSE  = 4,
    //! 同步房间在线人数请求
    LIVE_ONLINE_NUM_REQUEST  = 5,
    //! 同步房间在线人数回复
    LIVE_ONLINE_NUM_RESPONSE = 6,
}

//! 播单子协议
enum XtPlaylistMsgCategory
{
    //! 播单清理节目
    PLAYLIST_CLEAN_PROGRAM	 = 1,
    //! TODO
}

enum XtMissDataMsgCategory
{
	//! 缺流请求
	MISS_STREAM_REQUEST           = 1,
	//! 缺流回复
	MISS_STREAM_RESPONSE          = 2,
	//! 报告录流状态请求
	REPORT_RECORD_STATUS_REQUEST  = 3,
	//! 报告录流状态回复
	REPORT_RECORD_STATUS_RESPONSE = 4,
	//! 替换流请求
	REPLACE_STREAM_REQUEST		  = 5,
	//! 替换流回复
	REPLACE_STREAM_RESPONSE		  = 6,
}

//! 
struct NETPI2{
    //! 整数参数1
    1:required  i64      nData1,
    //! 整数参数2
    2:required  i64      nData2,
}

//! 
struct NETPI4{
    //! 整数参数1
    1:required  i64      nData1,
    //! 整数参数2
    2:required  i64      nData2,
    //! 整数参数3
    3:required  i64      nData3,
    //! 整数参数4
    4:required  i64      nData4,
}

//! 
struct NETPI8{
    //! 整数参数1
    1:required  i64      nData1,
    //! 整数参数2
    2:required  i64      nData2,
    //! 整数参数3
    3:required  i64      nData3,
    //! 整数参数4
    4:required  i64      nData4,
    //! 整数参数5
    5:required  i64      nData5,
    //! 整数参数6
    6:required  i64      nData6,
    //! 整数参数7
    7:required  i64      nData7,
    //! 整数参数8
    8:required  i64      nData8,
}

//! 
struct NETPI4S2{
    //! 整数参数1
    1:required  i64      nData1,
    //! 整数参数2
    2:required  i64      nData2,
    //! 整数参数3
    3:required  i64      nData3,
    //! 整数参数4
    4:required  i64      nData4,
    //! 字符串1
    5:required  string   szData1,
    //! 字符串2
    6:required  string   szData2,
}

struct NETPI4S4{
    //! 整数参数1
    1:required  i64      nData1,
    //! 整数参数2
    2:required  i64      nData2,
    //! 整数参数3
    3:required  i64      nData3,
    //! 整数参数4
    4:required  i64      nData4,
    //! 字符串1
    5:required  string   szData1,
    //! 字符串2
    6:required  string   szData2,
    //! 字符串3
    7:required  string   szData3,
    //! 字符串4
    8:required  string   szData4,
}

//! 
struct NETPI8D2S2{
    //! 整数参数1
    1:required  i64      nData1,
    //! 整数参数2
    2:required  i64      nData2,
    //! 整数参数3
    3:required  i64      nData3,
    //! 整数参数4
    4:required  i64      nData4,
    //! 整数参数5
    5:required  i64      nData5,
    //! 整数参数6
    6:required  i64      nData6,
    //! 整数参数7
    7:required  i64      nData7,
    //! 整数参数8
    8:required  i64      nData8,

    //! 整数参数5
    9:required  double   dData1,
    //! 整数参数6
    10:required double   dData2,
    //! 字符串1
    11:required string   szData1,
    //! 字符串2
    12:required string   szData2,
}

// 
struct RDSPKG_SYNLITTLEMSG{
    //! 总长度(序列化之后的长度)
    1:required  i32      nLength,
    //! 命令ID
    2:required  i32      nCmdID = XtEnumRedisCmdID.SYN_LITTLE_MSG,
    //! 子命令ID
    3:required  i32      nSubCmdID,
    //! 是哪个SrvTypeID发出的消息
    4:required  i32      nSendSrvTypeID,

    //! 整型数据
    5:required  i64      nD1,
     //! 
    6:required  i64      nD2,
     //! 
    7:required  i64      nD3,
     //! 
    8:required  i64      nD4,
     //! 
    9:required  i64      nD5,
    //! 单个整数数组
    10:required  list<i64>        anI1,
    //! 2个整数数组
    11:required  list<NETPI2>     anI2,
    //! 4个整数数组
    12:required  list<NETPI4>     anI4,
    //! 8个整数数组
    13:required  list<NETPI8>     anI8,
    //! 4个整数2个字符串数组
    14:required  list<NETPI4S2>   anI4S2,
    //! 8个整数2个浮点2个字符串数组
    15:required  list<NETPI8D2S2> anI8D2S2,
    //! 单个string数组
    16:required  list<string>     astrS1,
}

//一个私有协议服务器地址
struct ONEBINARYSRV
{
		1:required  i32 nSrvTypeID;			// 私有协议服务器类型编号
		2:required  string strIP;			// 私有协议服务器地址，可能是dns域名，也可能是ip，请注意转换
		3:required  i32 nPort;				// 私有协议服务器端口
		4:required  string strSrvName;			// 私有协议服务器类型名
		5:required  i32 nRecvBufSize;			// 私有协议socket接收数据缓冲区大小
		6:required  i32 nSendBufSize;			// 私有协议socket发送数据缓冲区大小
		7:required  i32 nMaxSessionCount;		// 私有协议服务器允许的最大连接请求
		8:required  i32 nRpcPort; 			// thrift服务器端口
}

struct RDSPKG_ONEBINARYSRV
{
	//!	总长度(序列化之后的长度)
	1:required  i32      nLength;
	//!	命令ID
	2:required  i32      nCmdID = XtEnumRedisCmdID.SYN_ONE_BINARY_SRV;
	//!	子命令ID
	3:required  i32      nSubCmdID;
	//!	是哪个SrvTypeID发出的消息
	4:required  i32      nSendSrvTypeID;
	5:required  ONEBINARYSRV data;//实际消息数据
}

//服务节点信息
struct SRVNODE {
    //!	服务名称
    1:required  string strSrvName;
    //!	服务ID
	2:required  i32    nSrvID;
    //!	服务端口
	3:required  i32    nVersion;
	//!	IP地址
	4:required  string strAddr;
	//!	服务端口
	5:required  i16    nPort;
}

//同步服务节点信息
struct RDSPKG_ONERPCSRV
{
	//!	总长度(序列化之后的长度)
	1:required  i32      nLength;
	//!	命令ID
	2:required  i32      nCmdID = XtEnumRedisCmdID.SYN_ONE_RPC_SRV;
	//!	子命令ID
	3:required  i32      nSubCmdID;
	//!	是哪个SrvTypeID发出的消息
	4:required  i32      nSendSrvTypeID;
	5:required  SRVNODE  data;//实际消息数据
}

//-------------------------nSubCmdID定义 end--------------------------