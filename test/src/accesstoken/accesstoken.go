package accesstoken

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	DEVICE_ID_TV_START         = 200000000
	DEVICE_ID_TV_END           = 299999999
	DEVICE_ID_CAMERA_START     = 300000000
	DEVICE_ID_CAMERA_END       = 499999999
	DEVICE_ID_ROUTER_START     = 500000000
	DEVICE_ID_ROUTER_END       = 599999999
	DEVICE_ID_GATEWAY_START    = 600000000
	DEVICE_ID_GATEWAY_END      = 699999999
	DEVICE_ID_SMART_HOME_START = 700000000
	DEVICE_ID_SMART_HOME_END   = 799999999
	DEVICE_ID_STB_START        = 1000000000
	DEVICE_ID_STB_END          = 1199999999
	DEVICE_ID_SMARTCARD_START  = 1400000000
	DEVICE_ID_SMARTCARD_END    = 1599999999
	DEVICE_ID_PAD_START        = 1800000000
	DEVICE_ID_PAD_END          = 1899999999
	DEVICE_ID_MOBILE_START     = 2000000000
	DEVICE_ID_MOBILE_END       = 2999999999
	DEVICE_ID_PC_START         = 3000000000
	DEVICE_ID_PC_END           = 3999999999
)

const (
	HOMED_TOKEN_VERSION_06 = 0x6
	HOMED_TOKEN_VERSION_07 = 0x7
	HOMED_TOKEN_VERSION_08 = 0x8
	HOMED_TOKEN_VERSION_09 = 0x9
	HOMED_TOKEN_VERSION    = HOMED_TOKEN_VERSION_09
)

const (
	SUPER_ADMIN_START_ID = 0xFA000000
	SUPER_ADMIN_END_ID   = 0xFAFFFFFF
)

const (
	RET_CODE_SUCCESS                 = 0    //成功
	RET_CODE_IUS_USER_NOT_EXIST      = 9020 //源用户不存在
	RET_CODE_IUS_USER_TOKEN_ERROR    = 9021 //源用户令牌错误
	RET_CODE_IUS_USER_TOKEN_TIMEOUT  = 9022 //源用户令牌过期
	RET_CODE_IUS_USER_PASSWORD_ERROR = 9023 //源用户密码错误
	RET_CODE_IUS_USER_LIMITED        = 9024 //源用户状态受限
	RET_CODE_IUS_GUEST_TOKEN_ERROR   = 9025 //游客令牌错误

	RET_CODE_IUS_DEVICE_TYPE_NOT_SUPPORT = 9100 //设备类型不支持
)

const (
	ACCOUNT_CHECK_TERMINAL = iota //终端用户
	ACCOUNT_CHECK_OPERATOR        //后台管理员用户
	ACCOUNT_CHECK_BOTH
)

const (
	IUSM_DEVICE_TYPE_ALL = iota
	IUSM_DEVICE_TYPE_STB
	IUSM_DEVICE_TYPE_SMARTCARD
	IUSM_DEVICE_TYPE_MOBILE
	IUSM_DEVICE_TYPE_PAD
	IUSM_DEVICE_TYPE_PC

	IUSM_DEVICE_TYPE_TV
	IUSM_DEVICE_TYPE_CAMERA
	IUSM_DEVICE_TYPE_ROUTER
	IUSM_DEVICE_TYPE_GATEWAY

	IUSM_DEVICE_TYPE_UNKNOWN
)

type HomeRegion struct {
	nProvinceId  int64 //(1级)省级区域码
	nCityId      int64 //(2级)市级区域码
	nAreaId      int64 //(3级)区县级区域码
	nTownId      int64 //(4级)乡镇级区域码
	nVillageId   int64 //(5级)村级区域码  行政区域码中目前这一级是最小的
	nCommunityId int64 //(6级)扩展小区编码
	nBuildingId  int64 //(7级)扩展楼栋编码
	nRegionId    int64 //可获取的最小级区域码
	nLevel       int64 //nRegionId的层级(1-7级)
}

type TOKEN_INFO struct {
	nDA          int64 // 用户DA
	nDeviceId    int64 // 访问设备ID
	nDeviceType  int16 // 访问设备类型
	nBusiPlat    int32 // 支付平台
	nUserGroup   int64 // 用户频道分组
	nLoginTime   int64 // 登录时间
	nLoginIp     int32 // token产生时的登录IP
	nAppEntry    int32 // 应用入口
	nOS          int32 // 操作系统类型 1:linux  2:android, 默认1
	nRole        int16 // 用户对应的角色, 0:普通终端用户, 1: 游客, 2: 后台用户
	nDefinition  int16 //分辨率， 取值0：标清 ； 1：高清； 2：超清； 3：4k。 默认值为2。
	nFramerate   int32 //帧率 ， 取值如: 30（表示30及以下), 60。 默认值为30。
	nEquipmentID int64 //设备型号ID
	nHomeType    int32
	region       HomeRegion
	nExtend1     int32
	nExtend2     int32
	nExtend3     int32
	bHasAbility  bool
}

func GetAccountTokenInfo(accessToken string) (int, TOKEN_INFO) {
	var (
		stToken TOKEN_INFO
		ret     int
	)

	if len(accessToken) < 5 {
		return RET_CODE_IUS_USER_TOKEN_ERROR, stToken
	}

	if accessToken[:5] == "TOKEN" {
		ret, stToken = decodeTestToken(accessToken)
	} else if accessToken[0] == 'R' {
		ret, stToken = decodeAccessToken(accessToken)
	} else if accessToken[0] == 'P' {
		ret, stToken = decodeAdminToken(accessToken)
	} else if accessToken[0] == 'G' || accessToken[0] == 'S' {
		ret = 0
	}

	return ret, stToken
}

/*!
测试TOKEN支持如下5种格式：
1.TOKEN+DA+设备类型+设备id
	accesstoken=TOKEN1000084STBID111111，系统可直接获取设备类型为机顶盒，设备id为111111
	accesstoken=TOKEN1000084PCID444444 ，设备类型为电脑，设备id为4444444
2.TOKEN+DA+设备类型 (STBID, CAID, MOBILEID, PADID)
	accesstoken=TOKEN1000084STBID，测试人员可以只输入设备类型，如果不提供设备id,那么系统会根据设备类型赋一个默认的设备id。
	设备类型为机顶盒，默认设备id为0xFFFFFFFA;
	设备类型为CA卡，默认设备id为0xFFFFFFFB;
	设备类型为手机，默认设备id为0xFFFFFFFC;
	设备类型为pad，默认设备id为0xFFFFFFFD;
	设备类型为电脑，默认设备id为0xFFFFFFFE;
3.TOKEN+DA+ID+设备id (注：ID仅作为分隔符,相当于请求路径的“&”)
	accesstoken = TOKEN1000084ID111111 ,如果测试人员没有传设备类型，只传了设备id,系统会根据设备id返回设备类型。
4.TOKEN+DA+ID
	accesstoken=TOKEN1000084ID,如果测试人员没有加任何设备信息的话，系统会默认设备类型为机顶盒，设备id为0xFFFFFFFA。
5.TOKEN+DA
	accesstoken=TOKEN1000084,同样会默认设备类型为机顶盒，设备id为0xFFFFFFFA。
*/
func decodeTestToken(accessToken string) (int, TOKEN_INFO) {

	var (
		stToken  TOKEN_INFO
		ret      int
		strValue string
	)

	ret, strValue = getTestTokenInfo(accessToken, "TOKEN")
	if len(strValue) != 0 {
		stToken.nDA, _ = strconv.ParseInt(strValue, 10, 64)
		//检查测试token使用是否开启，检查da是否是内置的账号
		if 0 == checkTestTokenSwitch() {
			getTestDeviceTypeId(accessToken, &stToken.nDeviceId, &stToken.nDeviceType)
			getTestLoginParam(accessToken, &stToken)
		}
	}

	return ret, stToken
}

func getTestDeviceTypeId(accessToken string, nDeviceId *int64, nDeviceType *int16) int {

	ret, strValue := getTestTokenInfo(accessToken, "STBID")
	if ret == 0 {
		*nDeviceType = IUSM_DEVICE_TYPE_STB
		if len(strValue) != 0 {
			*nDeviceId, _ = strconv.ParseInt(strValue, 10, 64)
		} else {
			*nDeviceId = DEVICE_ID_STB_END
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "CAID")
	if ret == 0 {
		*nDeviceType = IUSM_DEVICE_TYPE_SMARTCARD
		if len(strValue) != 0 {
			*nDeviceId, _ = strconv.ParseInt(strValue, 10, 64)
		} else {
			*nDeviceId = DEVICE_ID_SMARTCARD_END
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "MOBILEID")
	if ret == 0 {
		*nDeviceType = IUSM_DEVICE_TYPE_MOBILE
		if len(strValue) != 0 {
			*nDeviceId, _ = strconv.ParseInt(strValue, 10, 64)
		} else {
			*nDeviceId = DEVICE_ID_MOBILE_END
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "PADID")
	if ret == 0 {
		*nDeviceType = IUSM_DEVICE_TYPE_PAD
		if len(strValue) != 0 {
			*nDeviceId, _ = strconv.ParseInt(strValue, 10, 64)
		} else {
			*nDeviceId = DEVICE_ID_PAD_END
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "PCID")
	if ret == 0 {
		*nDeviceType = IUSM_DEVICE_TYPE_PC
		if len(strValue) != 0 {
			*nDeviceId, _ = strconv.ParseInt(strValue, 10, 64)
		} else {
			*nDeviceId = DEVICE_ID_PC_END
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "DID")
	if ret == 0 {
		//*nDeviceType = IUSM_DEVICE_TYPE_PC
		if len(strValue) != 0 {
			*nDeviceId, _ = strconv.ParseInt(strValue, 10, 64)
		}
	} else {
		*nDeviceType = IUSM_DEVICE_TYPE_STB
		*nDeviceId = DEVICE_ID_STB_END
	}
	return 0
}

func getTestTokenInfo(accessToken string, param string) (int, string) {
	ret := -1
	value := ""
	startIdx := strings.Index(accessToken, param)
	if startIdx != -1 {
		ret = 0
		startIdx += len(param)
		tmpData := accessToken[startIdx:]
		re := regexp.MustCompile("[0-9]+")
		value = re.FindString(tmpData)
	}
	return ret, value
}

func getTestLoginParam(accessToken string, stToken *TOKEN_INFO) {

	ret, strValue := getTestTokenInfo(accessToken, "DFN")
	if ret == 0 {
		if len(strValue) != 0 {
			data, _ := strconv.Atoi(strValue)
			stToken.nDefinition = int16(data)
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "FPS")
	if ret == 0 {
		if len(strValue) != 0 {
			data, _ := strconv.ParseInt(strValue, 10, 32)
			stToken.nFramerate = int32(data)
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "GID")
	if ret == 0 {
		if len(strValue) != 0 {
			stToken.nUserGroup, _ = strconv.ParseInt(strValue, 10, 64)
		}
	}

	ret, strValue = getTestTokenInfo(accessToken, "ZONE")
	if ret == 0 {
		if len(strValue) != 0 {
			stToken.region.nAreaId, _ = strconv.ParseInt(strValue, 10, 64)
		}
	}
	ret, strValue = getTestTokenInfo(accessToken, "EXT")
	if ret == 0 {
		if len(strValue) != 0 {
			data, _ := strconv.ParseInt(strValue[0:2], 10, 32)
			stToken.nExtend1 = int32(data)
			data, _ = strconv.ParseInt(strValue[2:4], 10, 32)
			stToken.nExtend2 = int32(data)
			data, _ = strconv.ParseInt(strValue[4:6], 10, 32)
			stToken.nExtend3 = int32(data)
		}
	}
}

func checkTestTokenSwitch() int {
	return 0
}

/*- version --------------------------内容--------------------------------------------------------------------------
|	0x06	| R+当前UTC时间(32b)+U+设备类型(4b)+平台(4b)+版本(4b)+随机数(4b)+服务器IP(16b)+K+设备ID(32b)+M+账号ID(32b)+W+索引(32b)
|	0x07	| R+当前UTC时间(32b)+U+设备类型(4b)+平台(4b)+版本(4b)+随机数(8b)+应用入口(4b)+服务器IP(8b)+K+设备ID(32b)+I+登录IP(32b)+M+账号ID(32b)+W+索引(32b)
|	0x08	| R+当前UTC时间(32b)+U+设备类型(4b)+平台(4b)+版本(4b)+随机数(8b)+应用入口(4b)+服务器IP(8b)+K+设备ID(32b)+I+登录IP(32b)+P+用户分组ID(16b)+M+账号ID(32b)+W+索引(32b)
|   0x10    | R+当前UTC时间(32b)+U+设备类型(4b)+平台(4b)+版本(4b)+随机数(5b)+操作系统类型(3b)+应用入口(4b)+服务器IP(8b)+K+设备ID(32b)+I+登录IP(32b)+P+用户分组ID(16b)
				  +M+账号ID(32b)+V+服务器版本号(32b)+Z+用于区域ID(64b)+Q+设备型号ID(32b)+T+家庭类型(32b)+O+分辨率(4b)+帧率(8b)W+索引(32b)
---------------------------------- 修改记录 -----------------------------------------------------------------------
| 20161201	| 版本号 0x06	| 添加版本信息、登录平台
| 20170208	| 版本号 0x07	| 添加终端登录IP地址，登录应用入口(web,apk,weixin)
| 20170421	| 版本号 0x08	| 添加用户分组ID
| 20200311  | 版本号 0x10   | 添加设备型号、家庭类型、设备分辨率、帧率
*/
func decodeAccessToken(accessToken string) (int, TOKEN_INFO) {
	var (
		stToken TOKEN_INFO
		ret     int
	)

	pR := strings.IndexByte(accessToken, 'R') //R(32b) +当前UTC时间
	pU := strings.IndexByte(accessToken, 'U') //U(32b) +设备类型(4b)+平台(4b)+版本(4b)+随机数(5b)+操作系统类型(3b)+应用入口(4b)+服务器IP(8b)
	pK := strings.IndexByte(accessToken, 'K') //K(32b) +设备ID
	pM := strings.IndexByte(accessToken, 'M') //M(32b) +账号ID
	pI := strings.IndexByte(accessToken, 'I') //I(32b) +登录IP
	pW := strings.IndexByte(accessToken, 'W') //W(32b) +索引

	if (pR == -1) || (pU == -1) ||
		(pK == -1) || (pM == -1) ||
		(pI == -1) || (pW == -1) {
		return RET_CODE_IUS_USER_TOKEN_ERROR, stToken
	}

	stToken.nLoginTime = strtoll(accessToken, pR+1, 16, 64)
	dataU := strtoll(accessToken, pU+1, 16, 32)
	content_u := uint32(dataU)
	stToken.nDeviceType = int16((content_u >> 28) & 0x0F)
	stToken.nBusiPlat = int32((content_u >> 24) & 0x0F)
	system_version := (content_u >> 20) & 0x0F
	ikey := (content_u >> 15) & 0x1F
	stToken.nOS = int32((content_u >> 12) & 0x07)
	stToken.nAppEntry = int32((content_u >> 8) & 0x0F)
	stToken.nDeviceId = strtoll(accessToken, pK+1, 16, 64)
	stToken.nDA = strtoll(accessToken, pM+1, 16, 64)
	dataI := strtoll(accessToken, pI+1, 16, 32)
	stToken.nLoginIp = int32(dataI)
	dataW := strtoll(accessToken, pW+1, 16, 64)

	if system_version >= HOMED_TOKEN_VERSION_09 {
		/* 密钥,可以还原,防止伪造*/
		tmp_random_key := fmt.Sprintf("%d%d%d", stToken.nDeviceId, stToken.nDA, dataW)
		hash_value := getStringHashVal(tmp_random_key) & 0xFF
		//! 兼容上一个版本的秘钥
		if (ikey != (hash_value & 0x1F)) && (ikey != ((hash_value >> 3) & 0x1F)) {
			fmt.Println("[decodeAccessToken] key not match")
			return RET_CODE_IUS_USER_TOKEN_ERROR, stToken
		}
	}

	pP := strings.IndexByte(accessToken, 'P') //P(32b) +用户组
	pQ := strings.IndexByte(accessToken, 'Q') //Q(32b) +设备型号ID
	pO := strings.IndexByte(accessToken, 'O') //I(32b) +设备详情
	pT := strings.IndexByte(accessToken, 'T') //T(32b) +家庭类型
	pZ := strings.IndexByte(accessToken, 'Z') //Z(32b) +区域信息

	if pP != -1 {
		stToken.nUserGroup = strtoll(accessToken, pP+1, 16, 64)
	}
	if pQ != -1 {
		stToken.nEquipmentID = strtoll(accessToken, pQ+1, 16, 64)
	}
	if pO != -1 {
		dataO := strtoll(accessToken, pO+1, 16, 32)
		device_detail := uint32(dataO)
		stToken.nDefinition = int16((device_detail >> 28) & 0x0F)
		stToken.nExtend1 = int32((device_detail >> 24) & 0x0F)
		stToken.nExtend2 = int32((device_detail >> 20) & 0x0F)
		stToken.nExtend3 = int32((device_detail >> 16) & 0x0F)
		stToken.nFramerate = int32(device_detail & 0xFF)
	} else {
		if stToken.nOS == 1 {
			stToken.nDefinition = 2
		} else {
			stToken.nDefinition = 3
		}
		stToken.nFramerate = 30
	}
	if pT != -1 {
		dataT := strtoll(accessToken, pT+1, 16, 32)
		stToken.nHomeType = int32(dataT)
	}
	if pZ != -1 {
		stToken.region.nRegionId = strtoll(accessToken, pZ+1, 16, 64)
	}

	return ret, stToken
}

func getStringHashVal(str string) uint32 {
	var hash uint32 = 0
	if len(str) == 0 {
		return hash
	}

	for _, ch := range str {
		hash = hash*31 + uint32(uint8(ch)) // 也可以乘以31、131、1313、13131、131313..
	}
	return (uint32)(hash & 0xffffffff)
}

func strtoll(str string, startIdx int, base int, bitSize int) int64 {
	var out int64 = 0
	endIdx := startIdx
	for _, ch := range str[startIdx:] {
		if (ch >= '0' && ch <= '9') ||
			(ch >= 'a' && ch <= 'f') ||
			(ch >= 'A' && ch <= 'F') {
			endIdx++
		} else {
			break
		}
	}

	if endIdx > startIdx {
		out, _ = strconv.ParseInt(str[startIdx:endIdx], base, bitSize)
	}

	return out
}

/*
后台免登陆超级管理员TOKEN定义
Key = Homed_Secret*Key2@17
System = s1 | s2 | s3 | s4
Key = Hash(s=System&m=Key&t=UTC)
UTC = time

Token = P + System + K + Key + T + UTC
*/
func decodeAdminToken(accessToken string) (int, TOKEN_INFO) {

	var (
		stToken TOKEN_INFO
		ret     int = 0
	)
	pP := strings.IndexByte(accessToken, 'P')
	pK := strings.IndexByte(accessToken, 'K')
	pT := strings.IndexByte(accessToken, 'T')

	if (pP == -1) || (pK == -1) || (pT == -1) {
		return RET_CODE_IUS_USER_TOKEN_ERROR, stToken
	}

	pSecretKey := "Homed_Secret*Key2@17"

	dataP := strtoll(accessToken, pP+1, 16, 32)
	system_id := uint32(dataP)
	dataK := strtoll(accessToken, pK+1, 16, 32)
	hashKey := uint32(dataK)
	utc := strtoll(accessToken, pT+1, 16, 64)
	tmp_buffer := fmt.Sprintf("s=%x&m=%s&t=%x", system_id, pSecretKey, utc)
	hashKey2 := getStringHashVal(tmp_buffer)
	if hashKey2 != hashKey {
		ret = RET_CODE_IUS_USER_TOKEN_ERROR
	}
	/* 校验通过,就是我们内部产生的KEY */
	stToken.nDA = int64(SUPER_ADMIN_START_ID | (system_id & 0x00FFFFFF))

	return ret, stToken
}
