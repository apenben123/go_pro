#ifndef __COM_PLAY_TOKEN_H__
#define __COM_PLAY_TOKEN_H__

#include <string>
#include <stdio.h>
#include <stdint.h>
#include <set>

using namespace std;

typedef int32_t PLATFORM_ID;

struct SPlayTokenInfo
{
    //! 播放端ip
    string strIP;
    // 文件名
    string strFileName;
    //! 是否购买
    uint8_t nIsOwn;
    //! 播放类型
    uint8_t nPlayType;
    //! 试看开始时间
    uint16_t nStartTime;
    //! 试看时间
    uint16_t nTrailTime;
    //! 播放平台
    set<PLATFORM_ID> setPlatform;
    SPlayTokenInfo()
    {
        nIsOwn = 0;
        nPlayType = 0;
        nStartTime = 0;
        nTrailTime = 360;
    }
};

struct COMSLocalConfig
{
    int32_t nSrvTypeID;

    // playtoken版本
    uint8_t nPlayTokenVer;
    // 是否检查播放次数
    bool bCheckPlayNum;
    // 有效播放次数
    uint8_t nValidPlayNum;
    // 是否检查播放ip
    bool bCheckPlayIP;
    // 过期时间
    uint16_t nPlayExpireTime;
    // 密码
    string strPlayPwd;
    // 是否需要试看前缀
    bool bNeedTrialPrefix;

    // 以下为服务器默认试看配置项
    string strFreeTrailPlaytoken;     // 推流试看token

    COMSLocalConfig()
    {
        nSrvTypeID = 0;
        nPlayTokenVer = (uint8_t)0;
        bCheckPlayNum = true;
        nValidPlayNum = (uint8_t)255;
        bCheckPlayIP = true;
        nPlayExpireTime = (uint16_t)10*3600;
        strPlayPwd = "playtokenpwd654321";
        bNeedTrialPrefix = false;
    }
};


//!获取数字形ip
int32_t getInetPtoN(const char *pstrIP, uint8_t *pnIP, int nLen, int &nVer);
//!获取playtoken
int32_t getPlayTokenVer1(const SPlayTokenInfo &info, string &strPlayToken);


#endif // __COM_PLAY_TOKEN_H__
