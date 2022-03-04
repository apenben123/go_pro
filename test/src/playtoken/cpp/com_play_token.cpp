#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "ext_sec_io.cpp"
#include "com_base62.cpp"
#include "com_crc.cpp"

#include "com_play_token.h"

COMSLocalConfig g_local_cfg;

/* 取得UTC时间(s) */
uint64_t vdl_get_utc()
{
	struct timeval time;

	gettimeofday( &time, NULL );

	return time.tv_sec;
}

//!获取数字形ip
int32_t getInetPtoN(const char *pstrIP, uint8_t *pnIP, int nLen, int &nVer)
{
	if (!pstrIP || !pnIP)
	{
		return -1;
	}

#if (defined WIN32) || (defined WIN64)
	return -1;
#else
	sockaddr_in in4;
	sockaddr_in6 in6;

	nVer = 0;
	if (nLen>=4 && inet_pton(AF_INET, pstrIP, &in4.sin_addr)==1)
	{
		*(uint32_t *)pnIP = *(uint32_t *)&in4.sin_addr;
		nVer = 4;
		return 0;
	}
	else if (nLen>=16 && inet_pton(AF_INET6, pstrIP, &in6.sin6_addr)==1)
	{
		memcpy(pnIP, (uint8_t *)&in6.sin6_addr, 16);
		nVer = 6;
		return 0;
	}

	return -1;
#endif
}

//!获取playtoken
int32_t getPlayTokenVer1(const SPlayTokenInfo &info, string &strPlayToken)
{
	uint8_t pBuf[1024], pEnBuf[1024], pIP[16];
	char pEncBase62[2048];
	int32_t nDataLen = 0, nVer = 0, nEncBase64Len;
	XteSecIO secIO;

	if (info.strFileName.size()>255)
	{
		return -1;
	}

	// 版本
	pBuf[nDataLen++] = g_local_cfg.nPlayTokenVer;
	
	// 是否启用ip检查
	if (g_local_cfg.bCheckPlayIP && !info.strIP.empty())
	{
		getInetPtoN(info.strIP.c_str(), pIP, (int)sizeof(pIP), nVer);
	}

	pBuf[nDataLen] = 0x00;
	if (g_local_cfg.bCheckPlayIP && (nVer==4 || nVer==6))
	{
		pBuf[nDataLen] |= 0x01;
	}

	if (nVer==4)
	{
		pBuf[nDataLen] |= 0x02;
	}
	else if (nVer==6)
	{
		pBuf[nDataLen] |= 0x04;
	}

	// 是否启用次数检查
	if (g_local_cfg.bCheckPlayNum)
	{
		pBuf[nDataLen] |= 0x08;
	}

	nDataLen++;

	// srvtypeid
	*(uint16_t *)(pBuf + nDataLen) = g_local_cfg.nSrvTypeID;
	nDataLen += 2;

	// tokenutc
	*(uint32_t *)(pBuf + nDataLen) = (uint32_t)vdl_get_utc();
	nDataLen += 4;

	// expiretime
	*(uint16_t *)(pBuf + nDataLen) = g_local_cfg.nPlayExpireTime;
	nDataLen += 2;

	// valid_num
	if (g_local_cfg.bCheckPlayNum)
	{
		*(uint8_t *)(pBuf + nDataLen) = g_local_cfg.nValidPlayNum;
		nDataLen += 1;
	}

	// ip
	if (nVer==4)
	{
		*(uint32_t *)(pBuf + nDataLen) = *(uint32_t *)pIP;
		nDataLen += 4;
	}
	else if (nVer==6)
	{
		memcpy(pBuf+nDataLen, pIP, 16);
		nDataLen += 16;
	}

	// filename
	*(uint8_t *)(pBuf + nDataLen) = (uint8_t)info.strFileName.size();
	nDataLen += 1;
	if ((uint8_t)info.strFileName.size()>0)
	{
		memcpy(pBuf+nDataLen, info.strFileName.data(), (uint8_t)info.strFileName.size());
		nDataLen += (uint8_t)info.strFileName.size();
	}

	// isown, playtype
	pBuf[nDataLen] = 0x00;
	pBuf[nDataLen] |= info.nIsOwn & 0x0f;
	pBuf[nDataLen] |= (info.nPlayType & 0x0f) << 4;
	nDataLen++;

	// 当playtype为1时是时移，时移2才表示购买
	if (!info.nIsOwn || (info.nPlayType==1 && info.nIsOwn!=2))
	{
		// starttime
		*(uint16_t *)(pBuf + nDataLen) = info.nStartTime;
		nDataLen += 2;

		// trailtime
		*(uint16_t *)(pBuf + nDataLen) = info.nTrailTime;
		nDataLen += 2;
	}

	uint8_t nPlatform = 0;
	set<PLATFORM_ID>::iterator platformIt;
	for (platformIt=info.setPlatform.begin(); platformIt!=info.setPlatform.end(); platformIt++)
	{
		if (*platformIt<8)
		{
			nPlatform |= (1 << *platformIt);
		}
	}

	*(uint8_t *)(pBuf + nDataLen) = nPlatform;
	nDataLen += 1;

	secIO.aesSetKeyByString(g_local_cfg.strPlayPwd.c_str());
	secIO.aesEncrypt(pBuf, nDataLen, pEnBuf);

	// crc校验码
	*(uint32_t *)(pEnBuf + nDataLen) = comGetCrc32(pEnBuf, nDataLen);
	nDataLen += 4;

	nEncBase64Len = com_base62_encode(pEnBuf, nDataLen, pEncBase62, sizeof(pEncBase62));
	if (nEncBase64Len>0)
	{
		strPlayToken.clear();
		// 需要试看前缀
		if ((!info.nIsOwn || (info.nPlayType==1 && info.nIsOwn!=2)) && g_local_cfg.bNeedTrialPrefix)
		{
			strPlayToken.append(g_local_cfg.strFreeTrailPlaytoken);
		}
		strPlayToken.append(pEncBase62, nEncBase64Len);
	}

	return 0;
}
