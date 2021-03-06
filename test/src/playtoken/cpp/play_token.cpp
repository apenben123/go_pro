#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "com_play_token.h"
#include "play_token.h"


char*  get_video_play_token_ver1(const char* ip_addr, const char* fileName, uint16_t nTrailTime, int32_t nPlatform, int32_t debug)
{
	SPlayTokenInfo tokenInfo;
	char* playToken = NULL;

	tokenInfo.nIsOwn 		= 1; //! 不鉴权
	tokenInfo.nPlayType 	= 3; //! EContentLabel::VOD
	tokenInfo.nStartTime	= 0; //! starttime 固定填 0
	tokenInfo.strIP			= ip_addr;
	tokenInfo.strFileName	= fileName;
	tokenInfo.nTrailTime	= nTrailTime;
	if (nPlatform!=(PLATFORM_ID)-1)
	{
		tokenInfo.setPlatform.insert(nPlatform);
	}

	string strPlayToken;
	getPlayTokenVer1(tokenInfo, strPlayToken);
	if (!strPlayToken.empty())
	{
		playToken = (char*)malloc(sizeof(char) * (strPlayToken.size() + 1));
		strcpy(playToken, strPlayToken.c_str());
		//memcpy(playToken, strPlayToken.c_str(), strPlayToken.size());
		//playToken[strPlayToken.size() + 1] = 0;
	}

    if (debug == 1)
    {
        printf("strPlayToken=%s\n", strPlayToken.c_str());
        printf("playToken=%s\n", playToken);
    }

	return playToken;
}

int main()
{
	char *playToken = NULL;
	char ip_addr[1024] = "192.168.49.210";
	char fileName[1024] = "test";

	playToken = get_video_play_token_ver1(ip_addr, fileName, 10, 1);
    if (playToken)
    {
        printf("playToken=%s", playToken);
        free(playToken);
    }
    else
    {
        printf("playtoken is nill");
    }

	return 0;
}

