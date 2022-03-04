#ifndef __PLAY_TOKEN_H__
#define __PLAY_TOKEN_H__


#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

char* get_video_play_token_ver1(const char* ip_addr, const char* fileName, uint16_t nTrailTime, int32_t nPlatform);

#ifdef __cplusplus
}
#endif

#endif /* __PLAY_TOKEN_H__ */
