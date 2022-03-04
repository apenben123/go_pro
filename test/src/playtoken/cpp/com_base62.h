#ifndef __COM_BASE62_H__
#define __COM_BASE62_H__

#include "stdafx.h"

int32_t com_base62_encode(const uchar_t *input, int32_t input_length, char_t *output, int32_t output_length);
int32_t com_base62_decode(const char_t *input, int32_t input_length, uchar_t *output, int32_t output_length);

#endif