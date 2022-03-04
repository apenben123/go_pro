#include "com_base62.h"
#include <string>

using namespace std;

/* base64 编解码 */
static char szComBase62Encodes[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8_t szComBase62Decodes[256];
static bool bComBase62Init = false;

void com_base62_init()
{
	int nLen = (int)strlen(szComBase62Encodes);
	for (int i = 0; i < nLen; i++) {
		szComBase62Decodes[szComBase62Encodes[i]] = (uchar_t)i;
	}
	bComBase62Init = true;
}

int32_t com_base62_encode(const uchar_t *input, int32_t input_length, char_t *output, int32_t output_length)
{
	if (bComBase62Init==false)
	{
		com_base62_init();
	}

	int pos = 0, val = 0, dst = 0;
	for (int i = 0; i < input_length; i++) {
		if (dst+2 >= output_length)
		{
			return -1;
		}

		val = (val << 8) | (input[i] & 0xFF);
		pos += 8;
		while (pos > 5) {
			char c = szComBase62Encodes[val >> (pos -= 6)];
			if (c == 'i')
			{
				output[dst++] = 'i';
				output[dst++] = 'a';
			}
			else if (c == '+')
			{
				output[dst++] = 'i';
				output[dst++] = 'b';
			}
			else if (c == '/')
			{
				output[dst++] = 'i';
				output[dst++] = 'c';
			}
			else
			{
				output[dst++] = c;
			}

			val &= ((1 << pos) - 1);
		}
	}
	if (pos > 0) {
		if (dst+2 >= output_length)
		{
			return -1;
		}

		char c = szComBase62Encodes[val << (6 - pos)];
		if (c == 'i')
		{
			output[dst++] = 'i';
			output[dst++] = 'a';
		}
		else if (c == '+')
		{
			output[dst++] = 'i';
			output[dst++] = 'b';
		}
		else if (c == '/')
		{
			output[dst++] = 'i';
			output[dst++] = 'c';
		}
		else
		{
			output[dst++] = c;
		}
	}

	if (dst>0 && dst<output_length)
	{
		output[dst] = '\0';
		return dst;
	}
	else
	{
		return -1;
	}
}

int32_t com_base62_decode(const char_t *input, int32_t input_length, uchar_t *output, int32_t output_length)
{
	if (bComBase62Init==false)
	{
		com_base62_init();
	}

	int pos = 0, val = 0, dst = 0;
	for (int i = 0; i < input_length; i++) {
		char c = input[i];
		if (c == 'i') {
			c = input[++i];
			c =
				c == 'a' ? 'i' :
				c == 'b' ? '+' :
				c == 'c' ? '/' : input[--i];
		}
		val = (val << 6) | szComBase62Decodes[c];
		pos += 6;
		while (pos > 7) {
			if (dst+1 >= output_length)
			{
				return -1;
			}

			output[dst++] = (uchar_t)(val >> (pos -= 8));
			val &= ((1 << pos) - 1);
		}
	}
	
	if (dst>0 && dst<output_length)
	{
		output[dst] = '\0';
		return dst;
	}
	else
	{
		return -1;
	}
}