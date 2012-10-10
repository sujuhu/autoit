#ifndef __STRING_H_ZXK_20100410
#define __STRING_H_ZXK_20100410

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	unsigned short  Length;
	unsigned short  MaximumLength;
	wchar_t*  Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

/*
Description:		分割字符串
Parameter:			lpszSrc	 所要分割的字符串
chSplit  分隔字符
aString	 分割结果，字符串数组的指针
cbMaxInRow	每一个字符串一行中最大字符数
pnMaxRow	分割了多少行
Return:				TRUE	 分割成功
FALSE	 分割失败
*/
bool	SplitString(
		const char* lpszSrc, 
		char chSplit, 
		OUT char* aString, 
		int cbMaxInRow, 
		int* pnMaxRow );

//删除字符串左侧的空格
void	TrimLeftString(char* lpsz);

//删除字符串右侧的空格
void	TrimRightString(char* lpsz);

int	CombinString(
	char chSplit, 
	OUT char* aString, 
	int cbMaxInRow, 
	int nRow, 
	OUT char* lpszDst, 
	int nLenDst);

char* MakeMacString(uint8_t mac[6], char* str, int max_cch);

char* MakeIPString(uint8_t ip[4], char* str, int max_cch);

char* MakeTimeString(
	SYSTEMTIME* tmSystem, 
	OUT LPSTR lpszDatatime, 
	DWORD cbBufferSize);

bool MakeHexString(uint8_t* buffer, DWORD size, OUT char* hex, DWORD max_cch);

int	MakeHexBinary(const char* hex_str, IN uint8_t* buffer, int max_cch);


#ifdef __cplusplus
}
#endif

#endif //__STRING_H_ZXK_20100410


