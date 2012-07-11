#pragma warning( disable:4996 )

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <memory.h>
#include <locale.h>
#include "autoit.h"


#ifdef __GNUC__
#ifdef __MINGW32__
//mingw on windows

#else
//linux or linux
#define w 32
#define _rotl(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define _rotr(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))

#define _snprintf snprintf
#define _snwprintf swprintf
#endif
#endif

typedef struct _LAME {

	unsigned long c0;
	unsigned long c1;
	unsigned long grp1[17];
	unsigned long grp2[17];
	unsigned long grp3[17];
	unsigned long field_D4;
} LAME;

double LAME_fpusht( LAME *l )
{
	union {

		double as_double;

		struct {
			unsigned long lo;
			unsigned long hi;
		} as_uint;

	} ret;

	unsigned long rolled = _rotl( l->grp1[l->c0], 9 ) + _rotl( l->grp1[l->c1], 13 );
	l->grp1[l->c0] = rolled;

	if (l->c0-- == 0) {
		l->c0 = 16;
	}

	if (l->c1-- == 0) {
		l->c1 = 16;
	}

	ret.as_uint.lo = rolled << 20;
	ret.as_uint.hi = (rolled >> 12) | 0x3FF00000;
	return ret.as_double - 1.0;
}

void LAME_srand( LAME *l, unsigned long seed )
{
	for (int i = 0; i < 17; i++)
	{
		seed *= 0x53A9B4FB;
		seed = 1 - seed;
		l->grp1[i] = seed;
	}

	l->c0 = 0;
	l->c1 = 10;

	memcpy( l->grp2, l->grp1, 17 * sizeof(unsigned long) );
	memcpy( l->grp3, l->grp1, 17 * sizeof(unsigned long) );

	for (int i = 0; i < 9; i++)
	{
		LAME_fpusht( l );
	}
}

void LAME_init( LAME *l )
{
	//__time64_t time = _time64( NULL );

	time_t t = time(NULL);
	LAME_srand( l, (unsigned long)t );
}

unsigned char LAME_getnext( LAME *l )
{
	double x;
	unsigned char ret;

	LAME_fpusht( l );

	x = LAME_fpusht(l) * 256.0;

	if ((unsigned long)x < 256) {
		ret = (unsigned char)x;
	} else {
		ret = 0xff;
	}

	return ret;
}

void LAME_decrypt( unsigned char *data, size_t size, unsigned long seed )
{
	LAME lame;

	// LAME_init( &lame );

	LAME_srand( &lame, seed );

	for (size_t i = 0; i < size; i++) {
		data[i] ^= LAME_getnext( &lame );
	}
}

unsigned char sig[] = { 0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 
                        0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 
                        0x48, 0x7D };

typedef struct _UN {
	unsigned char *outputbuf;
	unsigned char *inputbuf;
	unsigned long cur_output;
	unsigned long cur_input;
	unsigned long usize;

	union {
		unsigned long full;
		struct {

			unsigned short l;
			unsigned short h;
		} half;
	} bitmap;
	unsigned long bits_avail;
} UN;

unsigned short getbits( UN *u, unsigned long size )
{
	u->bitmap.half.h = 0;

	while (size != 0) {
		if (u->bits_avail == 0) {
			u->bitmap.half.l |= u->inputbuf[u->cur_input++] << 8;
			u->bitmap.half.l |= u->inputbuf[u->cur_input++];
			u->bits_avail = 16;
		}
		u->bitmap.full <<= 1;
		u->bits_avail--;
		size--;
	}
	return (unsigned short)u->bitmap.half.h;
}

unsigned long get_au3_start(const char *stream, size_t stream_size )
{
	//寻找AUTO3签名值
	for (size_t i = 0; i < stream_size; i++) {
		if (memcmp(&stream[i], sig, sizeof(sig) - 1) == 0) {
			return i;
		}
	}

	return -1;
}

//查找Autoit 数据
const char* au_open_script( const char *stream, size_t stream_size )
{
	//寻找autoit3脚本开始的位置
	unsigned long au3start = get_au3_start( stream, stream_size );
	if (au3start == 0) {
		return NULL;
	}

	//读取8个字节， 来进行验证 
	stream += au3start + 0x10;
	if (strncmp(stream + 0x4, "EA06", 4) != 0) {
		return NULL;
	}
	stream += 8;

	/* 后 16 字节数据，用来计算校验和，校验和永远为 0，直接跳过 */
	return stream + 0x10;
}

//定位脚本位置
const char* check_au3_header( const char *stream, int stream_size  )
{
	while (true) {
		/* 解密后为 "FILE" */
		char sigFILE[4];
    
		memcpy(sigFILE, stream, 4);
		LAME_decrypt( (unsigned char *)sigFILE, 4, 0x18EE );
		if (strncmp( sigFILE, "FILE", 4 ) != 0) {
			return NULL;
		}
    stream += 4;

		/* 下一段的大小 */
		unsigned long flagsz;
		memcpy( &flagsz, stream, 4 );
		flagsz = (flagsz ^ 0xADBC) * 2;
    stream += 4;

		/* 解密后为 ">>>AUTOIT SCRIPT<<<" */
		wchar_t flagAUTOIT[256] = L"\0";
		memcpy( flagAUTOIT, stream, flagsz );
		LAME_decrypt( (unsigned char *)flagAUTOIT, flagsz, 0xB33F + (flagsz / 2) );
    stream += flagsz;

		unsigned long pathsz;
		memcpy( &pathsz, stream, 4);
		pathsz = (pathsz ^ 0xF820) * 2;
    stream += 4;

		wchar_t path[256] = L"\0";
		memcpy(path, stream, pathsz);
		LAME_decrypt( (unsigned char *)path, pathsz, 0xF479 + (pathsz / 2) );
		stream += pathsz;
		if (wcsncmp( flagAUTOIT, L">>>AUTOIT SCRIPT<<<", 19 ) == 0) {
			break;
		}

		/* 重新验证下一段 */
		unsigned long next;
		stream ++;
		memcpy( &next, stream, 4);
    stream += 4;

		next = (next ^ 0x87BC) + 0x18;
    stream += next;
	}

	return stream;
}

unsigned long crc_data( unsigned char *src, int srclen )
{
	if (srclen == 0) return 0;

	unsigned long dwKey_ECX = 0;
	unsigned long dwKey_ESI = 1;
	for (int i= 0; i < srclen; i++)	{

		dwKey_ESI = ((unsigned long)src[i] + dwKey_ESI) % 0xFFF1;
		dwKey_ECX = (dwKey_ECX + dwKey_ESI) % 0xFFF1;
	}
	return (dwKey_ECX << 0x10) + dwKey_ESI;
}

//解压缩脚本
bool decompression_script( UN *u )
{
	if (strncmp( (const char *)u->inputbuf, "EA06", 4 ) != 0) {
		return false;
	}

	u->usize = u->inputbuf[4] << 24 | u->inputbuf[5] << 16 | u->inputbuf[6] << 8 | u->inputbuf[7];
	u->cur_input += 8;

	while (u->cur_output < u->usize) {

		if (getbits( u, 1 ) == 1) {

			u->outputbuf[u->cur_output] = (unsigned char)getbits( u, 8 );
			u->cur_output++;

		} else {

			unsigned long bb, bs, addme = 0;

			bb = getbits( u, 15 );

			if ((bs = getbits( u, 2 )) == 3) {
				addme = 3;
				if ((bs = getbits( u, 3 )) == 7) {
					addme = 10;
					if ((bs = getbits( u, 5 )) == 31) {
						addme = 41;
						if ((bs = getbits( u, 8 )) == 255) {
							addme = 296;
							while ((bs = getbits( u, 8 )) == 255) {
								addme += 255;
							}
						}
					}
				}
			}
			bs += (3 + addme);

			unsigned long i = u->cur_output - bb;

			while (bs--) {
				u->outputbuf[u->cur_output] = u->outputbuf[i];
				u->cur_output++;
				i++;
			}
		}
	}

	return true;
}

/* 还原Autoit脚本 */
void decode_dump( unsigned char *pcode, size_t size, const char *logfile )
{
	unsigned char *code = pcode;
	int sectionIndex = 0;
	int sectionNum = *(int *)pcode;
	int i, var = 0;
	wchar_t *data;
	char *cdata;
	i = 4;

	setlocale( LC_ALL, "" );

	FILE *aufp = fopen( logfile, "wb");
	if (aufp == NULL) return;

	while (sectionIndex < sectionNum) {

		switch (code[i]) {

		case 0x05:	/* int32 */
			{
				unsigned long x;
				char pp[1024];
				i++;
				x = *(unsigned long *)&code[i];
				_snprintf( pp, 1024, "%d ", x );
				fwrite( pp, strlen( pp ), 1, aufp );
				i += 4;
			}
			break;

		case 0x10: /* int64 */
			{
				long long x;
				char pp[1024];
				i++;
				x = *(long long *)&code[i];
				_snprintf( pp, 1024, "0x%lx ", x );
				fwrite( pp, strlen( pp ), 1, aufp );
				i += 8;
			}
			break;

		case 0x20: /* double */
			{
				double x;
				char pp[1024];
				i++;
				x = *(double *)&code[i];
				_snprintf( pp, 1024, "%e ", x );
				fwrite( pp, strlen( pp ), 1, aufp );
				i += 8;
			}
			break;

		case 0x31: case 0x36: case 0x32: case 0x37: case 0x30: case 0x33: case 0x34: case 0x35:
		case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: case 0x3e: case 0x3f:	/* 0x31-0x3f */
			{
				var = code[i];

				/* 变量 */
				if (var == 0x33) {
					fwrite( "$", 1, 1, aufp );
				}

				/* 字符串 */
				if (var == 0x36) {
					fwrite( "\"", 1, 1, aufp );
				}

				/* 关键字 */
				if (var == 0x30) {
				}

				/* 宏 */
				if (var == 0x32) {
					fwrite( "@", 1, 1, aufp );
				}

				/* 函数 */
				if (var == 0x34) {
				}

				/* 对象 */
				if (var == 0x35) {
				}

				unsigned long n;
				wchar_t key; 
				char m;
				n = 0;
				m = i ;
				i++;
				key = *(wchar_t *)&code[i];

				data = new wchar_t[key + 1];
				if (data == NULL) {

					return;
				}
				i = i + 4;
				for (unsigned long j = 0 ; j < key ; j++) {
					wchar_t xxtmp = *(wchar_t*)&code[i];
					data[n] = key ^ xxtmp;
					i = i + 2;
					n = n + 1;
				}
				data[n] = L'\0';

				cdata = new char[key * 2 + 1];
				if (cdata == NULL) {
					delete []data;

					return;
				}
				wcstombs( cdata, data, key * 2 + 1 );
				fwrite( cdata, strlen(cdata), 1, aufp );


				if (var == 0x36) {	/* 字符串 */
					fwrite( "\" ", 2, 1, aufp );
				} else if (var == 0x33 && code[i] == 0x35) {	/* 本次为 变量，下个是对象，则使用 . 分割 */
					fwrite( ".", 1, 1, aufp );
				} else {	/* 其他 */
					fwrite( " ", 1, 1, aufp );
				}

				delete []data;
				delete []cdata;
			}
			break;

		case 0x40:	/* , */
			i++;
			fwrite( ", ", 2, 1, aufp );
			break;

		case 0x41:	/* = */
			i++;
			fwrite( "= ", 2, 1, aufp );			
			break;

		case 0x42:	/* > */
			i++;
			fwrite( "> ", 2, 1, aufp );
			break;

		case 0x43:	/* < */
			i++;
			fwrite( "< ", 2, 1, aufp );
			break;

		case 0x44:	/* <> */
			i++;
			fwrite( "<> ", 3, 1, aufp );
			break;

		case 0x45:	/* >= */
			i++;
			fwrite( ">= ", 3, 1, aufp );
			break;

		case 0x46:	/* <= */
			i++;
			fwrite( "<= ", 3, 1, aufp );
			break;

		case 0x47:	/* ( */
			i++;
			fwrite( "( ", 2, 1, aufp );
			break;

		case 0x48:	/* ) */
			i++;
			fwrite( ") ", 2, 1, aufp );
			break;

		case 0x49:	/* + */
			i++;
			fwrite( "+ ", 2, 1, aufp );
			break;

		case 0x4a:	/* - */
			i++;
			fwrite( "- ", 2, 1, aufp );
			break;

		case 0x4b:	/* / */
			i++;
			fwrite( "/ ", 2, 1, aufp );
			break;

		case 0x4c:	/* * */
			i++;
			fwrite( "* ", 2, 1, aufp );
			break;

		case 0x4d:	/* & */
			i++;
			fwrite( "& ", 2, 1, aufp );
			break;

		case 0x4e:	/* [ */
			i++;
			fwrite( "[ ", 2, 1, aufp );
			break;

		case 0x4f:	/* ] */
			i++;
			fwrite( "] ", 2, 1, aufp );
			break;

		case 0x50:	/* == */
			i++;
			fwrite( "== ", 3, 1, aufp );
			break;

		case 0x51:	/* ^ */
			i++;
			fwrite( "^ ", 2, 1, aufp );
			break;

		case 0x52:	/* += */
			i++;
			fwrite( "+= ", 3, 1, aufp );
			break;

		case 0x53:	/* -= */
			i++;
			fwrite( "-= ", 3, 1, aufp );
			break;

		case 0x54:	/* /= */
			i++;
			fwrite( "/= ", 3, 1, aufp );
			break;

		case 0x55:	/* *= */
			i++;
			fwrite( "*= ", 3, 1, aufp );
			break;

		case 0x56:	/* &= */
			i++;
			fwrite( "&= ", 3, 1, aufp );
			break;

		case 0x7f:	/* 段结束 */
			i++;
			fwrite( "\r\n", 2, 1, aufp );
			sectionIndex++;
			break;

		default:	/* 未知　Code */

			if (code[i] <= 0x0F) {
				i += 4;
			} else if (code[i] <= 0x1F) {
				i += 8;
			} else if (code[i] <= 0x2F) {
				i += 8;
			} else {
				i++;
				i--;
			}
			i++;
			break;
		}

		fflush( aufp );
	}

	fclose( aufp );
}

//dump脚本
bool au_dump_script( const char *logfile, const char* stream, size_t stream_size )
{
  stream = check_au3_header(stream, stream_size );
	if (stream == NULL) {
		return false;
	}

	/* 是否被压缩 */
	unsigned char comp;
	memcpy(&comp, stream, 1);
  stream += 1;

	/* 加密数据大小 */
	unsigned long datasz;
	memcpy(&datasz, stream, 4);
  stream += 4;
	datasz = datasz ^ 0x87BC;

	/* 解密出的代码大小 */
	unsigned long codesz;
	memcpy(&codesz, stream, 4);
  stream += 4;
	codesz = codesz ^ 0x87BC;

	unsigned long crc;
	memcpy(&crc, stream, 4);
  stream += 4;
	crc = crc ^ 0xA685;

	unsigned char *data;
	unsigned char *code;

	data = new unsigned char[datasz];
	if (data == NULL) {
		return false;
	}

	code = new unsigned char[codesz];
	if (code == NULL) {
		delete []data;
		return false;
	}

	/* 跳过无用数据 */
  stream += 0x10;

	/* 读取并解密数据 */
	memcpy(data, stream, datasz);
	LAME_decrypt( data, datasz, 0x2477 );

	/* 检查 CRC */
	if ( crc != crc_data( data, datasz ) ) {
		delete []code;
		delete []data;
		return false;
	}

	unsigned char *buf = data;
	unsigned long bufsz = datasz;

	/* 解压缩 */
	if (comp == 1) {
		UN u;
		u.inputbuf = data;
		u.outputbuf = code;
		u.cur_input = 0;
		u.cur_output = 0;
		u.bits_avail = 0;
		u.bitmap.full = 0;
		if (!decompression_script( &u )) {
			delete []code;
			delete []data;
			return false;
		}

		buf = u.outputbuf;
		bufsz = u.usize;
	}

	/* Dump 数据为，Autoit 代码　*/
	decode_dump( buf, bufsz, logfile );

	delete []code;
	delete []data;

	return true;
}
