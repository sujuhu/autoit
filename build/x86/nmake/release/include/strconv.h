#ifndef UTIL_STRCONV_H_
#define UTIL_STRCONV_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

int _mbstowcs(wchar_t* wcs, char*mbs, size_t max_wc_count);

int _wcstombs(char *mbs, const wchar_t* wcs, size_t max_mbs_count);

#ifdef __cplusplus
}
#endif

#endif