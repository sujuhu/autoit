#ifndef LIB_STRCONV_H_
#define LIB_STRCONV_H_

int _mbstowcs(wchar_t* wcs, char*mbs, size_t max_wc_count);

int _wcstombs(char *mbs, const wchar_t* wcs, size_t max_mbs_count);


#endif