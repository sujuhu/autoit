#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef __MSC_VER__

#else
#include <locale.h>
#include <iconv.h>
#endif

int _mbstowcs(wchar_t* wcs, char*mbs, size_t max_wc_count)
{
#ifdef  __MSC_VER__
  return mbstowcs(wcs, mbs, max_wc_count);
#else
  iconv_t cd = iconv_open("UCS-2", "ASCII");
  if(cd == (iconv_t)(-1)) {
    return -1;
  } else {  
    char* in = mbs;
    size_t in_len = strlen(mbs);
    wchar_t* out = wcs;
    size_t out_len = (size_t)(max_wc_count * sizeof(wchar_t));

    //out_len = iconv(cd, &in, &in_len, NULL, NULL);
    //printf("before in len = %d, in = %s, out_len = %d, out = %S\n", in_len , in, out_len, out);
    int conv_cch = iconv(cd , &in, &in_len, (char**)&out, &out_len);
    if ( -1 == conv_cch) {
    //    printf("after in len = %d, in = %s, out_len = %d, out = %S\n", in_len , in, out_len, out );
    //    printf("iconv failed %d", errno);

    }
    //printf("after in len = %d, in = %s, out_len = %d, out = %S\n", in_len , in, out_len, out );

    //printf("mbstowcs total_size = %d %S rest = %d\n", NewSize, out, rest);
    iconv_close(cd);
    return conv_cch;
  }
#endif
}

int _wcstombs(char *mbs, const wchar_t* wcs, size_t max_mbs_count)
{
#ifdef __MSC_VER__
  return _wcstombs(mbs, wcs, max_mbs_count);
#else
  iconv_t cd = iconv_open("ASCII", "UCS-2");
  if(cd == (iconv_t)(-1)) {
    return -1;
  } else {  
    char* in = (char*)wcs;
    size_t in_len = wcslen(wcs) * sizeof(wchar_t);
    char* out = mbs;
    size_t out_len = max_mbs_count;

    //out_len = iconv(cd, &in, &in_len, NULL, NULL);
    //printf("before in len = %d, in = %s, out_len = %d, out = %S\n", in_len , in, out_len, out);
    int conv_cch = iconv(cd , &in, &in_len, (char**)&out, &out_len);
    if ( -1 == conv_cch) {
    //    printf("after in len = %d, in = %s, out_len = %d, out = %S\n", in_len , in, out_len, out );
    //    printf("iconv failed %d", errno);

    }
    //printf("after in len = %d, in = %s, out_len = %d, out = %S\n", in_len , in, out_len, out );

    //printf("mbstowcs total_size = %d %S rest = %d\n", NewSize, out, rest);
    iconv_close(cd);
    return conv_cch;
  }
#endif
}