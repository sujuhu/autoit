#ifndef LIB_AUTOIT_H_
#define LIB_AUTOIT_H_

#ifdef __cplusplus
extern "C" {
#endif

//查找Autoit 数据 
const char* au_open_script(
    const char* stream, 
    size_t stream_size);

//dump脚本
bool au_dump_script( 
	const char *logfile, 
    const char *stream, 
    size_t stream_size);

#ifdef __cplusplus
};
#endif

#endif