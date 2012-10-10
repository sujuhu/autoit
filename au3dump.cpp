// test.cpp : Defines the entry point for the console application.
//
#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <windows.h>
#include <assert.h>
#include "autoit.h"

int main(int argc, char* argv[])
{
	char* sample_file = argv[1];

	FILE* m_fhandle = fopen(sample_file, "rb");
	if( m_fhandle == NULL ) {
		printf( "sample not exist:%s\n", sample_file );
		return 0;
	}
	fseek( m_fhandle, 0,SEEK_END  );
	int filesize = ftell(m_fhandle);
	char* buf = (char*)malloc( filesize );
	memset( buf, 0, filesize );
	fseek(m_fhandle, 0, SEEK_SET );
	fread(buf,filesize,1,m_fhandle);
	const char* au_block = au_open_script(buf,filesize);
	if (au_block == NULL){
		printf("NOT autoit file");
		return 0;
	}

	int blocksize = filesize - ( au_block - buf);
	char* logfile = "test.log";
	if( !au_dump_script(logfile, au_block, blocksize)){
		printf("dump script failed");
		return 0;
	}

	printf("dump success");
	return 0;
}