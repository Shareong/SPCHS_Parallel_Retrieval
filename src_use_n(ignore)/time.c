//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-3-28
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#include <sys/time.h>
#include "global.h"
#include "time.h"

struct timeval stamp;

void set_time_stamp( void )
{
	gettimeofday( &stamp, NULL );
}

void get_time_usage( void )
{
	struct timeval now;
	gettimeofday( &now, NULL );
	if( now.tv_usec < stamp.tv_usec )
	{
		now.tv_sec -= 1;
		now.tv_usec += 1000000;
	}
	//print_info();
	printf( "Time usage is \x1b[31m%lds %ldus\x1b[0m\n", 
			now.tv_sec - stamp.tv_sec, now.tv_usec - stamp.tv_usec );
}
	
