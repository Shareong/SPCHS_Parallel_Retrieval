//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-3-28
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#ifndef HEADER_GLOBAL_
#define HEADER_GLOBAL_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* print the status of program */
#define print_info()  \
fprintf( stdout, "\x1b[34m[INFO %s line%d %s]\x1b[0m ", \
                  __FILE__, __LINE__, __func__ )
#define print_debug()  \
fprintf( stdout, "\x1b[34m[DEBUG %s line%d %s]\x1b[0m ", \
                  __FILE__, __LINE__, __func__ )
#define print_error()  \
fprintf( stderr, "\x1b[31m[ERROR %s line%d %s]\x1b[0m ", \
                  __FILE__, __LINE__, __func__ )
#endif
