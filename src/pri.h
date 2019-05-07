//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-3-29
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#ifndef HEADER_PRI_
#define HEADER_PRI_

#define WORD_LEN 16

typedef struct _pri_pair
{
	int  counter;
	char word[WORD_LEN];
	struct _pri_pair* next;
} pri_pair;

extern pri_pair* pri_pair_init( void );
extern pri_pair* pri_pair_find( pri_pair* head, const char* word );
extern void      pri_pair_free( pri_pair* head );

#endif
