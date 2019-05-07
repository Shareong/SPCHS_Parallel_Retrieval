//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-4-7
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#ifndef HEADER_SSPCPR_
#define HEADER_SSPCPR_

#include <pbc.h>
#include <pbc_test.h>

#define M   12  //the number of threads

typedef struct _public_key
{
	element_t g;
	element_t p;
} public_key;

typedef struct _param_key
{
	element_t sk;
	public_key pk;
} param_key;

typedef struct _struct_part
{
	element_t pri;
	element_t pub;
} struct_part;

extern char*  get_param( const char* path );

extern void   sspcpr_setup( const char* param_buff );

extern void   sspcpr_init( void );

extern void   sspcpr_map( const char* word );

extern void   sspcpr_encrypt( const char* word,
                                pri_pair* head, 
                                avl_handle* handle );
                                
extern char*  sspcpr_encrypt_new( int counter, int flag );   
                                 
extern void   sspcpr_trpdoor( const char* word );

extern int    sspcpr_search ( int flag, avl_handle* handle ); //flag[1-M] denotes the different thread

extern int    sspcpr_cipher_size( void );
    
extern void   sspcpr_free( pri_pair* head, avl_handle* handle );

#endif
