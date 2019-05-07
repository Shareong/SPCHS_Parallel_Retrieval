//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-4-7
//  Copyright (c) 2016 Render. All Rights Reserved.
//

#include "global.h"
#include "pri.h"
#include "avltree.h"
#include "sspcpr.h"
#include "time.h"

static param_key   psk;

static struct_part part;

static pairing_t   pairing;

static element_t  h;   
   
static element_t  hg;     //H(w)

static element_t  td;     //trapdoor

static element_t  zp[M+1];    //counter

static element_t  temp_l[M+1];

static element_t  temp_c[M+1]; //e(temp_l,P)

static element_t  c[M+1];      //cipher

static unsigned char* cipher[M+1];

static int CLEN;      //the length of cipher

char* get_param( const char* path )
{
	FILE* ret;
	if( (ret = fopen( path, "r" )) == NULL )
	{
		print_error();
		printf( "Open param file error!\n" );
		return NULL;
	}
	char *buff = NULL;
	buff = malloc(0);
	int count = 0, n = 0;
	do{
		buff = realloc( buff, count +512 );
		n = fread( buff+count, 1, 512, ret
		          );
		if( n < 0 )
		{
			print_error();
			printf( "Read param file error!\n" );
			return NULL;
		}
		count += n;
	}while( n == 512 );
   fclose(ret);
	//print_debug();
	//printf( "Get param successfully!\n" );
    return buff;
}

void   sspcpr_setup( const char* param_buff )
{
	/*init pairing from the string*/
	pairing_init_set_str( pairing, param_buff );
	
	/*generate system parameters*/
	element_init_G1( psk.pk.g, pairing );
	element_init_G1( psk.pk.p, pairing );
	element_init_Zr( psk.sk, pairing);
	
	element_random( psk.pk.g );  // generate generater g for G2
	//print_debug();
	//element_printf( "g = %B\n", psk.pk.g ); 
	
    element_random( psk.sk );     // generate sk a
    //print_debug();
	//element_printf( "sk = %B\n", psk.sk );
	
	element_pow_zn( psk.pk.p, psk.pk.g, psk.sk); // p = g^a
	//print_debug();
	//element_printf( "P = %B\n", psk.pk.p );
	
	//print_info();
	printf( "run setup successfully!\n" );

}

void sspcpr_init( void )
{
	int i;
	CLEN = pairing_length_in_bytes_GT( pairing ); 
  //printf( "CLEN = %d\n", CLEN );
 	element_init_Zr( part.pri, pairing ); //init (pri,pub)
	element_init_G1( part.pub, pairing );
	element_random( part.pri );
	element_pow_zn( part.pub, psk.pk.g, part.pri );
 
  element_init_G1( td, pairing );      //init mian trapdoor and H(w)
	element_init_G1( hg, pairing ); 
 
	/*init global variable*/
  element_init_G1( h, pairing );
	element_random( h );
	for( i = 0; i <= M; i++ )  
	{
		element_init_GT( c[i], pairing ); 
    element_init_GT( temp_c[i], pairing ); 
		element_init_G1( temp_l[i], pairing );
		element_init_Zr( zp[i], pairing );
		cipher[i] = (unsigned char*)malloc( CLEN );
	}
 
	//print_info();
	printf( "Run initization successfully!\n" );
}

void sspcpr_map( const char* word )
{
	element_from_hash( hg, (void*)word, strlen( word ) );
}

void sspcpr_encrypt( const char* word, pri_pair* head, avl_handle* handle )
{
	head = pri_pair_find( head, word );
	
	//print_debug();
	//printf( "counter = %d\n", head->counter );
	signed long int slong;
	slong = head->counter;
  element_set_si( zp[0], slong );
  element_pow_zn( temp_l[0], hg, zp[0] );
	
	/*generate cipher*/
	element_pairing( temp_c[0], temp_l[0], psk.pk.p );
	element_pow_zn( c[0], temp_c[0], part.pri );
	memset( cipher[0], 0 , CLEN );
	element_to_bytes( cipher[0], c[0] );
	avl_add( handle, cipher[0] );
}

extern char*  sspcpr_encrypt_new( int counter, int flag )
{
	signed long int slong;
	slong = counter;
	element_set_si( zp[flag], slong );
	element_pow_zn( temp_l[flag], hg, zp[flag] );
   
	/*generate cipher*/
  char* cipher = (char*)malloc( CLEN );
	element_pairing( temp_c[flag], temp_l[flag], psk.pk.p );
	element_pow_zn( c[flag], temp_c[flag], part.pri );
	element_to_bytes( (unsigned char*)cipher, c[flag] );
  return cipher;
}

extern void  sspcpr_trpdoor( const char* word )
{
	sspcpr_map( word );
	element_pow_zn( td, hg, psk.sk );	
	//print_debug();
	//printf( "generate trpdoor successfully!\n" );		
}


extern int  sspcpr_search( int flag, avl_handle* handle )
{
	int j,t;
	int result = 0;
	signed long int slong;
	
	for( j = 0;  ; j++ )
	{    
		t = j * M + flag;
		slong = t;
    element_set_si( zp[flag], slong );
    element_pow_zn( temp_l[flag], td, zp[flag] );
		
		/*generate cipher*/  
		element_pairing( c[flag], temp_l[flag], part.pub );
		memset( cipher[flag], 0 , CLEN );
		element_to_bytes( cipher[flag], c[flag] );
		
		if( avl_find( handle, cipher[flag] ) )
			result = t;
    else
	    break; 
	}
	return result;
}

int sspcpr_cipher_size( void )
{
	return pairing_length_in_bytes_GT( pairing );
}

extern void  sspcpr_free( pri_pair* head, avl_handle* handle )
{
  pri_pair_free( head );
  avl_free( handle );
  
	/*recover memory*/
  element_clear( psk.pk.g );
  element_clear( psk.pk.p );
  element_clear( psk.sk );
  element_clear( h );
	element_clear( part.pri );
	element_clear( part.pub );
  element_clear( td );
  element_clear( hg );
	
  int i;
	for( i = 0; i <= M; i++ )  
	{
		element_clear( c[i] );
		element_clear( zp[i] );
		element_clear( temp_l[i] );
 	  element_clear( temp_c[i] );
		free( cipher[i] );
	}
  pairing_clear( pairing );
  
  //print_info();
	printf( "Free sspcpr successfully!\n" );
}