//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-3-28
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#include <pthread.h>
#include "global.h"
#include "pri.h"
#include "time.h"
#include "avltree.h"
#include "sspcpr.h"

static char paramfile[128]  = "./param/a.param";
static char filename1[128]  = "./test/keyword1.txt";
static char filename2[128]  = "./test/keyword2.txt";
static char filename3[128]  = "./test/test.txt";
static pthread_mutex_t emutex;
static pthread_t    sthread[M], ethread[M];
static int          result[M];
static int          number;
static char*        cipher[M];

typedef struct enthread
{
  int num;              //total encryption times
  int gnum;				//current times
  int flag;             //thread
  int counter;          //counter of word
  char word[WORD_LEN];
  pri_pair* head;
  avl_handle* handle;
}enthread;

typedef struct scthread
{
  int flag;
  avl_handle* handle;
}scthread;

enthread* arr_enthd[M];
scthread* arr_scthd[M];

int cipher_cmp( void* a, void* b, size_t size )
{
	return memcmp( a, b, size );
}

static inline void print_infomation( void )
{
	puts( "Structured Searchable Public-key Ciphertexts for Parallel Retrieval" );
	puts( "Coding: Shuanghong he, CS School of HUST" );
	puts( "E-mail: 740310627@qq.com" );
}

static inline void print_operation( void )
{
	puts( "Please choose your operation!" );
	puts( "1. search keyword        2. encrypt one keyword" );
	puts( "3. encrypt for batch     4. encrypt by word frequency" );
  puts( "5. search testing        6. exit" );
}


static void* thread_encrrypt( void* enthd )
{
  pthread_mutex_lock( &emutex );
  ((enthread*)enthd)->gnum = number, number++;
  pthread_mutex_unlock( &emutex );
  while( ((enthread*)enthd)->gnum <= ((enthread*)enthd)->num )
  { 
     pthread_mutex_lock( &emutex );
     ((enthread*)enthd)->head = pri_pair_find( ((enthread*)enthd)->head, ((enthread*)enthd)->word );
     ((enthread*)enthd)->counter = ((enthread*)enthd)->head->counter;
     pthread_mutex_unlock( &emutex );
     cipher[((enthread*)enthd)->flag-1] = sspcpr_encrypt_new( ((enthread*)enthd)->counter, ((enthread*)enthd)->flag );
     pthread_mutex_lock( &emutex );
     avl_add( ((enthread*)enthd)->handle, cipher[((enthread*)enthd)->flag-1] );
     ((enthread*)enthd)->gnum = number, number++;
     pthread_mutex_unlock( &emutex );
  }
  return NULL;
}

static inline void thread_ewait( void )
{
  //wait all of the theads ending
  int i;
  for( i = 0; i < M; i++ )
  {
      if( ethread[i] )
      pthread_join( ethread[i], NULL );
    
  }
}

static inline void encryption_batch( const char* filename )
{
	FILE* fp;
	if( (fp = fopen( filename, "r" )) == NULL )
	{
		print_error();
		printf( "Open keyword file error!\n" );
		return;
	}
	char line[1024],word[WORD_LEN];
	int  i,num,temp;
  
    pthread_mutex_init(&emutex, NULL); // init mutex
	while( ( fgets( line, 1024, fp ) ) != NULL )
	{
		memset( word, 0, WORD_LEN );
		sscanf( line, "%s%d", word, &num );
        number = 1;
        sspcpr_map( word );
        memset( ethread, 0, sizeof(ethread));
   	for( i = 0; i < M; i++ )
    {
        memset( arr_enthd[i]->word, 0, WORD_LEN );
        strcpy( arr_enthd[i]->word, word );
        arr_enthd[i]->num = num;
        if( ( temp = pthread_create( &ethread[i], NULL, thread_encrrypt, (void*)arr_enthd[i] ) ) == 0 )
	    {
		  //print_debug();
		  //printf( "creat thread%d successfully!\n", i + 1 );
    	}
    }
       thread_ewait();
	   memset( line, 0, 1024 );
	}
  fclose(fp);
  pthread_mutex_destroy( &emutex ); // destroy mutex
}

static inline void encryption_frequency( const char* filename, int n )
{
	FILE* fp;
	if( (fp = fopen( filename, "r" )) == NULL )
	{
		print_error();
		printf( "Open keyword file error!\n" );
		return;
	}
	char line[1024],word[WORD_LEN];
	int  i,num,temp;
  float fre;
  
  pthread_mutex_init(&emutex, NULL); // init mutex
	while( ( fgets( line, 1024, fp ) ) != NULL )
	{
		memset( word, 0, WORD_LEN );
		sscanf( line, "%s%f", word, &fre );
    num = fre* n;
        number = 1;
        sspcpr_map( word );
        memset( ethread, 0, sizeof(ethread));
   	for( i = 0; i < M; i++ )
    {
        memset( arr_enthd[i]->word, 0, WORD_LEN );
        strcpy( arr_enthd[i]->word, word );
        arr_enthd[i]->num = num;
        if( ( temp = pthread_create( &ethread[i], NULL, thread_encrrypt, (void*)arr_enthd[i] ) ) == 0 )
	    {
		  //print_debug();
		  //printf( "creat thread%d successfully!\n", i + 1 );
    	}
    }
       thread_ewait();
	   memset( line, 0, 1024 );
	}
   fclose(fp);
   pthread_mutex_destroy( &emutex ); // destroy mutex
}

static void* thread_search( void* scthd )
{
  result[((scthread*)scthd)->flag-1] = sspcpr_search( ((scthread*)scthd)->flag, ((scthread*)scthd)->handle );
  return NULL;
}


static inline void thread_swait( void )
{
 //wait all of the theads ending
  int i;
  for( i = 0; i < M; i++ )
  {
      if( sthread[i] )
      pthread_join( sthread[i], NULL );
    
  }
}

static inline int getmax( int arr[], int n )
{
	int i,temp;
	temp = arr[0];
	for( i = 1; i < n; i++ )
	{
		if( temp < arr[i] )
			temp = arr[i];
	}
	return temp;
}

static inline int search( const char* word )
{
   sspcpr_trpdoor( word );
	//print_info();
	printf( "Generate trapdoor successfully!\n" );
	//print_info();
	printf( "Search is starting!\n" );
	int temp;
    memset( sthread, 0, sizeof(sthread));
    memset( result, 0, sizeof(result));
    set_time_stamp();
    int i;
    for( i = 0; i < M; i++ )
    {
       if( ( temp = pthread_create( &sthread[i], NULL, thread_search, (void*)arr_scthd[i] ) ) == 0 )
	   {
		  //print_debug();
		  //printf( "creat thread%d successfully!\n", i + 1 );
  	   }
   }
   thread_swait();
   get_time_usage();
   int ret = getmax( result, M );
   return ret;
}

static inline void search_test( const char* filename1, const char* filename2 )
{
  FILE* fp;
	if( (fp = fopen( filename1, "r" )) == NULL )
	{
		print_error();
		printf( "Open keyword file error!\n" );
	}
	char line[1024],word[WORD_LEN];

	while( ( fgets( line, 1024, fp ) ) != NULL )
	{
		memset( word, 0, WORD_LEN );
		sscanf( line, "%s", word );
    sspcpr_trpdoor( word );
  	int temp;
    memset( sthread, 0, sizeof(sthread));
    memset( result, 0, sizeof(result));
    set_time_stamp();
    int i;
    for( i = 0; i < M; i++ )
    {
       if( ( temp = pthread_create( &sthread[i], NULL, thread_search, (void*)arr_scthd[i] ) ) == 0 )
	     {
		  //print_debug();
		  //printf( "creat thread%d successfully!\n", i + 1 );
	     }
    }
    thread_swait();
    int ret = getmax( result, M );
    write_time_tofile( filename2, word, ret );
   }
}

int main( void )
{

  	print_infomation();
  	/*preparation*/  
    char* param = NULL;
    param = get_param( paramfile );
   
    /*setup*/
    sspcpr_setup( param );
        
    //print_info();
    printf( "Program is starting, please wait!\n" );
        
    /*initization*/
    sspcpr_init();
        
    int n = sspcpr_cipher_size();  //get the length of cipher
        
    pri_pair* head = pri_pair_init();
    avl_handle* handle = avl_init( n, cipher_cmp );
        
    int i;
    for( i = 0; i < M; i++ )
    {
        arr_enthd[i] = (enthread*)calloc( 1, sizeof( enthread ) );
        arr_enthd[i]->flag = i + 1;
        arr_enthd[i]->head = head;
        arr_enthd[i]->handle = handle;
        arr_scthd[i] = (scthread*)calloc( 1, sizeof( scthread ) );
        arr_scthd[i]->flag = i + 1;
        arr_scthd[i]->handle = handle;
    }  
	
    /*your operation*/
    print_operation();

    char word[WORD_LEN];
    int  ope,ret,k;
    scanf( "%d", &ope );
    while( ope != 6 )
    {
        if( ope == 1 )
        {
        	printf( "Please input keyword!\n" );
        	memset( word, 0, WORD_LEN );
        	scanf( "%s", word );
        	ret = search( (const char*)word );
        	printf( "\x1b[31m%d\x1b[0m ciphers have been found\n", ret );
        }
        else if( ope == 2 )
        {
        	printf( "Please input keyword!\n" );
        	scanf( "%s", word );
        	set_time_stamp();
		    	sspcpr_map( word );
        	sspcpr_encrypt( word, head, handle );
        	get_time_usage();
        	printf( "Encrypt %s successfully\n", word );
        }
        else if( ope == 3 )
        {
	  		  printf( "Encryption is starting, please wait!\n" );
        	set_time_stamp();
        	encryption_batch( filename1 );
        	get_time_usage();
		  	  printf( "Encrypt all of the words successfully!\n" );
 		    }
        else if( ope == 4 )
        {
	  		  printf( "Please input the total number of ciphers!\n" );
          scanf( "%d", &k);
          printf( "Encryption is starting, please wait!\n" );
        	set_time_stamp();
          encryption_frequency( filename2, k );
        	get_time_usage();
		  	  printf( "Encrypt all of the words successfully!\n" );
 		    }
        else if( ope == 5 )
        {
        	//remove( filename3 );
	  		  printf( "Generate test file, please wait!\n" );
        	search_test( filename2, filename3 );
		  	  printf( "Test is finished!\n" );
 		    }
	    	else
		    	printf( "Your input must be 1-6!\n" );

		memset( word, 0, WORD_LEN );
		print_operation();
		scanf( "%d", &ope );
	}
    /*exit*/
    sspcpr_free( head, handle );
    return 0;
}