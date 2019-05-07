//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-3-29
//  Copyright (c) 2016 Render. All Rights Reserved.
//

#include "global.h"
#include "pri.h"

pri_pair* pri_pair_init( void )
{
        pri_pair* head;
	head = (pri_pair*)calloc( 1, sizeof( pri_pair ) );
	//print_info();
	printf( "pri_pair init successfully!\n" );
	return head;
}

/* Search (W, counter) for W in Pri.
 * If it is not found, set Counter = 1, insert (W, counter) to Pri.
 * Otherwise, counter++, update Pri.
 * Return head, and the vaule of current counter is stored in head.
 */
pri_pair* pri_pair_find( pri_pair* head, const char* word )
{
	pri_pair* prep;   // the previous pair
	pri_pair* npair;  // the next pair
	pri_pair* newp;   // the new pair
	if( head->next == NULL )
	{
		newp = (pri_pair*)calloc( 1, sizeof( pri_pair ) );
		newp->counter = 1;
		memcpy( newp->word, word, WORD_LEN );
		head->counter = newp->counter;
		head->next    = newp;
	}
	else 
	{       
		npair = head;
	        while( prep = npair, npair = npair->next )
	        {
			int cmp = memcmp( npair->word, word, WORD_LEN );
			if( cmp < 0 )
		        {
		        	if( npair->next == NULL )
		        	{
		        		newp = (pri_pair*)calloc( 1, sizeof( pri_pair ) );
		        		newp->counter = 1;
					memcpy( newp->word, word, WORD_LEN );
					head->counter = newp->counter;
					npair->next    = newp;
					break;
		        	}
		        }
		        else if( cmp == 0 ) // Word is found, and update pri.
		        {
		        	npair->counter ++;
		        	head->counter = npair->counter;
		        	break;
		        }
		        else
		        {
		        	newp = (pri_pair*)calloc( 1, sizeof( pri_pair ) );
		        	newp->counter = 1;
				memcpy( newp->word, word, WORD_LEN );
				head->counter = newp->counter;
				newp->next    = npair;
				prep->next    = newp;
				break;
			}
		}
	}
	return head;
}	

void  pri_pair_free( pri_pair* head )
{
	pri_pair *q;
	while( head )
	{
		q = head->next;
		free( head );
		head = q;
	}
	//print_info();
	printf( "Free pri_pair successfully!\n" );
}


