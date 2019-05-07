//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-3-28
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#include <stdlib.h>
#include <string.h>
#include "global.h"
#include "avltree.h"

/* create a new avl tree node
 * if success, return newly created node
 * else      , return NULL
 */
static inline avl_node* avl_new( avl_handle* handle,
								 avl_node* parent, void* data )
{
	// allocate node and data buffer together
	avl_node* an = calloc( 1, sizeof(avl_node) + handle->data_size );
	if( an == 0 ) return 0;
	if( parent )
	{
		if( handle->avl_cmp(data, parent->data, handle->data_size) < 0 )
			parent->left  = an;
		else
			parent->right = an;
		an->parent = parent;
	}
	else
	{
		handle->root = an;
	}
	// let data pointer points to data buffer
	an->data = (char*) an + sizeof(avl_node);
	memcpy( an->data, data, handle->data_size );

	return an; // success
}

/* delete a avl tree node
 * without rebalancing tree or recalculate height
 * return the parent of truely deleted node
 * the return value is used to rebalance tree and recaluculate height
 */
static inline avl_node* avl_remove( avl_handle* handle, avl_node* target )
{
	avl_node* tgt_prt = target->parent;
	// `d`elete `p`arent ~ parent of real deleted node
	avl_node* dlt_prt = target->parent;
	// the node whose key value is closest to target node
	avl_node* closest;

	if( target->left == 0 && target->right == 0 ) // delete a leaf
	{
		if( dlt_prt->left == target )
			dlt_prt->left  = 0;
		else
			dlt_prt->right = 0;
		free( target );
	}
	else if( target->left == 0 && target->right != 0 )
	{
		closest = target->right;
		if( tgt_prt->left == target )
			tgt_prt->left  = closest;
		else
			tgt_prt->right = closest;
		closest->parent = tgt_prt;
		free( target );
	}
	else if( target->left != 0 && target->right == 0 )
	{
		closest = target->left;
		if( tgt_prt->left == target )
			tgt_prt->left  = closest;
		else
			tgt_prt->right = closest;
		closest->parent = tgt_prt;
		free( target );
	}
	else
	{
		if( target->left->height > target->right->height )
		{	// use left closest `data` node to replace target node
			/* find the closest `data` node */
			// now dlt_prt represents the node to be truely deleted
			dlt_prt = target->left;
			while( dlt_prt && dlt_prt->right )
				dlt_prt = dlt_prt->right;
			memcpy( target->data, dlt_prt->data, handle->data_size );

			// now dlt_prt has its original meaning
			dlt_prt = dlt_prt->parent;
			if( dlt_prt == target )
			{
				closest = dlt_prt->left->left;
				free( dlt_prt->left );
				dlt_prt->left = closest;
				if( closest )
					closest->parent = dlt_prt;
			}
			else
			{
				closest = dlt_prt->right->left;
				free( dlt_prt->right );
				dlt_prt->right = closest;
				if( closest )
					closest->parent = dlt_prt;
			}
		}
		else
		{	// use right closest `data` node to replace target node
			/* find the closest `data` node */
			// now dlt_prt represents the node to be truely deleted
			dlt_prt = target->right;
			while( dlt_prt && dlt_prt->left )
				dlt_prt = dlt_prt->left;
			memcpy( target->data, dlt_prt->data, handle->data_size );

			// now dlt_prt has its original meaning
			dlt_prt = dlt_prt->parent;
			if( dlt_prt == target )
			{
				closest = dlt_prt->right->right;
				free( dlt_prt->right );
				dlt_prt->right = closest;
				if( closest )
					closest->parent = dlt_prt;
			}
			else
			{
				closest = dlt_prt->left->right;
				free( dlt_prt->left );
				dlt_prt->left = closest;
				if( closest )
					closest->parent = dlt_prt;
			}
		}
	}

	if( dlt_prt )
		return dlt_prt;
	else
		return handle->root;
}

/* search in avltree with `key`
 * if found, param `node` contians the node found
 * else    , param `node` contains the node which has the closest `key` value
 * if found, reutrn 1
 * else    , return 0
 */
static int avl_search( avl_handle* handle, avl_node** node, void* key )
{
	int compare;
	avl_node* an = handle->root;
	avl_node* history = 0;

	while( an )
	{
		history = an;
		compare = handle->avl_cmp( key, an->data, handle->data_size);
		if( compare < 0 )
			an = an->left;
		else if( compare > 0 )
			an = an->right;
		else
			break;
	}

	if( an )
	{
		*node = an;
		return 1; // find the node with value `key`
	}
	else
	{
		*node = history; // the closest node compared with `key`
		return 0; // not find
	}
}

/* calulate the height of node `node`
 * if( `once` ), just calculate the node `node` itself
 * else        , calculate `node` and its parents up to root
 */
static void avl_height( avl_node* node, int once )
{
	int left_height, right_height;

	do
	{
		if( node->left )
			left_height  = node->left->height;
		else
			left_height  = 0;
		if( node->right )
			right_height = node->right->height;
		else
			right_height = 0;

		node->height = max_int( left_height, right_height ) + 1;

		node = node->parent;
		if( once ) break;
	}
	while( node );
}

static inline avl_node* avl_rotate_right( avl_handle* handle, avl_node* n1 )
{
	int left_height, right_height;
	avl_node* root = n1->parent;
	avl_node* n2   = n1->left;
	avl_node* n3   = n2->right;

	if( n2->left )
		left_height  = n2->left->height;
	else
		left_height  = 0;
	if( n2->right )
		right_height = n2->right->height;
	else
		right_height = 0;

	if( left_height >= right_height )
	/* single right rotation
	 *
	 *         n1         n2
	 *        /          /  \
	 *       n2   =>   new   n1
	 *      /  \            /
	 *    new  (n3)        n3
	 */
	{
		n2->right  = n1;
		n1->parent = n2;
		n1->left   = n3;
		if( n3 )
			n3->parent = n1;

		if( root )
		{
			if( root->left == n1 )
				root->left  = n2;
			else
				root->right = n2;
		}
		else
		{
			handle->root = n2;
		}
		n2->parent = root;

		/* rebuild height */
		avl_height( n1, 0 );

		return n2;
	}
	else
	/* left rotation then right rotation
	 *
	 *         n1        n1        n3
	 *        /         /         /  \
	 *       n2   =>   n3   =>   n2   n1
	 *         \      /
	 *       n3(new) n2
	 */
	{
		n2->right = n3->left ;
		if( n3->left )
			n3->left->parent  = n2;
		n1->left  = n3->right;
		if( n3->right )
			n3->right->parent = n1;
		n3->left   = n2;
		n2->parent = n3;
		n3->right  = n1;
		n1->parent = n3;

		if( root )
		{
			if( root->left == n1 )
				root->left  = n3;
			else
				root->right = n3;
		}
		else
		{
			handle->root = n3;
		}
		n3->parent = root;

		/* rebuild height */
		avl_height( n1, 1 );
		avl_height( n2, 0 );

		return n3;
	}
}

static inline avl_node* avl_rotate_left( avl_handle* handle, avl_node* n1 )
{
	int left_height, right_height;
	avl_node* root = n1->parent; // subtree root
	avl_node* n2   = n1->right;
	avl_node* n3   = n2->left;

	if( n2->left )
		left_height  = n2->left->height;
	else
		left_height  = 0;
	if( n2->right )
		right_height = n2->right->height;
	else
		right_height = 0;

	if( right_height >= left_height )
	/* single left rotation
	 *
	 *    n1             n2
	 *      \           /  \
	 *       n2   =>   n1  new
	 *      /  \         \
	 *    (n3) new        n3
	 */
	{
		n2->left   = n1;
		n1->parent = n2;
		n1->right  = n3;
		if( n3 )
			n3->parent = n1;

		if( root )
		{
			if( root->left == n1 )
				root->left  = n2;
			else
				root->right = n2;
		}
		else
		{
			handle->root = n2;
		}
		n2->parent = root;

		/* rebuild height */
		avl_height( n1, 0 );

		return n2;
	}
	else
	/* right rotation then left rotation
	 *
	 *   n1        n1             n3
	 *     \         \           /  \
	 *      n2   =>   n3   =>   n1   n2
	 *     /         /
	 *  n3(new)     n2
	 */
	{
		n2->left  = n3->right;
		if( n3->right )
			n3->right->parent = n2;
		n1->right = n3->left ;
		if( n3->left)
			n3->left->parent  = n1;
		n3->left   = n1;
		n1->parent = n3;
		n3->right  = n2;
		n2->parent = n3;

		if( root )
		{
			if( root->left == n1 )
				root->left  = n3;
			else
				root->right = n3;
		}
		else
		{
			handle->root = n3;
		}
		n3->parent = root;

		/* rebuild height */
		avl_height( n1, 1 );
		avl_height( n2, 0 );

		return n3;
	}
}

/* balance the avl tree using `rotate method`
 * the procedure begin with node `an` and up to root
 * if( `once` ), just balance the tree for once and return
 * else        , balance `an` and its parent up to root if necessary
 * param `once` is set when insert a node to tree
 * param `once` is unset when delete a node in tree
 */
static void avl_balance( avl_handle* handle, avl_node* an, int once )
{
	int left_height, right_height;
	int balance;

	do
	{
		if( an->left )
			left_height  = an->left->height;
		else
			left_height  = 0;
		if( an->right )
			right_height = an->right->height;
		else
			right_height = 0;

		balance = left_height - right_height;
		if( balance >  1 )
		{
			an = avl_rotate_right(handle, an);
			if( once ) break;
		}
		if( balance < -1 )
		{
			an = avl_rotate_left (handle, an);
			if( once ) break;
		}

		an = an->parent;
	}
	while( an );
}

/* pre order traverse */
static void avl_pre_trs( avl_node* an, int level, _avl_trs avl_trs )
{
	if( an )
	{
		avl_trs( an->data, level );
		avl_pre_trs( an->left , level+1, avl_trs );
		avl_pre_trs( an->right, level+1, avl_trs );
	}
	else
	{
		avl_trs( 0, level );
	}
}

/* mid order traverse */
static void avl_mid_trs( avl_node* an, int level, _avl_trs avl_trs )
{
	if( an )
	{
		avl_mid_trs( an->left , level+1, avl_trs );
		avl_trs( an->data, level );
		avl_mid_trs( an->right, level+1, avl_trs );
	}
	else
	{
		avl_trs( 0, level );
	}
}

/* back order traverse */
static void avl_bck_trs( avl_node* an, int level, _avl_trs avl_trs )
{
	if( an )
	{
		avl_bck_trs( an->left , level+1, avl_trs );
		avl_bck_trs( an->right, level+1, avl_trs );
		avl_trs( an->data, level );
	}
	else
	{
		avl_trs( 0, level );
	}
}

/* init the tree handle */
avl_handle* avl_init( size_t data_size, _avl_cmp acmp )
{
	avl_handle* ah = calloc( 1, sizeof(avl_handle) );
	if( ah == 0 ) return 0;

	ah->data_size = data_size;
	ah->avl_cmp   = acmp;
	return ah;
}

/* free the tree and tree handle */
void avl_free( avl_handle* handle )
{
	avl_node* parent = 0;
	avl_node* target = 0;

	/* delete nodes in avl tree */
	if( handle->root )
	{
		target = handle->root;
		while( target )
		{
			if( target->left )
			{
				parent = target;
				target = target->left;
			}
			else if( target->right )
			{
				parent = target;
				target = target->right;
			}
			else
			{
				if( parent )
				{
					if( parent->left == target )
						parent->left = 0;
					else
						parent->right = 0;
					free( target );
				}
				else
				{
					free( target );
				}
				target = parent;
				if( parent )
					parent = parent->parent;
			}
		}
	}
	/* delete avl handle */
	free( handle );
	//print_info();
	printf( "Free avltree successfully!\n" );
}

/* add `data` to tree */
int avl_add( avl_handle* handle, void* data )
{
	avl_node* an;
	avl_node* closest; // the node which carries closest value to `data`

	if( avl_search(handle, &closest, data) )
	{
		return 0; // `data` already exist in tree
	}
	else
	{
		an = avl_new( handle, closest, data );
		if( an == 0 ) return 0;
		avl_height( an, 0 );
		if( an->parent && an->parent->parent )
			avl_balance( handle, an->parent->parent, 1 );
		return 1;
	}
}

/* delete a node has value `key` */
int avl_delete( avl_handle* handle, void* key )
{
	avl_node* parent; // parent of the truely deleted node
	avl_node* target; // the node has the value `key`

	if( avl_search(handle, &target, key) )
	{
		parent = avl_remove( handle, target );
		if( parent ) // target node is not root
		{
			avl_height( parent, 0 );
			avl_balance( handle, parent, 0 );
		}
		return 1;
	}
	else
	{
		return 0; // data not exists
	}
}

/* find the node has value `key`
 * return the `data` buffer in the tree node
 */
void* avl_find( avl_handle* handle, void* key )
{
	avl_node* target;
	if( avl_search(handle, &target, key) )
		return target->data;
	else
		return 0;
}

/* traverse the tree
 * param `order` represent traverse order
 * param `avl_trs` represent the function used to handle data in each node
 */
void avl_traverse( avl_handle* handle, int order, _avl_trs avl_trs )
{
	avl_node* an = handle->root;
	switch( order )
	{
		case PRE_TRS:
			avl_pre_trs( an, 0, avl_trs );
			break;
		case MID_TRS:
			avl_mid_trs( an, 0, avl_trs );
			break;
		case BCK_TRS:
			avl_bck_trs( an, 0, avl_trs );
		default:
			break;
	}
}
