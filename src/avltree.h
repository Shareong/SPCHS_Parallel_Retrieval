//
//  Structured Searchable Public-key Ciphertexts for Parallel Retrieval
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-3-28
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#ifndef HEADER_AVLTREE_
#define HEADER_AVLTREE_

#define PRE_TRS 0 // pre  order traverse
#define MID_TRS 1 // mid  order traverse
#define BCK_TRS 2 // back order traverse

#define max_int(a, b) ((a)>(b) ? (a) : (b))

/* tree node */
typedef struct _avl_node
{
	struct _avl_node* left;
	struct _avl_node* right;
	struct _avl_node* parent;
	int               height; // height of node, used to balance the avl tree
	void*             data;   // point to the buffer where data is stored
} avl_node;

typedef int  (*_avl_cmp) (void*, void*, size_t); // data compare function
typedef void (*_avl_trs) (void*, int  ); // tree traverse function

/* tree handle */
typedef struct _avl_Handle
{
	avl_node* root;      // tree root node
	size_t    data_size; // data buffer size
	_avl_cmp  avl_cmp;   // data compare function
} avl_handle;

extern avl_handle* avl_init    ( size_t data_size, _avl_cmp acmp );
extern void        avl_free    ( avl_handle* handle );
extern int         avl_add     ( avl_handle* handle, void* data );
extern int         avl_delete  ( avl_handle* handle, void* key );
extern void*       avl_find    ( avl_handle* handle, void* key );
extern void        avl_traverse( avl_handle* handle, int order, _avl_trs avl_trs );

#endif
