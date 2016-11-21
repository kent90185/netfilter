#ifndef _NETFILTER_SRCIP_H_
#define _NETFILTER_SRCIP_H_

#include "netfilter_struct.h"

extern net_info_node *srcip_Divide( net_info_node *p );
extern net_info_node *srcip_Merge( net_info_node *p , net_info_node *q );
extern net_info_node *srcip_MergeSort( net_info_node *p );
extern int srcip_hash( unsigned int src_ip );
extern void srcip_hash_init(void);
extern int srcip_list_insert_tail(unsigned int addr , net_info_node *srcipnode );
extern void srcip_hash_insert( net_info_node *srcipnode );
extern net_info_node *srcip_hash_search( unsigned int srcip );
extern net_info_node *srcip_hash_find( unsigned int srcip );
extern int srcip_bucket_check( void );


#endif
