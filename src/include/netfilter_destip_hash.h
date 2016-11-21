#ifndef _NETFILTER_DESTIP_H_
#define _NETFILTER_DESTIP_H_

#include "netfilter_struct.h"

net_info_node *destip_Divide( net_info_node *p );
net_info_node *destip_Merge( net_info_node *p , net_info_node *q );
net_info_node *destip_MergeSort( net_info_node *p );
int destip_hash( unsigned int src_ip );
void destip_hash_init(void);
int destip_list_insert_tail(unsigned int addr , net_info_node *destipnode );
void destip_hash_insert( net_info_node *destipnode );
net_info_node *destip_hash_search( unsigned int destip );
net_info_node *destip_hash_find( unsigned int destip );
int destip_bucket_check( void );


#endif
