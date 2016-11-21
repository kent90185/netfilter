#ifndef NETFILTER_MYSTRUCT_H
#define NETFILTER_MYSTRUCT_H
#include <linux/workqueue.h>
/*********************** packet struct ******************************/
typedef struct netinfo
{
//    unsigned long time;//jiffy       
    int my_local_minu;
    int my_local_sec;
    unsigned int src_ip;
    unsigned int src_port;
    unsigned int dest_ip;
    unsigned int dest_port;
    char protocol;
    struct netinfo *protocol_next;
    struct netinfo *srcip_next_same;
    struct netinfo *srcip_next_diff;
    struct netinfo *destip_next_same;
    struct netinfo *destip_next_diff;
	struct work_struct my_netinfo_job;
}net_info_node ;


#endif
