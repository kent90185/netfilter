#ifndef NETFILTER_MYSTRUCT_H
#define NETFILTER_MYSTRUCT_H
#include <linux/workqueue.h>
#include <linux/spinlock.h>

/* print ip format*/
#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
     ((unsigned char *)&addr)[0], \
     ((unsigned char *)&addr)[1], \
     ((unsigned char *)&addr)[2], \
     ((unsigned char *)&addr)[3]
#endif

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

/* protocol chain */
    struct netinfo *protocol_next;

/* srcip and destip hash table chain */
    struct netinfo *srcip_next_same;
    struct netinfo *srcip_next_diff;
    struct netinfo *destip_next_same;
    struct netinfo *destip_next_diff;

/* workqueue struct */
    struct work_struct my_netinfo_job;
//    struct work_struct my_sort_job;
}net_info_node ;



#endif
