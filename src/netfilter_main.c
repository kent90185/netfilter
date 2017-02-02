/* 
* * file netfilter.c 
* 
* author Riverwind Yeh
* version 1.0.1 
* date 13Nov16 
* 
* history \arg 1.0.1, 13Nov16, Riverwind Yeh , fix kernel panic (kernel version 2.6->4.4)
*		  \arg 1.0.2, 20Nov16, Riverwind Yeh , add workqueue to sort hash table
* 
* \arg 1.0.0, 10Feb16, Riverwind Yeh , Create the file. 
*/

#define IP_TEST 1
#define PROTOCOL_TEST 1

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>

#include "include/netfilter_struct.h"

#if PROTOCOL_TEST
#include "include/netfilter_mergesort.h"
#endif

#if IP_TEST
#include "include/netfilter_srcip_hash.h"
#include "include/netfilter_destip_hash.h"
#endif

/********** MUTEX **********/
static DEFINE_MUTEX (lock);
static DEFINE_MUTEX (lock1);
static DEFINE_MUTEX (lock2);

/********** Debugfs Entry **********/
static struct dentry *dir = 0;
#if PROTOCOL_TEST
static struct dentry *debugfs_file_ptcl = 0;
static struct dentry *debugfs_file_ptclsearch = 0;
#endif
#if IP_TEST
static struct dentry *debugfs_file_srcip = 0;
static struct dentry *debugfs_file_srcipsearch = 0;
static struct dentry *debugfs_file_destip = 0;
static struct dentry *debugfs_file_destipsearch = 0;
#endif
/********** Real Time **********/
static struct timeval time;
unsigned long local_time;
static struct rtc_time tm;

/********** Protocol Tag **********/
char TCP_tag = 'T';
char UDP_tag = 'U';

/********** Hook Function **********/
static struct nf_hook_ops nfho;

/**************memory array*******************/

#define MAX_LIST_NUMBER 10000
net_info_node netinfo_list[MAX_LIST_NUMBER];
static unsigned int netinfo_list_number = 0;
/*******************************work queue init******************************************/

static struct workqueue_struct *queue_for_insert_hash = NULL;

/*************************packet list*************************************/
static net_info_node *my_netinfo_current = NULL;

static net_info_node *ptcl_TCP_head = NULL;
static net_info_node *ptcl_TCP_current = NULL;

static net_info_node *ptcl_UDP_head = NULL;
static net_info_node *ptcl_UDP_current = NULL;

static net_info_node *ptcl_search = NULL;

static net_info_node *srcip_search = NULL;

static net_info_node *destip_search = NULL;

/********************************************************************************/
void my_hash_insert (struct work_struct *my_netinfo_job)
{
	net_info_node *netinfohash = container_of (my_netinfo_job, net_info_node, my_netinfo_job)    ;
	mutex_lock(&lock1);
	srcip_hash_insert (netinfohash);
//	srcip_hash_search( netinfohash->src_ip );
	destip_hash_insert (netinfohash);
//	destip_hash_search( netinfohash->dest_ip );

	mutex_unlock(&lock1);
}

/*static unsigned int hook_func ( const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out, 
			int (*okfn) (struct sk_buff *) )*/
static unsigned int hook_func(void *priv,
             struct sk_buff *skb,
             const struct nf_hook_state *state)
{
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct iphdr *ip_header;

	if (!skb)
    {
    	return NF_ACCEPT;
    }

  	ip_header = (struct iphdr *) skb_network_header (skb);
  	if (!ip_header)
    {
      	return NF_ACCEPT;
    }

  	if (netinfo_list_number == MAX_LIST_NUMBER)
    {
//    	netinfo_list_number = 0 ;
      	return NF_ACCEPT;
    }


  	if ((IPPROTO_UDP == ip_header->protocol) || (IPPROTO_TCP == ip_header->protocol))
    {
//  	mutex_lock(&lock);
      	
		my_netinfo_current = &netinfo_list[netinfo_list_number];

      	do_gettimeofday (&time);
      	local_time = (u32) (time.tv_sec - (sys_tz.tz_minuteswest * 60));
      	rtc_time_to_tm (local_time, &tm);

      	if (IPPROTO_UDP == ip_header->protocol)
		{
	  		udp_header = (struct udphdr *) skb_transport_header (skb);
	  		my_netinfo_current->src_port =
	    	ntohs ((unsigned short int) udp_header->source);
	  		my_netinfo_current->dest_port =
	    	ntohs ((unsigned short int) udp_header->dest);
	  		my_netinfo_current->protocol = UDP_tag;
#if PROTOCOL_TEST
	  		ptcl_UDP_current = my_netinfo_current;
#endif
		}
      	else if (IPPROTO_TCP == ip_header->protocol)
		{
	  		tcp_header = (struct tcphdr *) skb_transport_header (skb);
	  		my_netinfo_current->src_port  = ntohs ((unsigned short int) tcp_header->source);
	  		my_netinfo_current->dest_port = ntohs ((unsigned short int) tcp_header->dest);
	  		my_netinfo_current->protocol = TCP_tag;
#if PROTOCOL_TEST
	  		ptcl_TCP_current = my_netinfo_current;
#endif
		}
      	my_netinfo_current->src_ip = ip_header->saddr;
      	my_netinfo_current->dest_ip = ip_header->daddr;

      	my_netinfo_current->protocol_next = NULL;
      	my_netinfo_current->srcip_next_same = NULL;
      	my_netinfo_current->srcip_next_diff = NULL;
      	my_netinfo_current->destip_next_same = NULL;
      	my_netinfo_current->destip_next_diff = NULL;
      	my_netinfo_current->my_local_minu = tm.tm_min;
      	my_netinfo_current->my_local_sec = tm.tm_sec;
#if PROTOCOL_TEST
      	if (IPPROTO_UDP == ip_header->protocol)
		{
	  		if (NULL == ptcl_UDP_head)
	   	 	{
	      		ptcl_UDP_head = ptcl_UDP_current;
	      		ptcl_UDP_current = NULL;
	    	}
	  		else
	    	{
	      		ptcl_UDP_current->protocol_next = ptcl_UDP_head;
	      		ptcl_UDP_head = ptcl_UDP_current;
	      		ptcl_UDP_current = NULL;
	    	}
		}

      	if (IPPROTO_TCP == ip_header->protocol)
		{
	  		if (NULL == ptcl_TCP_head)
	    	{
	      		ptcl_TCP_head = ptcl_TCP_current;
	      		ptcl_TCP_current = NULL;
	    	}
	  		else
	    	{
	      		ptcl_TCP_current->protocol_next = ptcl_TCP_head;
	      		ptcl_TCP_head = ptcl_TCP_current;
	      		ptcl_TCP_current = NULL;
	    	}
		}
#endif
//      mutex_unlock (&lock);

// queue_for inser hash
    	INIT_WORK (&(my_netinfo_current->my_netinfo_job), my_hash_insert);
    	queue_work (queue_for_insert_hash, &(my_netinfo_current->my_netinfo_job));

/*
#if IP_TEST
		srcip_hash_insert( my_netinfo_current );
		destip_hash_insert( my_netinfo_current );
#endif        
*/
    	printk ("[Riverwind]netinfo_list_number = %u , %d\n",netinfo_list_number, __LINE__);
      	++netinfo_list_number;
    }
  	return NF_ACCEPT;
}

#if PROTOCOL_TEST
//protocol ops
static char protocol_type[4];
static ssize_t protocol_write (struct file *file, const char __user * ubuf, size_t len, loff_t * pos)
{
 	if (copy_from_user (protocol_type, ubuf, min (len, sizeof (protocol_type))))
    {
      	printk (KERN_INFO "protocol_type error\n");
      	return -EFAULT;
    }
  	if (memcmp ("TCP", protocol_type, 1) == 0)
    {
      	ptcl_TCP_head = MergeSort (ptcl_TCP_head);
      	ptcl_search = ptcl_TCP_head;
    }
  	else if (memcmp ("UDP", protocol_type, 1) == 0)
    {
      	ptcl_UDP_head = MergeSort (ptcl_UDP_head);
      	ptcl_search = ptcl_UDP_head;
    }
  	else
    {
      	ptcl_search = NULL;
    }
  	return len;
}

static void *protocol_start (struct seq_file *s, loff_t * pos)
{
  	rcu_read_lock ();

  	//printk("ptcl_start\n");

  	return ptcl_search;
}

static int protocol_show (struct seq_file *s, void *v)
{
  	//printk("ptcl_show\n");
  	seq_printf (s,
	    	"%02d:%02d src_ip:" NIPQUAD_FMT ":%d	dest_ip:" NIPQUAD_FMT
	      	":%d	protocol:%c\n", ptcl_search->my_local_minu,
	      	ptcl_search->my_local_sec, NIPQUAD (ptcl_search->src_ip),
	      	ptcl_search->src_port, NIPQUAD (ptcl_search->dest_ip),
	      	ptcl_search->dest_port, ptcl_search->protocol);
  	return 0;
}

static void *protocol_next (struct seq_file *s, void *v, loff_t * pos)
{
  	//printk("ptcl_next\n");
  	ptcl_search = ptcl_search->protocol_next;
  	return ptcl_search;
}

static void protocol_stop (struct seq_file *s, void *v)
{
  	//printk("ptcl_stop\n");
  	rcu_read_unlock ();
}

static struct seq_operations protocol_sops = 
{
  	.start = protocol_start,
  	.next = protocol_next,
  	.show = protocol_show,
  	.stop = protocol_stop,
};

int	protocol_open (struct inode *inode, struct file *filp)
{
  	//printk("seq_open\n");
  	return seq_open (filp, &protocol_sops);
}

static const struct file_operations protocol_fops = 
{
  	.open = protocol_open,
  	.read = seq_read,
  	.llseek = seq_lseek,
  	.release = seq_release,
};

static const struct file_operations protocol_fops_write = 
{
  	.write = protocol_write,
};

// protocol ops end
#endif

#if IP_TEST
//srcip ops
static unsigned int
inet_addr (char *str)
{
  	int a, b, c, d;
  	char arr[4];
  	sscanf (str, "%d.%d.%d.%d", &a, &b, &c, &d);
  	arr[0] = a;
  	arr[1] = b;
  	arr[2] = c;
  	arr[3] = d;
  	return *(unsigned int *) arr;
}

static char srcip_type[16];
unsigned int srcip_tag;
static ssize_t
srcip_write (struct file *file, const char __user * ubuf, size_t len, loff_t * pos)
{
  	if (copy_from_user (srcip_type, ubuf, min (len, sizeof (srcip_type))))
    {
      	printk (KERN_INFO "srcip_type error\n");
      	return -EFAULT;
    }
	
  	srcip_tag = inet_addr (srcip_type);
  	srcip_bucket_check ();

  	printk ("srcip input = %s\n", srcip_type);
  	printk ("srcip_type = %u\n", srcip_tag);

    srcip_hash_search( srcip_tag );
  	srcip_search = srcip_hash_find (srcip_tag);
  	return len;
}

static void *srcip_start (struct seq_file *s, loff_t * pos)
{
  	rcu_read_lock ();

  	if (srcip_search == NULL)
    {
      	printk ("hash bucket is empty!\n");
      	return srcip_search;
    }
  // printk("srcip_start\n");

  	return srcip_search;
}

static int srcip_show (struct seq_file *s, void *v)
{
  	//printk("srcip_show\n");
  	if (!srcip_search)
    {
      	printk ("srcip_search is NULL \n");
      	return 0;
    }
  	seq_printf (s,
	      	"%02d:%02d src_ip:" NIPQUAD_FMT ":%d	dest_ip:" NIPQUAD_FMT
	      	":%d	protocol:%c\n", srcip_search->my_local_minu,
	      	srcip_search->my_local_sec, NIPQUAD (srcip_search->src_ip),
	      	srcip_search->src_port, NIPQUAD (srcip_search->dest_ip),
	      	srcip_search->dest_port, srcip_search->protocol);
  	return 0;
}

static void *srcip_next (struct seq_file *s, void *v, loff_t * pos)
{
  	//printk("srcip_next\n"); 

  	srcip_search = srcip_search->srcip_next_same;

 	return srcip_search;
}

static void srcip_stop (struct seq_file *s, void *v)
{
  	//printk("srcip_stop\n");

  	rcu_read_unlock ();
}

static struct seq_operations srcip_sops = 
{
  	.start = srcip_start,
  	.next = srcip_next,
  	.show = srcip_show,
  	.stop = srcip_stop,
};

int srcip_open (struct inode *inode, struct file *filp)
{
  	//printk("seq_open\n");
  	return seq_open (filp, &srcip_sops);
}

static const struct file_operations srcip_fops = 
{
  	.open = srcip_open,
  	.read = seq_read,
  	.llseek = seq_lseek,
  	.release = seq_release,
};

static const struct file_operations srcip_fops_write = 
{
  	.write = srcip_write,
};

//srcip ops end
//destip ops
static char destip_type[16];
unsigned int destip_tag;
static ssize_t destip_write(struct file *file, const char __user * ubuf, size_t len, loff_t * pos)
{
  	if (copy_from_user (destip_type, ubuf, min (len, sizeof (destip_type))))
    {
      	printk (KERN_INFO "destip_type error\n");
      	return -EFAULT;
    }

  	destip_tag = inet_addr (destip_type);
  	destip_bucket_check ();

  	printk ("destip input = %s\n", destip_type);
  	printk ("destip_type = %u\n", destip_tag);

	destip_hash_search( destip_tag );
	destip_search = destip_hash_find (destip_tag);
  	return len;
}

static void *destip_start (struct seq_file *s, loff_t * pos)
{
  	rcu_read_lock ();

  	if (destip_search == NULL)
    {
      	printk ("hash bucket is empty!\n");
      	return destip_search;
    }
  	//printk("destip_start\n");

  	return destip_search;
}

static int destip_show (struct seq_file *s, void *v)
{
  	//printk("destip_show\n");
  	if (!destip_search)
    {
     	printk ("destip_search is NULL \n");
      	return 0;
    }
  	seq_printf (s,
	      	"%02d:%02d src_ip:" NIPQUAD_FMT ":%d	dest_ip:" NIPQUAD_FMT
	      	":%d	protocol:%c\n", destip_search->my_local_minu,
	      	destip_search->my_local_sec, NIPQUAD (destip_search->src_ip),
	      	destip_search->src_port, NIPQUAD (destip_search->dest_ip),
	      	destip_search->dest_port, destip_search->protocol);
  	return 0;
}

static void *destip_next (struct seq_file *s, void *v, loff_t * pos)
{
  //printk("destip_next\n"); 

  	destip_search = destip_search->destip_next_same;
  	if (destip_search == NULL)
    {
      	return destip_search;
    }

  	return destip_search;
}

static void destip_stop (struct seq_file *s, void *v)
{
  	//printk("destip_stop\n");

  	rcu_read_unlock ();
}

static struct seq_operations destip_sops = 
{
  	.start = destip_start,
  	.next = destip_next,
  	.show = destip_show,
  	.stop = destip_stop,
};

int destip_open (struct inode *inode, struct file *filp)
{
  	//printk("seq_open\n");
  	return seq_open (filp, &destip_sops);
}

static const struct file_operations destip_fops = 
{
  	.open = destip_open,
  	.read = seq_read,
  	.llseek = seq_lseek,
  	.release = seq_release,
};

static const struct file_operations destip_fops_write = 
{
  	.write = destip_write,
};

//destip ops end

#endif
/////////////////////////////////////////////////////////////////////
static int __init init_main (void)
{
  	dir = debugfs_create_dir ("my_netfilter", 0);
  	if (!dir)
    {
      	printk (KERN_ALERT "create debugfs dir failed.");
      	return -1;
    }
#if PROTOCOL_TEST
//protocol    
  	debugfs_file_ptcl = debugfs_create_file ("protocol", 0664, dir, protocol_type, &protocol_fops_write);
  	if (!debugfs_file_ptcl)
    {
      	printk (KERN_ALERT "create protocol failed.");
      	return -1;
    }

  	debugfs_file_ptclsearch = debugfs_create_file ("protocol_search", 0664, dir, NULL, &protocol_fops);
  	if (!debugfs_file_ptclsearch)
    {
      	printk (KERN_ALERT "create protocol_search failed.");
      	return -1;
    }
#endif
#if IP_TEST
// srcip
 	debugfs_file_srcip =
    debugfs_create_file ("srcip", 0664, dir, srcip_type, &srcip_fops_write);
  	if (!debugfs_file_srcip)
    {
      	printk (KERN_ALERT "create srcip failed.");
      	return -1;
    }

  	debugfs_file_srcipsearch = debugfs_create_file ("srcip_search", 0664, dir, NULL, &srcip_fops);
  	if (!debugfs_file_srcipsearch)
    {
      	printk (KERN_ALERT "create srcip_search failed.");
      	return -1;
    }

// destip
  	debugfs_file_destip = debugfs_create_file ("destip", 0664, dir, destip_type, &destip_fops_write);
  	if (!debugfs_file_destip)
    {
      	printk (KERN_ALERT "create destip failed.");
      	return -1;
    }

  	debugfs_file_destipsearch = debugfs_create_file ("destip_search", 0664, dir, NULL, &destip_fops);
  	if (!debugfs_file_destipsearch)
    {
     	printk (KERN_ALERT "create destip_search failed.");
      	return -1;
    }
#endif
  	
	queue_for_insert_hash = create_singlethread_workqueue ("my job: queue for insert hash");


  /* hook NF_INET_PRE_ROUTING */
  	nfho.hook = hook_func;
  	nfho.hooknum = NF_INET_PRE_ROUTING;	//if kernel version < 2.6: NF_IP_PRE_ROUTING
  	nfho.pf = PF_INET;
  	nfho.priority = NF_IP_PRI_FIRST;

  	nf_register_hook (&nfho);
  	printk (KERN_INFO "[Riverwind]Successfully inserted a PRE_ROUTING hook into kernel\n");

  /*hash table */
#if IP_TEST
  	srcip_hash_init ();
  	destip_hash_init ();
#endif
  	return 0;
}

static void __exit cleanup_main (void)
{
  	nf_unregister_hook (&nfho);
#if PROTOCOL_TEST
  	ptcl_TCP_current = NULL;

  	ptcl_UDP_current = NULL;

  	ptcl_TCP_head = NULL;
  	ptcl_UDP_head = NULL;

  	debugfs_remove_recursive (debugfs_file_ptcl);
  	debugfs_remove_recursive (debugfs_file_ptclsearch);
#endif
#if IP_TEST
  	debugfs_remove_recursive (debugfs_file_srcip);
  	debugfs_remove_recursive (debugfs_file_srcipsearch);
  	debugfs_remove_recursive (debugfs_file_destip);
  	debugfs_remove_recursive (debugfs_file_destipsearch);
#endif
  	debugfs_remove_recursive (dir);
    
  	flush_workqueue( queue_for_insert_hash );
	printk (KERN_INFO "[Riverwind]flush_workqueue(queue_for_insert_hash)\n");
  	destroy_workqueue( queue_for_insert_hash );
  	printk (KERN_INFO "[Riverwind]destroy_workqueue( queue_for_insert_hash )\n");
	printk (KERN_INFO "[Riverwind]Successfully unloaded the hook PRE_ROUTING\n");
}

module_init (init_main);
module_exit (cleanup_main);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("Riverwind_Yeh");
MODULE_DESCRIPTION ("A simple netfilter Y@.<Y");

