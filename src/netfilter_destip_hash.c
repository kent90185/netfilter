#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>

#define LE( a , b ) ( a >= b ) //a >= b

#define m 769 //numbers of hash bucket   http://planetmath.org/goodhashtableprimes 
#define EMPTY -1
#define OCCUPIED 1;

#include "include/netfilter_struct.h"
#include "include/netfilter_destip_hash.h"

net_info_node *destip_Divide( net_info_node *p )
{
    net_info_node *q , *r;
    q = p;
    r = p->destip_next_same->destip_next_same;

    while( r )
    {
        r = r->destip_next_same;
        q = q->destip_next_same;
        if( r )
        {
            r = r->destip_next_same;
        }
    }
    r = q->destip_next_same;
    q->destip_next_same = NULL;
    return r;
}

net_info_node *destip_Merge( net_info_node *p , net_info_node *q )
{
    net_info_node *head , *r;
    if( !p || !q )
    {
        printk(KERN_INFO" Merge called with empty list.");
    }

    if( LE( p->dest_port, q->dest_port ) )
    {
        head = p;
        p = p->destip_next_same;
    }
    else
    {   
        head = q;
        q = q->destip_next_same;
    }   

    r = head;
    while( p && q ) 
    {   
        if( LE( p->dest_port, q->dest_port ) ) 
        {
            r = r->destip_next_same = p;
            p = p->destip_next_same;
        }
        else
        {
            r = r->destip_next_same = q;
            q = q->destip_next_same ;
        }
    }

    if(p) 
    {
        r->destip_next_same = p;
    }
    else
    {
        r->destip_next_same = q;
    }
    return head ;
}

net_info_node *destip_MergeSort( net_info_node *p )
{
    net_info_node *q;
    net_info_node *head = p ;

    if(p && p->destip_next_same)
    {
        q = destip_Divide( p );
        p = destip_MergeSort( p );
        q = destip_MergeSort( q );
        head =destip_Merge( p , q );
    }

    return head;
}


// hash function , input key value 
int destip_hash( unsigned int dest_ip )
{
    return ( dest_ip % m );
}

net_info_node destip_table[m];

void destip_hash_init(void)
{
    unsigned int i;
    for( i = 0 ; i < m ; ++i )
    {
        destip_table[i].dest_ip = EMPTY;
	destip_table[i].destip_next_same = NULL;
	destip_table[i].destip_next_diff = NULL;
    }
}

int destip_list_insert_tail(unsigned int addr , net_info_node *destipnode )
{
    net_info_node *p , *q , *r ;
    
    p=&destip_table[addr];
    if( NULL == p->destip_next_same )
    {   
        p->destip_next_same = destipnode ;
    }
    else  // p->destip_next_same != NULL
    {
        q = p->destip_next_same ;
	r = p->destip_next_same ;
	
	if( q->dest_ip == destipnode->dest_ip)
	{
	    destipnode->destip_next_same = q->destip_next_same ;
	    q->destip_next_same = destipnode ;
	}
	else   // q->dest_ip != destipnode->dest_ip 
	{
	    while( NULL != q->destip_next_diff )
            {
                r = q ;
                q = q->destip_next_diff ;

                if( q->dest_ip == destipnode->dest_ip )
                {
	            destipnode->destip_next_same = q->destip_next_same;
		    q->destip_next_same = destipnode;

		    break ;
                }
            }
            
	    if( q->dest_ip == destipnode->dest_ip )
	    {
	        destipnode->destip_next_same = q->destip_next_same;
		q->destip_next_same = destipnode;
	    }
	    else
	    {
                q->destip_next_diff = destipnode;
	    }
        }
    }   
    return 0;
}

void destip_hash_insert( net_info_node *destipnode )
{
    unsigned int addr;

    addr = destip_hash( destipnode->dest_ip );           //call hash function 
    if( destip_table[addr].dest_ip == EMPTY )
    {
        destip_table[addr].dest_ip = OCCUPIED;
        destip_list_insert_tail( addr , destipnode ); //if collision , create link list
    }
    else  //destip_table[addr].dest_ip == OCCUPIED
    {
	destip_list_insert_tail( addr , destipnode );
    }
}

net_info_node *destip_hash_search( unsigned int destip )
{
    unsigned int addr_search ;
    net_info_node *p , *q , *r;
    
    addr_search = destip_hash( destip );
    p = &destip_table[ addr_search ]; 
    
//    printk("in hash addr = %u\n",addr_search);
    if( p->dest_ip == EMPTY )
    {
        return NULL;
    }
    else
    {
        q = p->destip_next_same;
	if( q->dest_ip == destip )
	{
            p->destip_next_diff = q->destip_next_diff;
	    p->destip_next_same = NULL ;
	    q->destip_next_diff = NULL ;
	    q = destip_MergeSort( q ) ;
	    p->destip_next_same = q;
	    q->destip_next_diff = p->destip_next_diff;
	    p->destip_next_diff = NULL ;
	    return q;
	}
	else // ( q->dest_ip != destip )
	{
	    while( NULL != q )
	    {
	        r = q;
                q = q->destip_next_diff;
 
		if( q->dest_ip == destip )
		{
                    r->destip_next_diff = q->destip_next_diff ;
		    q->destip_next_diff = NULL ;
		    q = destip_MergeSort(q);
		    q->destip_next_diff = r->destip_next_diff;
		    r->destip_next_same = q;
		    return q ;
		}
	    }
            return q; 
	}
    }
}

net_info_node *destip_hash_find( unsigned int destip )
{
    unsigned int addr_search ;
    net_info_node *p , *q , *r;
    
    addr_search = destip_hash( destip );
    p = &destip_table[ addr_search ]; 
    
//    printk("in hash addr = %u\n",addr_search);
    if( p->dest_ip == EMPTY )
    {
        return NULL;
    }
    else
    {
        q = p->destip_next_same;
		if( q->dest_ip == destip )
		{
	    	return q;
		}
		else // ( q->dest_ip != destip )
		{
	    	while( NULL != q )
	    	{
	        	r = q;
                q = q->destip_next_diff;
 
				if( q->dest_ip == destip )
				{
		    		return q ;
				}
	    	}
        	return q; 
		}
    }
}

int destip_bucket_check( void )
{
    int i ;
    for(i = 0; i < m; ++ i)
    {
        if( destip_table[i].dest_ip != -1)
	{
	    printk("bucket NO. %3d:%3d  ip = "NIPQUAD_FMT"\n",
	           i,
	           destip_table[i].dest_ip , NIPQUAD(destip_table[i].destip_next_same->dest_ip)
		  );
	}
    }
    return 0;
}

