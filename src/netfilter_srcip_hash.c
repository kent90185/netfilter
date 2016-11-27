#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>

#define LE( a , b ) ( a >= b ) //a >= b

#define m 769 //numbers of hash bucket   http://planetmath.org/goodhashtableprimes 
#define EMPTY -1
#define OCCUPIED 1;

#include "include/netfilter_struct.h"
#include "include/netfilter_srcip_hash.h"

net_info_node *srcip_Divide( net_info_node *p )
{
    net_info_node *q , *r;
    q = p;
    r = p->srcip_next_same->srcip_next_same;

    while( r )
    {
        r = r->srcip_next_same;
        q = q->srcip_next_same;
        if( r )
        {
            r = r->srcip_next_same;
        }
    }
    r = q->srcip_next_same;
    q->srcip_next_same = NULL;
    return r;
}

net_info_node *srcip_Merge( net_info_node *p , net_info_node *q )
{
    net_info_node *head , *r;
    if( !p || !q )
    {
        printk(KERN_INFO" Merge called with empty list.");
    }

    if( LE( p->src_port, q->src_port ) )
    {
        head = p;
        p = p->srcip_next_same;
    }
    else
    {   
        head = q;
        q = q->srcip_next_same;
    }   

    r = head;
    while( p && q ) 
    {   
        if( LE( p->src_port, q->src_port ) ) 
        {
            r = r->srcip_next_same = p;
            p = p->srcip_next_same;
        }
        else
        {
            r = r->srcip_next_same = q;
            q = q->srcip_next_same ;
        }
    }

    if(p) 
    {
        r->srcip_next_same = p;
    }
    else
    {
        r->srcip_next_same = q;
    }
    return head ;
}

net_info_node *srcip_MergeSort( net_info_node *p )
{
    net_info_node *q;
    net_info_node *head = p ;

    if(p && p->srcip_next_same)
    {
        q = srcip_Divide( p );
        p = srcip_MergeSort( p );
        q = srcip_MergeSort( q );
        head =srcip_Merge( p , q );
    }

    return head;
}


// hash function , input key value 
int srcip_hash( unsigned int src_ip )
{
    return ( src_ip % m );
}

net_info_node srcip_table[m];

void srcip_hash_init(void)
{
    unsigned int i;
    for( i = 0 ; i < m ; ++i )
    {
        srcip_table[i].src_ip = EMPTY;
		srcip_table[i].srcip_next_same = NULL;
		srcip_table[i].srcip_next_diff = NULL;
    }
}

int srcip_list_insert_tail(unsigned int addr , net_info_node *srcipnode )
{
    net_info_node *p , *q , *r ;
    
    p=&srcip_table[addr];
    if( NULL == p->srcip_next_same )
    {   
        p->srcip_next_same = srcipnode ;
    }
    else  // p->srcip_next_same != NULL
    {
        q = p->srcip_next_same ;
		r = p->srcip_next_same ;
	
		if( q->src_ip == srcipnode->src_ip)
		{
	    	srcipnode->srcip_next_same = q->srcip_next_same ;
	    	q->srcip_next_same = srcipnode ;
		}
		else   // q->src_ip != srcipnode->src_ip 
		{
	    	while( NULL != q->srcip_next_diff )
            {
                r = q ;
                q = q->srcip_next_diff ;

                if( q->src_ip == srcipnode->src_ip )
                {
	            	srcipnode->srcip_next_same = q->srcip_next_same;
		    		q->srcip_next_same = srcipnode;

		    		break ;
                }
            }
            
	    	if( q->src_ip == srcipnode->src_ip )
	    	{
	        	srcipnode->srcip_next_same = q->srcip_next_same;
				q->srcip_next_same = srcipnode;
	    	}
	    	else
	    	{
                q->srcip_next_diff = srcipnode;
	    	}
        }
    }   
    return 0;
}

void srcip_hash_insert( net_info_node *srcipnode )
{
    unsigned int addr;

    addr = srcip_hash( srcipnode->src_ip );           //call hash function 
    if( srcip_table[addr].src_ip == EMPTY )
    {
        srcip_table[addr].src_ip = OCCUPIED;
        srcip_list_insert_tail( addr , srcipnode ); //if collision , create link list
    }
    else  //srcip_table[addr].src_ip == OCCUPIED
    {
		srcip_list_insert_tail( addr , srcipnode );
    }
}

net_info_node *srcip_hash_search( unsigned int srcip )
{
    unsigned int addr_search ;
    net_info_node *p , *q , *r;
    
    addr_search = srcip_hash( srcip );
    p = &srcip_table[ addr_search ]; 
    
//    printk("in hash addr = %u\n",addr_search);
    if( p->src_ip == EMPTY )
    {
        return NULL;
    }
    else
    {
        q = p->srcip_next_same;
		if( q->src_ip == srcip )
		{
            p->srcip_next_diff = q->srcip_next_diff;
	    	p->srcip_next_same = NULL ;
	    	q->srcip_next_diff = NULL ;
	    	q = srcip_MergeSort( q ) ;
	    	p->srcip_next_same = q;
	    	q->srcip_next_diff = p->srcip_next_diff;
	    	p->srcip_next_diff = NULL ;
	    	return q;
		}
		else // ( q->src_ip != srcip )
		{
	    	while( NULL != q )
	    	{
	        	r = q;
                q = q->srcip_next_diff;
 
				if( q->src_ip == srcip )
				{
                    r->srcip_next_diff = q->srcip_next_diff ;
		    		q->srcip_next_diff = NULL ;
		    		q = srcip_MergeSort(q);
		    		q->srcip_next_diff = r->srcip_next_diff;
		   			r->srcip_next_same = q;
		    		return q ;
				}
	    	}
            return q; 
		}
    }
}

net_info_node *srcip_hash_find( unsigned int srcip )
{
    unsigned int addr_search ;
    net_info_node *p , *q , *r;
    
    addr_search = srcip_hash( srcip );
    p = &srcip_table[ addr_search ]; 
    
//    printk("in hash addr = %u\n",addr_search);
    if( p->src_ip == EMPTY )
    {
        return NULL;
    }
    else
    {
        q = p->srcip_next_same;
		if( q->src_ip == srcip )
		{
	    	return q;
		}
		else // ( q->src_ip != srcip )
		{
	    	while( NULL != q )
	    	{
	        	r = q;
                q = q->srcip_next_diff;
 
				if( q->src_ip == srcip )
				{
		    		return q ;
				}
	    	}
            return q; 
		}
    }
}

int srcip_bucket_check( void )
{
    int i ;
    for(i = 0; i < m; ++ i)
    {
        if( srcip_table[i].src_ip != -1)
		{
	    	printk("bucket NO. %3d:%3d  ip = "NIPQUAD_FMT"\n", 
								i, 
								srcip_table[i].src_ip , 
								NIPQUAD(srcip_table[i].srcip_next_same->src_ip));
		}
    }
    return 0;
}

