#include "include/netfilter_struct.h"
#include "include/netfilter_mergesort.h"
#define LE( a , b ) ( a >= b ) //a >= b

net_info_node *Divide( net_info_node *p )
{
    net_info_node *q , *r;
    q = p;
    r = p->protocol_next->protocol_next;

    while( r )
    {
        r = r->protocol_next;
	q = q->protocol_next;
	if( r )
	{
            r = r->protocol_next;
	}
    }
    r = q->protocol_next;
    q->protocol_next = NULL;
    return r;
}

net_info_node *Merge( net_info_node *p , net_info_node *q )
{
    net_info_node *head , *r;
    if( !p || !q )
    {
        printk(KERN_INFO" Merge called with empty list.");
    }

    if( LE( p->src_port, q->src_port ) )
    { 
        head = p;
	p = p->protocol_next;
    }
    else
    {
        head = q;
	q = q->protocol_next;
    }

    r = head;
    while( p && q )
    {
        if( LE( p->src_port, q->src_port ) )
	{
            r = r->protocol_next = p;
	    p = p->protocol_next;
	}
	else
	{
            r = r->protocol_next = q;
	    q = q->protocol_next;
	}
    }

    if(p)
    {
        r->protocol_next = p;
    }
    else
    {
        r->protocol_next = q;
    }

    return head;
}

net_info_node *MergeSort( net_info_node *p )
{
    net_info_node *q;
    net_info_node *head = p ;

    if(p && p->protocol_next)
    {
        q = Divide( p );
	p = MergeSort( p );
	q = MergeSort( q );
	head = Merge( p , q );
    }

    return head;
}

