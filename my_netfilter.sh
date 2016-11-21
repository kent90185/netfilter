#!/bin/bash

# A simple netfilter 
# Dump 100000 packets from kernel skb_buff
# Packet sort by port 

DEBUGFS_DIR=/sys/kernel/debug/my_netfilter
SCRIPT_VERSION=1.0

function show_help()
{
    echo " "
    echo " Usage: $0 [-h] [--help] [-srcip] [-destip] [-protocol]"
    echo " Version $SCRIPT_VERSION, by Riverwind Yeh"
    echo " "
    echo " -h   --help		:this help"
    echo " -srcip  <IP>		: show source IP go through prerouting hook "
    echo " -destip <IP>		: show destination IP go through prerouting hook "
    echo " -protocol <TCP/UDP> 	: show TCP or UDP packet go through prerouting hook "
    echo " "
}

function parse_args()
{
    local key="$1"
    shift
    #echo $KEY: $key

    case $key in
    
	-srcip)
        echo "$1" > ${DEBUGFS_DIR}/srcip
		cat ${DEBUGFS_DIR}/srcip_search
		exit 0
        ;;
	
	-destip)
		echo "$1" > ${DEBUGFS_DIR}/destip
        cat ${DEBUGFS_DIR}/destip_search
		exit 0
		;;

	-protocol)
		echo "$1" > ${DEBUGFS_DIR}/protocol
        cat ${DEBUGFS_DIR}/protocol_search
		exit 0
		;;

	-h|--help)
		show_help
		exit 0
		;;

	*)
		echo "Unknown option $key found..."
		show_help
        exit 0
		;;
	
    esac
}

# main
parse_args $*


