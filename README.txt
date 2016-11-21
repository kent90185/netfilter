# A simple netfilter 
# Dump 100000 packets from kernel skb_buff
# Packet sort by source IP port 

# Usage: $0 [-h] [--help] [-srcip] [-destip] [-protocol]
# Version $SCRIPT_VERSION, by Riverwind Yeh
#  -h   --help          :this help"
#  -srcip  <IP>         : show source IP go through prerouting hook "
#  -destip <IP>         : show destination IP go through prerouting hook "
#  -protocol <TCP/UDP>  : show TCP or UDP packet go through prerouting hook "

