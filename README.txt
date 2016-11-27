# A simple netfilter 
# More than 2 cpu cores is prefered
# Dump 100000 sk_buff packets information kernel 
# Packet sort by  port 

# Usage: $0 [-h] [--help] [-srcip] [-destip] [-protocol]
# Version $SCRIPT_VERSION, by Riverwind Yeh
#  -h   --help          :this help"
#  -srcip  <IP>         : show source IP go through prerouting hook "
#  -destip <IP>         : show destination IP go through prerouting hook "
#  -protocol <TCP/UDP>  : show TCP or UDP packet go through prerouting hook "

