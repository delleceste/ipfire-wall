# Loopback interface
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -i lo -j ACCEPT

# HTTP (TCP 80)
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

# DNS (UDP 53)
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# POP3 mail (TCP 110)
iptables -A OUTPUT -p tcp --dport 110 -m state --state NEW,ESTABLISHED -j ACCEPT

# SMTP mail (TCP 25)
iptables -A OUTPUT -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT

# FTP control (TCP 21) with connection tracking for FTP
iptables -A OUTPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT

# ICMP
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT

# HTTPS (TCP 443)
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# SSH out
iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
# SSH in
iptables -A INPUT  -p tcp --dport 22 -m state --state ESTABLISHED -j ACCEPT

# Unix printing (TCP 631)
iptables -A OUTPUT -p tcp --dport 631 -m state --state NEW,ESTABLISHED -j ACCEPT

# Generic TCP out
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT

# Generic UDP out
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT

# iperf3 traffic (TCP/UDP 5201)
iptables -A OUTPUT -p tcp --dport 5201 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -p tcp --dport 5201 -m state --state NEW,ESTABLISHED -j ACCEPT

