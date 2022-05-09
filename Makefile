LWIPDIR=/mnt/lwip-2.1.3/src
LWIPPPRT=/mnt/lwip-2.1.3/port

CFLAGS=-I/mnt/lwip-2.1.3 -I/mnt/lwip-2.1.3/src/include  \
		-I/mnt/lwip-2.1.3/port/include 


COREFILES=$(LWIPDIR)/core/init.c \
	$(LWIPDIR)/core/def.c \
	$(LWIPDIR)/core/dns.c \
	$(LWIPDIR)/core/inet_chksum.c \
	$(LWIPDIR)/core/ip.c \
	$(LWIPDIR)/core/mem.c \
	$(LWIPDIR)/core/memp.c \
	$(LWIPDIR)/core/netif.c \
	$(LWIPDIR)/core/pbuf.c \
	$(LWIPDIR)/core/raw.c \
	$(LWIPDIR)/core/stats.c \
	$(LWIPDIR)/core/sys.c \
	$(LWIPDIR)/core/altcp.c \
	$(LWIPDIR)/core/altcp_alloc.c \
	$(LWIPDIR)/core/altcp_tcp.c \
	$(LWIPDIR)/core/tcp.c \
	$(LWIPDIR)/core/tcp_in.c \
	$(LWIPDIR)/core/tcp_out.c \
	$(LWIPDIR)/core/timeouts.c \
	$(LWIPDIR)/core/udp.c

CORE4FILES=$(LWIPDIR)/core/ipv4/autoip.c \
	$(LWIPDIR)/core/ipv4/dhcp.c \
	$(LWIPDIR)/core/ipv4/etharp.c \
	$(LWIPDIR)/core/ipv4/icmp.c \
	$(LWIPDIR)/core/ipv4/igmp.c \
	$(LWIPDIR)/core/ipv4/ip4_frag.c \
	$(LWIPDIR)/core/ipv4/ip4.c \
	$(LWIPDIR)/core/ipv4/ip4_addr.c



# APIFILES: The files which implement the sequential and socket APIs.
APIFILES=$(LWIPDIR)/api/api_lib.c \
	$(LWIPDIR)/api/api_msg.c \
	$(LWIPDIR)/api/err.c \
	$(LWIPDIR)/api/if_api.c \
	$(LWIPDIR)/api/netbuf.c \
	$(LWIPDIR)/api/netdb.c \
	$(LWIPDIR)/api/netifapi.c \
	$(LWIPDIR)/api/sockets.c \
	$(LWIPDIR)/api/tcpip.c


# NETIFFILES: Files implementing various generic network interface functions
NETIFFILES=$(LWIPDIR)/netif/ethernet.c \
	$(LWIPDIR)/netif/bridgeif.c \
	$(LWIPDIR)/netif/bridgeif_fdb.c 

# NETIFFILES: Files implementing various generic network interface functions
NETIF=$(LWIPPPRT)/netif/tapif.c \
	$(LWIPPPRT)/perf.c \
	$(LWIPPPRT)/sys_arch.c 
# core.so:
# 	gcc $(CFLAGS)  -shared -fPIC -o core.so $(COREFILES) $(CORE4FILES)

main:
	gcc $(CFLAGS) -g -o main  main.c default_netif.c  \
	tcpecho.c  $(COREFILES) $(CORE4FILES) $(APIFILES) $(NETIFFILES) $(NETIF) -lpthread 
clean:
	rm -f main
.PHONY:clean