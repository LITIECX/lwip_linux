
#ifndef LWIPOPTS_H
#define LWIPOPTS_H


#define LWIP_IPV4                  1
#define NO_SYS                     0
#define LWIP_SOCKET                (NO_SYS==0)
#define LWIP_NETCONN               (NO_SYS==0)
#define LWIP_NETIF_API             (NO_SYS==0)

#define LWIP_TCPIP_CORE_LOCKING    0

#endif /* LWIP_LWIPOPTS_H */
