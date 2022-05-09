/* C runtime includes */
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

/* lwIP core includes */
#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/init.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/api.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "tcpecho.h"
#include "lwip/ip.h"
#include "default_netif.h"

ip4_addr_t ipaddr, netmask, gw;

static void
test_init(void *arg)
{ 
	LWIP_UNUSED_ARG(arg);
	sys_sem_t *init_sem;
	LWIP_ASSERT("arg != NULL", arg != NULL);
	init_sem = (sys_sem_t *)arg;
	srand((unsigned int)time(0));
	IP4_ADDR(&gw,192,168,0,1);
	IP4_ADDR(&ipaddr,192,168,0,100);
	IP4_ADDR(&netmask,255,255,255,0);
	init_default_netif(&ipaddr,&netmask,&gw); //启动网卡程序进程
	sys_sem_signal(init_sem);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	err_t err;
	sys_sem_t init_sem;
	err = sys_sem_new(&init_sem, 0);
	LWIP_ASSERT("failed to create init_sem", err == ERR_OK);
	LWIP_UNUSED_ARG(err);
	tcpip_init(test_init, &init_sem); //启动协议栈内核进程
	sys_sem_wait(&init_sem);
	sys_sem_free(&init_sem);
	tcpecho_thread(NULL);
	default_netif_shutdown();
	return 0;
}