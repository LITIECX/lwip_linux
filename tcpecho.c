#include "tcpecho.h"
#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/api.h"

/*-----------------------------------------------------------------------------------*/
void
tcpecho_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);

#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 7);
#else  /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, IP_ADDR_ANY, 7000);  //IP_ADDR_ANY 就是 0.0.0.0
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  netconn_listen(conn);
  while (1)
  {
    err = netconn_accept(conn, &newconn);
    printf("accepted new connection %p\n", newconn);
 
    if (err == ERR_OK)
    {
      struct netbuf *buf;
      void *data;
      u16_t len;

      while ((err = netconn_recv(newconn, &buf)) == ERR_OK)
      {
        printf("Recved\n");
        do
        {
          netbuf_data(buf, &data, &len);
          err = netconn_write(newconn, data, len, NETCONN_COPY);
          #if 0
                      if (err != ERR_OK) {
                        printf("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
                      }
          #endif
        } while (netbuf_next(buf) >= 0);
        netbuf_delete(buf);
      }
      netconn_close(newconn);
      netconn_delete(newconn);
    }
  }
}
/*-----------------------------------------------------------------------------------*/
void tcpecho_init(void)
{
  sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}
/*-----------------------------------------------------------------------------------*/
