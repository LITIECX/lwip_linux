#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define ser_ip "192.168.0.100"   //改为对方的ip
unsigned short portnum = 7000;

char data[]="hello cell";
int main(int argc, char **argv)
{
	int cfd;
	int recbyte;
	int sin_size;
	char buffer[1024] = {0};
	struct sockaddr_in s_add, c_add;
	printf("Hello,welcome to client!\r\n");
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == cfd)
	{
			printf("socket fail ! \r\n");
			return -1;
	}

	printf("socket ok !\r\n");

	bzero(&s_add,sizeof(struct sockaddr_in));
	s_add.sin_family=AF_INET;
	s_add.sin_addr.s_addr= inet_addr(ser_ip);
	s_add.sin_port=htons(portnum);
	//printf("s_addr = %#x ,port : %#x\r\n",s_add.sin_addr.s_addr,s_add.sin_port);
	if(-1 == connect(cfd,(struct sockaddr *)(&s_add), sizeof(struct sockaddr)))
	{
			printf("connect fail !\r\n");
			return -1;
	}
	printf("connect ok !\r\n");
	if(send(cfd,data,strlen(data),0)<0)
	{
		perror("send fail:");
	}
	while(1)
	{
			if(-1 == (recbyte = recv(cfd, buffer, 1024,0)))
			{
					printf("read data fail !\r\n");
					return -1;
			}
			printf("read ok\r\nREC:\r\n");
			 buffer[recbyte]='\0';
			 printf("%s\n",buffer);	
	}
	close(cfd);
	return 0;
}