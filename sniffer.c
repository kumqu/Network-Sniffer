#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* 以太网头部14个字节 */
#define SIZE_ETHERNET 14

/* 以太网地址6个字节 */
#define ETHER_ADDR_LEN 6

#define TCP_FLAG   0
#define UDP_FLAG   1
#define MYIP "192.168.253.134"

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)


struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct sniff_udp {
    uint16_t sport;       /* source port */
    uint16_t dport;       /* destination port */
    uint16_t udp_length;
    uint16_t udp_sum;     /* checksum 检验和 */
};

typedef unsigned long tcp_seq;
struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
    u_char  th_flags;
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};


void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);


int main()
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;

    //获取网络设备
    devStr = pcap_lookupdev(errBuf);
    if(devStr)
    {
        printf("success: device: %s\n", devStr);
    }
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }

    //打开网络设备
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    if(!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }

    //过滤数据包(tcp和udp)
    struct bpf_program filter;
    pcap_compile(device, &filter, "tcp || udp", 1, 0);
    pcap_setfilter(device, &filter);

    //等待接收数据包
    int id = 0;
    pcap_loop(device, -1, getPacket, (u_char*)&id);

    //关闭设备
    pcap_close(device);

    return 0;
}

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
    int j;

    struct sniff_ethernet *ethernet;        /* 以太网头部 */
    struct sniff_ip *ip;                    /* IP 头部    */
    struct sniff_tcp *tcp;                  /* TCP 头部   */
    struct sniff_udp *udp;                  /* UDP 头部   */
    unsigned char *payload;                 /* Packet payload */
    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;

    int proto_flag = 2;                     // 0=TCP_FLAG; 1=UDP_FLAG

    printf("\nPacket number: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    /* 定义以太网头部 */
    ethernet = (struct sniff_ethernet*)(packet);
    /* 定义/计算 IP 头部偏移 */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;              // ip头部长度
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    //打印MAC地址
    u_char *ptr;
    ptr = ethernet->ether_dhost;
    printf("Dst MAC addr: ");
    j = ETHER_ADDR_LEN;
    do{
        printf("%s%x",(j == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--j>0);
    printf("\n");

    ptr = ethernet->ether_shost;
    printf("Src MAC addr: ");
    j = ETHER_ADDR_LEN;
    do{
        printf("%s%x",(j == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--j>0);

    printf("\n==============================================\n");


    /* 显示源IP和目的IP     print source and destination IP addresses */
    // only print internet->me information
    if(strcmp(inet_ntoa(ip->ip_src), MYIP) == 0)
        return;

    /* 确定协议 determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:       //useful
            printf("Protocol: TCP\n");
            proto_flag=0;
            break;
        case IPPROTO_UDP:       //useful
            printf("Protocol: UDP\n");
            proto_flag=1;
            break;
        case IPPROTO_IP:        //useful
            printf("Protocol: IP\n");
            return;
        default:
            printf("Protocol: unknown\n");
            return;
    }

//This packet is TCP.
    if (proto_flag == 0) {
        /* 定义/计算 TCP 头部偏移 */
        tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
        printf("Src ip: %s\n", inet_ntoa(ip->ip_src));
        printf("Dst ip: %s\n", inet_ntoa(ip->ip_dst));
        printf ("Src port  : %d\n", ntohs (tcp->th_sport));
        printf ("Dst port  : %d\n", ntohs (tcp->th_dport));

        payload = (unsigned char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
        size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
    }

//This packet is UDP.
    else if (proto_flag == 1) {
      /* define/compute udp header offset */
        udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);
        printf("Src ip: %s\n", inet_ntoa(ip->ip_src));
        printf("Dst ip: %s\n", inet_ntoa(ip->ip_dst));
        printf ("Src port: %d\n", ntohs (udp->sport));
        printf ("Dst port: %d\n", ntohs (udp->dport));

        payload = (unsigned char *) (packet + SIZE_ETHERNET + size_ip + 8);
        size_payload = ntohs (ip->ip_len) - (size_ip + 8);
    }

    print_payload(payload,size_payload);

    printf("\n\n");
}




void print_payload(const u_char *payload, int len)
{

 int len_rem = len;
 int line_width = 16;   /* number of bytes per line */
 int line_len;
 int offset = 0;     /* zero-based offset counter */
 const u_char *ch = payload;

 if (len <= 0)
  return;

 /* data fits on one line */
 if (len <= line_width) {
  print_hex_ascii_line(ch, len, offset);
  return;
 }

 /* data spans multiple lines */
 for ( ;; ) {
  /* compute current line length */
  line_len = line_width % len_rem;
  /* print line */
  print_hex_ascii_line(ch, line_len, offset);
  /* compute total remaining */
  len_rem = len_rem - line_len;
  /* shift pointer to remaining bytes to print */
  ch = ch + line_len;
  /* add offset */
  offset = offset + line_width;
  /* check if we have line width chars or less */
  if (len_rem <= line_width) {
   /* print last line and get out */
   print_hex_ascii_line(ch, len_rem, offset);
   break;
  }
 }

return;
}


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

 int i;
 int gap;
 const u_char *ch;

 /* offset */
 printf("%05d   ", offset);

 /* hex */
 ch = payload;
 for(i = 0; i < len; i++) {
  printf("%02x ", *ch);
  ch++;
  /* print extra space after 8th byte for visual aid */
  if (i == 7)
   printf(" ");
 }
 /* print space to handle line less than 8 bytes */
 if (len < 8)
  printf(" ");

 /* fill hex gap with spaces if not full line */
 if (len < 16) {
  gap = 16 - len;
  for (i = 0; i < gap; i++) {
   printf("   ");
  }
 }
 printf("   ");

 /* ascii (if printable) */
 ch = payload;
 for(i = 0; i < len; i++) {
  if (isprint(*ch))
   printf("%c", *ch);
  else
   printf(".");
  ch++;
 }

 printf("\n");

return;
}



