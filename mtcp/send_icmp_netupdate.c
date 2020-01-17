#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <linux/ip.h>

#define SRC_IP "10.0.0.5"
#define DST_IP "10.0.0.4"

#define BUFSIZ 1024

struct icmphdr {
  uint8_t  icmp_type;
  uint8_t  icmp_code;
  uint16_t icmp_checksum;
  union {
    struct {
      uint16_t icmp_id;
      uint16_t icmp_sequence;
    } echo;                     // ECHO | ECHOREPLY
    struct {
      uint16_t unused;
      uint16_t nhop_mtu;
    } dest;                     // DEST_UNREACH
    struct {
#if BYTE_ORDER == LITTLE_ENDIAN 
      uint32_t unused:24,
              newnet_id:8;
#endif
#if BYTE_ORDER == BIG_ENDIAN 
      uint32_t newnet_id:8,
              unused:24;
#endif
    } tdupdate;
  } un;
};

uint16_t checksum(uint16_t *data, int len) {

  uint16_t ret = 0;
  uint32_t sum = 0;
  uint16_t odd_byte;
  
  while (len > 1) {
    sum += *data++;
    len -= 2;
  }
  
  if (len == 1) {
    *(uint8_t*)(&odd_byte) = * (uint8_t*)data;
    sum += odd_byte;
  }
  
  sum =  (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  ret =  ~sum;
  
  return ret; 
}

int main(void) {

  // create a raw socket
  int sock;
  if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  // set socket option so that we provide the ip header
  int on = 1;
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
  {
    perror("setsockopt()");
    exit(EXIT_FAILURE);
  }

  // create an ICMP network update header
  uint8_t snd_buf[BUFSIZ] = {0};
  struct in_addr srcip, dstip;
  inet_aton(SRC_IP, &srcip);
  inet_aton(DST_IP, &dstip);
  struct iphdr * iph = (struct iphdr*)snd_buf;

  iph->version = 4;
  iph->ihl = 4;
  iph->tos = 0;
  iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
  iph->id = 0;
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_ICMP;
  iph->check = 0;
  iph->saddr = srcip.s_addr;
  iph->daddr = dstip.s_addr;

  struct icmphdr * icmph = (struct icmphdr*)(snd_buf + sizeof(iph));
  icmph->icmp_type = 123; 
  icmph->icmp_code = 0;
  icmph->icmp_checksum = 0;
  icmph->un.tdupdate.unused = 0;
  icmph->un.tdupdate.newnet_id = 1;

  icmph->icmp_checksum = checksum((uint16_t*)icmph, sizeof(icmph));
  iph->check = checksum((uint16_t*)iph, sizeof(iph));

  // send it
  struct sockaddr_in dst = {
    .sin_family = AF_INET,
    .sin_port = 0,
    .sin_addr = dstip
  };


  int rv;
  if ((rv = sendto(sock, snd_buf, sizeof(iph)+sizeof(icmph), 0, 
    (struct sockaddr *)&dst, sizeof(dst))) < 0) {
    perror("sendto()");
    exit(EXIT_FAILURE);
  } 

  fprintf(stderr, "Sent icmp succeed\n");
  
  close(sock);
  return 0;

}