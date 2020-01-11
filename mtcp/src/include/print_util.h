#ifndef PRINT_UTIL_H
#define PRINT_UTIL_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/ip.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  struct ethhdr *ehdr = (struct ethhdr *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->h_dest);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->h_source);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->h_proto));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  struct iphdr *ip_header = (struct iphdr *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", ip_header->version);
  fprintf(stderr, "\theader length: %d\n", ip_header->ihl);
  fprintf(stderr, "\ttype of service: %d\n", ip_header->tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(ip_header->tot_len));
  fprintf(stderr, "\tid: %d\n", ntohs(ip_header->id));

  if (ntohs(ip_header->frag_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(ip_header->frag_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(ip_header->frag_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(ip_header->frag_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", ip_header->ttl);
  fprintf(stderr, "\tprotocol: %d\n", ip_header->protocol);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", ip_header->check);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(ip_header->saddr));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(ip_header->daddr));
}


#endif // PRINT_UTIL_H

