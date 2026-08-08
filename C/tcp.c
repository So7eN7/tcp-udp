#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }
  if (len == 1) sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

struct pseudo_header {
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int8_t tcp_length;
};

int main() {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) { perror("Socket"); exit(1); }

  int one = 1;
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

  char packet[4096];
  memset(packet, 0, 4096);

  struct iphdr *iph = (struct iphdr *)packet;
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  iph->id = htonl(54321);
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;
  iph->saddr = inet_addr("127.0.0.1");
  iph->daddr = dest.sin_addr.s_addr;
  
  struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
  tcph->source = htons(12345);
  tcph->dest = htons(7);
  tcph->seq = 0;
  tcph->ack_seq = 0;
  tcph->doff = 5;
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->window = htons(5840);
  tcph->check = 0;
  tcph->urg_ptr = 0;

  iph->check = checksum((unsigned short *)packet, iph->tot_len);

  struct pseudo_header psh;
  psh.source_address = iph->saddr;
  psh.dest_address = iph->daddr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr));
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
  char pseudogram[psize];
  memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
  tcph->check = checksum((unsigned short *)pseudogram, psize);

  if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
    perror("Sendto");
    exit(1);
  }

  printf("TCP SYN sent\n");
  close(sock);
  return 0;
}
















