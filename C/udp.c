#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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

int main() {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) {
    perror("Socket creation failed");
    exit(1);
  }

  int one = 1;
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);
  dest.sin_port = htons(7);

  char packet[4096];
  memset(packet, 0, 4096);

  struct iphdr *iph = (struct iphdr *)packet;
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->id = htonl(54321);
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0;
  iph->saddr = inet_addr("127.0.0.1");
  iph->daddr = dest.sin_addr.s_addr;

  struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
  udph->source = htons(12345);
  udph->dest = htons(7);
  udph->check = 0;

  char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
  strcpy(data, "Halo will shine");
  int data_len = strlen(data) + 1;

  udph->len = htons(sizeof(struct udphdr) + data_len);
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;

  iph->check = checksum((unsigned short *)packet, iph->tot_len);

  char pseudo[4096];
  struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
  } psh;

  psh.source_address = iph->saddr;
  psh.dest_address = iph->daddr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_UDP;
  psh.udp_length = udph->len;

  int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data_len;
  memcpy(pseudo, &psh, sizeof(struct pseudo_header));
  memcpy(pseudo + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + data_len);

  udph->check = checksum((unsigned short *)pseudo, psize);

  if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
      perror("Sendto");
      exit(1);
    }

  printf("UDP packet sent\n");
  close(sock);
  return 0;
}

