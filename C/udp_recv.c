#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock < 0) {
    perror("socket");
    exit(1);
  }

  char buffer[65536];
  struct sockaddr_in src;
  socklen_t src_len = sizeof(src);

  printf("Listening for UDP packets on port 12345......\n");

  while (1) {
    int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&src, &src_len);
    if (len < 0) {
      perror("recvfrom");
      continue;
    }

    struct iphdr *iph = (struct iphdr *)buffer;
    if (iph->protocol != IPPROTO_UDP) continue;

    struct udphdr *udph = (struct udphdr *)(buffer + iph->ihl * 4);
    if (ntohs(udph->dest) != 12345) continue;

    char *data = buffer + iph->ihl * 4 + sizeof(struct udphdr);
    int data_len = ntohs(udph->len) - sizeof(struct udphdr);
    data[data_len] = '\0';

    printf("Received: %s\n", data);
  }

  close(sock);
  return 0;
}
