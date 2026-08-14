#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

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
  u_int16_t tcp_length;
};

void send_tcp_packet(int sock, struct sockaddr_in *dest, struct iphdr *iph, struct tcphdr * tcph, char *data, int data_len) {
  char packet[4096];
  memset(packet, 0, 4096);
  memcpy(packet, iph, sizeof(struct iphdr));
  memcpy(packet + sizeof(struct iphdr), tcph, sizeof(struct tcphdr));
  if (data_len > 0) memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), data, data_len);
  iph = (struct iphdr *)packet;
  tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
  iph->check = checksum((unsigned short *)packet, iph->tot_len);

  struct pseudo_header psh;
  psh.source_address = iph->saddr;
  psh.dest_address = iph->daddr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + data_len);
  char pseudogram[sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len];
  memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + data_len);
  tcph->check = checksum((unsigned short *)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len);

  sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest));
}

int main() {
  srand(time(NULL));
  int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (send_sock < 0) { perror("Socket"); exit(1); }
  int one = 1;
  setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

  int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (recv_sock < 0) { perror("recv_sock"); exit(1); }

  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

  uint32_t my_seq = rand();
  u_int32_t my_ack = 0;
  u_int16_t src_port = 12345;
  u_int16_t dest_port = 7;

  struct iphdr iph;
  iph.ihl = 5;
  iph.version = 4;
  iph.tos = 0;
  iph.id = htonl(54321);
  iph.frag_off = 0;
  iph.ttl = 64;
  iph.protocol = IPPROTO_TCP;
  iph.saddr = inet_addr("127.0.0.1");
  iph.daddr = dest.sin_addr.s_addr;

  // SYN packet
  struct tcphdr tcph;
  memset(&tcph, 0, sizeof(tcph));
  tcph.source = htons(src_port);
  tcph.dest = htons(dest_port);
  tcph.seq = htonl(my_seq);
  tcph.ack_seq = htonl(my_ack);
  tcph.doff = 5;
  tcph.syn = 1;
  tcph.window = htons(5840);
  send_tcp_packet(send_sock, &dest, &iph, &tcph, NULL, 0);
  printf("SYN sent\n");

  // Receive SYN-ACK
  char buffer[65536];
  while (1) {
    int len = recv(recv_sock, buffer, sizeof(buffer), 0);
    if (len < 0) continue;

    struct iphdr *rx_iph = (struct iphdr *)buffer;
    if (rx_iph->protocol != IPPROTO_TCP || rx_iph->saddr != iph.daddr || rx_iph->daddr != iph.saddr) continue;

    struct tcphdr *rx_tcph = (struct tcphdr *)(buffer + rx_iph->ihl * 4);
    if (ntohs(rx_tcph->source) != dest_port || ntohs(rx_tcph->dest) != src_port) continue;
    if(rx_tcph->syn == 1 && rx_tcph->ack == 1 && ntohl(rx_tcph->ack_seq) == my_seq + 1) {
      my_ack = ntohl(rx_tcph->seq) + 1;
      my_seq += 1;
      printf("SYN-ACK received\n");
      break;
    }
  }

  // Send ACK 
  memset(&tcph, 0, sizeof(tcph));
  tcph.source = htons(src_port);
  tcph.dest = htons(dest_port);
  tcph.seq = htonl(my_seq);
  tcph.ack_seq = htonl(my_ack);
  tcph.doff = 5;
  tcph.ack = 1;
  tcph.window = htons(5840);
  send_tcp_packet(send_sock, &dest, &iph, &tcph, NULL, 0);
  printf("ACK sent. Handshake complete\n");

  char *data_str = "Hello TCP";
  int data_len = strlen(data_str);

  // Send data (PSH+ACK)
  memset(&tcph, 0, sizeof(tcph));
  tcph.source = htons(src_port);
  tcph.dest = htons(dest_port);
  tcph.seq = htonl(my_seq);
  tcph.ack_seq = htonl(my_ack);
  tcph.doff = 5;
  tcph.ack = 1;
  tcph.psh = 1;
  tcph.window = htons(5840);
  send_tcp_packet(send_sock, &dest, &iph, &tcph, data_str, data_len);
  my_seq += data_len;
  printf("Data sent (seq=%u, len=%d)\n", my_seq - data_len, data_len);

  // 3-second timeout
  struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
  setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  //char buffer[65536];
  int got_response = 0;

  while (!got_response) {
      struct sockaddr_in from;
      socklen_t fromlen = sizeof(from);

      int len = recvfrom(recv_sock, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&from, &fromlen);

      if (len < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
              printf("→ Timeout (no packet received in 3 seconds)\n");
              break;
          }
          perror("recvfrom");
          continue;
      }

      // ---------- Debug: show every packet ----------
      struct iphdr *rx_iph = (struct iphdr *)buffer;
      printf("Got %d bytes  proto=%d  %s → %s\n",
             len, rx_iph->protocol,
             inet_ntoa(*(struct in_addr *)&rx_iph->saddr),
             inet_ntoa(*(struct in_addr *)&rx_iph->daddr));

      if (rx_iph->protocol != IPPROTO_TCP) continue;

      // Make sure it is for our connection
      if (rx_iph->saddr != iph.daddr || rx_iph->daddr != iph.saddr)
          continue;

      struct tcphdr *rx_tcph = (struct tcphdr *)(buffer + rx_iph->ihl * 4);

      uint16_t sport = ntohs(rx_tcph->source);
      uint16_t dport = ntohs(rx_tcph->dest);

      printf("  TCP  %u → %u  flags=0x%02x  seq=%u  ack=%u\n",
             sport, dport, rx_tcph->th_flags,
             ntohl(rx_tcph->seq), ntohl(rx_tcph->ack_seq));

      if (sport != dest_port || dport != src_port) continue;

      // Accept any ACK (with or without data)
      if (rx_tcph->ack) {
          printf("→ Valid ACK received!\n");

          int tcp_hdr_len = rx_tcph->doff * 4;
          int payload_len = ntohs(rx_iph->tot_len) - (rx_iph->ihl * 4) - tcp_hdr_len;

          if (payload_len > 0) {
              char *data = buffer + rx_iph->ihl * 4 + tcp_hdr_len;
              printf("  Payload (%d bytes): %.*s\n", payload_len, payload_len, data);
              my_ack = ntohl(rx_tcph->seq) + payload_len;
          } else {
              my_ack = ntohl(rx_tcph->seq);
          }

          // Send our ACK back
          memset(&tcph, 0, sizeof(tcph));
          tcph.source   = htons(src_port);
          tcph.dest     = htons(dest_port);
          tcph.seq      = htonl(my_seq);
          tcph.ack_seq  = htonl(my_ack);
          tcph.doff     = 5;
          tcph.ack      = 1;
          tcph.window   = htons(5840);
          send_tcp_packet(send_sock, &dest, &iph, &tcph, NULL, 0);

          got_response = 1;
      }
  }  
  close(send_sock);
  close(recv_sock);
  return 0;
}
















