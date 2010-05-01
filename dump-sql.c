#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

#define MYSQL_MODE 1
#define DUMP_MODE 2
#define ETH_ADDR_LEN 6
#define ETHERNET_SIZE 14

int main(int argc, char * argv[]) {
  // Mode Vars
  MYSQL * conn = mysql_init(NULL);
  FILE * df;
  int mode;

  // Pcap vars
  pcap_t * handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr * header;
  const u_char * packet;

  // Ethernet Header
  struct ethhdr {
    u_char eth_dst_host[ETH_ADDR_LEN];
    u_char eth_src_host[ETH_ADDR_LEN];
    u_short eth_type;
  };

  const struct ethhdr * ethernet_hdr;
  const struct ip * ip_hdr;
  const struct tcphdr * tcp_hdr;

  // Check num of args to determine mode
  if (argc == 6)
    mode = MYSQL_MODE;
  else if (argc == 3)
    mode = DUMP_MODE;
  else {
    fprintf(stderr, "Usage:\nMySQL Connect: dump-sql [Capture File] [MySQL Host] [MySQL User] [MySQL Pass] [MySQL DB Name]\nDump Output:   dump-sql [Capture File] [Output File]\n");
    return 2;
  }

  // Open packet capture file
  if ((handle = pcap_open_offline(argv[1], errbuf)) == NULL) {
    fprintf(stderr, "[ERROR] Could not open capture file: %s\n", errbuf);
    return 2;
  }

  // If MYSQL, then connect to DB
  if (mode == MYSQL_MODE) {
    if (!mysql_real_connect(conn, argv[2], argv[3], argv[4], argv[5], 0, NULL, 0)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
      return 2;
    }

    printf("Connected to %s, populating tables...\n", argv[2]);
  }
  // else open a file write to
  else if (mode == DUMP_MODE) {
    if ((df = fopen(argv[2], "w")) == NULL) {
      fprintf(stderr, "[ERROR] Could not open file for writing: %s\n", argv[2]);
      return 2;
    }
  }

  int packet_num = 1, iter;
  while(pcap_next_ex(handle, &header, &packet) != -2) {
    /* 
     * Each packet has the three structures sitting in line, so to find the location
     * of the next, just add the size of it to the previous
     */
    ethernet_hdr = (struct ethhdr *)(packet);
    ip_hdr = (struct ip *)(packet + ETHERNET_SIZE);
    tcp_hdr = (struct tcphdr *)(packet + ETHERNET_SIZE + (ip_hdr->ip_hl*4));

    char dst_mac[12];
    char src_mac[12];
    char byte[2];
    char eth_type[4];
    
    // null offset
    int os = 0;
    char * sql_string = (char *)malloc(150 * sizeof(char *));
    
    /*
     * Since sprintf returns the number of chars written (excluding null), then
     * to append to sql_string, rather than overwrite it, just keep track of
     * the offset (os) and add that amount to the char pointer at each successive
     * write
     */
    // Ethernet
    os += sprintf(sql_string, "INSERT INTO eth VALUES(%d, '", packet_num);
    for (iter = 0; iter < ETH_ADDR_LEN; iter++)
      os += sprintf(sql_string + os, "%.2x", ethernet_hdr->eth_dst_host[iter]);
    
    os += sprintf(strchr(sql_string, 0), "', '");
    for (iter = 0; iter < ETH_ADDR_LEN; iter++)
      os += sprintf(sql_string + os, "%.2x", ethernet_hdr->eth_src_host[iter]);
    
    os += sprintf(sql_string + os, "', '");
    os += sprintf(sql_string + os, "%.4x')", ntohs(ethernet_hdr->eth_type));
    
    // Perform a DB call or write to a file
    if (mode == MYSQL_MODE) {
      if (mysql_query(conn, sql_string))
	fprintf(stderr, "%s\n", mysql_error(conn));
    }
    else if (mode == DUMP_MODE) {
      fprintf(df, "%s;\n", sql_string);
    }
    
    os = 0;
    free(sql_string);
    sql_string = NULL;
    
    sql_string = (char *)malloc(150 * sizeof(char *));
    
    // IP
    os += sprintf(sql_string, "INSERT INTO ip VALUES(%d, ", packet_num);
    os += sprintf(sql_string + os, "%d, ", ip_hdr->ip_v);
    os += sprintf(sql_string + os, "%d, ", ip_hdr->ip_hl*4);
    os += sprintf(sql_string + os, "%d, ", ip_hdr->ip_tos);
    os += sprintf(sql_string + os, "%d, ", ntohs(ip_hdr->ip_len));
    os += sprintf(sql_string + os, "'%x', ", ntohs(ip_hdr->ip_id));
    
    u_int ip_off = ntohs(ip_hdr->ip_off);
    if (ip_off & IP_RF)
      os += sprintf(sql_string + os, "1, ");
    else
      os += sprintf(sql_string + os, "0, ");
    if (ip_off & IP_DF)
      os += sprintf(sql_string + os, "1, ");
    else
      os += sprintf(sql_string + os, "0, ");
    if (ip_off & IP_MF)
      os += sprintf(sql_string + os, "1, ");
    else
      os += sprintf(sql_string + os, "0, ");
    os += sprintf(sql_string + os, "%d, ", (ip_off & IP_OFFMASK) << 3);
    os += sprintf(sql_string + os, "%d, ", ip_hdr->ip_ttl);
    os += sprintf(sql_string + os, "%.2x, ", ip_hdr->ip_p);
    os += sprintf(sql_string + os, "'%x', ", ntohs(ip_hdr->ip_sum));
    os += sprintf(sql_string + os, "'%s', ", inet_ntoa(*(struct in_addr *) &ip_hdr->ip_src.s_addr));
    os += sprintf(sql_string + os, "'%s')", inet_ntoa(*(struct in_addr *) &ip_hdr->ip_dst.s_addr));
    
    if (mode == MYSQL_MODE) {
      if (mysql_query(conn, sql_string))
	fprintf(stderr, "%s\n", mysql_error(conn));
    }
    else if (mode == DUMP_MODE) {
      fprintf(df, "%s;\n", sql_string);
    }
    
    os = 0;
    free(sql_string);
    sql_string = NULL;
    
    sql_string = (char *)malloc(150 * sizeof(char *));      
    
    // TCP
    os += sprintf(sql_string, "INSERT INTO tcp VALUES(%d, ", packet_num);
    os += sprintf(sql_string + os, "%d, ", ntohs(tcp_hdr->source));
    os += sprintf(sql_string + os, "%d, ", ntohs(tcp_hdr->dest));
    os += sprintf(sql_string + os, "%d, ", ntohl(tcp_hdr->seq));
    os += sprintf(sql_string + os, "%d, ", ntohl(tcp_hdr->ack_seq));
    os += sprintf(sql_string + os, "%d, ", tcp_hdr->doff*4);
    os += sprintf(sql_string + os, "%x, ", tcp_hdr->urg);
    os += sprintf(sql_string + os, "%x, ", tcp_hdr->ack);
    os += sprintf(sql_string + os, "%x, ", tcp_hdr->psh);
    os += sprintf(sql_string + os, "%x, ", tcp_hdr->rst);
    os += sprintf(sql_string + os, "%x, ", tcp_hdr->syn);
    os += sprintf(sql_string + os, "%x, ", tcp_hdr->fin);
    os += sprintf(sql_string + os, "%d, ", ntohs(tcp_hdr->window));
    os += sprintf(sql_string + os, "'%.4x')", ntohs(tcp_hdr->check));
    
    if (mode == MYSQL_MODE) {
      if (mysql_query(conn, sql_string))
	fprintf(stderr, "%s\n", mysql_error(conn));
    }
    else if (mode == DUMP_MODE) {
      fprintf(df, "%s;\n", sql_string);
    }
    
    free(sql_string);
    sql_string = NULL;

    packet_num++;
  }

  // Close out
  if (mode == MYSQL_MODE)
    mysql_close(conn);
  else if (mode == DUMP_MODE)
    fclose(df);

  return 0;
}
