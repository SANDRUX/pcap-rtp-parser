#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2
#define SCRC_MAX 15
#define RTP_HEADER_SIZE 12


typedef struct RTPHeader{
    uint32_t nVersion;
    uint32_t nPadding;
    uint32_t nSequence;
    uint32_t nExtension;
    uint32_t nSCRCCount;
    uint32_t nMarkerBit;
    uint32_t nPayloadType;
    uint32_t SCRC[SCRC_MAX];
    uint32_t nTimeStamp;
    uint32_t nSSRC;
} rtp_header_t;

FILE * file;

void packet_handler(u_char*,  const struct pcap_pkthdr*, const u_char * packet);
int RTP_ParseHeader(rtp_header_t *, const u_char *, size_t);

int main(int argc, char ** argv)
{
    if (argc == 1)
    {
        fprintf(stderr, "Usage: parser <file>.pcap <file>.ts");
        exit(EXIT_FAILURE);
    }
    pcap_t * fp;

    char errBuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];

    fp = pcap_open_offline(argv[1], errBuf);

    if (fp == NULL)
    {
        fprintf(stderr, "pcap_open_offline() failed: %s", errBuf);
        exit(EXIT_FAILURE);
    }

    file = fopen(argv[2], "wb");

    if (file == NULL)
    {
        fprintf(stderr, "fopen() failed");
        exit(EXIT_FAILURE);
    }

    if (pcap_loop(fp, 0, packet_handler, NULL) < 0)
    {
        fprintf(stderr, "pcap_loop() failed: %s", pcap_geterr(fp));
    }

    fclose(file);

    char command[50];

    sprintf(command, "ffplay %s", argv[2]);

    system(command);

    return 0;
}

void packet_handler(u_char * userData,  const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
   const struct ether_header* ethernetHeader;
   const struct ip* ipHeader;
   const struct udphdr* udpHeader;
   char sourceIP[INET_ADDRSTRLEN];
   char destIP[INET_ADDRSTRLEN];
   u_int sourcePort, destPort;
   u_char *data;
   int dataLength = 0;

    ethernetHeader = (struct ether_header *)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
    {
        ipHeader = (struct ip *)(packet + sizeof (struct ether_header));
//        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
//        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
    }

    if (ipHeader->ip_p == IPPROTO_UDP)
    {
        udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
//        sourcePort = ntohs(udpHeader->source);
//        destPort = ntohs(udpHeader->dest);

        data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        dataLength = ntohs(udpHeader->len);

        rtp_header_t rtpHeader;

        int PayloadOffset = RTP_ParseHeader(&rtpHeader, data, dataLength);
        int PayloadSize = dataLength - (4 * ((int)rtpHeader.nSCRCCount + 3));

        if (PayloadOffset != -1)
        {
            fwrite(data + PayloadOffset, PayloadSize, 1, file);
        }
    }
}

int RTP_ParseHeader(rtp_header_t *pHeader, const u_char *pData, size_t nLength)
{
    if (pData == NULL || nLength < RTP_HEADER_SIZE ||
            (pData[0] & 0xc0) != (2 << 6)) return -1;

        /* Parse RTP header */
        pHeader->nVersion = (pData[0] & 0xc0) >> 6;
        pHeader->nPadding = (pData[0] & 0x40) >> 5;
        pHeader->nExtension = (pData[0] & 0x20) >> 4;
        pHeader->nSCRCCount = (pData[0] & 0x0f);
        pHeader->nMarkerBit = (pData[1] & 0x80) >> 7;
        pHeader->nPayloadType = (pData[1] & 0x7F);
        pHeader->nSequence = ntohs(((unsigned short *) pData)[1]);
        pHeader->nTimeStamp = ntohl(((unsigned int *) pData)[1]);
        pHeader->nSSRC = ntohl(((unsigned int *) pData)[2]);

        uint32_t i;
        if (!pHeader->nSCRCCount)
        {
            for (i = 0; i < SCRC_MAX; i++) pHeader->SCRC[i] = 0;
            return RTP_HEADER_SIZE;
        }

        for (i = 0; i < pHeader->nSCRCCount; i++)
        {
            pHeader->SCRC[i] = ntohl(((unsigned int *) pData)[3 + i]);
            if (i >= SCRC_MAX) break;
        }

        /* Offset to pPayload */
        return RTP_HEADER_SIZE + pHeader->nSCRCCount * 4;
}
























