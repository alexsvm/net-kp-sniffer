/*
Simple IP sniffer
File: dns_sniffer.cpp

Compile example:
bcc32 -osniffer.exe sniffer.cpp Ws2_32.lib

(c) 2009, BSTU. Dmitry Korostelyov
*/

#include <conio.h>
#include <stdio.h>
#include <winsock2.h>
#include <string.h>

#define MAX_PACKET_SIZE    0x10000
#define MAX_PACKET_SIZE    0x10000
#define SIO_RCVALL         0x98000001
#define LIL_ENDIAN 0
#define BIG_ENDIAN 1
#define BYTE_ORDER BIG_ENDIAN

#define IP_HDR_LEN 20
#define TCP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define DNS_HDR_LEN 12

// ����� ��� ����� ������
char Buffer[MAX_PACKET_SIZE]; // 64 Kb#define 

typedef struct IPHeader {
	UCHAR   iph_verlen;   // ������ � ����� ���������
	UCHAR   iph_tos;      // ��� �������
	USHORT  iph_length;   // ����� ����� ������
	USHORT  iph_id;       // �������������
	USHORT  iph_offset;   // ����� � ��������
	UCHAR   iph_ttl;      // ����� ����� ������
	UCHAR   iph_protocol; // ��������
	USHORT  iph_xsum;     // ����������� �����
	ULONG   iph_src;      // IP-����� �����������
	ULONG   iph_dest;     // IP-����� ����������
} IPHeader;

typedef struct TCPHeader
{
	USHORT  source_port;       // (16 bits)
	USHORT  destination_port;  // (16 bits)
	ULONG	seq_number;        // Sequence Number (32 bits)
	ULONG	ack_number;        // Acknowledgment Number (32 bits)
	USHORT  info_ctrl;         // Data Offset (4 bits), Reserved (6 bits), Control bits (6 bits)
	USHORT  window;            // (16 bits)
	USHORT  checksum;          // (16 bits)
	USHORT  urgent_pointer;    // (16 bits)
} TCPHeader;


typedef struct UDPHeader
{
	USHORT   source_port;
	USHORT   destination_port;
	USHORT   length;
	USHORT   checksum;
} UDPHeader;

struct DNSHeader
{
	USHORT        id;
#if BYTE_ORDER == LIL_ENDIAN
	USHORT        recursion_desired : 1;
	USHORT        truncated_message : 1;
	USHORT        authoritive_answer : 1;
	USHORT        operation_code : 4;
	USHORT        is_response : 1;

	USHORT        response_code : 4;
	USHORT        checking_disabled : 1;
	USHORT        authenticated_data : 1;
	USHORT        reserved : 1;
	USHORT        recursion_available : 1;
#elif BYTE_ORDER == BIG_ENDIAN
	USHORT        is_response : 1;
	USHORT        operation_code : 4;
	USHORT        authoritive_answer : 1;
	USHORT        truncated_message : 1;
	USHORT        recursion_desired : 1;

	USHORT        recursion_available : 1;
	USHORT        reserved : 1;
	USHORT        authenticated_data : 1;
	USHORT        checking_disabled : 1;
	USHORT        response_code : 4;
#else
#    error BYTE_ORDER not defined.
#endif

	USHORT        question_count;
	USHORT        answer_count;
	USHORT        authority_record_count;
	USHORT        additional_record_count;
};

IPHeader* hdr = (IPHeader *)Buffer;
TCPHeader* tcp_hdr = (TCPHeader*)(Buffer + IP_HDR_LEN);
UDPHeader* udp_hdr = (UDPHeader*)(Buffer + IP_HDR_LEN);
DNSHeader* dns_hdr;

#define DNS_QUERY_DATA_LEN 4
struct DNSQuestionData
{
	unsigned short        question_type;
	unsigned short        question_class;
};

struct DNSQuestion
{
	unsigned char*      name;
	DNSQuestionData*    data;
};

#define DNS_RECORD_DATA_LEN 10
struct DNSRecordData
{
	unsigned short    record_type;
	unsigned short    record_class;
	unsigned int      ttl;
	unsigned short    response_length;
};

struct DNSRecord
{
	unsigned char*    name;
	DNSRecordData*    data;
	unsigned char*    response;
};

char * ConvertToBinary(int b)
{
	char s[10];
	int c = b;
	for (int i = 0; i<8; i++)
	{
		s[7 - i] = (c % 2) + '0';
		c = c / 2;
	}
	s[8] = '\0';
	return s;
}

unsigned short ip_sum_calc(char *buffer, int len)
{
	unsigned short word16;
	char myBuf[80];
	memcpy(myBuf, buffer, len);
	myBuf[10] = '\0';
	myBuf[11] = '\0';
	unsigned sum = 0;
	int i;

	// ��������� ��������� �� 16-������ ����� � ��������� ��
	for (i = 0; i<len; i = i + 2) {
		word16 = ((myBuf[i] << 8) & 0xFF00) + (myBuf[i + 1] & 0xFF);
		sum = sum + (unsigned long)word16;
	}

	// �� 32-������ ����� �������� 16-������ �����, ��������� ������� ����� � �������
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// ��������� ����������
	sum = ~sum;

	return ((unsigned short)sum);
}

int parse_dns_query(unsigned char* buffer, int offset)
//unsigned char* parse_dns_query(unsigned char* buffer, int offset)
{
	char buf[1024] = { 0 };
	char tmp[100] = { 0 };

	offset += 12;
	unsigned char *curr = buffer + offset;
	while (*curr) {
		strncpy(tmp, (const char*)curr + 1, *curr);
		strcat(tmp, ".");
		strcat(buf, tmp);
		memset(tmp, '\0', sizeof(tmp));
		offset += *curr + 1;
		curr += *curr + 1;
	}
	buf[strlen(buf) - 1] = '\0';
	printf("\t\tDNS lookup:\n\t\t  target=%s\n", buf);
	unsigned short* query_type = (unsigned short*) (curr+3);
	unsigned short* query_class = (unsigned short*) (curr+1);
	printf("\t\t  query type=%u\n", htons(*query_type));
	printf("\t\t  query class=%u\n", htons(*query_class)); 
	//return curr + 5;
	return offset + 5;
}

unsigned short parse_dns_answer(unsigned char* buffer, int offset)
{
	char buf[1024] = { 0 };
	char tmp[100] = { 0 };

	unsigned char *curr = buffer + offset;
	unsigned char LLLL = *(curr);
	unsigned long long l1 = *(curr);
	if (LLLL & 0xC0) {
		unsigned short off = htons((unsigned short)(*curr)) & 0x3fff;
		curr = buffer + off + 12;
	}

	while (*curr) {
		strncpy(tmp, (const char*)curr + 1, *curr);
		strcat(tmp, ".");
		strcat(buf, tmp);
		memset(tmp, '\0', sizeof(tmp));
		//offset += *curr + 1;
		curr += *curr + 1;
	}
	if (LLLL & 0xC0) {
		curr = buffer + offset + 1;
	}
	buf[strlen(buf) - 1] = '\0';
	printf("\t\tDNS answer:\n\t\t  target=%s\n", buf);
	unsigned short* query_type = (unsigned short*)(curr + 3);
	unsigned short* query_class = (unsigned short*)(curr + 1);
	unsigned long* ttl = (unsigned long*)(curr + 5);
	unsigned short* data_length = (unsigned short*)(curr + 9);
	printf("\t\t  query type=%u\n", htons(*query_type));
	printf("\t\t  query class=%u\n", htons(*query_class));
	printf("\t\t  data length=%u\n", htons(*data_length));
	printf("\t\t  addr=");
	char dl;
	int L = (htons(*data_length));
	if (L == 4)
		dl = '.';
	else
		dl = ':';
	for (int i = 0; i < L; i++) {
		unsigned char* B = (curr + 11 + i);
		if (dl == '.')
			printf("%u", *B);
		else
			printf("%x", *B);
		if ((L - i) > 1)
			printf("%c", dl);
	}

	return offset;
}


int main()
{
	WSADATA         wsadata;   // ������������� WinSock.
	SOCKET          s;         // C�������� �����.
	char            name[128]; // ��� ����� (����������).
	HOSTENT*        phe;       // ���������� � �����.
	SOCKADDR_IN     sa;        // ����� �����
	IN_ADDR         sa1;        //
	unsigned long   flag = 1;  // ���� PROMISC ���/����.
							   //
	fd_set          s_set;
	struct timeval  wait_;
	int             sel_res;
	char			temp[128];

	// �������������
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	gethostname(name, sizeof(name));
	phe = gethostbyname(name);

	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ((struct in_addr *)phe->h_addr_list[0])->s_addr;

	bind(s, (SOCKADDR *)&sa, sizeof(SOCKADDR));

	// ��������� promiscuous mode.
	ioctlsocket(s, SIO_RCVALL, &flag);
	// ��������� promiscuous mode.
	if (ioctlsocket(s, SIO_RCVALL, &flag) != 0)
	{
		printf("��� ������ ��������� ���������� ����� ��������������!\n");
		return -1;
	}

	FD_ZERO(&s_set);
	FD_SET(s, &s_set);
	//
	wait_.tv_sec = 0;
	wait_.tv_usec = 500;

	// ����������� ���� ����� IP-�������.
	while (!kbhit())
	{
		FD_ZERO(&s_set);
		FD_SET(s, &s_set);

		sel_res = select(0, &s_set, 0, 0, &wait_);

		if (sel_res <= 0) continue;

		int count;
		char str[10];
		count = recv(s, Buffer, sizeof(Buffer), 0);
		// ��������� IP-������
		if (count >= sizeof(IPHeader))
		{
			//IPHeader* hdr = (IPHeader *)Buffer;
			//TCPHeader* tcp_hdr = (TCPHeader*)(Buffer + IP_HDR_LEN);
			//UDPHeader* udp_hdr = (UDPHeader*)(Buffer + IP_HDR_LEN);
			// cast dns header
			//DNSHeader* dns_hdr;

			// ���������, �������� �� ����� DNS
			switch (hdr->iph_protocol)
			{
			case IPPROTO_TCP:
				if (!(htons(tcp_hdr->destination_port) == 53 || htons(tcp_hdr->source_port) == 53))
					continue;
				dns_hdr = (DNSHeader*)(Buffer + IP_HDR_LEN + TCP_HDR_LEN);
				break;

			case IPPROTO_UDP:
				if (!(htons(udp_hdr->destination_port) == 53 || htons(udp_hdr->source_port) == 53))
					continue;
				dns_hdr = (DNSHeader*)(Buffer + IP_HDR_LEN + UDP_HDR_LEN);
				break;
			}
			//�������� ������ ������...
			//��������� ���������
			printf("----------==========IP-Packet==========----------\r\nHeader:\r\n");
			//������� ������ IP-���������
			printf("Version: %i\r\n", ((hdr->iph_verlen & 0xF0) >> 4));
			//������� ����� ���������
			printf("Header length: %i bytes\r\n", (hdr->iph_verlen & 0xF) * 4);
			//������� ���� ������������
			strcpy(str, ConvertToBinary(hdr->iph_tos));
			printf("Differentiated Services Field: 0x%sb\r\n", str);
			// ��������� � ������� ������ ������. ��� ��� � ���� ������ ������ �������
			// ������, � �� ��������, �� �������� �������� ����� �������.
			printf("Total length: %u\r\n", htons(hdr->iph_length));
			//������� ����� ������������������
			printf("Identification: %u\r\n", htons(hdr->iph_id));
			//������� �����
			strcpy(str, ConvertToBinary(hdr->iph_offset));
			str[3] = '\0';
			printf("Flags: 0x%sb", str);
			if (str[2] == '1' || str[1] == '1') {
				strcpy(temp, " (");
				if (str[1] == '1') {
					strcat(temp, "Don't Fragment");
					if (str[2] == '1') {
						strcat(temp, ", ");
					}
				}
				if (str[2] == '1') {
					strcat(temp, "More Fragments");
				}
				strcat(temp, ")");
				printf("%s", temp);
			}
			printf("\r\n");
			//������� �������� � ������ ������
			printf("Fragment offset: %u\r\n", htons(hdr->iph_offset) & 0x1FFF);
			//������� ����� ����� ������
			printf("Time to live: %u\r\n", hdr->iph_ttl);
			// ������� �������� ���������� ������. ������ ������ ���� ��������
			// ���������� � ����� winsock2.h
			printf("Protocol: ");
			switch (hdr->iph_protocol)
			{
			case IPPROTO_TCP:
				printf("TCP");
				break;
			case IPPROTO_UDP:
				printf("UDP");
				break;
			//case IPPROTO_ICMP:
			//	printf("ICMP");
			//	break;

			//case 47:
			//	printf("GRE");
			//	break;

			//default:
			//	printf("OTHER %i", hdr->iph_protocol);
			//	break;
			}
			printf("\r\n");
			printf("Header checksum: %x", hdr->iph_xsum);
			unsigned short correctCRC = ip_sum_calc(Buffer, (hdr->iph_verlen & 0xF) * 4);
			if (hdr->iph_xsum == htons(correctCRC)) printf("[correct]\r\n"); else printf("[not corrent]\r\n");

			//����������� � �������� ��� ����� �����������.
			printf("Source: ");
			sa1.s_addr = hdr->iph_src;
			printf(inet_ntoa(sa1));
			printf("\r\n");

			// ����������� � �������� ��� ����� ����������.
			printf("Destination: ");
			sa1.s_addr = hdr->iph_dest;
			printf(inet_ntoa(sa1));
			printf("\r\n");
			
			// �������� ��������� TCP ��� UDP ������...
			switch (hdr->iph_protocol)
			{
			case IPPROTO_TCP:
				printf("\t> TCP-Packet:\r\n");
				printf("\tTCP source port: %d, ", htons(tcp_hdr->source_port));
				printf("\tTCP destination port: %d\n", htons(tcp_hdr->destination_port));
				printf("\tSequence Number: %d\n", htonl(tcp_hdr->seq_number));
				printf("\tAcknowledgement Number: %d\n", htonl(tcp_hdr->ack_number));
				printf("\tChecksumm: 0x%04x\n", htons(tcp_hdr->checksum));
				break;

			case IPPROTO_UDP:
				printf("\t> UDP-Packet:\r\n");
				printf("\tUDP source port: %d, ", htons(udp_hdr->source_port));
				printf("\tUDP destination port: %d\n", htons(udp_hdr->destination_port));
				printf("\tLength: %d\n", htons(udp_hdr->length));
				printf("\tChecksumm: 0x%04x\n", htons(udp_hdr->checksum));
				break;
			}

			// �������� ��������� DNS ������...
			printf("\t\t> DNS-Packet:\r\n");
			printf("\t\tTransaction ID: 0x%04x \r\n", htons(dns_hdr->id));
			printf("\t\tFlags:\r\n");
			printf("\t\t  Is response: %d\n", dns_hdr->is_response);
			printf("\t\t  Opcode: %d\n", dns_hdr->operation_code);
			printf("\t\t  Truncated: %d\n", dns_hdr->truncated_message);
			printf("\t\t  Recursion desired: %d\n", dns_hdr->recursion_desired);
			printf("\t\t  Reserver: %d\n", dns_hdr->reserved);
			//printf("    Truncated: %d\n", dns_hdr->authenticated_data);
			printf("\t\tQuestions: %d\n", htons(dns_hdr->question_count));
			printf("\t\tAnswer RRs: %d\n", htons(dns_hdr->answer_count));
			printf("\t\tAuthority RRs: %d\n", htons(dns_hdr->authority_record_count));
			printf("\t\tAdditional RRs: %d\n", htons(dns_hdr->additional_record_count));

			// �������� dns-������
			//unsigned char* rr = parse_dns_query((unsigned char*)dns_hdr, 0);
			int rr = parse_dns_query((unsigned char*)dns_hdr, 0);
			// �������� dns-������
			if (htons(dns_hdr->answer_count))
				parse_dns_answer((unsigned char*)dns_hdr, rr);
			printf("\n\n");
		}
	}

	closesocket(s);
	WSACleanup();

	return 0;
}
