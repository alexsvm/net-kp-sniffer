/*
Simple IP sniffer
File: sniffer.cpp

Compile example:
bcc32 -osniffer.exe sniffer.cpp Ws2_32.lib

(c) 2007, BSTU. Alexey Drozdov
(c) 2009, BSTU. Dmitry Korostelyov
*/

#include <conio.h>
#include <stdio.h>
#include <winsock2.h>
#include <string.h>


#define MAX_PACKET_SIZE    0x10000
#define MAX_PACKET_SIZE    0x10000
#define SIO_RCVALL         0x98000001
// ����� ��� ����� ������
char Buffer[MAX_PACKET_SIZE]; // 64 Kb

							  //��������� ��������� IP-������

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
			IPHeader* hdr = (IPHeader *)Buffer;
			//�������� ������ ������...
			//��������� ���������
			printf("-=IP-Packet=-\r\nHeader:\r\n");
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
			if (str[2] == '1' || str[1] == '1')
			{
				strcpy(temp, " (");
				if (str[1] == '1')
				{
					strcat(temp, "Don't Fragment");
					if (str[2] == '1')
					{
						strcat(temp, ", ");
					}
				}
				if (str[2] == '1')
				{
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

			case IPPROTO_ICMP:
				printf("ICMP");
				break;

			case 47:
				printf("GRE");
				break;

			default:
				printf("OTHER %i", hdr->iph_protocol);
				break;
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

			unsigned short packet_size = ntohs(hdr->iph_length);

			char *buff = (char*)(Buffer + sizeof(IPHeader));
			int size = packet_size - sizeof(IPHeader);

			printf("DATA: \r\n");
			int count = 0;
			for (int i = 0; i<size; i++)
			{
				printf("%02X ", buff[i] & 0xff);
				count++;
				if (count == 16)
				{
					printf("\r\n");
					count = 0;
				}
			}
			printf("\n\n");
		}
	}

	closesocket(s);
	WSACleanup();

	return 0;
}
