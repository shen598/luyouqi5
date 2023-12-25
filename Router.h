#pragma once
#include<iostream>
#include"winsock2.h"
using namespace std;
//�����ݰ��Ķ���
#pragma pack(1)

//��̫��֡�ײ�
struct Ethernet_Header {
	BYTE DesMAC[6];    //Ŀ�ĵ�ַ
	BYTE SrcMAC[6];    //Դ��ַ
	WORD FrameType;    //֡����
};


//ARP֡
struct ARP_Packet {
	Ethernet_Header FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};


//IP�����ݲ���
typedef struct IP_Data {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	u_long SrcIP;
	u_long DstIP;
};

//IP���ݰ�
typedef struct IP_Packet {
	Ethernet_Header FrameHeader;    //֡�ײ�
	IP_Data IPHeader;    //IP֡
};

#pragma pack()


//·�ɱ���
struct Router_Table_Item {
	u_long DesIP;    //Ŀ��IP
	u_long Netmask;    //��������
	u_long Nextjump;     //��һ����
	int is_default;
	Router_Table_Item() {
		memset(this, 0, sizeof(*this));
	}

	Router_Table_Item(u_long ip, u_long mask, u_long nextjump, int Is_default) {
		this->DesIP = ip;
		this->Netmask = mask;
		this->Nextjump = nextjump;
		this->is_default = Is_default;
	}
};


//IP��MAC��Ӧ��ϵ
struct IP_MAC {
	u_long ip;
	u_char mac[6];
	IP_MAC(u_long ip, u_char* mac) {
		this->ip = ip;
		memcpy(this->mac, mac, 6);
	}
};