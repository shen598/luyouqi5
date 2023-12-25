#pragma once
#include<iostream>
#include"winsock2.h"
using namespace std;
//各数据包的定义
#pragma pack(1)

//以太网帧首部
struct Ethernet_Header {
	BYTE DesMAC[6];    //目的地址
	BYTE SrcMAC[6];    //源地址
	WORD FrameType;    //帧类型
};


//ARP帧
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


//IP包数据部分
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

//IP数据包
typedef struct IP_Packet {
	Ethernet_Header FrameHeader;    //帧首部
	IP_Data IPHeader;    //IP帧
};

#pragma pack()


//路由表项
struct Router_Table_Item {
	u_long DesIP;    //目的IP
	u_long Netmask;    //子网掩码
	u_long Nextjump;     //下一跳步
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


//IP与MAC对应关系
struct IP_MAC {
	u_long ip;
	u_char mac[6];
	IP_MAC(u_long ip, u_char* mac) {
		this->ip = ip;
		memcpy(this->mac, mac, 6);
	}
};