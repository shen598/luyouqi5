#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<iostream>
#include<string>
#include<ws2tcpip.h>
#include<winsock2.h>
#include<winsock.h>
#include<vector>
#include<algorithm>
#include<iomanip>
#include"pcap.h"
#include"Router.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
using namespace std;


//全局变量
vector<Router_Table_Item> router_table;    //路由表
vector<IP_MAC> ip_mac;    //ip与mac对应关系
pcap_if_t* alldevs;    //指向设备链表首部的指针
pcap_if_t* d;
pcap_addr_t* a;
int ip_num = 0;    //ip数量
u_long* local_ip;    //本机网卡的ip
u_long* local_mask;    //本机网卡的子网掩码
BYTE local_MAC[6];    //本机网卡的MAC地址
pcap_t* hand;
char* t = new char[25];    //存储时间


//获取时间
void get_time(char* get_time) {
	struct tm stime;
	time_t now = time(0);
	localtime_s(&stime, &now);
	strftime(get_time, 25, "%Y-%m-%d %H:%M:%S", &stime);
	return;
}


//转化ip
string getIP(u_long ip) {
	in_addr addr;
	memcpy(&addr, &ip, sizeof(ip));
	string result_ip = inet_ntoa(addr);
	return result_ip;
}


//IP数据报日志输出
void print_iplog(IP_Packet* ip_packet) {
	get_time(t);
	cout << "====================================================================================================" << endl;
	cout << "[log]" << t << endl;
	cout << "数据包类型:" << "IP" << endl;
	cout << "源MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", ip_packet->FrameHeader.SrcMAC[i]);
	}
	printf("%02x", ip_packet->FrameHeader.SrcMAC[5]);

	cout << endl;

	cout << "目的MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", ip_packet->FrameHeader.DesMAC[i]);
	}
	printf("%02x", ip_packet->FrameHeader.DesMAC[5]);

	cout << endl;

	cout << "源IP:";
	cout << getIP(ip_packet->IPHeader.SrcIP) << endl;
	cout << "目的IP:";
	cout << getIP(ip_packet->IPHeader.DstIP) << endl;
	cout << "====================================================================================================" << endl;
	return;
}


//ARP数据报日志输出
void print_arplog(ARP_Packet* arp_packet) {
	get_time(t);
	cout << "====================================================================================================" << endl;
	cout << "[log]" << t << endl;
	cout << "数据包类型:" << "ARP" << endl;
	cout << "源MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", arp_packet->FrameHeader.SrcMAC[i]);
	}
	printf("%02x", arp_packet->FrameHeader.SrcMAC[5]);

	cout << endl;

	cout << "目的MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", arp_packet->FrameHeader.DesMAC[i]);
	}
	printf("%02x", arp_packet->FrameHeader.DesMAC[5]);

	cout << endl;

	cout << "源IP:";
	cout << getIP(arp_packet->SendIP) << endl;
	cout << "目的IP:";
	cout << getIP(arp_packet->RecvIP) << endl;
	cout << "====================================================================================================" << endl;
	return;
}


//计算校验和
void calculate_checksum(IP_Data* packet) {
	packet->Checksum = 0;
	int count = (sizeof(IP_Data) + 1) / 2;
	u_short* bit16 = (u_short*)packet;
	u_long checksum = 0;
	for (int i = 0; i < count; i++) {
		checksum += *(bit16++);
		if (checksum & 0xffff0000) {
			checksum -= 0xffff;
			checksum += 1;
		}
	}
	packet->Checksum = ~checksum;
	return;
}


//验证校验和
bool verify_checksum(IP_Data* packet) {
	int count = (sizeof(IP_Data) + 1) / 2;
	u_short* bit16 = (u_short*)packet;
	u_long checksum = 0;
	for (int i = 0; i < count; i++) {
		checksum += *(bit16++);
		if (checksum & 0xffff0000) {
			checksum -= 0xffff;
			checksum += 1;
		}
	}
	if ((checksum == 0xffff))
		return true;
	else
		return false;
}


//向量元素排序规则
bool cmp(Router_Table_Item item1, Router_Table_Item item2) {
	return item1.Netmask > item2.Netmask;
}

//添加路由表项
void add_item(u_long ip, u_long mask, u_long jump) {
	Router_Table_Item item(ip, mask, jump, 0);
	router_table.push_back(item);
	sort(router_table.begin(), router_table.end(), cmp);
	return;
}


//删除路由表项
void delete_item(u_long ip, u_long mask, u_long jump) {
	for (int i = 0; i < router_table.size(); i++) {
		if (router_table[i].DesIP == ip && router_table[i].Netmask == mask && router_table[i].Nextjump == jump) {
			if (router_table[i].is_default == 0) {
				router_table.erase(router_table.begin() + i);
			}
			else {
				cout << "目标为默认路由表项，删除失败!" << endl;
				return;
			}
		}
		else {
			cout << "没有找到相应的路由表项，删除失败!" << endl;
			return;
		}
	}
}


//输出路由表
void show_item() {
	cout << setw(15) << "目的IP" << setw(15) << "子网掩码" << setw(15) << "下一跳步" << endl;
	cout << "====================================================================" << endl;
	for (int i = 0; i < router_table.size(); i++)
		cout << setw(15) << getIP(router_table[i].DesIP) << setw(15) << getIP(router_table[i].Netmask) << setw(15) << getIP(router_table[i].Nextjump) << endl;
	return;
}


//查找路由表
int find_item(u_long dstip) {
	for (int i = 0; i < router_table.size(); i++) {
		if ((dstip & router_table[i].Netmask) == router_table[i].DesIP) {
			if (router_table[i].Nextjump != 0)
				return router_table[i].Nextjump;
			else
				return -1;    //直接投递
		}
	}

	//没有查到
	return 0;
}


//添加IP-MAC对应关系
void add_ipmac(u_long ip, u_char* mac) {
	IP_MAC item(ip, mac);
	ip_mac.push_back(item);
	return;
}


//根据IP找到对应的MAC地址
u_char* find_mac(u_long ip) {
	u_char* result = 0;
	for (int i = 0; i < ip_mac.size(); i++) {
		if (ip == ip_mac[i].ip) {
			result = ip_mac[i].mac;
		}
	}
	return result;
}



//找到并打开用户指定的网卡
void find_and_open_devs() {
	bool flag = false;
	char errbuf[PCAP_ERRBUF_SIZE];    //错误信息缓冲区
	vector<string> ip_address_set;


	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1) {    //错误处理
		cout << "Error! Can't get information!" << endl;
	}

	int dev_num = 0;    //计算设备数目
	int request_num, count = 1;    //request_num为用户输入，要求捕获第几个设备的数据包；count用于从设备链表中遍历，判断是否到达用户要求的设备


	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		dev_num++;
		string name = d->name;		//利用d->name获取该网络接口设备的名字
		string description = d->description;		//利用d->description获取该网络接口设备的描述信息


		//输出信息
		cout << "设备名称:" << name << endl;
		cout << "描述信息:" << description << endl;


		//获取该网络接口设备的IP地址信息
		for (a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				flag = true;
				printf("%s%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				ip_address_set.push_back(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			}
		}
		if (flag == false)
			ip_address_set.push_back("没有IPv4地址");
		flag = false;
		cout << endl;
	}


	//用户输入想要监听的接口
	cout << endl;
	cout << "输入你选择的网卡:";
	while (1) {
		cin >> request_num;
		if (request_num > dev_num || request_num <= 0)
			cout << "输入错误!" << endl;
		else {
			break;
		}
	}

	cout << "====================================================================================================" << endl;

	//遍历到用户需要的设备
	for (d = alldevs; count != request_num; count++)
		d = d->next;

	//打开网络接口
	hand = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (hand == NULL) {
		cout << "连接失败!" << endl;
		return;
	}
	cout << "正在监听:" << d->description << endl;
	return;
}


//获取所选网卡MAC地址
void get_local_mac() {
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			ip_num++;
		}
	}
	local_ip = new u_long[ip_num];
	local_mask = new u_long[ip_num];
	int index = 0;

	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			//将ip地址存入local_ip数组
			local_ip[index] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			if (a->netmask)
			{
				//将子网掩码存入local_mask数组
				local_mask[index] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			}
			index++;
		}
	}
	cout << "所选网卡的ip地址与子网掩码分别为:" << endl;
	for (int i = 0; i < index; i++)
		cout << "ip地址:" << getIP(local_ip[i]) << " | " << "子网掩码:" << getIP(local_mask[i]) << endl;

	//构造虚拟主机向所选网卡发送的ARP帧
	ARP_Packet First_Packet;

	//ARPFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC设置为***虚拟主机***的MAC地址
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.SrcMAC[i] = 0x0f;

	//帧类型为ARP
	First_Packet.FrameHeader.FrameType = htons(0x0806);

	//硬件类型为以太网
	First_Packet.HardwareType = htons(0x0001);

	//协议类型为IP
	First_Packet.ProtocolType = htons(0x0800);

	//硬件地址长度为6
	First_Packet.HLen = 6;

	//协议地址长度为4
	First_Packet.PLen = 4;

	//操作为ARP请求
	First_Packet.Operation = htons(0x0001);

	//将SendHa设置为虚拟主机的MAC地址
	for (int i = 0; i < 6; i++)
		First_Packet.SendHa[i] = 0x0f;

	//将SendIP设置为***虚拟主机***绑定的IP地址
	First_Packet.SendIP = inet_addr("192.192.192.192");

	//将RecvHa设置为0（目标未知）
	for (int i = 0; i < 6; i++)
		First_Packet.RecvHa[i] = 0;

	//将RecvIP设置为请求的IP地址
	First_Packet.RecvIP = local_ip[0];


	//发送ARP包
	pcap_sendpacket(hand, (u_char*)&First_Packet, sizeof(ARP_Packet));

	//声明要捕获的回复包
	ARP_Packet* First_Packet_Reply;

	//捕获回复包，获取选取网卡的MAC地址
	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//强制类型转换
			First_Packet_Reply = (ARP_Packet*)content;
			if (First_Packet_Reply->RecvIP == inet_addr("192.192.192.192")) {    //ARP类型
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (First_Packet_Reply->FrameHeader.DesMAC[i] != First_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//捕捉到的包的源MAC应是虚拟主机的MAC地址
				if (compare_flag) {
					for (int i = 0; i < 6; i++)
						local_MAC[i] = First_Packet_Reply->FrameHeader.SrcMAC[i];

					cout << "MAC地址为:";
					for (int i = 0; i < 5; i++) {
						printf("%02x:", First_Packet_Reply->FrameHeader.SrcMAC[i]);
					}
					printf("%02x", First_Packet_Reply->FrameHeader.SrcMAC[5]);
					break;
				}
			}
		}
	}
	cout << endl;
	cout << "====================================================================================================" << endl;

	//将路由表项添加至路由表中
	for (int i = 0; i < ip_num; i++) {
		add_ipmac(local_ip[i], local_MAC);
	}
	return;
}


//获得目的ip的MAC地址
u_char* get_mac(u_long dstip) {
	//构造ARP帧
	ARP_Packet arp_Packet;

	//ARPFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		arp_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC设置为***虚拟主机***的MAC地址
	for (int i = 0; i < 6; i++)
		arp_Packet.FrameHeader.SrcMAC[i] = local_MAC[i];

	//帧类型为ARP
	arp_Packet.FrameHeader.FrameType = htons(0x0806);

	//硬件类型为以太网
	arp_Packet.HardwareType = htons(0x0001);

	//协议类型为IP
	arp_Packet.ProtocolType = htons(0x0800);

	//硬件地址长度为6
	arp_Packet.HLen = 6;

	//协议地址长度为4
	arp_Packet.PLen = 4;

	//操作为ARP请求
	arp_Packet.Operation = htons(0x0001);

	//将SendHa设置为选取网卡的MAC地址
	for (int i = 0; i < 6; i++)
		arp_Packet.SendHa[i] = local_MAC[i];

	//将SendIP设置为选取网卡绑定的IP地址
	arp_Packet.SendIP = local_ip[0];

	//将RecvHa设置为0（目标未知）
	for (int i = 0; i < 6; i++)
		arp_Packet.RecvHa[i] = 0;

	//将RecvIP设置为输入的IP地址
	arp_Packet.RecvIP = dstip;

	//发送ARP包
	pcap_sendpacket(hand, (u_char*)&arp_Packet, sizeof(ARP_Packet));

	//声明要捕获的回复包
	ARP_Packet* Second_Packet_Reply;

	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//强制类型转换
			Second_Packet_Reply = (ARP_Packet*)content;
			if (Second_Packet_Reply->RecvIP == local_ip[0]) {    //ARP类型
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (Second_Packet_Reply->FrameHeader.DesMAC[i] != arp_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//捕捉到的包的源MAC应是虚拟主机的MAC地址
				if (compare_flag) {
					cout << "MAC地址为:";
					for (int i = 0; i < 5; i++) {
						printf("%02x:", Second_Packet_Reply->FrameHeader.SrcMAC[i]);
					}
					printf("%02x", Second_Packet_Reply->FrameHeader.SrcMAC[5]);
					break;
				}
			}
		}
	}
	add_ipmac(dstip, Second_Packet_Reply->FrameHeader.SrcMAC);    //可能有error的地方
	cout << endl;
	cout << "====================================================================================================" << endl;
	return Second_Packet_Reply->FrameHeader.SrcMAC;
}


//增删路由表项
void add_or_delete_item() {
	int state;
	char desip[20], mask[20], nextjump[20];
	while (1) {
		cout << "请选择你的操作:" << endl;
		cout << "1.增加路由表项" << endl;
		cout << "2.删除路由表项" << endl;
		cout << "3.查看路由表" << endl;
		cout << "4.退出" << endl;
		cin >> state;
		if (state == 1) {
			cout << "输入目的ip:";
			cin >> desip;
			cout << "输入子网掩码:";
			cin >> mask;
			cout << "输入下一跳步:";
			cin >> nextjump;
			add_item(inet_addr(desip), inet_addr(mask), inet_addr(nextjump));
		}
		else if (state == 2) {
			cout << "输入目的ip:";
			cin >> desip;
			cout << "输入子网掩码:";
			cin >> mask;
			cout << "输入下一跳步:";
			cin >> nextjump;
			delete_item(inet_addr(desip), inet_addr(mask), inet_addr(nextjump));
		}
		else if (state == 3)
			show_item();
		else if (state == 4)
			break;
		else {
			cout << "输入有误!" << endl;
			continue;
		}
	}
}



//转发信息(核心功能)
void router() {
	cout << "开始启动转发服务!" << endl;
	int i = 0;
	while (1) {
		pcap_pkthdr* header;
		const u_char* content;

		//接收、发送数据包成功
		while (1) {
			int result = pcap_next_ex(hand, &header, &content);
			if (result == 1) {
				break;
			}
		}

		Ethernet_Header* et_header = new Ethernet_Header;
		et_header = (Ethernet_Header*)content;
		bool flag1 = true;
		bool flag2 = true;

		//判断数据包是否和自己有关
		for (int i = 0; i < 6; i++) {
			if (local_MAC[i] != et_header->DesMAC[i]) {
				flag1 = false;
				break;
			}
		}

		for (int i = 0; i < 6; i++) {
			if (local_MAC[i] != et_header->SrcMAC[i]) {
				flag2 = false;
				break;
			}
		}


		//与自己无关，扔掉（捕获到没用的数据包）
		if (!flag1 && !flag2)
			continue;

		//数据包为IP类型
		if (ntohs(et_header->FrameType) == 0x0800) {
			IP_Packet* ip_packet = new IP_Packet;
			ip_packet = (IP_Packet*)content;
			if (ip_packet->IPHeader.SrcIP != inet_addr("206.1.1.2") && ip_packet->IPHeader.SrcIP != inet_addr("206.1.3.2") && ip_packet->IPHeader.DstIP != inet_addr("206.1.3.2") && ip_packet->IPHeader.DstIP != inet_addr("206.1.1.2"))
				continue;
			i++;

			
			//检查校验和
			if (!verify_checksum(&(ip_packet->IPHeader))) {
				cout << "校验和错误!" << endl;
				continue;
			}

			print_iplog(ip_packet);

			int result = find_item(ip_packet->IPHeader.DstIP);

			cout << "这里是测试用的result:" << result << endl;
			//查不到
			if (result == 0) {
				cout << "查询不到对应的路由表项!" << endl;
				continue;
			}

			//直接投递
			else if (result == -1) {
				cout << "直接投递!" << endl;
				u_char* dstMAC = find_mac(ip_packet->IPHeader.DstIP);

				//查不到MAC地址
				if (dstMAC == 0) {
					cout << "表中查询不到MAC地址，开始获取" << endl;
					dstMAC = get_mac(ip_packet->IPHeader.DstIP);
					if (dstMAC == 0) {
						cout << "获取MAC失败!" << endl;
						continue;
					}
				}

				//查到了MAC地址
				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.DesMAC[i] = dstMAC[i];
				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.SrcMAC[i] = local_MAC[i];

				//计算校验和
				calculate_checksum(&ip_packet->IPHeader);

				if (pcap_sendpacket(hand, (u_char*)ip_packet, header->len) != 0)
					cout << "转发失败!" << endl;
				else
					cout << "转发成功!" << endl;
				print_iplog(ip_packet);
			}

			//查到对应表项
			else {
				cout << "查到对应路由表项!" << endl;
				u_char* dstMAC = find_mac(ip_packet->IPHeader.DstIP);
				if (dstMAC == 0) {
					cout << "表中查询不到MAC地址，开始获取" << endl;
					dstMAC = get_mac(ip_packet->IPHeader.DstIP);
					if (dstMAC == 0) {
						cout << "获取MAC失败!" << endl;
						continue;
					}
				}

				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.DesMAC[i] = dstMAC[i];
				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.SrcMAC[i] = local_MAC[i];

				if (pcap_sendpacket(hand, (u_char*)ip_packet, header->len) != 0)
					cout << "转发失败!" << endl;
				else
					cout << "转发成功!" << endl;
				print_iplog(ip_packet);
			}
		}

		//数据包类型为ARP类型
		if (ntohs(et_header->FrameType) == 0x0806) {
			ARP_Packet* arp_packet = new ARP_Packet;
			arp_packet = (ARP_Packet*)content;
			if (arp_packet->SendIP != inet_addr("206.1.1.2") && arp_packet->SendIP != inet_addr("206.1.3.2") && arp_packet->RecvIP != inet_addr("206.1.3.2") && arp_packet->RecvIP != inet_addr("206.1.1.2"))
				continue;
			i++;
			print_arplog(arp_packet);
		}
	}
	return;
}


int main() {
	//发现设备并打开所选网卡
	find_and_open_devs();

	//捕获所选网卡的MAC地址
	get_local_mac();

	//添加默认路由表项
	for (int i = 0; i < ip_num; i++)
		router_table.push_back(Router_Table_Item(local_ip[i] & local_mask[i], local_mask[i], 0, 1));

	//添加路由表项
	add_item(inet_addr("206.1.3.0"), inet_addr("255.255.255.0"), inet_addr("206.1.2.2"));

	//增删路由表项
	add_or_delete_item();

	//作为路由器转发消息
	router();

	//释放设备列表
	pcap_freealldevs(alldevs);
	return 0;
}