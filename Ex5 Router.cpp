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


//ȫ�ֱ���
vector<Router_Table_Item> router_table;    //·�ɱ�
vector<IP_MAC> ip_mac;    //ip��mac��Ӧ��ϵ
pcap_if_t* alldevs;    //ָ���豸�����ײ���ָ��
pcap_if_t* d;
pcap_addr_t* a;
int ip_num = 0;    //ip����
u_long* local_ip;    //����������ip
u_long* local_mask;    //������������������
BYTE local_MAC[6];    //����������MAC��ַ
pcap_t* hand;
char* t = new char[25];    //�洢ʱ��


//��ȡʱ��
void get_time(char* get_time) {
	struct tm stime;
	time_t now = time(0);
	localtime_s(&stime, &now);
	strftime(get_time, 25, "%Y-%m-%d %H:%M:%S", &stime);
	return;
}


//ת��ip
string getIP(u_long ip) {
	in_addr addr;
	memcpy(&addr, &ip, sizeof(ip));
	string result_ip = inet_ntoa(addr);
	return result_ip;
}


//IP���ݱ���־���
void print_iplog(IP_Packet* ip_packet) {
	get_time(t);
	cout << "====================================================================================================" << endl;
	cout << "[log]" << t << endl;
	cout << "���ݰ�����:" << "IP" << endl;
	cout << "ԴMAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", ip_packet->FrameHeader.SrcMAC[i]);
	}
	printf("%02x", ip_packet->FrameHeader.SrcMAC[5]);

	cout << endl;

	cout << "Ŀ��MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", ip_packet->FrameHeader.DesMAC[i]);
	}
	printf("%02x", ip_packet->FrameHeader.DesMAC[5]);

	cout << endl;

	cout << "ԴIP:";
	cout << getIP(ip_packet->IPHeader.SrcIP) << endl;
	cout << "Ŀ��IP:";
	cout << getIP(ip_packet->IPHeader.DstIP) << endl;
	cout << "====================================================================================================" << endl;
	return;
}


//ARP���ݱ���־���
void print_arplog(ARP_Packet* arp_packet) {
	get_time(t);
	cout << "====================================================================================================" << endl;
	cout << "[log]" << t << endl;
	cout << "���ݰ�����:" << "ARP" << endl;
	cout << "ԴMAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", arp_packet->FrameHeader.SrcMAC[i]);
	}
	printf("%02x", arp_packet->FrameHeader.SrcMAC[5]);

	cout << endl;

	cout << "Ŀ��MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02x:", arp_packet->FrameHeader.DesMAC[i]);
	}
	printf("%02x", arp_packet->FrameHeader.DesMAC[5]);

	cout << endl;

	cout << "ԴIP:";
	cout << getIP(arp_packet->SendIP) << endl;
	cout << "Ŀ��IP:";
	cout << getIP(arp_packet->RecvIP) << endl;
	cout << "====================================================================================================" << endl;
	return;
}


//����У���
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


//��֤У���
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


//����Ԫ���������
bool cmp(Router_Table_Item item1, Router_Table_Item item2) {
	return item1.Netmask > item2.Netmask;
}

//���·�ɱ���
void add_item(u_long ip, u_long mask, u_long jump) {
	Router_Table_Item item(ip, mask, jump, 0);
	router_table.push_back(item);
	sort(router_table.begin(), router_table.end(), cmp);
	return;
}


//ɾ��·�ɱ���
void delete_item(u_long ip, u_long mask, u_long jump) {
	for (int i = 0; i < router_table.size(); i++) {
		if (router_table[i].DesIP == ip && router_table[i].Netmask == mask && router_table[i].Nextjump == jump) {
			if (router_table[i].is_default == 0) {
				router_table.erase(router_table.begin() + i);
			}
			else {
				cout << "Ŀ��ΪĬ��·�ɱ��ɾ��ʧ��!" << endl;
				return;
			}
		}
		else {
			cout << "û���ҵ���Ӧ��·�ɱ��ɾ��ʧ��!" << endl;
			return;
		}
	}
}


//���·�ɱ�
void show_item() {
	cout << setw(15) << "Ŀ��IP" << setw(15) << "��������" << setw(15) << "��һ����" << endl;
	cout << "====================================================================" << endl;
	for (int i = 0; i < router_table.size(); i++)
		cout << setw(15) << getIP(router_table[i].DesIP) << setw(15) << getIP(router_table[i].Netmask) << setw(15) << getIP(router_table[i].Nextjump) << endl;
	return;
}


//����·�ɱ�
int find_item(u_long dstip) {
	for (int i = 0; i < router_table.size(); i++) {
		if ((dstip & router_table[i].Netmask) == router_table[i].DesIP) {
			if (router_table[i].Nextjump != 0)
				return router_table[i].Nextjump;
			else
				return -1;    //ֱ��Ͷ��
		}
	}

	//û�в鵽
	return 0;
}


//���IP-MAC��Ӧ��ϵ
void add_ipmac(u_long ip, u_char* mac) {
	IP_MAC item(ip, mac);
	ip_mac.push_back(item);
	return;
}


//����IP�ҵ���Ӧ��MAC��ַ
u_char* find_mac(u_long ip) {
	u_char* result = 0;
	for (int i = 0; i < ip_mac.size(); i++) {
		if (ip == ip_mac[i].ip) {
			result = ip_mac[i].mac;
		}
	}
	return result;
}



//�ҵ������û�ָ��������
void find_and_open_devs() {
	bool flag = false;
	char errbuf[PCAP_ERRBUF_SIZE];    //������Ϣ������
	vector<string> ip_address_set;


	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1) {    //������
		cout << "Error! Can't get information!" << endl;
	}

	int dev_num = 0;    //�����豸��Ŀ
	int request_num, count = 1;    //request_numΪ�û����룬Ҫ�󲶻�ڼ����豸�����ݰ���count���ڴ��豸�����б������ж��Ƿ񵽴��û�Ҫ����豸


	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		dev_num++;
		string name = d->name;		//����d->name��ȡ������ӿ��豸������
		string description = d->description;		//����d->description��ȡ������ӿ��豸��������Ϣ


		//�����Ϣ
		cout << "�豸����:" << name << endl;
		cout << "������Ϣ:" << description << endl;


		//��ȡ������ӿ��豸��IP��ַ��Ϣ
		for (a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				flag = true;
				printf("%s%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				ip_address_set.push_back(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			}
		}
		if (flag == false)
			ip_address_set.push_back("û��IPv4��ַ");
		flag = false;
		cout << endl;
	}


	//�û�������Ҫ�����Ľӿ�
	cout << endl;
	cout << "������ѡ�������:";
	while (1) {
		cin >> request_num;
		if (request_num > dev_num || request_num <= 0)
			cout << "�������!" << endl;
		else {
			break;
		}
	}

	cout << "====================================================================================================" << endl;

	//�������û���Ҫ���豸
	for (d = alldevs; count != request_num; count++)
		d = d->next;

	//������ӿ�
	hand = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (hand == NULL) {
		cout << "����ʧ��!" << endl;
		return;
	}
	cout << "���ڼ���:" << d->description << endl;
	return;
}


//��ȡ��ѡ����MAC��ַ
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
			//��ip��ַ����local_ip����
			local_ip[index] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			if (a->netmask)
			{
				//�������������local_mask����
				local_mask[index] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			}
			index++;
		}
	}
	cout << "��ѡ������ip��ַ����������ֱ�Ϊ:" << endl;
	for (int i = 0; i < index; i++)
		cout << "ip��ַ:" << getIP(local_ip[i]) << " | " << "��������:" << getIP(local_mask[i]) << endl;

	//����������������ѡ�������͵�ARP֡
	ARP_Packet First_Packet;

	//ARPFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC����Ϊ***��������***��MAC��ַ
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.SrcMAC[i] = 0x0f;

	//֡����ΪARP
	First_Packet.FrameHeader.FrameType = htons(0x0806);

	//Ӳ������Ϊ��̫��
	First_Packet.HardwareType = htons(0x0001);

	//Э������ΪIP
	First_Packet.ProtocolType = htons(0x0800);

	//Ӳ����ַ����Ϊ6
	First_Packet.HLen = 6;

	//Э���ַ����Ϊ4
	First_Packet.PLen = 4;

	//����ΪARP����
	First_Packet.Operation = htons(0x0001);

	//��SendHa����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		First_Packet.SendHa[i] = 0x0f;

	//��SendIP����Ϊ***��������***�󶨵�IP��ַ
	First_Packet.SendIP = inet_addr("192.192.192.192");

	//��RecvHa����Ϊ0��Ŀ��δ֪��
	for (int i = 0; i < 6; i++)
		First_Packet.RecvHa[i] = 0;

	//��RecvIP����Ϊ�����IP��ַ
	First_Packet.RecvIP = local_ip[0];


	//����ARP��
	pcap_sendpacket(hand, (u_char*)&First_Packet, sizeof(ARP_Packet));

	//����Ҫ����Ļظ���
	ARP_Packet* First_Packet_Reply;

	//����ظ�������ȡѡȡ������MAC��ַ
	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//ǿ������ת��
			First_Packet_Reply = (ARP_Packet*)content;
			if (First_Packet_Reply->RecvIP == inet_addr("192.192.192.192")) {    //ARP����
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (First_Packet_Reply->FrameHeader.DesMAC[i] != First_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//��׽���İ���ԴMACӦ������������MAC��ַ
				if (compare_flag) {
					for (int i = 0; i < 6; i++)
						local_MAC[i] = First_Packet_Reply->FrameHeader.SrcMAC[i];

					cout << "MAC��ַΪ:";
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

	//��·�ɱ��������·�ɱ���
	for (int i = 0; i < ip_num; i++) {
		add_ipmac(local_ip[i], local_MAC);
	}
	return;
}


//���Ŀ��ip��MAC��ַ
u_char* get_mac(u_long dstip) {
	//����ARP֡
	ARP_Packet arp_Packet;

	//ARPFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		arp_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC����Ϊ***��������***��MAC��ַ
	for (int i = 0; i < 6; i++)
		arp_Packet.FrameHeader.SrcMAC[i] = local_MAC[i];

	//֡����ΪARP
	arp_Packet.FrameHeader.FrameType = htons(0x0806);

	//Ӳ������Ϊ��̫��
	arp_Packet.HardwareType = htons(0x0001);

	//Э������ΪIP
	arp_Packet.ProtocolType = htons(0x0800);

	//Ӳ����ַ����Ϊ6
	arp_Packet.HLen = 6;

	//Э���ַ����Ϊ4
	arp_Packet.PLen = 4;

	//����ΪARP����
	arp_Packet.Operation = htons(0x0001);

	//��SendHa����Ϊѡȡ������MAC��ַ
	for (int i = 0; i < 6; i++)
		arp_Packet.SendHa[i] = local_MAC[i];

	//��SendIP����Ϊѡȡ�����󶨵�IP��ַ
	arp_Packet.SendIP = local_ip[0];

	//��RecvHa����Ϊ0��Ŀ��δ֪��
	for (int i = 0; i < 6; i++)
		arp_Packet.RecvHa[i] = 0;

	//��RecvIP����Ϊ�����IP��ַ
	arp_Packet.RecvIP = dstip;

	//����ARP��
	pcap_sendpacket(hand, (u_char*)&arp_Packet, sizeof(ARP_Packet));

	//����Ҫ����Ļظ���
	ARP_Packet* Second_Packet_Reply;

	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//ǿ������ת��
			Second_Packet_Reply = (ARP_Packet*)content;
			if (Second_Packet_Reply->RecvIP == local_ip[0]) {    //ARP����
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (Second_Packet_Reply->FrameHeader.DesMAC[i] != arp_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//��׽���İ���ԴMACӦ������������MAC��ַ
				if (compare_flag) {
					cout << "MAC��ַΪ:";
					for (int i = 0; i < 5; i++) {
						printf("%02x:", Second_Packet_Reply->FrameHeader.SrcMAC[i]);
					}
					printf("%02x", Second_Packet_Reply->FrameHeader.SrcMAC[5]);
					break;
				}
			}
		}
	}
	add_ipmac(dstip, Second_Packet_Reply->FrameHeader.SrcMAC);    //������error�ĵط�
	cout << endl;
	cout << "====================================================================================================" << endl;
	return Second_Packet_Reply->FrameHeader.SrcMAC;
}


//��ɾ·�ɱ���
void add_or_delete_item() {
	int state;
	char desip[20], mask[20], nextjump[20];
	while (1) {
		cout << "��ѡ����Ĳ���:" << endl;
		cout << "1.����·�ɱ���" << endl;
		cout << "2.ɾ��·�ɱ���" << endl;
		cout << "3.�鿴·�ɱ�" << endl;
		cout << "4.�˳�" << endl;
		cin >> state;
		if (state == 1) {
			cout << "����Ŀ��ip:";
			cin >> desip;
			cout << "������������:";
			cin >> mask;
			cout << "������һ����:";
			cin >> nextjump;
			add_item(inet_addr(desip), inet_addr(mask), inet_addr(nextjump));
		}
		else if (state == 2) {
			cout << "����Ŀ��ip:";
			cin >> desip;
			cout << "������������:";
			cin >> mask;
			cout << "������һ����:";
			cin >> nextjump;
			delete_item(inet_addr(desip), inet_addr(mask), inet_addr(nextjump));
		}
		else if (state == 3)
			show_item();
		else if (state == 4)
			break;
		else {
			cout << "��������!" << endl;
			continue;
		}
	}
}



//ת����Ϣ(���Ĺ���)
void router() {
	cout << "��ʼ����ת������!" << endl;
	int i = 0;
	while (1) {
		pcap_pkthdr* header;
		const u_char* content;

		//���ա��������ݰ��ɹ�
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

		//�ж����ݰ��Ƿ���Լ��й�
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


		//���Լ��޹أ��ӵ�������û�õ����ݰ���
		if (!flag1 && !flag2)
			continue;

		//���ݰ�ΪIP����
		if (ntohs(et_header->FrameType) == 0x0800) {
			IP_Packet* ip_packet = new IP_Packet;
			ip_packet = (IP_Packet*)content;
			if (ip_packet->IPHeader.SrcIP != inet_addr("206.1.1.2") && ip_packet->IPHeader.SrcIP != inet_addr("206.1.3.2") && ip_packet->IPHeader.DstIP != inet_addr("206.1.3.2") && ip_packet->IPHeader.DstIP != inet_addr("206.1.1.2"))
				continue;
			i++;

			
			//���У���
			if (!verify_checksum(&(ip_packet->IPHeader))) {
				cout << "У��ʹ���!" << endl;
				continue;
			}

			print_iplog(ip_packet);

			int result = find_item(ip_packet->IPHeader.DstIP);

			cout << "�����ǲ����õ�result:" << result << endl;
			//�鲻��
			if (result == 0) {
				cout << "��ѯ������Ӧ��·�ɱ���!" << endl;
				continue;
			}

			//ֱ��Ͷ��
			else if (result == -1) {
				cout << "ֱ��Ͷ��!" << endl;
				u_char* dstMAC = find_mac(ip_packet->IPHeader.DstIP);

				//�鲻��MAC��ַ
				if (dstMAC == 0) {
					cout << "���в�ѯ����MAC��ַ����ʼ��ȡ" << endl;
					dstMAC = get_mac(ip_packet->IPHeader.DstIP);
					if (dstMAC == 0) {
						cout << "��ȡMACʧ��!" << endl;
						continue;
					}
				}

				//�鵽��MAC��ַ
				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.DesMAC[i] = dstMAC[i];
				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.SrcMAC[i] = local_MAC[i];

				//����У���
				calculate_checksum(&ip_packet->IPHeader);

				if (pcap_sendpacket(hand, (u_char*)ip_packet, header->len) != 0)
					cout << "ת��ʧ��!" << endl;
				else
					cout << "ת���ɹ�!" << endl;
				print_iplog(ip_packet);
			}

			//�鵽��Ӧ����
			else {
				cout << "�鵽��Ӧ·�ɱ���!" << endl;
				u_char* dstMAC = find_mac(ip_packet->IPHeader.DstIP);
				if (dstMAC == 0) {
					cout << "���в�ѯ����MAC��ַ����ʼ��ȡ" << endl;
					dstMAC = get_mac(ip_packet->IPHeader.DstIP);
					if (dstMAC == 0) {
						cout << "��ȡMACʧ��!" << endl;
						continue;
					}
				}

				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.DesMAC[i] = dstMAC[i];
				for (int i = 0; i < 6; i++)
					ip_packet->FrameHeader.SrcMAC[i] = local_MAC[i];

				if (pcap_sendpacket(hand, (u_char*)ip_packet, header->len) != 0)
					cout << "ת��ʧ��!" << endl;
				else
					cout << "ת���ɹ�!" << endl;
				print_iplog(ip_packet);
			}
		}

		//���ݰ�����ΪARP����
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
	//�����豸������ѡ����
	find_and_open_devs();

	//������ѡ������MAC��ַ
	get_local_mac();

	//���Ĭ��·�ɱ���
	for (int i = 0; i < ip_num; i++)
		router_table.push_back(Router_Table_Item(local_ip[i] & local_mask[i], local_mask[i], 0, 1));

	//���·�ɱ���
	add_item(inet_addr("206.1.3.0"), inet_addr("255.255.255.0"), inet_addr("206.1.2.2"));

	//��ɾ·�ɱ���
	add_or_delete_item();

	//��Ϊ·����ת����Ϣ
	router();

	//�ͷ��豸�б�
	pcap_freealldevs(alldevs);
	return 0;
}