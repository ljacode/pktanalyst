#include  "ljapkt.h"
#include  "ljapcap.h"
#include  <stdio.h>
#include  <assert.h>


void deal_pcappkt(struct pcap_pkthdr *hdr,u_char *data)
{
	//TODO: 这里暂时使用局部变量保存各层的协议信息
	net_info netinfo;
	tran_info traninfo;
	app_info  appinfo;

	display_pcap_pkthdr(hdr);
	printf("\n");
	display_pcap_data(hdr,data);
	printf("\n");

	parse_data_linker(hdr->caplen,data,&netinfo);
	parse_net(&netinfo,&traninfo);
	parse_tran(&traninfo,&appinfo);
}

int main(int argc, char *argv[])
{
	pcap_if_t *devs;
	pcap_if_t *dev;
	pcap_t *handle;
	struct pcap_pkthdr *pcaphdr;
	u_char *pktdata;
	int count=5;

	int devnum;
	int chose = -1;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int re;

	if(-1==pcap_findalldevs(&devs,errbuf)){
		fprintf(stderr,"Error %s %n\n",__FILE__,__LINE__);
	}
	devnum = display_devs(devs);

	printf("Chose a dev[0-%d]:",devnum);
	scanf("%d",&chose);
	while(chose < 1 || chose > devnum){
		printf("Chose a dev[1-%d]:",devnum);
		scanf("%d",&chose);
	}

	dev=devs;
	for(i=1; i<chose; i++)
	{
		dev=dev->next;
	}
	
	display_dev(dev);

	handle=pcap_open_live(dev->name,65536,1,1000,errbuf);
	if(handle == NULL)
	{
		fprintf(stderr,"Failed pcap_open_live %s:%d\n",__FILE__,__LINE__);
		goto EXIT;
	}
	
	for(i=0; i<count; i++)
	{
		re=pcap_next_ex(handle,&pcaphdr,(const u_char**)&pktdata);
		switch (re)
		{
			case 1 :
				printf("\n========== %d [NORMAL]  ==========\n",i);
				break;
			case 0 :
				printf("\n========== %d [EXPIRED] ==========\n",i);
				break;
			case -1:
				printf("\n========== %d [ERROR]   ==========\n",i);
				printf("%s\n",pcap_geterr(handle));
				continue;
				break;
			default :
				fprintf(stderr,"Failed pcap_next_ex unknown value %s:%d\n",__FILE__,__LINE__);
				goto EXIT;
				break;
		}

		if(pcaphdr != NULL && pktdata != NULL)
		{
			deal_pcappkt(pcaphdr,pktdata);
		}else if(pcaphdr == NULL)
		{
			printf("pcaphdr is NULL!\n");
		}else
		{
			printf("pktdata is NULL!\n");
		}
	}

EXIT:
	pcap_freealldevs(devs);
	return 0;
}
