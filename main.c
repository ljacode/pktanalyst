#include  "ljapkt.h"
#include  "ljapcap.h"
#include  <stdio.h>
#include  <assert.h>
#include  <string.h>

#define FILTER_SIZE 1024

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
	int count=50;

	int devnum;
	int chose = -1;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *tmp = NULL;
	int re;

	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net; 
	char *filter = (char *)malloc(FILTER_SIZE);
	memset(filter,'\0',FILTER_SIZE);

	if(argc > 0){
		tmp = filter;
		for(i=1; i<argc; i++)
		{
			snprintf(tmp,FILTER_SIZE,"%s ",argv[i]);
			tmp+=strlen(tmp);
		}
	}


	if(-1==pcap_findalldevs(&devs,errbuf)){
		fprintf(stderr,"Error %s %d\n",__FILE__,__LINE__);
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
	printf("filter: %s \n",filter);

	handle=pcap_open_live(dev->name,65536,0,1000,errbuf);
	if(handle == NULL)
	{
		fprintf(stderr,"Failed pcap_open_live %s:%d\n",__FILE__,__LINE__);
		goto EXIT;
	}

	if(pcap_lookupnet(dev->name,&net,&mask,errbuf) == -1)
	{
		fprintf(stderr,"Failed pcap_lookupnet %s:%d %s\n",__FILE__,__LINE__,errbuf);
		goto EXIT;
	}

	if(pcap_compile(handle,&fp,filter,1,net) == -1)
	{
		fprintf(stderr,"Failed pcap_compile %s:%d  %s\n",__FILE__,__LINE__,pcap_geterr(handle));
		goto EXIT;
	}

	if(pcap_setfilter(handle,&fp) == -1)
	{
		fprintf(stderr,"Failed pcap_setfilter %s:%d %s\n",__FILE__,__LINE__,pcap_geterr(handle));
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
	free(filter);
	return 0;
}
