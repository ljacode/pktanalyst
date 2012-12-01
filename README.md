计划写一个分析网络报文的东西。最终会成为什么样子，我也不清楚。

它处理的是最原始的报文（在线路上传输的报文）。

pktanalyst依赖libpcap.

当前的原始报文是通过pcap获取的，在这里pcap的作用仅局限于此，可以很方便的被替换。

pktanalyst还依赖ljac。

更确切的讲，是将一些比较通用的函数在ljac中实现了，这样做是为了扩充ljac，方便在其它地方使用。所以或许可以将pktanalyst看作ljac的一个使用实例...

obj/          编译时生成的中间文件
main.c        main函数所在的文件
makefile      可以根据自己的情况修改对应的ljac或者pcap的路径
