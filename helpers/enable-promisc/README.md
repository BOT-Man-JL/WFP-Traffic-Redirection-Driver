# Enable Promisc Tool

> A tool to enable promisc mode on all NICs, based on WinPcap SDK

## How to run

- install WinPcap/Npcap (WinPcap Compatible)
- run enable-promisc.exe

## Internals

### wpcap.dll

``` cpp
// in function pcap_activate_win32
  PacketSetHwFilter(p->adapter, NDIS_PACKET_TYPE_PROMISCUOUS);
  return 0;
```

### enable-promisc.exe

``` cpp
// in function main
  pcap_if_t* alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
```
