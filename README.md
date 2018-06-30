# WFP Traffic Redirection Driver

_WFP Traffic Redirection Driver_ is used to redirect NIC traffic on network layer and framing layer, based on Windows Filtering Platform (WFP).

This project is forked from [Windows Filtering Platform Traffic Inspection Sample](https://github.com/Microsoft/Windows-driver-samples/tree/master/network/trans/inspect).

## Features

- Flexible & configurable
- Anti _traffic sniffing_ (WinPcap/Npcap/Rawsock Sniffing)

## How to build/deploy

### Requirements

- Visual Studio 2017
- Windows Driver Kit 10

### Steps to build/deploy

1. Build `.vcxproj` in Visual Studio on _host computer_
2. Enable _test signing_ on _target computer_
3. Install `.cer` (Certificate) and `.inf` (Driver Config) on _target computer_

> For more, see [Windows Filtering Platform Traffic Inspection Sample](https://github.com/Microsoft/Windows-driver-samples/tree/master/network/trans/inspect).

## How to use

### Setup Registries

Setup values under the key:

```
HKLM\System\CurrentControlSet\Services\inspect\Parameters
```

All values are shown in the following table:

Value                 | Type      | Example
----------------------|-----------|------------------
LocalRealAddress      | REG_SZ    | 10.109.16.202
LocalFakeAddress      | REG_SZ    | 10.109.19.108
RemoteRealAddress     | REG_SZ    | 10.109.18.799
RemoteFakeAddress     | REG_SZ    | 10.109.17.253
LocalRealPort         | REG_DWORD | 80
LocalFakePort         | REG_DWORD | 202
RemoteRealPort        | REG_DWORD | 80
RemoteFakePort        | REG_DWORD | 799
LocalEthernetAddress  | REG_SZ    | 74-27-ea-00-00-02
RemoteEthernetAddress | REG_SZ    | 74-27-ea-00-00-03

Note that:

- _Address_, _Port_ and _EthernetAddress_ stand for IP address, TCP/UDP port and ethernet MAC address respectively.
- _Local_ means _src of outbound_ / _dst of inbound_ traffic, while _Remote_ means _dst of outbound_ / _src of inbound_ traffic.
- For _outbound traffic_, _Real_ address/port are replaced with _Fake_; for _inbound traffic_, _Fake_ address/port are restored by _Real_.
- Config cascade:
  - _Port_ values are used at network layer only if enabling _RemoteAddress_ modification.
  - Value `LocalEthernetAddress` and `RemoteEthernetAddress` are used for _outbound traffic_ at framing layer only if enabling _LocalAddress_ modification.
- Setting value of zero (`0.0.0.0`/`0`/`00-00-00-00-00-00`) will disable address/port modification.

### Start/Stop driver

- Run `net start inspect` as administrator to start the driver service
- Run `net stop inspect` as administrator to stop the driver service

## Internals

Key ideas are posted by _BOT Man_ in **Chinese**:

- [Learn TCP/IP from WFP 1](https://bot-man-jl.github.io/articles/?post=2018/Learn-TCP-IP-from-WFP-1)
- [Learn TCP/IP from WFP 2](https://bot-man-jl.github.io/articles/?post=2018/Learn-TCP-IP-from-WFP-2)
- [Anonymous Communication Client Design](https://bot-man-jl.github.io/articles/?post=2018/Anonymous-Communication-Client-Design)

### ./sys

- `tl_drv.c`: entry and init
- `protocol-headers.h`: Ethernet/IPv4/ICMP/TCP/UDP header
- `inspect.h/c`: handle classification/reinjection logic
- `util.h/c`: helper functions
- `inspect.inf`: driver config

### ./helpers

- _enable-promisc_: enable _Promisc Mode_ on all NICs (based on wpcap)
  - `enable-promisc.exe`: calling pcap_findalldevs_ex
  - `wpcap.dll`: modified pcap_activate_win32
- `check-promisc.ps1`: check if all NICs in _Promisc Mode_
- `restart-nic.bat`: restart NIC `以太网`
- `enable-dbgprint.reg`: enable `dbgprint` on DbgView (use once)
- `enable-testsigning.bat:` enable test signing (use once)

## License

Copyright (C) 2018  BOT Man

GPL-3.0 License