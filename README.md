# tcpkill6
[tcpkill](https://linux.die.net/man/8/tcpkill) with IPv6 support. See [this post](https://hechao.li/2019/10/14/Tcpkill-for-IPv6/) for more information.

## Requirements
* libpcap
* libnet

## Build
```
$ make tcpkill6
```

## Run
```
$ sudo ./tcpkill6 -i eth0 port 5201
```
