# tcpkill6
[tcpkill](https://linux.die.net/man/8/tcpkill) with IPv6 support. See [this post](https://hechao.li/2019/10/14/Tcpkill-for-IPv6/) for more information.

# BLUF
```
cd project_root && make

# make install  -- installs dependencies
# make tcpkill  -- make standard tcpkill
# make tcpkill6 -- make tcpkill6 for ipv6
```

## Requirements
* libpcap
* libnet
```
# in
project_root/dependencies
```

## Build
```
$ make tcpkill6
```

## Run
```
$ sudo ./tcpkill6 -i eth0 port 5201
```
