TCP Lifetime
----
SOCKET\_FILTER example program for show duration of TCP sessions. For Linux, uses libbpf

# Build
```shellsession
$ git clone https://github.com/shun159/tcp_lifetime
$ cargo build
```

# Usage
```shellsession
$ sudo target/debug/tcp_lifetime
libbpf: elf: skipping unrecognized data section(11) .rodata.str1.1
           time            |    pid     |       comm       |          src          →          dst          |  duration  
2021/08/26 13:24:30 +09:00 |  1332040   |       curl       | 192.168.3.29:50428    → 172.217.175.36:80     |      105 ms
2021/08/26 13:24:30 +09:00 |  1332040   |       curl       | 192.168.3.29:57224    → 172.217.175.110:80    |      169 ms
2021/08/26 13:24:45 +09:00 |   32661    | Chrome_ChildIOT  | 192.168.3.29:59870    → 118.215.181.174:443   |      416 ms
2021/08/26 13:25:11 +09:00 |  1332450   |      cargo       | 172.17.0.2:34150      → 13.249.162.107:443    |     1712 ms
2021/08/26 13:25:11 +09:00 |  1332450   |      cargo       | 172.17.0.2:47742      → 13.225.159.78:443     |     2199 ms
2021/08/26 13:25:12 +09:00 |   32661    | Chrome_ChildIOT  | 192.168.3.29:48030    → 64.233.189.188:5228   |     3160 ms
```

