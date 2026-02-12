# IPFIRE-wall test set up

We will use iperf3 test tool with the firewall running on the client side.

We will then set up *network namespaces* and *virtual interfaces* to simulate 
proper `forwarding`.

## 1. BASE TEST – sanity check

Goal: confirm connectivity and basic throughput.

Duration: short, low load.

#### Receiver (server side):

on host `taeyang`

> iperf3 -s -p 5201

#### Sender (client running IPFIRE-wall)

TCP:

iperf3 -c <receiver_ip> -p 5201 -t 10 -P 1


UDP:

on host `dal`

> iperf3 -c dal.elettra.eu  -p 5201 -u -b 100M -t 10

##### without 

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   119 MBytes   100 Mbits/sec  0.000 ms  0/86336 (0%)  sender
[  5]   0.00-10.00  sec   119 MBytes   100 Mbits/sec  0.005 ms  0/86336 (0%)  receiver
```

##### with

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   119 MBytes   100 Mbits/sec  0.000 ms  0/86336 (0%)  sender
[  5]   0.00-10.00  sec   119 MBytes   100 Mbits/sec  0.006 ms  0/86336 (0%)  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   119 MBytes   100 Mbits/sec  0.000 ms  0/86336 (0%)  sender
[  5]   0.00-10.00  sec   119 MBytes   100 Mbits/sec  0.001 ms  0/86336 (0%)  receiver
```

What to measure: throughput, packet loss (UDP), jitter (UDP), basic CPU usage.

## 2 MODERATE TEST – multiple streams / bigger bandwidth

Goal: simulate heavier use, closer to real-world load.

Duration: medium, multiple streams.

What to measure: throughput, packet loss/jitter, CPU spikes on sender, receiver, firewall.

Sender:

### TCP:

> iperf3 -c taeyang.elettra.eu  -p 5201 -t 30 -P 4

##### Notes:

-P 4 → 4 parallel TCP streams; better saturates link

##### without 

Test #1

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   829 MBytes   232 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   829 MBytes   232 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   829 MBytes   232 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   830 MBytes   232 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   829 MBytes   232 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   929 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.24 GBytes   927 Mbits/sec                  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   832 MBytes   232 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   929 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.24 GBytes   928 Mbits/sec                  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   931 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.25 GBytes   929 Mbits/sec                  receiver
```

#### With

> iperf3 -c taeyang.elettra.eu  -p 5201 -t 30 -P 4

Test #1

```
[OK] OUT: [eno1] |TCP| 192.168.205.245:42278-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:42278 |S|A|SETUP OK [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42278-->192.168.205.25:targus-getdata1 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42278-->192.168.205.25:targus-getdata1 |P|A|EST [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:42278 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42294-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:42294 |S|A|SETUP OK [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42294-->192.168.205.25:targus-getdata1 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42294-->192.168.205.25:targus-getdata1 |P|A|EST [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:42294 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42296-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:42296 |S|A|SETUP OK [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42296-->192.168.205.25:targus-getdata1 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42296-->192.168.205.25:targus-getdata1 |P|A|EST [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:42296 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:42308-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
```


Test #1

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   930 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.24 GBytes   929 Mbits/sec                  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   831 MBytes   232 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   830 MBytes   232 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   930 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.24 GBytes   928 Mbits/sec                  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   832 MBytes   233 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   831 MBytes   232 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   931 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.24 GBytes   929 Mbits/sec                  receiver
```


### UDP:

> iperf3 -c taeyang.elettra.eu -p 5201 -u -b 500M -t 30

UDP bandwidth -b increased; watch for packet drops

##### without

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294936 (0%)  sender
[  5]   0.00-31.63  sec  1.60 GBytes   436 Mbits/sec  0.012 ms  67/1189648 (0.0056%)  receiver
```


Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294937 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.013 ms  0/1294937 (0%)  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294903 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.023 ms  67/1294903 (0.0052%)  receiver
```

##### with

```
[OK] OUT: [eno1] |UDP| 192.168.205.245:34283-->192.168.205.25:targus-getdata1  [me -> the UDP world]
[OK] IN:  [eno1] |UDP| 192.168.205.25:targus-getdata1-->192.168.205.245:34283 STREAM [me -> the UDP world]
[OK] OUT: [eno1] |UDP| 192.168.205.245:34283-->192.168.205.25:targus-getdata1 STREAM [me -> the UDP world]
```

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294921 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.011 ms  295/1294921 (0.023%)  receiver
```


Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294940 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.032 ms  12/1294940 (0.00093%)  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294935 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.019 ms  55/1294935 (0.0042%)  receiver
```

## 3. STRESS TEST – push to limits

Goal: max out the network/firewall; see failure point.

Duration: longer, high load, high parallelism.

Sender:

### TCP:

> iperf3 -c taeyang.elettra.eu  -p 5201 -t 60 -P 8

##### without

Test #1

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4547            sender
[  5]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4562            sender
[  7]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4583            sender
[  9]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4720            sender
[ 11]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4539            sender
[ 13]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4712            sender
[ 15]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4495            sender
[ 17]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4581            sender
[ 19]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.44 GBytes   921 Mbits/sec  36739             sender
[SUM]   0.00-60.00  sec  6.43 GBytes   920 Mbits/sec                  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4643            sender
[  5]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4657            sender
[  7]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4697            sender
[  9]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4632            sender
[ 11]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4611            sender
[ 13]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4654            sender
[ 15]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4689            sender
[ 17]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4637            sender
[ 19]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.48 GBytes   928 Mbits/sec  37220             sender
[SUM]   0.00-60.00  sec  6.48 GBytes   927 Mbits/sec                  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4703            sender
[  5]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4672            sender
[  7]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4700            sender
[  9]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4797            sender
[ 11]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4604            sender
[ 13]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4764            sender
[ 15]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4690            sender
[ 17]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4733            sender
[ 19]   0.00-60.00  sec   827 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.47 GBytes   926 Mbits/sec  37663             sender
[SUM]   0.00-60.00  sec  6.46 GBytes   925 Mbits/sec                  receiver
```

##### with

Test #1

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4711            sender
[  5]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4469            sender
[  7]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4577            sender
[  9]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4639            sender
[ 11]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4617            sender
[ 13]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4696            sender
[ 15]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4591            sender
[ 17]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4759            sender
[ 19]   0.00-60.00  sec   826 MBytes   115 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.46 GBytes   925 Mbits/sec  37059             sender
[SUM]   0.00-60.00  sec  6.45 GBytes   924 Mbits/sec                  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4626            sender
[  5]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4633            sender
[  7]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4753            sender
[  9]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4693            sender
[ 11]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4529            sender
[ 13]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4622            sender
[ 15]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   828 MBytes   116 Mbits/sec  4700            sender
[ 17]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   827 MBytes   116 Mbits/sec  4612            sender
[ 19]   0.00-60.00  sec   826 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.46 GBytes   925 Mbits/sec  37168             sender
[SUM]   0.00-60.00  sec  6.46 GBytes   924 Mbits/sec                  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4663            sender
[  5]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4776            sender
[  7]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4711            sender
[  9]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4719            sender
[ 11]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4688            sender
[ 13]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4624            sender
[ 15]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4624            sender
[ 17]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   824 MBytes   115 Mbits/sec  4645            sender
[ 19]   0.00-60.00  sec   823 MBytes   115 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.44 GBytes   921 Mbits/sec  37450             sender
[SUM]   0.00-60.00  sec  6.43 GBytes   920 Mbits/sec                  receiver
```

### UDP:

iperf3 -c <receiver_ip> -p 5201 -u -b 2G -t 60

##### without

Test #1

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.42 GBytes   776 Mbits/sec  0.000 ms  0/4021475 (0%)  sender
[  5]   0.00-60.00  sec  5.42 GBytes   776 Mbits/sec  0.047 ms  1010/4021431 (0.025%)  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.44 GBytes   779 Mbits/sec  0.000 ms  0/4035884 (0%)  sender
[  5]   0.00-60.00  sec  5.44 GBytes   779 Mbits/sec  0.054 ms  777/4035838 (0.019%)  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.41 GBytes   775 Mbits/sec  0.000 ms  0/4015225 (0%)  sender
[  5]   0.00-60.00  sec  5.41 GBytes   775 Mbits/sec  0.019 ms  1209/4015220 (0.03%)  receiver
```

##### With

Test #1

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.35 GBytes   765 Mbits/sec  0.000 ms  0/3963938 (0%)  sender
[  5]   0.00-60.00  sec  5.34 GBytes   765 Mbits/sec  0.013 ms  774/3963925 (0.02%)  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.34 GBytes   765 Mbits/sec  0.000 ms  0/3963185 (0%)  sender
[  5]   0.00-60.00  sec  5.34 GBytes   765 Mbits/sec  0.013 ms  798/3963185 (0.02%)  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.36 GBytes   767 Mbits/sec  0.000 ms  0/3974821 (0%)  sender
[  5]   0.00-60.00  sec  5.36 GBytes   767 Mbits/sec  0.028 ms  1324/3974821 (0.033%)  receiver
```

## Optional test

Optional extreme variant: UDP flood at “unlimited” bandwidth (on lab links only!):

iperf3 -c <receiver_ip> -p 5201 -u -b 0 -t 60


-b 0 → as fast as possible

What to measure:

max sustainable throughput

packet loss and jitter curves

firewall CPU & state table saturation

receiver CPU & NIC queue drops

## iperf3 across network namespaces and forwarding (locally)

Execute *setup_lab_test.sh* from the *test/* directory:

> test/setup_lab_test.sh

On namespace *ns2* (server)

>  sudo  ip netns exec ns2 iperf3 -s

On namespace *ns1* (client)

> sudo ip netns exec ns1 iperf3 -c 10.0.2.2 -u -b 500M

#### Without IPFIRE-wall

Test #1

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431670 (0%)  sender
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.001 ms  0/431670 (0%)  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431639 (0%)  sender
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.008 ms  138/431639 (0.032%)  receiver
```

Test #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431665 (0%)  sender
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.001 ms  0/431665 (0%)  receiver
```

#### With

```
[OK] FWD: [veth1->veth2] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |S| [all FWD to iperf3]
[OK] IN:  [veth2-ns] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |S|STATE: 68 [all out to iperf3 (P5201)]
[OK] OUT: [veth2-ns] |TCP| 10.0.2.2:targus-getdata1-->10.0.1.2:58270 |S|A|STATE: 67 [all out to iperf3 (P5201)]
[OK] FWD: [veth2->veth1] |TCP| 10.0.2.2:targus-getdata1-->10.0.1.2:58270 |S|A|STATE: 69 [all FWD to iperf3]
[OK] IN:  [veth1-ns] |TCP| 10.0.2.2:targus-getdata1-->10.0.1.2:58270 |S|A|STATE: 64 [all out to iperf3 (P5201)]
[OK] OUT: [veth1-ns] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |A|EST? [all out to iperf3 (P5201)]
[OK] FWD: [veth1->veth2] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |A|EST [all FWD to iperf3]
[OK] IN:  [veth2-ns] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |A|STATE: 70 [all out to iperf3 (P5201)]
[OK] OUT: [veth1-ns] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |P|A|EST [all out to iperf3 (P5201)]
[OK] FWD: [veth1->veth2] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |P|A|EST [all FWD to iperf3]
[OK] IN:  [veth2-ns] |TCP| 10.0.1.2:58270-->10.0.2.2:targus-getdata1 |P|A|STATE: 70 [all out to iperf3 (P5201)]
```

Test #1

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431636 (0%)  sender
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.001 ms  0/431636 (0%)  receiver
```

Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431678 (0%)  sender
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431678 (0%)  receiver
```

Test #3

```
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431668 (0%)  sender
[  5]   0.00-10.00  sec   596 MBytes   500 Mbits/sec  0.000 ms  0/431668 (0%)  receiver
```


## PPS Apocalypse (Small Packet Storm)

Bandwidth lies. Packets per second tell the truth.

Small packets hammer:

1.  rule lookup

1.  state tracking

1. cache efficiency

1. lock contention

Test

> ip netns exec ns1 iperf3 -c 10.0.2.2 -u -b 1G -l 64 -t 60


Why this hurts:

1. 64-byte payload

1. very high PPS

1. routing + firewall per packet cost explodes

If your firewall scales badly, CPU will peg long before 1G is reached.

#### Without

> sudo ip netns exec ns1 iperf3 -c 10.0.2.2 -u -b 1G -l 64 -t 60

Run #1

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  3.79 GBytes   542 Mbits/sec  0.000 ms  0/63552091 (0%)  sender
[  5]   0.00-60.00  sec  3.79 GBytes   542 Mbits/sec  0.001 ms  15362/63552091 (0.024%)  receiver
```

Run #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  3.80 GBytes   543 Mbits/sec  0.000 ms  0/63677077 (0%)  sender
[  5]   0.00-60.00  sec  3.80 GBytes   543 Mbits/sec  0.001 ms  6722/63677077 (0.011%)  receiver
```

#### With

Run #1
```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec   810 MBytes   113 Mbits/sec  0.000 ms  0/13270399 (0%)  sender
[  5]   0.00-60.00  sec   810 MBytes   113 Mbits/sec  0.001 ms  45/13270399 (0.00034%)  receiver
```

Run #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec   806 MBytes   113 Mbits/sec  0.000 ms  0/13209027 (0%)  sender
[  5]   0.00-60.00  sec   806 MBytes   113 Mbits/sec  0.001 ms  1655/13209027 (0.013%)  receiver
```


Run #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec   826 MBytes   115 Mbits/sec  0.000 ms  0/13532077 (0%)  sender
[  5]   0.00-60.00  sec   826 MBytes   115 Mbits/sec  0.001 ms  0/13532077 (0%)  receiver
```

