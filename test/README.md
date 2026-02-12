# IPFIRE-wall test set up

## BASE TEST – sanity check

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

2️⃣ MODERATE TEST – multiple streams / bigger bandwidth

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
```


### UDP:

iperf3 -c <receiver_ip> -p 5201 -u -b 500M -t 30

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

3️⃣ STRESS TEST – push to limits

Goal: max out the network/firewall; see failure point.

Duration: longer, high load, high parallelism.

Sender:

### TCP:

iperf3 -c <receiver_ip> -p 5201 -t 60 -P 8

##### without

Test #1

```
```

Test #2

```
```

Test #3

```
```

##### with

Test #1

```
```

Test #2

```
```

Test #3

```
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


Optional extreme variant: UDP flood at “unlimited” bandwidth (on lab links only!):

iperf3 -c <receiver_ip> -p 5201 -u -b 0 -t 60


-b 0 → as fast as possible

What to measure:

max sustainable throughput

packet loss and jitter curves

firewall CPU & state table saturation

receiver CPU & NIC queue drops
