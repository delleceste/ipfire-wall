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

## 1 MODERATE TEST – multiple streams / somehow big bandwidth

Goal: simulate heavier use, closer to real-world load.

Duration: medium, multiple streams.

What to measure: throughput, packet loss/jitter, CPU spikes on sender, receiver, firewall.

Sender:

### TCP:

> iperf3 -c taeyang.elettra.eu  -p 5201 -t 30 -P 4

##### Notes:

-P 4 → 4 parallel TCP streams; better saturates link

##### without 

Three tests have been made, with equivalent results:

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

You can see the four parallel flows (look for SYN flag)

```
[OK] OUT: [eno1] |TCP| 192.168.205.245:41576-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:41576 |S|A|SETUP OK [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41576-->192.168.205.25:targus-getdata1 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41576-->192.168.205.25:targus-getdata1 |P|A|EST [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:41576 |A|EST [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:41576 |P|A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41588-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:41588 |S|A|SETUP OK [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41588-->192.168.205.25:targus-getdata1 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41588-->192.168.205.25:targus-getdata1 |P|A|EST [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:41588 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41602-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:41602 |S|A|SETUP OK [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41602-->192.168.205.25:targus-getdata1 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41602-->192.168.205.25:targus-getdata1 |P|A|EST [me -> all the world!]
[OK] IN:  [eno1] |TCP| 192.168.205.25:targus-getdata1-->192.168.205.245:41602 |A|EST [me -> all the world!]
[OK] OUT: [eno1] |TCP| 192.168.205.245:41608-->192.168.205.25:targus-getdata1 |S| [me -> all the world!]
```

Test #1

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   932 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.25 GBytes   930 Mbits/sec                  receiver
```


Test #2

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   932 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.25 GBytes   930 Mbits/sec                  receiver
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
[  5]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   833 MBytes   233 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   832 MBytes   233 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.25 GBytes   932 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.25 GBytes   931 Mbits/sec                  receiver
```

##### Old legacy version

```
[  5]   0.00-30.00  sec   835 MBytes   233 Mbits/sec    0            sender
[  5]   0.00-30.00  sec   834 MBytes   233 Mbits/sec                  receiver
[  7]   0.00-30.00  sec   835 MBytes   234 Mbits/sec    0            sender
[  7]   0.00-30.00  sec   834 MBytes   233 Mbits/sec                  receiver
[  9]   0.00-30.00  sec   835 MBytes   234 Mbits/sec    0            sender
[  9]   0.00-30.00  sec   834 MBytes   233 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec   836 MBytes   234 Mbits/sec    0            sender
[ 11]   0.00-30.00  sec   834 MBytes   233 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec  3.26 GBytes   934 Mbits/sec    0             sender
[SUM]   0.00-30.00  sec  3.26 GBytes   933 Mbits/sec                  receiver
```

### UDP:

> iperf3 -c taeyang.elettra.eu -p 5201 -u -b 500M -t 30

UDP bandwidth -b increased; watch for packet drops

##### without

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294938 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.013 ms  0/1294938 (0%)  receiver
```


###### Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294937 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.013 ms  0/1294937 (0%)  receiver
```

###### Test #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294903 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.023 ms  67/1294903 (0.0052%)  receiver
```

##### with

###### Test #1

```
[OK] OUT: [eno1] |UDP| 192.168.205.245:41026-->192.168.205.25:targus-getdata1  [me -> the UDP world]
[OK] IN:  [eno1] |UDP| 192.168.205.25:targus-getdata1-->192.168.205.245:41026 STREAM [me -> the UDP world]
[OK] OUT: [eno1] |UDP| 192.168.205.245:41026-->192.168.205.25:targus-getdata1 STREAM [me -> the UDP world]
```

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294935 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.042 ms  0/1294933 (0%)  receiver
```

###### Test #2

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294939 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.016 ms  0/1294939 (0%)  receiver
```

###### Test #3

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294937 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.011 ms  0/1294937 (0%)  receiver
```

#### Legacy IPFIRE-wall

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.000 ms  0/1294937 (0%)  sender
[  5]   0.00-30.00  sec  1.75 GBytes   500 Mbits/sec  0.017 ms  0/1294937 (0%)  receiver
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
[  5]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4505            sender
[  5]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4424            sender
[  7]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4602            sender
[  9]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4538            sender
[ 11]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4590            sender
[ 13]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   833 MBytes   117 Mbits/sec  4522            sender
[ 15]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   833 MBytes   116 Mbits/sec  4461            sender
[ 17]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4525            sender
[ 19]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.51 GBytes   932 Mbits/sec  36167             sender
[SUM]   0.00-60.00  sec  6.50 GBytes   931 Mbits/sec                  receiver
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
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   829 MBytes   116 Mbits/sec  4558            sender
[  5]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4579            sender
[  7]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4533            sender
[  9]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4554            sender
[ 11]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4491            sender
[ 13]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4560            sender
[ 15]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4494            sender
[ 17]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   830 MBytes   116 Mbits/sec  4375            sender
[ 19]   0.00-60.00  sec   829 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.48 GBytes   928 Mbits/sec  36144             sender
[SUM]   0.00-60.00  sec  6.47 GBytes   927 Mbits/sec                  receiver

```

##### with

> rc.ipfire start

```
starting IPFIRE: IPFIRE 1.99.9 "lin".
```

Test #1 with

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4527            sender
[  5]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4501            sender
[  7]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4566            sender
[  9]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4545            sender
[ 11]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4589            sender
[ 13]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4368            sender
[ 15]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4486            sender
[ 17]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4659            sender
[ 19]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.50 GBytes   931 Mbits/sec  36241             sender
[SUM]   0.00-60.00  sec  6.49 GBytes   930 Mbits/sec                  receiver
```

Test #2 with

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4563            sender
[  5]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4498            sender
[  7]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4527            sender
[  9]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4479            sender
[ 11]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4434            sender
[ 13]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4542            sender
[ 15]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4404            sender
[ 17]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   832 MBytes   116 Mbits/sec  4609            sender
[ 19]   0.00-60.00  sec   831 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.50 GBytes   930 Mbits/sec  36056             sender
[SUM]   0.00-60.00  sec  6.49 GBytes   929 Mbits/sec                  receiver
```

Test #3 with

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   950 MBytes   133 Mbits/sec  4427            sender
[  5]   0.00-60.00  sec   949 MBytes   133 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   950 MBytes   133 Mbits/sec  4398            sender
[  7]   0.00-60.00  sec   949 MBytes   133 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   950 MBytes   133 Mbits/sec  4375            sender
[  9]   0.00-60.00  sec   949 MBytes   133 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   950 MBytes   133 Mbits/sec  4476            sender
[ 11]   0.00-60.00  sec   949 MBytes   133 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   950 MBytes   133 Mbits/sec  4457            sender
[ 13]   0.00-60.00  sec   949 MBytes   133 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   950 MBytes   133 Mbits/sec  4458            sender
[ 15]   0.00-60.00  sec   949 MBytes   133 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   431 MBytes  60.2 Mbits/sec  3564            sender
[ 17]   0.00-60.00  sec   430 MBytes  60.1 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   520 MBytes  72.7 Mbits/sec  3970            sender
[ 19]   0.00-60.00  sec   519 MBytes  72.6 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.50 GBytes   930 Mbits/sec  34125             sender
[SUM]   0.00-60.00  sec  6.49 GBytes   929 Mbits/sec                  receiver

```

##### Legacy ipfire-wall

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   833 MBytes   117 Mbits/sec  4597            sender
[  5]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[  7]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4630            sender
[  7]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[  9]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4400            sender
[  9]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 11]   0.00-60.00  sec   833 MBytes   117 Mbits/sec  4494            sender
[ 11]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 13]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4560            sender
[ 13]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 15]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4602            sender
[ 15]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 17]   0.00-60.00  sec   834 MBytes   117 Mbits/sec  4483            sender
[ 17]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[ 19]   0.00-60.00  sec   833 MBytes   117 Mbits/sec  4524            sender
[ 19]   0.00-60.00  sec   833 MBytes   116 Mbits/sec                  receiver
[SUM]   0.00-60.00  sec  6.51 GBytes   932 Mbits/sec  36290             sender
[SUM]   0.00-60.00  sec  6.51 GBytes   931 Mbits/sec                  receiver
```


### UDP:

iperf3 -c taeyang.elettra.eu -p 5201 -u -b 2G -t 60

##### without

Test #1

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.37 GBytes   768 Mbits/sec  0.000 ms  0/3980185 (0%)  sender
[  5]   0.00-60.00  sec  5.37 GBytes   768 Mbits/sec  0.030 ms  520/3980151 (0.013%)  receiver
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
[  5]   0.00-60.00  sec  5.46 GBytes   781 Mbits/sec  0.000 ms  0/4047697 (0%)  sender
[  5]   0.00-60.00  sec  5.46 GBytes   781 Mbits/sec  0.031 ms  0/4047656 (0%)  receiver
```

##### With ipfire

Test #1

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  5.34 GBytes   765 Mbits/sec  0.000 ms  0/3962189 (0%)  sender
[  5]   0.00-60.00  sec  5.34 GBytes   765 Mbits/sec  0.012 ms  91/3962173 (0.0023%)  receiver
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

#### Legacy IPFIRE-wall

```
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-60.00  sec  2.48 GBytes   356 Mbits/sec  0.000 ms  0/41689765 (0%)  sender
[  5]   0.00-60.00  sec  2.48 GBytes   356 Mbits/sec  0.001 ms  739/41689765 (0.0018%)  receiver
```

# Firewall Test Summary – Visual

| Test Type | Protocol | Load / Params | Without Firewall | With Firewall | Notes / Observations |
|-----------|----------|---------------|-----------------|---------------|--------------------|
| **Base** | TCP | 1 stream, 10s | ✅ ~100% link | ✅ ~100% link | Minimal overhead |
| **Base** | UDP | 100 Mbit/s, 10s | ✅ 0–0.005% loss | ✅ 0–0.006% loss | Low jitter/loss |
| **Moderate** | TCP | 4 streams, 30s | ✅ 929 Mbit/s | ✅ 928–931 Mbit/s | Firewall almost invisible |
| **Moderate** | UDP | 500 Mbit/s, 30s | ✅ 0.0056% loss | ⚪ 0.0009–0.023% loss | Slight jitter increase |
| **Stress** | TCP | 8 streams, 60s | ⚪ 920–928 Mbit/s | ⚪ 924–925 Mbit/s | CPU spikes, high retransmits |
| **Stress** | UDP | 2 Gbit/s, 60s | ⚪ 775–779 Mbit/s | ⚠️ 765–767 Mbit/s | Small drop due to firewall |
| **PPS Apocalypse** | UDP | 1 Gbit/s, 64B packets | ⚪ 542–543 Mbit/s | ❌ 113–115 Mbit/s | CPU-bound per-packet bottleneck |
| **Local NS Forwarding** | TCP | 500 Mbit/s, 10s | ✅ 500 Mbit/s | ✅ 500 Mbit/s | Transparent |
| **Local NS Forwarding** | UDP | 500 Mbit/s, 10s | ✅ ~0–0.03% loss | ⚪ 0–0.023% loss | Minor packet loss |

## Legend

- ✅ Excellent / negligible impact  
- ⚪ Minor impact / slight throttling  
- ⚠️ Noticeable degradation / CPU spikes  
- ❌ Severe bottleneck / throughput collapse  

> ⚡ PPS Apocalypse clearly shows the firewall’s per-packet limits. Even at 1 Gbit/s link, 64-byte packets saturate CPU before bandwidth.

