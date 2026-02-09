# IPFIRE-wall test set up

### Run the netns setup script

Creates the network namespaces:

```
Your Host (102.168.205.245/24)
├── Physical NIC (eth0) ← Connected to company network
│   └── [UNTOUCHED - works normally]
│
└── Network Namespaces (isolated bubbles)
    ├── hostA (192.168.1.10) ← Virtual, isolated
    ├── hostB (192.168.1.1, 10.0.0.1) ← Virtual, isolated
    └── hostC (10.0.0.10) ← Virtual, isolated
```

### Load ipfire module on host B

# Enter Host B namespace
ip netns exec hostB bash
# Load your kernel module
cd /home/giacomo/devel/ipfire-wall/kernel
insmod build/ipfi.ko
# Verify it's loaded
lsmod | grep ipfi

### Testing scenarios

##### From Host A, ping Host B's internal interface
ip netns exec hostA ping -c 3 192.168.1.1

##### From Host C, ping Host B's external interface
ip netns exec hostC ping -c 3 10.0.0.1



