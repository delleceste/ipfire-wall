#!/bin/sh

# ==============================
# UDP Stress Script (netns)
# ==============================

NS="ns1"
DST="10.0.0.2"
DPORT=5201
TOTAL=5000 # ${1:-2000}     # default 2000 connections
BATCH=5000            # max concurrent processes
START_PORT=40000

echo "======================================"
echo "UDP Stress Test"
echo "Namespace: $NS"
echo "Target: $DST:$DPORT"
echo "Total flows: $TOTAL"
echo "Batch size: $BATCH"
echo "======================================"
echo ""
echo "Before running, start UDP server in ns2:"
echo ""
echo "  sudo ip netns exec ns2 nc -u -l $DPORT"
echo ""
echo "Press Ctrl+C to abort."
echo ""

sleep 3

END_TOTAL=$((START_PORT + TOTAL - 1))
CURRENT=$START_PORT

while [ $CURRENT -le $END_TOTAL ]; do
    END_BATCH=$((CURRENT + BATCH - 1))

    if [ $END_BATCH -gt $END_TOTAL ]; then
        END_BATCH=$END_TOTAL
    fi

    echo "Launching flows $CURRENT -> $END_BATCH"

    for SRC in $(seq $CURRENT $END_BATCH); do
        sudo ip netns exec $NS \
            hping3 --udp -p $DPORT -s $SRC $DST --fast \
            > /dev/null 2>&1 &
    done

    wait
    CURRENT=$((END_BATCH + 1))
done

echo ""
echo "All flows completed."

