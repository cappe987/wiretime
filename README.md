# Wiretime

Measure the time a packet is on the wire accurately using hardware timestamping.
This is useful for measuring the impact of traffic congestion and testing QoS
features.

```
wiretime --tx eth0 --rx eth1
```

## TODO
- Use receiving ports MAC as DMAC instead of broadcast.


## Credit

This project initially started as a fork of [OpenIL's
TSNTool](https://github.com/nxp-archive/openil_tsntool/blob/master/tools/timestamping.c),
which in of itself appears to come from the file
[selftests/net/timestamping.c](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/timestamping.c)
in the Linux kernel.
