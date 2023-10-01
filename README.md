<!--SPDX-License-Identifier: MIT-->
<!--SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>-->
# Wiretime

Measure the time a packet is on the wire accurately using hardware timestamping.
This is useful for measuring the impact of traffic congestion and testing QoS
features.

```
wiretime --tx eth0 --rx eth1
```

For more detailed explanation refer to https://casan.se/docs/wiretime/.

Plot nice graphs using Gnuplot. Use `-O <filename>` to save the measurements to
a file. Then transfer the file to a device that has Gnuplot and run the script
`scripts/plot_latency.sh <input> <output.pdf>` on it. Or if your target device
has Gnuplot you can use the flag `--plot <filename.pdf>` directly.

## Credit

This project initially started as a fork of [OpenIL's
TSNTool](https://github.com/nxp-archive/openil_tsntool/blob/master/tools/timestamping.c),
which in of itself appears to come from the file
[selftests/net/timestamping.c](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/timestamping.c)
in the Linux kernel.
