// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#ifndef __LIBLINK_H__
#define __LIBLINK_H__

#include <net/if.h>

#define ERR(str, ...) fprintf(stderr, "Error: "str, ##__VA_ARGS__)

int get_iface_index(int sockfd, char iface[IFNAMSIZ]);
int get_smac(int sockfd, char ifname[IFNAMSIZ], unsigned char smac[6]);
int get_iface_mac(char ifname[IFNAMSIZ], unsigned char mac_address[ETH_ALEN]);
void set_dmac(unsigned char *frame, unsigned char mac[ETH_ALEN]);
void set_smac(unsigned char *frame, unsigned char mac[ETH_ALEN]);


#endif /* __LIBLINK_H__ */
