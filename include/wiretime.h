// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#ifndef __WIRETIME_H__
#define __WIRETIME_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>


struct pkt_time {
	__u16 seq;
	struct timespec xmit;
	struct timespec recv;
};

typedef struct packets {
	pthread_mutex_t list_lock;
	struct pkt_time *list;
	int list_head;
	int list_len;
	__u16 next_seq;
	bool txcount_flag;
	unsigned char *frame;
} Packets;

typedef struct config {
	int pkts_per_sec; /* Max 1000 (1 pkts per ms) */
	int pkts_per_summary; /* Defaults to pkt_per_sec if not set*/
	int pcp;
	int priority;
	int vlan;
	bool one_step;
	bool ptp_only;
	bool has_first;
	bool plot;
	char *plot_filename;
	struct timespec first_tstamp;
	FILE *out_file;
	char *out_filename;
	char *tx_iface;
	char *rx_iface;
} Config;

struct thread_data {
	Config *cfg;
	Packets *pkts;
	int sockfd;
};


void get_timestamp(struct msghdr *msg, struct timespec **stamp, int recvmsg_flags, Packets *pkts);


#endif /* __WIRETIME_H__ */
