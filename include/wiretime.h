// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#ifndef __WIRETIME_H__
#define __WIRETIME_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef SO_TIMESTAMPING
# define SO_TIMESTAMPING         37
# define SCM_TIMESTAMPING        SO_TIMESTAMPING
#endif

#ifndef SO_TIMESTAMPNS
# define SO_TIMESTAMPNS 35
#endif

#ifndef SIOCGSTAMPNS
# define SIOCGSTAMPNS 0x8907
#endif

#ifndef SIOCSHWTSTAMP
# define SIOCSHWTSTAMP 0x89b0
#endif

#ifndef CLOCK_TAI
#define CLOCK_TAI                       11
#endif

#ifndef SCM_TXTIME
#define SO_TXTIME               61
#define SCM_TXTIME              SO_TXTIME
#endif
#define _DEBUG(file, fmt, ...) do { \
	if (debugen) { \
		fprintf(file, " " fmt, \
		##__VA_ARGS__); \
	} else { \
		; \
	} \
} while (0)

#define DEBUG(...) _DEBUG(stderr, __VA_ARGS__)

static void bail(const char *error)
{
	printf("%s: %s\n", error, strerror(errno));
	exit(1);
}


extern bool debugen;// = false;
extern bool running;// = true;

struct pkt_time {
	bool invalid;
	__u16 seq;
	struct timespec xmit;
	struct timespec recv;
};

typedef struct packets {
	pthread_mutex_t list_lock;
	struct pkt_time *list;
	int list_start;
	int list_head;
	int list_len;
	__u16 next_seq;
	bool txcount_flag;
	unsigned char *frame;
	size_t frame_size;
	int timerfd;
	int triggers_behind_timer;
} Packets;

typedef struct config {
	//int pkts_per_sec; /* Max 1000 (1 pkt per ms) */
	int interval; /* Milliseconds. */
	//int pkts_per_summary; /* Defaults to pkt_per_sec if not set*/
	int batch_size; /* Default: 1 */
	int pcp;
	int priority;
	int vlan;
	bool software_ts;
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

/* timestamping.c */
void get_timestamp(struct msghdr *msg, struct timespec **stamp, int recvmsg_flags, Packets *pkts, Config *cfg);
void *rcv_pkt(void *arg);
void rcv_xmit_tstamp(int sock, Config *cfg, Packets *pkts, __u16 tx_seq);
int setup_tx_sock(char *iface, int prio, bool ptp_only, bool one_step, bool software_ts);
int setup_rx_sock(char *iface, int prio, bool ptp_only, bool software_ts);

/* wiretime.c */
void save_tstamp(struct timespec *stamp, unsigned char *data, size_t length,
		 Config *cfg, Packets *pkts, __s32 tx_seq, int recvmsg_flags);


#endif /* __WIRETIME_H__ */
