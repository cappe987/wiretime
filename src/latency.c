// SPDX-License-Identifier: (GPL-2.0 OR MIT)
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
/*
 * Copyright 2019 NXP
 */

/* TODO: Fix bug with TX side getting stuck on 'select' when another
 * application transmits a lot of data on the same interface.
 *
 * TODO: Don't allow mixing one-step and tagged VLAN. One-step assumes the
 * packet is not tagged.
 *
 * TODO: PHY timestamping with only a looped cable reports earlier RX time than
 * TX time. Possibly hardware related issue.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <asm/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <sys/queue.h>
#include <signal.h>
#include <getopt.h>
#include <endian.h>

#include <asm/types.h>

#include <linux/if_ether.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

#include "version.h"
#include "liblink.h"

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

#define VLAN_TAG_SIZE 4
#define PRIO_OFFSET 14
#define DOMAIN_NUM_OFFSET 18
#define SEQ_OFFSET 44
#define TIME_SEC_OFFSET 48
#define TIME_NSEC_OFFSET 54

#define DOMAIN_NUM 0xff

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
	int prio;
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

static bool debugen = false;
static bool running = true;

/*static int delay_us = 0;*/
/*static int send_now = 0;*/
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

void help()
{
	fputs(  "latency - Measure latency using hardware timestamping\n"
		"\n"
		"USAGE:\n"
		"        latency --tx <IFACE1> --rx <IFACE2> [OPTIONS]\n"
		"\n"
		"        Transmits on <IFACE1> and receives on <IFACE2>.\n"
		"        Both interfaces must support hardware timestamping of non-PTP packets.\n"
		"\n"
		"OPTIONS:\n"
		"        -t, --tx <IFACE>\n"
		"            Transmit packets on <IFACE>. Can be a VLAN or other interface,\n"
		"            as long as the physical port supports hardware timestamping.\n"
		"        -r, --rx <IFACE>\n"
		"            Receive packets on <IFACE>. Can be a VLAN or other interface,\n"
		"            as long as the physical port supports hardware timestamping.\n"
		"        -p, --prio <PRIO>\n"
		"            PCP priority. If VLAN is not set it will use VLAN 0.\n"
		"        -v, --vlan <VID>\n"
		"            VLAN to use when (useful when used together with prio).\n"
		"        -o, --one-step\n"
		"            Use one-step TX instead of two-step.\n"
		"        -O, --out <filename>\n"
		"            Output data into file for plotting.\n"
		"        -s, --pkts_per_sec <count>\n"
		"            Amount of packets to transmit per second. Default: 100\n"
		"        -S, --pkts_per_summary <count>\n"
		"            Amount of packets to include in every output.\n"
		"            Together with pkts_per_sec this determines how often it will\n"
		"            show outputs. Default: pkts_per_sec (meaning once every second)\n"
		"        -d, --debug\n"
		"            Enable debug output\n"
		"        -h, --help\n"
		"            Show this text\n"
		"        -V, --version\n"
		"            Show version\n"
		"        --plot <filename>\n"
		"            Plots the data using Gnuplot and exports as PDF. If -O is \n"
		"            not used it will create a temporary file for storing the data.\n"
		/*"\n"*/
		,stderr);

}
//static unsigned char sync_packet[] = {
//	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* dmac */
//	0x11, 0x00, 0x80, 0x00, 0x00, 0x00,
//	0x08, 0x00,		/* eth header */
//	0x45, 0x00,			/* hardware type */
//	0x08, 0x00,		/* IP type */
//	0x06, 0x04,			/* hw len, protocol len */
//	0x00, 0x01,			/* request type: 1: ARP, 2: ARP REPLY */
//	0x00, 0x00, 0xff, 0x00, 0x00, 0x00,		/* source mac */
//	0x09, 0x09, 0x09, 0x09,
//	0x00, 0x00, 0x00, 0x00,	0x00, 0x00,
//	0x0a, 0x0a, 0x0a, 0x0a,
//	0x00, 0x80,
//	0x00, 0xb0,
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00, 0x00, 0x00,	/* correctionField */
//	0x00, 0x00, 0x00, 0x00,	/* reserved */
//	0x00, 0x04, 0x9f, 0xff,
//	0xfe, 0x03, 0xd9, 0xe0,
//	0x00, 0x01,		/* sourcePortIdentity */
//	0x00, 0x1d,		/* sequenceId */
//	0x00,			/* controlField */
//	0x00,			/* logMessageInterval */
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00,
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00,
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00,		/* originTimestamp */
//	0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00		/* originTimestamp */
//};

static void sig_handler(int sig)
{
	running = false;
}


int str2mac(const char *s, unsigned char mac[ETH_ALEN])
{
	unsigned char buf[ETH_ALEN];
	int c;
	c = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
	if (c != ETH_ALEN) {
		return -1;
	}
	memcpy(mac, buf, ETH_ALEN);
	return 0;
}

static uint64_t gettime_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_TAI, &ts))
		printf("error gettime");

	return ts.tv_sec * (1000ULL * 1000 * 1000) + ts.tv_nsec;
}

/*static unsigned char sync_packet[] = {*/
	/*0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, [> dmac <]*/
	/*0x11, 0x00, 0x80, 0x00, 0x00, 0x00, [> smac <]*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
/*};*/


static unsigned char sync_packet[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dmac
	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, // smac
	0x88, 0xf7, // PTPv2 ethertype
	0x00, // majorSdoId, messageType (0x0=Sync)
	0x02, // minorVersionPtp, versionPTP
	0x00, 0x2c, // messageLength
	DOMAIN_NUM, // domainNumber (use domain number 0xff for this)
	0x00, // majorSdoId
	0x02, 0x00, // flags
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // correctionField
	0x00, 0x00, 0x00, 0x00, // messageTypeSpecific
	0xbb, 0xbb, 0xbb, 0xff, 0xfe, 0xbb, 0xbb, 0xbb, // clockIdentity
	0x00, 0x01, // sourcePort
	0x00, 0x01, // sequenceId
	0x00, // controlField
	0x00, // logMessagePeriod
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originTimestamp (seconds)
	0x00, 0x00, 0x00, 0x00, // originTimestamp (nanoseconds)
};

static unsigned char sync_packet_tagged[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dmac
	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, // smac
	0x81, 0x00, 0x00, 0x00, // VLAN tag
	0x88, 0xf7, // PTPv2 ethertype
	0x00, // majorSdoId, messageType (0x0=Sync)
	0x02, // minorVersionPtp, versionPTP
	0x00, 0x2c, // messageLength
	DOMAIN_NUM, // domainNumber (use domain number 0xff for this)
	0x00, // majorSdoId
	0x02, 0x00, // flags
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // correctionField
	0x00, 0x00, 0x00, 0x00, // messageTypeSpecific
	0xbb, 0xbb, 0xbb, 0xff, 0xfe, 0xbb, 0xbb, 0xbb, // clockIdentity
	0x00, 0x01, // sourcePort
	0x00, 0x01, // sequenceId
	0x00, // controlField
	0x00, // logMessagePeriod
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originTimestamp (seconds)
	0x00, 0x00, 0x00, 0x00, // originTimestamp (nanoseconds)
};

void u16_to_char(unsigned char a[], __u16 n) {
	memcpy(a, &n, 2);
}

__u16 char_to_u16(unsigned char a[]) {
	__u16 n = 0;
	memcpy(&n, a, 2);
	return n;
}

static inline int using_tagged(Config *cfg)
{
	return cfg->vlan != 0 || cfg->prio != 0;
}

static void set_sequenceId(Config *cfg, unsigned char *packet, __u16 seq_id)
{
	/* Convert to Big Endian so sequenceId looks correct when viewed in
	 * Wireshark or Tcpdump.
	 */
	seq_id = htons(seq_id);
	if (using_tagged(cfg))
		u16_to_char(&packet[SEQ_OFFSET + VLAN_TAG_SIZE], seq_id);
	else
		u16_to_char(&packet[SEQ_OFFSET], seq_id);
}

static void set_vid_pcp(Config *cfg, Packets *pkts)
{
	if (!using_tagged(cfg))
		return;
	pkts->frame[PRIO_OFFSET] = ((cfg->prio & 0x7) << 5) | ((cfg->vlan & 0xf00) >> 8);
	pkts->frame[PRIO_OFFSET+1] = (unsigned char) cfg->vlan;
}

static __u16 get_sequenceId(unsigned char *buf)
{
	// Will arive without tag when received on the socket
	/*if (using_tagged())*/
		/*return char_to_u16(&buf[SEQ_OFFSET + VLAN_TAG_SIZE]);*/
	/*else*/
		return ntohs(char_to_u16(&buf[SEQ_OFFSET]));
}

static int is_rx_tstamp(unsigned char *buf)
{
	// Will arive without tag when received on the socket
	/*if (using_tagged())*/
		/*return buf[DOMAIN_NUM_OFFSET + VLAN_TAG_SIZE] == DOMAIN_NUM;*/
	/*else*/
		return buf[DOMAIN_NUM_OFFSET] == DOMAIN_NUM;
}



/* ======= Receiving ======= */

static void parse_and_save_tstamp(struct msghdr *msg, int res,
				  int recvmsg_flags, size_t length,
				  Config *cfg, Packets *pkts, __s32 tx_seq)
{
	struct sockaddr_in *from_addr = (struct sockaddr_in *)msg->msg_name;
	struct cmsghdr *cmsg;
	struct timespec *stamp = NULL;
	struct timespec one_step_ts;
	struct timeval now;
	__u16 pkt_seq;
	unsigned char *data;
	int idx;
	int got_tx = 0;
	int got_rx = 0;

	if (debugen)
		gettimeofday(&now, 0);

	DEBUG("%ld.%06ld: received %s data, %d bytes from %s, %zu bytes control messages\n",
	       (long)now.tv_sec, (long)now.tv_usec,
	       (recvmsg_flags & MSG_ERRQUEUE) ? "error" : "regular",
	       res,
	       inet_ntoa(from_addr->sin_addr),
	       msg->msg_controllen);

	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		DEBUG("   cmsg len %zu: ", cmsg->cmsg_len);
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
			DEBUG("SOL_SOCKET ");
			switch (cmsg->cmsg_type) {
			case SO_TIMESTAMP: {
				struct timeval *stamp =
					(struct timeval *)CMSG_DATA(cmsg);
				DEBUG("SO_TIMESTAMP %ld.%06ld",
				       (long)stamp->tv_sec,
				       (long)stamp->tv_usec);
				break;
			}
			case SO_TIMESTAMPNS: {
				struct timespec *stamp =
					(struct timespec *)CMSG_DATA(cmsg);
				DEBUG("SO_TIMESTAMPNS %ld.%09ld",
				       (long)stamp->tv_sec,
				       (long)stamp->tv_nsec);
				break;
			}
			case SO_TIMESTAMPING: {
				DEBUG("SO_TIMESTAMPING ");
				stamp = (struct timespec *)CMSG_DATA(cmsg);
				/* stamp is an array containing 3 timespecs:
				 * SW, HW transformed, HW raw.
				 * Only HW raw is set
				 */
				/* skip SW */
				stamp++;
				/* skip deprecated HW transformed */
				stamp++;
				if (recvmsg_flags & MSG_ERRQUEUE)
					pkts->txcount_flag = 1;
				break;
			}
			default:
				DEBUG("type %d", cmsg->cmsg_type);
				break;
			}
			break;
		default:
			DEBUG("level %d type %d",
				cmsg->cmsg_level,
				cmsg->cmsg_type);
			break;
		}
		DEBUG("\n");
	}

	if (!stamp)
		return;

	data = (unsigned char*)msg->msg_iov->iov_base;
	/*int printlen = using_tagged(cfg) ? sizeof(sync_packet_tagged) : sizeof(sync_packet);*/
	/*printf("Length %d\n", length);*/
	/*if (length > 0) {*/
		/*for (int i = 0; i < length; i++)*/
			/*printf("%02x ", data[i]);*/
		/*printf("\n");*/
	/*}*/

	if (tx_seq >= 0) {
		got_tx = 1;
		pkt_seq = tx_seq;
		/*printf("Got TX seq %d. %lu.%lu\n", pkt_seq, stamp->tv_sec, stamp->tv_nsec);*/
	} else if (is_rx_tstamp(data)) {
		got_rx = 1;
		pkt_seq = get_sequenceId(data);
		/*printf("Got RX seq %d. %lu.%lu\n", pkt_seq, stamp->tv_sec, stamp->tv_nsec);*/
	} else {
		// If the packet we read was not the tx packet then set back
		// txcount_flag and try again.
		if (recvmsg_flags & MSG_ERRQUEUE)
			pkts->txcount_flag = 0;
		return;
	}

	idx = pkt_seq % pkts->list_len;

	if (got_rx && cfg->one_step) {
		// XXX: Assumes 64-bit time
		// Since we need the lower 6 bytes, copy 8 and set the upper 2 to zero.
		memcpy(&one_step_ts.tv_sec, &data[TIME_SEC_OFFSET-2], 8);
		memset(&one_step_ts.tv_sec, 0, 2);
		memcpy(&one_step_ts.tv_nsec, &data[TIME_NSEC_OFFSET], 4);
		one_step_ts.tv_sec = be64toh(one_step_ts.tv_sec);
		one_step_ts.tv_nsec = ntohl(one_step_ts.tv_nsec);
		if (pkts->list[idx].seq == pkt_seq)
			pkts->list[idx].xmit = one_step_ts;
		/*printf("Got TX one-step seq %d. %lu.%lu\n", pkt_seq, stamp->tv_sec, stamp->tv_nsec);*/
	}

	if (!cfg->has_first) {
		cfg->has_first = 1;
		cfg->first_tstamp = cfg->one_step ? one_step_ts : *stamp;
	}


	pthread_mutex_lock(&pkts->list_lock);
	if (pkts->list[idx].seq == pkt_seq) {
		if (got_tx)
			pkts->list[idx].xmit = *stamp;
		else if (got_rx)
			pkts->list[idx].recv = *stamp;
	}
	pthread_mutex_unlock(&pkts->list_lock);
}

static void recvpacket(int sock, int recvmsg_flags,
		       Config *cfg, Packets *pkts,
		       __s32 tx_seq)
{
	char data[256];
	struct msghdr msg;
	struct iovec entry;
	struct sockaddr_in from_addr;
	struct {
		struct cmsghdr cm;
		char control[512];
	} control;
	int res;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = sizeof(data);
	memset(data, 0, sizeof(data));
	msg.msg_name = (caddr_t)&from_addr;
	msg.msg_namelen = sizeof(from_addr);
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	res = recvmsg(sock, &msg, recvmsg_flags | MSG_DONTWAIT);
	if (res < 0)
		DEBUG("%s %s: %s\n",
		       "recvmsg",
		       "regular",
		       strerror(errno));
	else
		parse_and_save_tstamp(&msg, res, recvmsg_flags, res, cfg, pkts, tx_seq);
}

void *rcv_pkt(void *arg)
{
	struct thread_data *data = arg;
	int sock = data->sockfd;
	fd_set readfs, errorfs;
	int res;


	while (running) {
		FD_ZERO(&readfs);
		FD_ZERO(&errorfs);
		FD_SET(sock, &readfs);
		FD_SET(sock, &errorfs);

		struct timeval tv = {0, 100000};   // sleep for ten minutes!
		res = select(sock + 1, &readfs, 0, &errorfs, &tv);
		/*res = select(sock + 1, &readfs, 0, &errorfs, NULL);*/
		if (res > 0) {
			recvpacket(sock, 0, data->cfg, data->pkts, -1);
		}
	}

}

void rcv_xmit_tstamp(int sock, Config *cfg, Packets *pkts, __u16 tx_seq) {
	fd_set readfs, errorfs;
	int res;

	while (!pkts->txcount_flag) {
		FD_ZERO(&readfs);
		FD_ZERO(&errorfs);
		FD_SET(sock, &readfs);
		FD_SET(sock, &errorfs);

		res = select(sock + 1, &readfs, 0, &errorfs, NULL);
		if (res > 0) {
			recvpacket(sock, 0, cfg, pkts, tx_seq);
			recvpacket(sock, MSG_ERRQUEUE, cfg, pkts, tx_seq);
		}
	}

	return;
}

/* ======= Sending ======= */

static int do_send_one(int fdt, int length)
{
	char control[CMSG_SPACE(sizeof(uint64_t))];
	struct msghdr msg = {0};
	struct iovec iov = {0};
	struct cmsghdr *cm;
	uint64_t tdeliver;
	int ret;
	char *buf;

	buf = (char *)malloc(length);
	memcpy(buf, sync_packet, sizeof(sync_packet));

	iov.iov_base = buf;
	iov.iov_len = length;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/*if (packet_delay_us >= 0) {*/
		/*memset(control, 0, sizeof(control));*/
		/*msg.msg_control = &control;*/
		/*msg.msg_controllen = sizeof(control);*/

		/*tdeliver = gettime_ns() + delay_us * 1000;*/
		/*printf("set TXTIME is %ld\n", tdeliver);*/
		/*cm = CMSG_FIRSTHDR(&msg);*/
		/*cm->cmsg_level = SOL_SOCKET;*/
		/*cm->cmsg_type = SCM_TXTIME;*/
		/*cm->cmsg_len = CMSG_LEN(sizeof(tdeliver));*/
		/*memcpy(CMSG_DATA(cm), &tdeliver, sizeof(tdeliver));*/
	/*}*/

	ret = sendmsg(fdt, &msg, 0);
	if (ret == -1)
		printf("error write, return error sendmsg!\n");
	if (ret == 0)
		printf("error write: 0B");

	free(buf);
	return ret;
}

static void pkts_append_seq(Packets *pkts, __u16 tx_seq)
{
	pthread_mutex_lock(&pkts->list_lock);
	pkts->list[tx_seq % pkts->list_len].seq = tx_seq;
	pkts->list_head = (pkts->list_head + 1) % pkts->list_len;
	pthread_mutex_unlock(&pkts->list_lock);
}

static __u16 sendpacket(int sock, unsigned int length, unsigned char *mac,
			Config *cfg, Packets *pkts)
{
	struct timeval now, nowb;
	__u16 tx_seq;
	int res;

	tx_seq = pkts->next_seq;
	pkts->next_seq++;
	/*printf("Xmit: %llu\n", tx_seq);*/

	set_sequenceId(cfg, pkts->frame, tx_seq);

	pkts_append_seq(pkts, tx_seq);

	gettimeofday(&nowb, 0);

	/*if (length < sizeof(sync_packet)) {*/
	if (using_tagged(cfg))
		res = send(sock, pkts->frame, sizeof(sync_packet_tagged), 0);
	else
		res = send(sock, pkts->frame, sizeof(sync_packet), 0);
	/*} else {*/
#if 0
		char *buf = (char *)malloc(length);

		memcpy(buf, sync_packet, sizeof(sync_packet));
		res = send(sock, buf, length, 0);
		free(buf);
#endif
		/*res = do_send_one(sock, length);*/
	/*}*/

	gettimeofday(&now, 0);
	if (res < 0)
		DEBUG("%s: %s\n", "send", strerror(errno));
	else
		DEBUG("%ld.%06ld - %ld.%06ld: sent %d bytes\n",
		      (long)nowb.tv_sec, (long)nowb.tv_usec,
		      (long)now.tv_sec, (long)now.tv_usec,
		      res);
	return tx_seq;
}

struct timespec diff_timespec(const struct timespec *time1,
			      const struct timespec *time0)
{
	struct timespec diff = {
		.tv_sec  = time1->tv_sec - time0->tv_sec,
		.tv_nsec = time1->tv_nsec - time0->tv_nsec
	};
	if (diff.tv_nsec < 0) {
		diff.tv_nsec += 1000000000; // nsec/sec
		diff.tv_sec--;
	}
	return diff;
}

__u64 timespec_to_ns(const struct timespec *time)
{
	return (time->tv_sec * 1000000000) + time->tv_nsec;
}

bool try_get_latency(Packets *pkts, int idx, __u64 *ns)
{
	struct timespec diff;
	int ret = false;

	/* Packet is considered lost if recv timespec is 0 */
	if (pkts->list[idx].recv.tv_sec != 0 || pkts->list[idx].recv.tv_nsec != 0) {
		diff = diff_timespec(&pkts->list[idx].recv, &pkts->list[idx].xmit);
		*ns = timespec_to_ns(&diff);
		ret = true;
	}

	pkts->list[idx].seq          = 0;
	pkts->list[idx].xmit.tv_sec  = 0;
	pkts->list[idx].xmit.tv_nsec = 0;
	pkts->list[idx].recv.tv_sec  = 0;
	pkts->list[idx].recv.tv_nsec = 0;
	return ret;
}

void calculate_latency(Config *cfg, Packets *pkts)
{

	/* pktlist holds packets for two full intervals. This allows 1-2
	 * intervals for the packets to come back and have their latency
	 * measured. When the list is full it takes the earliest half of the
	 * packets and calculates their average and sets their values to zero
	 * so it can use those for the next transmission interval.
	 *
	 * Must have sent more than pkts_per_summary to qualify. If the
	 * limit is 5 then it should wait until it has sent out 10
	 * packets so the first 5 are hopefully available. From there
	 * on it can do summary at 15, 20, 25, etc.
	 */
	int stop = (pkts->next_seq + cfg->pkts_per_summary) % pkts->list_len;
	int i = pkts->next_seq % pkts->list_len;
	struct timespec diff;
	struct timespec first_interval;
	int first_iteration = 1;
	__u64 total_nsec = 0;
	__u64 nsec;
	int lost = 0;

	pthread_mutex_lock(&pkts->list_lock);
	for (; i != (stop % pkts->list_len); i = (i+1) % pkts->list_len) {
		if (first_iteration) {
			first_iteration = 0;
			first_interval = pkts->list[i].xmit;
		}

		if (try_get_latency(pkts, i, &nsec))
			total_nsec += nsec;
		else
			lost++;
	}
	pthread_mutex_unlock(&pkts->list_lock);

	if (cfg->pkts_per_summary == lost) {
		printf("Lost all packets\n");
		if (!cfg->out_file)
			return;
		fprintf(cfg->out_file, "\n");
	} else {
		int pkts_got = cfg->pkts_per_summary - lost;
		__u64 avg_ns = (total_nsec/pkts_got);
		__u64 avg_us = avg_ns / 1000;
		__u64 avg_ms = avg_us / 1000;
		diff = diff_timespec(&first_interval, &cfg->first_tstamp);
		__u64 offset_ms = diff.tv_nsec / 1000000;
		__u64 offset_s = diff.tv_sec;
		printf("%llu.%03llu: Avg: %3llu ms. %3llu us. %3llu ns. Lost: %d/%d\n",
			offset_s, offset_ms,
			avg_ms, avg_us % 1000, avg_ns % 1000,
			lost, cfg->pkts_per_summary);

		if (!cfg->out_file)
			return;
		fprintf(cfg->out_file, "%llu.%03llu %09llu\n", offset_s, offset_ms, avg_ns);
	}
}

void sender(int sock, unsigned char mac[ETH_ALEN], Config *cfg, Packets *pkts)
{
	int length = 0;
	__u16 tx_seq;
	int delay_us = 1000 * (1000 / cfg->pkts_per_sec);

	while (running) {
		 /*write one packet */
		tx_seq = sendpacket(sock, length, mac, cfg, pkts);
		pkts->txcount_flag = 0;
		 /* Receive xmit timestamp for packet */
		if (!cfg->one_step)
			rcv_xmit_tstamp(sock, cfg, pkts, tx_seq);
		usleep(delay_us);

		/* The first condition checks that it has transmitted more than
		 * one interval, so we don't check the average right after
		 * sending the first interval. Average is always calculated one
		 * interval after the final packet of that interval was sent.
		 */
		if (pkts->next_seq > (__u16)cfg->pkts_per_summary
		    && (pkts->next_seq % cfg->pkts_per_summary) == 0)
			calculate_latency(cfg, pkts);
	}
}

/* ======= Setup ======= */

static void setsockopt_txtime(int fd)
{
	struct sock_txtime so_txtime_val = {
			.clockid =  CLOCK_TAI,
			/*.flags = SOF_TXTIME_DEADLINE_MODE | SOF_TXTIME_REPORT_ERRORS */
			.flags = SOF_TXTIME_REPORT_ERRORS
			};
	struct sock_txtime so_txtime_val_read = { 0 };
	socklen_t vallen = sizeof(so_txtime_val);

	/*if (send_now)*/
		/*so_txtime_val.flags |= SOF_TXTIME_DEADLINE_MODE;*/

	if (setsockopt(fd, SOL_SOCKET, SO_TXTIME,
		       &so_txtime_val, sizeof(so_txtime_val)))
		printf("setsockopt txtime error!\n");

	if (getsockopt(fd, SOL_SOCKET, SO_TXTIME,
		       &so_txtime_val_read, &vallen))
		printf("getsockopt txtime error!\n");

	if (vallen != sizeof(so_txtime_val) ||
	    memcmp(&so_txtime_val, &so_txtime_val_read, vallen))
		printf("getsockopt txtime: mismatch\n");
}

int setup_sock(char *interface, int prio, int st_tstamp_flags, bool ptp_only, bool one_step)
{
	struct hwtstamp_config hwconfig, hwconfig_requested;
	struct sockaddr_ll addr;
	struct ifreq hwtstamp;
	struct ifreq device;
	socklen_t len;
	int sock;
	int val;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		bail("socket");

	memset(&device, 0, sizeof(device));
	strncpy(device.ifr_name, interface, sizeof(device.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &device) < 0)
		bail("getting interface index");

	/* Set the SIOCSHWTSTAMP ioctl */
	memset(&hwtstamp, 0, sizeof(hwtstamp));
	strncpy(hwtstamp.ifr_name, interface, sizeof(hwtstamp.ifr_name));
	hwtstamp.ifr_data = (void *)&hwconfig;
	memset(&hwconfig, 0, sizeof(hwconfig));

	if (st_tstamp_flags & SOF_TIMESTAMPING_TX_HARDWARE) {
		if (one_step)
			hwconfig.tx_type = HWTSTAMP_TX_ONESTEP_SYNC;
		else
			hwconfig.tx_type = HWTSTAMP_TX_ON;
	} else {
		hwconfig.tx_type = HWTSTAMP_TX_OFF;
	}
	if (ptp_only)
		hwconfig.rx_filter =
			(st_tstamp_flags & SOF_TIMESTAMPING_RX_HARDWARE) ?
			HWTSTAMP_FILTER_PTP_V2_SYNC : HWTSTAMP_FILTER_NONE;
	else
		hwconfig.rx_filter =
			(st_tstamp_flags & SOF_TIMESTAMPING_RX_HARDWARE) ?
			HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;

	hwconfig_requested = hwconfig;
	if (ioctl(sock, SIOCSHWTSTAMP, &hwtstamp) < 0) {
		if ((errno == EINVAL || errno == ENOTSUP) &&
		    hwconfig_requested.tx_type == HWTSTAMP_TX_OFF &&
		    hwconfig_requested.rx_filter == HWTSTAMP_FILTER_NONE) {
			printf("SIOCSHWTSTAMP: disabling hardware time stamping not possible\n");
			exit(1);
		}
		else {
			printf("SIOCSHWTSTAMP: operation not supported!\n");
			exit(1);
		}
	}
	printf("SIOCSHWTSTAMP: tx_type %d requested, got %d; rx_filter %d requested, got %d\n",
	       hwconfig_requested.tx_type, hwconfig.tx_type,
	       hwconfig_requested.rx_filter, hwconfig.rx_filter);

	/* bind to PTP port */
	addr.sll_ifindex = device.ifr_ifindex;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_pkttype = PACKET_BROADCAST;
	addr.sll_hatype   = ARPHRD_ETHER;
	memset(addr.sll_addr, 0, 8);
	addr.sll_halen = 0;
	if (bind(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_ll)) < 0)
		bail("bind");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)))
		bail("setsockopt SO_BINDTODEVICE");
	if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(int)))
		bail("setsockopt SO_PRIORITY");

	if (st_tstamp_flags &&
	    setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING,
		       &st_tstamp_flags, sizeof(st_tstamp_flags)) < 0)
		printf("setsockopt SO_TIMESTAMPING not supported\n");

	/* verify socket options */
	len = sizeof(val);

	if (getsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &val, &len) < 0) {
		printf("%s: %s\n", "getsockopt SO_TIMESTAMPING", strerror(errno));
	} else {
		DEBUG("SO_TIMESTAMPING %d\n", val);
		if (val != st_tstamp_flags)
			printf("   not the expected value %d\n", st_tstamp_flags);
	}

	setsockopt_txtime(sock);

	return sock;
}

int setup_tx_sock(char *iface, int prio, bool ptp_only, bool one_step)
{
	int so_tstamp_flags = 0;
	so_tstamp_flags |= (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_OPT_TSONLY);
	so_tstamp_flags |= (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_CMSG);
	so_tstamp_flags |= SOF_TIMESTAMPING_RAW_HARDWARE;

	return setup_sock(iface, prio, so_tstamp_flags, ptp_only, one_step);
}

int setup_rx_sock(char *iface, int prio, bool ptp_only)
{
	int so_tstamp_flags = 0;
	so_tstamp_flags |= (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_CMSG);
	so_tstamp_flags |= SOF_TIMESTAMPING_RAW_HARDWARE;

	return setup_sock(iface, prio, so_tstamp_flags, ptp_only, false);
}

void plot(Config *cfg, char *data_filename)
{
	char plot[200];
	char output[200];
	int num_cmd;
	int i;

	memset(plot, 0, 200);
	memset(output, 0, 200);

	char *commandsForGnuplot[] = {
		"set format y '%0.f'",
		"set yrange [0:*]",
		"set xlabel 'Time since start (s)'",
		"set ylabel 'Latency (ns)'",
		"set grid mytics",
		"set grid ytics",
		"set grid xtics",
		"set grid mxtics",
		"set mytics 4",
		"set mxtics 4",
		"set xtics nomirror",
		"set ytics nomirror",
		"set autoscale xfix",
		"unset key",
		"set style line 1 lc rgb '#E41A1C' pt 1 ps 1 lt 1 lw 2 # red",
		"set terminal pdfcairo enhanced color dashed font 'Arial, 14' rounded size 16 cm, 9.6 cm",
	};

	num_cmd = sizeof(commandsForGnuplot) / sizeof(char *);

	/* Opens an interface that one can use to send commands as if they were
	 * typing into the gnuplot command line.
	 */
	FILE * gnuplotPipe = popen ("gnuplot", "w");
	for (i = 0; i < num_cmd; i++) {
		/* Send commands to gnuplot one by one */
		fprintf(gnuplotPipe, "%s \n", commandsForGnuplot[i]);
	}

	fprintf(gnuplotPipe, "set output '%s'\n", cfg->plot_filename);
	fprintf(gnuplotPipe, "plot '%s' with histeps ls 1\n", data_filename);
	fclose(gnuplotPipe);
	printf("\nPlot written to '%s'\n", cfg->plot_filename);
}

static int parse_args(int argc, char **argv, Config *cfg)
{
	int opt_index;
	int c;

	struct option long_options[] = {
		{ "version",          no_argument,       NULL,    'V' },
		{ "help",             no_argument,       NULL,    'h' },
		{ "tx",               required_argument, NULL,    't' },
		{ "rx",               required_argument, NULL,    'r' },
		{ "prio",             required_argument, NULL,    'p' },
		{ "vlan",             required_argument, NULL,    'v' },
		{ "pkts_per_summary", required_argument, NULL,    'S' },
		{ "pkts_per_sec",     required_argument, NULL,    's' },
		{ "out",              required_argument, NULL,    'O' },
		{ "plot",             required_argument, NULL,    'P' },
		{ "one-step",         no_argument,       NULL,    'o' },
		{ "tstamp-all",       no_argument,       NULL,    'a' },
		{ "debug",            no_argument,       NULL,    'd' },
		{ NULL,               0,                 NULL,     0  }
	};

	while ((c = getopt_long(argc, argv, "O:S:s:p:v:r:t:hdV", long_options, &opt_index)) != -1) {
		switch (c)
		{
			case 'O':
				cfg->out_filename = optarg;
				break;
			case 'o':
				cfg->one_step = true;
				break;
			case 'a':
				cfg->ptp_only = false;
				break;
			case 'P':
				cfg->plot = true;
				cfg->plot_filename = optarg;
				break;
			case 't':
				cfg->tx_iface = optarg;
				break;
			case 'r':
				cfg->rx_iface = optarg;
				break;
			case 'p':
				cfg->prio = strtol(optarg, NULL, 0);
				if (cfg->prio < 0 || cfg->prio > 7) {
					fprintf(stderr, "Out of range: Prio must be 0-7\n");
					return EINVAL;
				}
				break;
			case 'v':
				cfg->vlan = strtol(optarg, NULL, 0);
				if (cfg->vlan < 0 || cfg->prio > 4095) {
					fprintf(stderr, "Out of range: VLAN must be 0-4095\n");
					return EINVAL;
				}
				break;
			case 's':
				cfg->pkts_per_sec = strtoul(optarg, NULL, 0);
				if (cfg->pkts_per_sec <= 0 || cfg->pkts_per_sec > 1000) {
					bail("Packets per second must be 0 < x <= 1000");
				}
				break;
			case 'S':
				cfg->pkts_per_summary = strtoul(optarg, NULL, 0);
				if (cfg->pkts_per_summary <= 0) {
					bail("Packets per summary must be greater than 0");
				}
				break;
			case 'd':
				debugen = 1;
				break;
			case 'h':
				help();
				exit(0);
			case 'V':
				LATENCY_VERSION();
				exit(0);
			case '?':
				if (optopt == 'c')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else
					fprintf (stderr,
						"Unknown option character `\\x%x'.\n",
						optopt);
				return EINVAL;
			default:
				help();
				exit(0);
		}
	}

	if (!cfg->tx_iface) {
		ERR("missing tx interface\n");
		return -1;
	}
	if (!cfg->rx_iface) {
		ERR("missing rx interface\n");
		return -1;
	}

	if (strcmp(cfg->tx_iface, cfg->rx_iface) == 0) {
		ERR("tx and rx iface cannot be the same\n");
		return -1;
	}

	if (!cfg->ptp_only && cfg->one_step) {
		ERR("can't combine tstamp-all with one-step\n");
		return -1;
	}

	/* If not set, default to one summary per second */
	if (cfg->pkts_per_summary == 0)
		cfg->pkts_per_summary = cfg->pkts_per_sec;


	return 0;
}

int main(int argc, char **argv)
{
	unsigned char mac[ETH_ALEN];
	bool using_tmpfile = false;
	struct thread_data args;
	pthread_t receiver;
	char tmpnamebuf[24];
	Packets pkts;
	Config cfg;
	int tx_sock;
	int err;

	memset(&cfg, 0, sizeof(Config));
	memset(&pkts, 0, sizeof(Packets));

	cfg.has_first = false;
	cfg.one_step = false;
	cfg.ptp_only = true;
	cfg.pkts_per_sec = 100;
	cfg.pkts_per_summary = 0;
	cfg.out_file = NULL;
	cfg.prio = 0;
	cfg.vlan = 0;
	cfg.plot = false;
	cfg.plot_filename = NULL;

	pkts.txcount_flag = false;
	pkts.list_head = 0;
	pkts.next_seq = 0;

	err = parse_args(argc, argv, &cfg);
	if (err)
		return err;

	if (using_tagged(&cfg))
		pkts.frame = sync_packet_tagged;
	else
		pkts.frame = sync_packet;

	set_vid_pcp(&cfg, &pkts);

	if (cfg.out_filename) {
		cfg.out_file = fopen(cfg.out_filename, "w");
		if (!cfg.out_file) {
			ERR("invalid filename '%s'\n", cfg.out_filename);
			return EINVAL;
		}
	}

	if (cfg.plot && !cfg.out_filename) {
		using_tmpfile = true;
		memset(tmpnamebuf, 0, sizeof(tmpnamebuf));
		cfg.out_filename = tmpnamebuf;
		strncpy(tmpnamebuf, "/tmp/latency-XXXXXX", 19);
		int fd = mkstemp(tmpnamebuf);
		cfg.out_file = fdopen(fd, "w");
		if (!cfg.out_file) {
			ERR("problems creating tempfile\n");
			return EINVAL;
		}
	}

	signal(SIGINT, sig_handler);
	pthread_mutex_init(&pkts.list_lock, NULL);
	/* pktlist is a circular buffer with space for two intervals of packets */
	pkts.list_len = cfg.pkts_per_summary * 2;
	pkts.list = calloc(sizeof(struct pkt_time), pkts.list_len);
	if (!pkts.list)
		return ENOMEM;

	/* Receiver */
	args.sockfd = setup_rx_sock(cfg.rx_iface, cfg.prio, cfg.ptp_only);
	args.cfg = &cfg;
	args.pkts = &pkts;
	pthread_create(&receiver, NULL, rcv_pkt, &args);

	/* Sender */
	tx_sock = setup_tx_sock(cfg.tx_iface, cfg.prio, cfg.ptp_only, cfg.one_step);
	get_smac(tx_sock, cfg.tx_iface, mac);
	set_smac(pkts.frame, mac);

	/* Main loop */
	printf("Transmitting...\n");
	sender(tx_sock, mac, &cfg, &pkts);

	/* Cleanup */
	if (cfg.out_file)
		fclose(cfg.out_file);
	pthread_join(receiver, NULL);
	free(pkts.list);

	if (cfg.plot)
		plot(&cfg, cfg.out_filename);

	if (using_tmpfile)
		remove(cfg.out_filename);

	return 0;
}

