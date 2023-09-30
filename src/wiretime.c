// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
/*
 * Copyright 2019 NXP
 */

/* TODO: Fix bug with TX side getting stuck on 'select' when another
 * application transmits a lot of data on the same interface.
 *
 * TODO: Don't allow mixing one-step and tagged VLAN. One-step assumes the
 * packet is not tagged on some (all?) timestamping engines. So the timestamp
 * may be written to the wrong location, or not at all.
 *
 * TODO: PHY timestamping with only a looped cable reports earlier RX time than
 * TX time. Possibly hardware related issue.
 *
 * TODO: Doing 100's of packets per second on laptop (e1000e driver, single
 * port) causes certain packets to not have their timestamp fetched on RX. Not
 * sure if other devices are affected.
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <getopt.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <fcntl.h>

#include <asm/types.h>

#include <linux/if_ether.h>

#include "version.h"
#include "liblink.h"
#include "wiretime.h"


#define VLAN_TAG_SIZE 4
#define PRIO_OFFSET 14
#define DOMAIN_NUM_OFFSET 18
#define SEQ_OFFSET 44
#define TIME_SEC_OFFSET 48
#define TIME_NSEC_OFFSET 54

#define DOMAIN_NUM 0xff


bool debugen = false;
bool running = true;


void help()
{
	fputs(  "wiretime - Measure packet time on wire using hardware timestamping\n"
		"\n"
		"USAGE:\n"
		"        wiretime --tx <IFACE1> --rx <IFACE2> [OPTIONS]\n"
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
		"        -p, --pcp <PRIO>\n"
		"            PCP priority. If VLAN is not set it will use VLAN 0.\n"
		"        -v, --vlan <VID>\n"
		"            Tag with this VID (useful when used together with PCP).\n"
		"        -P, --prio <PRIO>\n"
		"            Socket priority. Useful for egress QoS.\n"
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
		"        --tstamp-all\n"
		"            Enable timestamping of non-PTP packets. On some NICs this will behave\n"
		"            differently than timestamping PTP packets only.\n"

		/*"\n"*/
		,stderr);

}

static void u16_to_char(unsigned char a[], __u16 n) {
	memcpy(a, &n, 2);
}

static __u16 char_to_u16(unsigned char a[]) {
	__u16 n = 0;
	memcpy(&n, a, 2);
	return n;
}

static void debug_packet_data(size_t length, uint8_t *data)
{
	size_t i;

	if (!debugen)
		return;

	DEBUG("Length %ld\n", length);
	if (length > 0) {
		fprintf(stderr, " ");
		for (i = 0; i < length; i++)
			fprintf(stderr, "%02x ", data[i]);
		fprintf(stderr, "\n");
	}
}


static void sig_handler(int sig)
{
	running = false;
}

static uint64_t gettime_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_TAI, &ts))
		printf("error gettime");

	return ts.tv_sec * (1000ULL * 1000 * 1000) + ts.tv_nsec;
}

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

static inline int using_tagged(Config *cfg)
{
	return cfg->vlan != 0 || cfg->pcp != 0;
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
	pkts->frame[PRIO_OFFSET] = ((cfg->pcp & 0x7) << 5) | ((cfg->vlan & 0xf00) >> 8);
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

/* Checks that the packet received was actually one sent by us */
static int is_rx_tstamp(unsigned char *buf)
{
	// Will arive without tag when received on the socket
	/*if (using_tagged())*/
		/*return buf[DOMAIN_NUM_OFFSET + VLAN_TAG_SIZE] == DOMAIN_NUM;*/
	/*else*/
		return buf[DOMAIN_NUM_OFFSET] == DOMAIN_NUM;
}



/* ======= Receiving ======= */

static struct timespec get_one_step(Packets *pkts, int idx, unsigned char *data, __u16 pkt_seq)
{
	struct timespec one_step_ts;

	// XXX: Assumes 64-bit time
	// Since we need the lower 6 bytes, copy 8 and set the upper 2 to zero.
	memcpy(&one_step_ts.tv_sec, &data[TIME_SEC_OFFSET-2], 8);
	memset(&one_step_ts.tv_sec, 0, 2);
	memcpy(&one_step_ts.tv_nsec, &data[TIME_NSEC_OFFSET], 4);
	one_step_ts.tv_sec = be64toh(one_step_ts.tv_sec);
	one_step_ts.tv_nsec = ntohl(one_step_ts.tv_nsec);
	if (pkts->list[idx].seq == pkt_seq)
		pkts->list[idx].xmit = one_step_ts;
	DEBUG("Got TX one-step seq %d. %lu.%lu\n", pkt_seq, one_step_ts.tv_sec, one_step_ts.tv_nsec);

	return one_step_ts;
}

void save_tstamp(struct timespec *stamp, unsigned char *data, size_t length,
		 Config *cfg, Packets *pkts, __s32 tx_seq, int recvmsg_flags)
{
	struct timespec one_step_ts;
	__u16 pkt_seq;
	int idx;
	int got_tx = 0;
	int got_rx = 0;

	debug_packet_data(length, data);

	if (tx_seq >= 0) {
		got_tx = 1;
		pkt_seq = tx_seq;
		DEBUG("Got TX seq %d. %lu.%lu\n", pkt_seq, stamp->tv_sec, stamp->tv_nsec);
	} else if (is_rx_tstamp(data)) {
		got_rx = 1;
		pkt_seq = get_sequenceId(data);
		DEBUG("Got RX seq %d. %lu.%lu\n", pkt_seq, stamp->tv_sec, stamp->tv_nsec);
	} else {
		// If the packet we read was not the tx packet then set back
		// txcount_flag and try again.
		if (recvmsg_flags & MSG_ERRQUEUE)
			pkts->txcount_flag = 0;
		return;
	}

	idx = pkt_seq % pkts->list_len;

	if (got_rx && cfg->one_step)
		one_step_ts = get_one_step(pkts, idx, data, pkt_seq);

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

/* ======= Sending ======= */

static void pkts_append_seq(Packets *pkts, __u16 tx_seq)
{
	pthread_mutex_lock(&pkts->list_lock);
	pkts->list[tx_seq % pkts->list_len].seq = tx_seq;
	pkts->list_head = (pkts->list_head + 1) % pkts->list_len;
	pthread_mutex_unlock(&pkts->list_lock);
}

__u16 prepare_packet(Config *cfg, Packets *pkts)
{
	__u16 tx_seq;

	tx_seq = pkts->next_seq;
	pkts->next_seq++;
	DEBUG("Xmit: %u\n", tx_seq);

	set_sequenceId(cfg, pkts->frame, tx_seq);

	pkts_append_seq(pkts, tx_seq);

	return tx_seq;
}

static __u16 sendpacket(int sock, unsigned int length,
			Config *cfg, Packets *pkts)
{
	__u16 tx_seq;

	tx_seq = prepare_packet(cfg, pkts);

	send(sock, pkts->frame, pkts->frame_size, 0);

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

void calculate_latency(Config *cfg, Packets *pkts, int start, int end)
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
	/*int stop = (pkts->next_seq + cfg->pkts_per_summary) % pkts->list_len;*/
	/*int i = pkts->next_seq % pkts->list_len;*/
	struct timespec diff;
	struct timespec first_interval;
	int first_iteration = 1;
	__u64 total_nsec = 0;
	__u64 nsec;
	int pkts_got = 0;

	pthread_mutex_lock(&pkts->list_lock);
	for (int i = start; i != (end % pkts->list_len); i = (i+1) % pkts->list_len) {
		if (first_iteration) {
			first_iteration = 0;
			first_interval = pkts->list[i].xmit;
		}
		if (try_get_latency(pkts, i, &nsec)) {
			total_nsec += nsec;
			pkts_got++;
		}
	}
	pthread_mutex_unlock(&pkts->list_lock);

	if (pkts_got == 0) {
		printf("Lost all packets\n");
		if (!cfg->out_file)
			return;
		fprintf(cfg->out_file, "\n");
	} else {
		__u64 avg_ns = (total_nsec/pkts_got);
		__u64 avg_us = avg_ns / 1000;
		__u64 avg_ms = avg_us / 1000;
		diff = diff_timespec(&first_interval, &cfg->first_tstamp);
		__u64 offset_ms = diff.tv_nsec / 1000000;
		__u64 offset_s = diff.tv_sec;
		printf("%llu.%03llu: Avg: %3llu ms. %3llu us. %3llu ns. Got %d/%d\n",
			offset_s, offset_ms,
			avg_ms, avg_us % 1000, avg_ns % 1000,
			pkts_got, cfg->batch_size);

		if (!cfg->out_file)
			return;
		fprintf(cfg->out_file, "%llu.%03llu %09llu\n", offset_s, offset_ms, avg_ns);
	}
}

void *sender(void *args)
{
	struct thread_data *data = args;
	int sock = data->sockfd;
	Config *cfg = data->cfg;
	Packets *pkts = data->pkts;

	int length = 0;
	__u16 tx_seq;
	/*int delay_us = 1000 * (1000 / cfg->pkts_per_sec);*/
	int delay_us = cfg->interval * 1000;

	/*while (running) {*/
		 /*write one packet */
		tx_seq = sendpacket(sock, length, cfg, pkts);
		pkts->txcount_flag = 0;

		// TODO: Move this part onto the rx thread (rcv_pkt function)?
		// That way the sender can focus purely on sending and the
		// receiver can handle all timestamp readouts.

		 /* Receive xmit timestamp for packet */
		if (!cfg->one_step)
			rcv_xmit_tstamp(sock, cfg, pkts, tx_seq);
		/*usleep(delay_us);*/

		/* The first condition checks that it has transmitted more than
		 * one interval, so we don't check the average right after
		 * sending the first interval. Average is always calculated one
		 * interval after the final packet of that interval was sent.
		 */
		/*if (pkts->next_seq > (__u16)cfg->pkts_per_summary*/
		    /*&& (pkts->next_seq % cfg->pkts_per_summary) == 0)*/
			/*calculate_latency(cfg, pkts);*/
	/*}*/
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
		{ "pcp",              required_argument, NULL,    'p' },
		{ "vlan",             required_argument, NULL,    'v' },
		{ "prio",             required_argument, NULL,    'P' },
		{ "pkts_per_summary", required_argument, NULL,    'S' },
		{ "pkts_per_sec",     required_argument, NULL,    's' },
		{ "out",              required_argument, NULL,    'O' },
		{ "plot",             required_argument, NULL,    '1' },
		{ "one-step",         no_argument,       NULL,    'o' },
		{ "tstamp-all",       no_argument,       NULL,    '2' },
		{ "debug",            no_argument,       NULL,    'd' },
		{ NULL,               0,                 NULL,     0  }
	};

	while ((c = getopt_long(argc, argv, "O:b:i:P:p:v:r:t:hdVSo", long_options, &opt_index)) != -1) {
		switch (c)
		{
			case 'O':
				cfg->out_filename = optarg;
				break;
			case 'o':
				cfg->one_step = true;
				break;
			case 'S':
				cfg->software_ts = true;
				break;
			case '1':
				cfg->plot = true;
				cfg->plot_filename = optarg;
				break;
			case '2':
				cfg->ptp_only = false;
				break;
			case 't':
				cfg->tx_iface = optarg;
				break;
			case 'r':
				cfg->rx_iface = optarg;
				break;
			case 'p':
				cfg->pcp = strtol(optarg, NULL, 0);
				if (cfg->pcp < 0 || cfg->pcp > 7) {
					fprintf(stderr, "Out of range: PCP must be 0-7\n");
					return EINVAL;
				}
				break;
			case 'P':
				cfg->priority = strtol(optarg, NULL, 0);
				if (cfg->priority < 0 || cfg->priority > 7) {
					fprintf(stderr, "Out of range: priority must be 0-7\n");
					return EINVAL;
				}
				break;
			case 'v':
				cfg->vlan = strtol(optarg, NULL, 0);
				if (cfg->vlan < 0 || cfg->vlan > 4095) {
					fprintf(stderr, "Out of range: VLAN must be 0-4095\n");
					return EINVAL;
				}
				break;
			case 'i':
				cfg->interval = strtoul(optarg, NULL, 0);
				if (cfg->interval <= 0) {
					bail("Interval must be greater than 0");
				}
				break;
			case 'b':
				cfg->batch_size = strtoul(optarg, NULL, 0);
				if (cfg->batch_size <= 0 || cfg->batch_size > 32768) {
					bail("Batch size must be a value 1-32768");
				}
				break;
			case 'd':
				debugen = 1;
				break;
			case 'h':
				help();
				exit(0);
			case 'V':
				WIRETIME_VERSION();
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
	/*if (cfg->pkts_per_summary == 0)*/
		/*cfg->pkts_per_summary = cfg->pkts_per_sec;*/


	return 0;
}

static int make_tmp_fd(char *tmpnamebuf)
{
	memset(tmpnamebuf, 0, sizeof(tmpnamebuf));
	/*cfg.out_filename = tmpnamebuf;*/
	strncpy(tmpnamebuf, "/tmp/wiretime-XXXXXX", 20);
	return mkstemp(tmpnamebuf);
}

int main(int argc, char **argv)
{
	unsigned char mac[ETH_ALEN];
	bool using_tmpfile = false;
	struct thread_data tx_args;
	struct thread_data rx_args;
	pthread_t rx_thread;
	pthread_t tx_thread;
	char tmpnamebuf[20];
	Packets pkts;
	Config cfg;
	int tx_sock;
	int err;

	memset(&cfg, 0, sizeof(Config));
	memset(&pkts, 0, sizeof(Packets));

	cfg.has_first = false;
	cfg.one_step = false;
	cfg.ptp_only = true;
	cfg.interval = 1000;
	cfg.batch_size = 1;
	cfg.out_file = NULL;
	cfg.pcp  = 0;
	cfg.vlan = 0;
	cfg.priority = 0;
	cfg.plot = false;
	cfg.plot_filename = NULL;

	pkts.txcount_flag = false;
	pkts.list_head = 0;
	pkts.next_seq = 0;

	err = parse_args(argc, argv, &cfg);
	if (err)
		return err;

	if (using_tagged(&cfg)) {
		pkts.frame = sync_packet_tagged;
		pkts.frame_size = sizeof(sync_packet_tagged);
	} else {
		pkts.frame = sync_packet;
		pkts.frame_size = sizeof(sync_packet);
	}

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
		int fd = make_tmp_fd(tmpnamebuf);
		cfg.out_filename = tmpnamebuf;
		cfg.out_file = fdopen(fd, "w");
		if (!cfg.out_file) {
			ERR("problems creating tempfile\n");
			return EINVAL;
		}
	}

	signal(SIGINT, sig_handler);
	pthread_mutex_init(&pkts.list_lock, NULL);
	/* pktlist is a circular buffer with space for two intervals of packets */
	/* pkts is a circular buffer with space for two intervals of packets */

	int timer_interval_ms; // = cfg.batch_size * cfg.interval;//) + 1000;
	pkts.timerfd = timerfd_create(CLOCK_REALTIME, 0);
	struct itimerspec timer;
	timer.it_value.tv_sec = cfg.interval / 1000;
	timer.it_value.tv_nsec = (cfg.interval % 1000) * 1000000;
	timer.it_interval.tv_sec = cfg.interval / 1000;
	timer.it_interval.tv_nsec = (cfg.interval % 1000) * 1000000;

	/* How many times the timer has to trigger until 1 second has passed */
	/*pkts.triggers_behind_timer = 1000 / (cfg.batch_size * cfg.interval);*/
	pkts.triggers_behind_timer = 0;
	for (int i = 0; i < 1000; i += cfg.interval)
		pkts.triggers_behind_timer++;

	pkts.list_len = 65536;
	pkts.list = calloc(sizeof(struct pkt_time), pkts.list_len);
	if (!pkts.list)
		return ENOMEM;

	/* Receiver */
	rx_args.sockfd = setup_rx_sock(cfg.rx_iface, cfg.priority, cfg.ptp_only, cfg.software_ts);
	rx_args.cfg = &cfg;
	rx_args.pkts = &pkts;
	pthread_create(&rx_thread, NULL, rcv_pkt, &rx_args);

	/* Sender */
	tx_args.sockfd = setup_tx_sock(cfg.tx_iface, cfg.priority, cfg.ptp_only, cfg.one_step, cfg.software_ts);
	get_smac(tx_sock, cfg.tx_iface, mac);
	set_smac(pkts.frame, mac);
	tx_args.cfg = &cfg;
	tx_args.pkts = &pkts;
	/*pthread_create(&tx_thread, NULL, sender, &tx_args);*/

	/* Main loop */
	/*printf("Transmitting...\n");*/
	/*sender(tx_sock, &cfg, &pkts);*/

	timerfd_settime(pkts.timerfd, 0, &timer, NULL);

	/* Wait */
	fd_set rfds;
	int retval;

	/* Watch timerfd file descriptor */
	FD_ZERO(&rfds);
	/*FD_SET(0, &rfds);*/
	FD_SET(pkts.timerfd, &rfds);

	__u64 triggers = 0;
	/* Count to ensure a whole batch has been sent when the time is reached */
	int current_batch = 0;

	char dummybuf[8];
	/*struct timeval tv;*/
	/*tv.tv_sec = 0;*/
	/*tv.tv_usec = 1000000;*/
	/*read(pkts.timerfd, dummybuf, 8);*/

	while (running) {
		/*printf("Trigger %llu\n", triggers);*/
		retval = select(pkts.timerfd+1, &rfds, NULL, NULL, NULL); /* Last parameter = NULL --> wait forever */
		if (retval < 0 && errno == EINTR) {
			break;
		}
		if (retval < 0) {
			perror("Error");
			break;
		}
		if (retval == 0) {
			printf("Continuing...\n");
			continue;
		}

		if (FD_ISSET(pkts.timerfd, &rfds))
			read(pkts.timerfd, dummybuf, 8);

		/*pkts.next_seq++;*/
		sender(&tx_args);
		triggers++;
		current_batch++;

		if (current_batch >= cfg.batch_size && triggers > (pkts.triggers_behind_timer + cfg.batch_size)){
			int idx = triggers-pkts.triggers_behind_timer-cfg.batch_size-1;
			calculate_latency(&cfg, &pkts, idx, idx+cfg.batch_size);
			current_batch = 0;
		}
	}

	/* Cleanup */
	if (cfg.out_file)
		fclose(cfg.out_file);
	/*pthread_join(rx_thread, NULL);*/
	/*pthread_join(tx_thread, NULL);*/
	free(pkts.list);

	if (cfg.plot)
		plot(&cfg, cfg.out_filename);

	if (using_tmpfile)
		remove(cfg.out_filename);

	return 0;
}

