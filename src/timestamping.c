// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <asm/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_arp.h>

#include <asm/types.h>

#include <linux/net_tstamp.h>

#include "wiretime.h"

static void bail(const char *error)
{
	printf("%s: %s\n", error, strerror(errno));
	exit(1);
}

void print_timestamp(const char *str, struct timespec stamp)
{
	printf("Timestamp %s: %ld.%ld\n", str, stamp.tv_sec, stamp.tv_nsec);
}

void get_timestamp(struct msghdr *msg, struct timespec **stamp, int recvmsg_flags, Packets *pkts, Config *cfg)
{
	struct sockaddr_in *from_addr = (struct sockaddr_in *)msg->msg_name;
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
			switch (cmsg->cmsg_type) {
			case SO_TIMESTAMPING: {
				*stamp = (struct timespec *)CMSG_DATA(cmsg);
				/* stamp is an array containing 3 timespecs:
				 * SW, HW transformed, HW raw.
				 * Use SW or HW raw
				 */
				if (!cfg->software_ts) {
					/* skip SW */
					(*stamp)++;
					/* skip deprecated HW transformed */
					(*stamp)++;
				}
				if (recvmsg_flags & MSG_ERRQUEUE)
					pkts->txcount_flag = 1;
				break;
			}
			default:
				/*DEBUG("type %d\n", cmsg->cmsg_type);*/
				break;
			}
			break;
		default:
			/*DEBUG("level %d type %d\n",*/
				/*cmsg->cmsg_level,*/
				/*cmsg->cmsg_type);*/
			break;
		}
	}
}

static void recvpacket(int sock, int recvmsg_flags,
		       Config *cfg, Packets *pkts,
		       __s32 tx_seq)
{
	char data[256];
	struct msghdr msg;
	struct iovec entry;
	struct sockaddr_in from_addr;
	struct timespec *stamp = NULL;
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
	if (res >= 0) {
		get_timestamp(&msg, &stamp, recvmsg_flags, pkts, cfg);
		if (!stamp)
			return;
		save_tstamp(stamp, msg.msg_iov->iov_base,
			    res, cfg, pkts, tx_seq, recvmsg_flags);
	}
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

static void setsockopt_txtime(int fd)
{
	struct sock_txtime so_txtime_val = {
			.clockid =  CLOCK_TAI,
			/*.flags = SOF_TXTIME_DEADLINE_MODE | SOF_TXTIME_REPORT_ERRORS */
			.flags = SOF_TXTIME_REPORT_ERRORS
			};
	struct sock_txtime so_txtime_val_read = { 0 };
	socklen_t vallen = sizeof(so_txtime_val);

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

static void setup_hwconfig(char *interface, int sock, int st_tstamp_flags,
			   bool ptp_only, bool one_step)
{
	struct hwtstamp_config hwconfig, hwconfig_requested;
	struct ifreq hwtstamp;

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
}

int setup_sock(char *interface, int prio, int st_tstamp_flags,
	       bool ptp_only, bool one_step, bool software_ts)
{
	struct sockaddr_ll addr;
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

	if (!software_ts) {
		setup_hwconfig(interface, sock, st_tstamp_flags, ptp_only, one_step);
	}

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

int setup_tx_sock(char *iface, int prio, bool ptp_only, bool one_step, bool software_ts)
{
	int so_tstamp_flags = 0;

	if (software_ts) {
		so_tstamp_flags |= (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_OPT_TSONLY);
		so_tstamp_flags |= (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_OPT_CMSG);
		so_tstamp_flags |= SOF_TIMESTAMPING_SOFTWARE;
	} else {
		so_tstamp_flags |= (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_OPT_TSONLY);
		so_tstamp_flags |= (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_CMSG);
		so_tstamp_flags |= SOF_TIMESTAMPING_RAW_HARDWARE;
	}

	return setup_sock(iface, prio, so_tstamp_flags, ptp_only, one_step, software_ts);
}

int setup_rx_sock(char *iface, int prio, bool ptp_only, bool software_ts)
{
	int so_tstamp_flags = 0;

	if (software_ts) {
		so_tstamp_flags |= (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_OPT_CMSG);
		so_tstamp_flags |= SOF_TIMESTAMPING_SOFTWARE;
	}
	else {
		so_tstamp_flags |= (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_CMSG);
		so_tstamp_flags |= SOF_TIMESTAMPING_RAW_HARDWARE;
	}

	return setup_sock(iface, prio, so_tstamp_flags, ptp_only, false, software_ts);
}
