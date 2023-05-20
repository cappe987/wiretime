// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

/*#include <stdio.h>*/
/*#include <stdbool.h>*/
/*#include <stdlib.h>*/
/*#include <errno.h>*/
/*#include <string.h>*/
/*#include <unistd.h>*/
/*#include <pthread.h>*/
/*#include <sys/time.h>*/
#include <asm/socket.h>
/*#include <sys/types.h>*/
/*#include <sys/select.h>*/
/*#include <sys/ioctl.h>*/
#include <arpa/inet.h>
/*#include <net/if.h>*/
/*#include <linux/if_arp.h>*/
/*#include <sys/queue.h>*/
/*#include <signal.h>*/
/*#include <getopt.h>*/
/*#include <endian.h>*/

#include <asm/types.h>

#include <linux/if_ether.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

#include "wiretime.h"


void get_timestamp(struct msghdr *msg, struct timespec **stamp, int recvmsg_flags, Packets *pkts)
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
				 * Only HW raw is set
				 */
				/* skip SW */
				(*stamp)++;
				/* skip deprecated HW transformed */
				(*stamp)++;
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
