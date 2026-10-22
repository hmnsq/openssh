/*
 * Copyright (c) 2005 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/ioctl.h>

#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <arpa/inet.h>
#অন্তর্ভাৱ <netinet/ip.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "openbsd-compat/sys-queue.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "channels.h"
#অন্তর্ভাৱ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#যদি defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#অন্তর্ভাৱ <linux/if.h>
#endif

#যদি defined(SYS_RDOMAIN_LINUX)
ৱর্ণ *
sys_get_rdomain(পূর্ণাঙ্ক fd)
{
	ৱর্ণ dev[IFNAMSIZ + 1];
	socklen_t len = পরিমাণ(dev) - 1;

	যদি (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ঘূৰাই রিক্ত;
	}
	dev[len] = '\0';
	ঘূৰাই strdup(dev);
}

পূর্ণাঙ্ক
sys_set_rdomain(পূর্ণাঙ্ক fd, ধ্রুৱ ৱর্ণ *name)
{
	যদি (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ঘূৰাই -1;
	}
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sys_valid_rdomain(ধ্রুৱ ৱর্ণ *name)
{
	পূর্ণাঙ্ক fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	যদি ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ঘূৰাই 0;
	যদি (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		ঘূৰাই 0;
	}
	close(fd);
	ঘূৰাই 1;
}
#নোচেদ্যদি defined(SYS_RDOMAIN_XXX)
/* XXX examples */
ৱর্ণ *
sys_get_rdomain(পূর্ণাঙ্ক fd)
{
	ঘূৰাই রিক্ত;
}

পূর্ণাঙ্ক
sys_set_rdomain(পূর্ণাঙ্ক fd, ধ্রুৱ ৱর্ণ *name)
{
	ঘূৰাই -1;
}

পূর্ণাঙ্ক
valid_rdomain(ধ্রুৱ ৱর্ণ *name)
{
	ঘূৰাই 0;
}

শূন্য
sys_set_process_rdomain(ধ্রুৱ ৱর্ণ *name)
{
	fatal("%s: not supported", __func__);
}
#endif /* defined(SYS_RDOMAIN_XXX) */

/*
 * This is the portable version of the SSH tunnel forwarding, it
 * uses some preprocessor definitions for various platform-specific
 * settings.
 *
 * SSH_TUN_LINUX	Use the (newer) Linux tun/tap device
 * SSH_TUN_FREEBSD	Use the FreeBSD tun/tap device
 * SSH_TUN_COMPAT_AF	Translate the OpenBSD address family
 * SSH_TUN_PREPEND_AF	Prepend/remove the address family
 */

/*
 * System-specific tunnel open function
 */

#যদি defined(SSH_TUN_LINUX)
#অন্তর্ভাৱ <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

পূর্ণাঙ্ক
sys_tun_open(পূর্ণাঙ্ক tun, পূর্ণাঙ্ক mode, ৱর্ণ **ifname)
{
	সংরচনা ifreq ifr;
	পূর্ণাঙ্ক fd = -1;
	ধ্রুৱ ৱর্ণ *name = রিক্ত;

	যদি (ifname != রিক্ত)
		*ifname = রিক্ত;
	যদি ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ঘূৰাই (-1);
	}

	bzero(&ifr, পরিমাণ(ifr));

	যদি (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} অন্যথা {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	যদি (tun != SSH_TUNID_ANY) {
		যদি (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			গচ্ছ failed;
		}
		snprintf(ifr.ifr_name, পরিমাণ(ifr.ifr_name), name, tun);
	}

	যদি (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		গচ্ছ failed;
	}

	যদি (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	অন্যথা
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	যদি (ifname != রিক্ত && (*ifname = strdup(ifr.ifr_name)) == রিক্ত)
		গচ্ছ failed;

	ঘূৰাই (fd);

 failed:
	close(fd);
	ঘূৰাই (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#অন্তর্ভাৱ <net/if_tun.h>
#endif

পূর্ণাঙ্ক
sys_tun_open(পূর্ণাঙ্ক tun, পূর্ণাঙ্ক mode, ৱর্ণ **ifname)
{
	সংরচনা ifreq ifr;
	ৱর্ণ name[100];
	পূর্ণাঙ্ক fd = -1, sock;
	ধ্রুৱ ৱর্ণ *tunbase = "tun";
#যদি defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	পূর্ণাঙ্ক flag;
#endif

	যদি (ifname != রিক্ত)
		*ifname = রিক্ত;

	যদি (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ঘূৰাই (-1);
#অন্যথা
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	যদি (tun <= SSH_TUNID_MAX) {
		snprintf(name, পরিমাণ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} অন্যথা যদি (tun == SSH_TUNID_ANY) {
		বাবে (tun = 100; tun >= 0; tun--) {
			snprintf(name, পরিমাণ(name), "/dev/%s%d",
			    tunbase, tun);
			যদি ((fd = open(name, O_RDWR)) >= 0)
				ভঙ্গ;
		}
	} অন্যথা {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ঘূৰাই (-1);
	}

	যদি (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ঘূৰাই (-1);
	}

	/* Turn on tunnel headers */
#যদি defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	যদি (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, পরিমাণ(ifr.ifr_name), "%s%d", tunbase, tun);
	যদি ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		গচ্ছ failed;

	যদি (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		গচ্ছ failed;
	যদি ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		যদি (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			গচ্ছ failed;
	}

	যদি (ifname != রিক্ত && (*ifname = strdup(ifr.ifr_name)) == রিক্ত)
		গচ্ছ failed;

	close(sock);
	ঘূৰাই (fd);

 failed:
	যদি (fd >= 0)
		close(fd);
	যদি (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	ঘূৰাই (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#যদি defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

পূর্ণাঙ্ক
sys_tun_infilter(সংরচনা ssh *ssh, সংরচনা Channel *c, ৱর্ণ *buf, পূর্ণাঙ্ক _len)
{
	পূর্ণাঙ্ক r;
	size_t len;
	ৱর্ণ *ptr = buf;
#যদি defined(SSH_TUN_PREPEND_AF)
	ৱর্ণ rbuf[CHAN_RBUF];
	সংরচনা ip iph;
#endif
#যদি defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	যদি (_len < 0)
		ঘূৰাই -1;
	len = _len;

#যদি defined(SSH_TUN_PREPEND_AF)
	যদি (len <= পরিমাণ(iph) || len > পরিমাণ(rbuf) - 4)
		ঘূৰাই -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, পরিমাণ(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#নোচেদ্যদি defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	যদি (len <= 4)
		ঘূৰাই -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	যদি ((r = sshbuf_put_string(c->প্ৰবেশ, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ঘূৰাই (0);
}

u_char *
sys_tun_outfilter(সংরচনা ssh *ssh, সংরচনা Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	পূর্ণাঙ্ক r;

	/* XXX new API is incompatible with this signature. */
	যদি ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	যদি (*dlen < পরিমাণ(af))
		ঘূৰাই (রিক্ত);
	buf = *data;

#যদি defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= পরিমাণ(af);
	buf = *data + পরিমাণ(af);
#নোচেদ্যদি defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	ঘূৰাই (buf);
}
#endif /* SSH_TUN_FILTER */
