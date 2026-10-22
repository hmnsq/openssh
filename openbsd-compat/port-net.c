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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "openbsd-compat/sys-queue.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "channels.h"
#include "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#nếu defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#include <linux/if.h>
#endif

#nếu defined(SYS_RDOMAIN_LINUX)
char *
sys_get_rdomain(số_nguyên fd)
{
	char dev[IFNAMSIZ + 1];
	socklen_t len = sizeof(dev) - 1;

	nếu (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		trả_về NULL;
	}
	dev[len] = '\0';
	trả_về strdup(dev);
}

số_nguyên
sys_set_rdomain(số_nguyên fd, const char *name)
{
	nếu (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		trả_về -1;
	}
	trả_về 0;
}

số_nguyên
sys_valid_rdomain(const char *name)
{
	số_nguyên fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	nếu ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		trả_về 0;
	nếu (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		trả_về 0;
	}
	close(fd);
	trả_về 1;
}
#elif defined(SYS_RDOMAIN_XXX)
/* XXX examples */
char *
sys_get_rdomain(số_nguyên fd)
{
	trả_về NULL;
}

số_nguyên
sys_set_rdomain(số_nguyên fd, const char *name)
{
	trả_về -1;
}

số_nguyên
valid_rdomain(const char *name)
{
	trả_về 0;
}

void
sys_set_process_rdomain(const char *name)
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

#nếu defined(SSH_TUN_LINUX)
#include <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

số_nguyên
sys_tun_open(số_nguyên tun, số_nguyên mode, char **ifname)
{
	struct ifreq ifr;
	số_nguyên fd = -1;
	const char *name = NULL;

	nếu (ifname != NULL)
		*ifname = NULL;
	nếu ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		trả_về (-1);
	}

	bzero(&ifr, sizeof(ifr));

	nếu (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} không_thì {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	nếu (tun != SSH_TUNID_ANY) {
		nếu (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			goto failed;
		}
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), name, tun);
	}

	nếu (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		goto failed;
	}

	nếu (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	không_thì
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	nếu (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	trả_về (fd);

 failed:
	close(fd);
	trả_về (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#include <sys/socket.h>
#include <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

số_nguyên
sys_tun_open(số_nguyên tun, số_nguyên mode, char **ifname)
{
	struct ifreq ifr;
	char name[100];
	số_nguyên fd = -1, sock;
	const char *tunbase = "tun";
#nếu defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	số_nguyên flag;
#endif

	nếu (ifname != NULL)
		*ifname = NULL;

	nếu (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		trả_về (-1);
#không_thì
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	nếu (tun <= SSH_TUNID_MAX) {
		snprintf(name, sizeof(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} không_thì nếu (tun == SSH_TUNID_ANY) {
		cho (tun = 100; tun >= 0; tun--) {
			snprintf(name, sizeof(name), "/dev/%s%d",
			    tunbase, tun);
			nếu ((fd = open(name, O_RDWR)) >= 0)
				break;
		}
	} không_thì {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		trả_về (-1);
	}

	nếu (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		trả_về (-1);
	}

	/* Turn on tunnel headers */
#nếu defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	nếu (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", tunbase, tun);
	nếu ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	nếu (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		goto failed;
	nếu ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		nếu (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			goto failed;
	}

	nếu (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	close(sock);
	trả_về (fd);

 failed:
	nếu (fd >= 0)
		close(fd);
	nếu (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	trả_về (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#nếu defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

số_nguyên
sys_tun_infilter(struct ssh *ssh, struct Channel *c, char *buf, số_nguyên _len)
{
	số_nguyên r;
	size_t len;
	char *ptr = buf;
#nếu defined(SSH_TUN_PREPEND_AF)
	char rbuf[CHAN_RBUF];
	struct ip iph;
#endif
#nếu defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	nếu (_len < 0)
		trả_về -1;
	len = _len;

#nếu defined(SSH_TUN_PREPEND_AF)
	nếu (len <= sizeof(iph) || len > sizeof(rbuf) - 4)
		trả_về -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, sizeof(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#elif defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	nếu (len <= 4)
		trả_về -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	nếu ((r = sshbuf_put_string(c->input, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	trả_về (0);
}

u_char *
sys_tun_outfilter(struct ssh *ssh, struct Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	số_nguyên r;

	/* XXX new API is incompatible with this signature. */
	nếu ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	nếu (*dlen < sizeof(af))
		trả_về (NULL);
	buf = *data;

#nếu defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= sizeof(af);
	buf = *data + sizeof(af);
#elif defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	trả_về (buf);
}
#endif /* SSH_TUN_FILTER */
