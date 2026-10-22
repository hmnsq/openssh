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

#ако defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#include <linux/if.h>
#endif

#ако defined(SYS_RDOMAIN_LINUX)
char *
sys_get_rdomain(цяло fd)
{
	char dev[IFNAMSIZ + 1];
	socklen_t len = sizeof(dev) - 1;

	ако (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		върни NULL;
	}
	dev[len] = '\0';
	върни strdup(dev);
}

цяло
sys_set_rdomain(цяло fd, const char *name)
{
	ако (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		върни -1;
	}
	върни 0;
}

цяло
sys_valid_rdomain(const char *name)
{
	цяло fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	ако ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		върни 0;
	ако (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		върни 0;
	}
	close(fd);
	върни 1;
}
#elif defined(SYS_RDOMAIN_XXX)
/* XXX examples */
char *
sys_get_rdomain(цяло fd)
{
	върни NULL;
}

цяло
sys_set_rdomain(цяло fd, const char *name)
{
	върни -1;
}

цяло
valid_rdomain(const char *name)
{
	върни 0;
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

#ако defined(SSH_TUN_LINUX)
#include <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

цяло
sys_tun_open(цяло tun, цяло mode, char **ifname)
{
	struct ifreq ifr;
	цяло fd = -1;
	const char *name = NULL;

	ако (ifname != NULL)
		*ifname = NULL;
	ако ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		върни (-1);
	}

	bzero(&ifr, sizeof(ifr));

	ако (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} иначе {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	ако (tun != SSH_TUNID_ANY) {
		ако (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			goto failed;
		}
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), name, tun);
	}

	ако (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		goto failed;
	}

	ако (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	иначе
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	ако (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	върни (fd);

 failed:
	close(fd);
	върни (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#include <sys/socket.h>
#include <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

цяло
sys_tun_open(цяло tun, цяло mode, char **ifname)
{
	struct ifreq ifr;
	char name[100];
	цяло fd = -1, sock;
	const char *tunbase = "tun";
#ако defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	цяло flag;
#endif

	ако (ifname != NULL)
		*ifname = NULL;

	ако (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		върни (-1);
#иначе
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	ако (tun <= SSH_TUNID_MAX) {
		snprintf(name, sizeof(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} иначе ако (tun == SSH_TUNID_ANY) {
		за (tun = 100; tun >= 0; tun--) {
			snprintf(name, sizeof(name), "/dev/%s%d",
			    tunbase, tun);
			ако ((fd = open(name, O_RDWR)) >= 0)
				break;
		}
	} иначе {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		върни (-1);
	}

	ако (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		върни (-1);
	}

	/* Turn on tunnel headers */
#ако defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	ако (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", tunbase, tun);
	ако ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	ако (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		goto failed;
	ако ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		ако (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			goto failed;
	}

	ако (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	close(sock);
	върни (fd);

 failed:
	ако (fd >= 0)
		close(fd);
	ако (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	върни (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#ако defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

цяло
sys_tun_infilter(struct ssh *ssh, struct Channel *c, char *buf, цяло _len)
{
	цяло r;
	size_t len;
	char *ptr = buf;
#ако defined(SSH_TUN_PREPEND_AF)
	char rbuf[CHAN_RBUF];
	struct ip iph;
#endif
#ако defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	ако (_len < 0)
		върни -1;
	len = _len;

#ако defined(SSH_TUN_PREPEND_AF)
	ако (len <= sizeof(iph) || len > sizeof(rbuf) - 4)
		върни -1;
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
	ако (len <= 4)
		върни -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	ако ((r = sshbuf_put_string(c->input, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	върни (0);
}

u_char *
sys_tun_outfilter(struct ssh *ssh, struct Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	цяло r;

	/* XXX new API is incompatible with this signature. */
	ако ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ако (*dlen < sizeof(af))
		върни (NULL);
	buf = *data;

#ако defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= sizeof(af);
	buf = *data + sizeof(af);
#elif defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	върни (buf);
}
#endif /* SSH_TUN_FILTER */
