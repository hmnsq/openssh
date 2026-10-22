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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>
#ضمن <netinet/ip.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "openbsd-compat/sys-queue.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "channels.h"
#ضمن "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#ܐܢ defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#ضمن <linux/if.h>
#endif

#ܐܢ defined(SYS_RDOMAIN_LINUX)
حرف *
sys_get_rdomain(صحيح fd)
{
	حرف dev[IFNAMSIZ + 1];
	socklen_t len = حجم(dev) - 1;

	ܐܢ (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ܦܢܐ عدم;
	}
	dev[len] = '\0';
	ܦܢܐ strdup(dev);
}

صحيح
sys_set_rdomain(صحيح fd, ثابت حرف *name)
{
	ܐܢ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ܦܢܐ -1;
	}
	ܦܢܐ 0;
}

صحيح
sys_valid_rdomain(ثابت حرف *name)
{
	صحيح fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	ܐܢ ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ܦܢܐ 0;
	ܐܢ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		ܦܢܐ 0;
	}
	close(fd);
	ܦܢܐ 1;
}
#وإلاإذا defined(SYS_RDOMAIN_XXX)
/* XXX examples */
حرف *
sys_get_rdomain(صحيح fd)
{
	ܦܢܐ عدم;
}

صحيح
sys_set_rdomain(صحيح fd, ثابت حرف *name)
{
	ܦܢܐ -1;
}

صحيح
valid_rdomain(ثابت حرف *name)
{
	ܦܢܐ 0;
}

فراغ
sys_set_process_rdomain(ثابت حرف *name)
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

#ܐܢ defined(SSH_TUN_LINUX)
#ضمن <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

صحيح
sys_tun_open(صحيح tun, صحيح mode, حرف **ifname)
{
	بنية ifreq ifr;
	صحيح fd = -1;
	ثابت حرف *name = عدم;

	ܐܢ (ifname != عدم)
		*ifname = عدم;
	ܐܢ ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ܦܢܐ (-1);
	}

	bzero(&ifr, حجم(ifr));

	ܐܢ (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} ܐܚܪܢܐ {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	ܐܢ (tun != SSH_TUNID_ANY) {
		ܐܢ (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			اذهب failed;
		}
		snprintf(ifr.ifr_name, حجم(ifr.ifr_name), name, tun);
	}

	ܐܢ (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		اذهب failed;
	}

	ܐܢ (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	ܐܚܪܢܐ
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	ܐܢ (ifname != عدم && (*ifname = strdup(ifr.ifr_name)) == عدم)
		اذهب failed;

	ܦܢܐ (fd);

 failed:
	close(fd);
	ܦܢܐ (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#ضمن <sys/socket.h>
#ضمن <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#ضمن <net/if_tun.h>
#endif

صحيح
sys_tun_open(صحيح tun, صحيح mode, حرف **ifname)
{
	بنية ifreq ifr;
	حرف name[100];
	صحيح fd = -1, sock;
	ثابت حرف *tunbase = "tun";
#ܐܢ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	صحيح flag;
#endif

	ܐܢ (ifname != عدم)
		*ifname = عدم;

	ܐܢ (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ܦܢܐ (-1);
#ܐܚܪܢܐ
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	ܐܢ (tun <= SSH_TUNID_MAX) {
		snprintf(name, حجم(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ܐܚܪܢܐ ܐܢ (tun == SSH_TUNID_ANY) {
		لكل (tun = 100; tun >= 0; tun--) {
			snprintf(name, حجم(name), "/dev/%s%d",
			    tunbase, tun);
			ܐܢ ((fd = open(name, O_RDWR)) >= 0)
				اكسر;
		}
	} ܐܚܪܢܐ {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ܦܢܐ (-1);
	}

	ܐܢ (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ܦܢܐ (-1);
	}

	/* Turn on tunnel headers */
#ܐܢ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	ܐܢ (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, حجم(ifr.ifr_name), "%s%d", tunbase, tun);
	ܐܢ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		اذهب failed;

	ܐܢ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		اذهب failed;
	ܐܢ ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		ܐܢ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			اذهب failed;
	}

	ܐܢ (ifname != عدم && (*ifname = strdup(ifr.ifr_name)) == عدم)
		اذهب failed;

	close(sock);
	ܦܢܐ (fd);

 failed:
	ܐܢ (fd >= 0)
		close(fd);
	ܐܢ (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	ܦܢܐ (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#ܐܢ defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

صحيح
sys_tun_infilter(بنية ssh *ssh, بنية Channel *c, حرف *buf, صحيح _len)
{
	صحيح r;
	size_t len;
	حرف *ptr = buf;
#ܐܢ defined(SSH_TUN_PREPEND_AF)
	حرف rbuf[CHAN_RBUF];
	بنية ip iph;
#endif
#ܐܢ defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	ܐܢ (_len < 0)
		ܦܢܐ -1;
	len = _len;

#ܐܢ defined(SSH_TUN_PREPEND_AF)
	ܐܢ (len <= حجم(iph) || len > حجم(rbuf) - 4)
		ܦܢܐ -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, حجم(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#وإلاإذا defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	ܐܢ (len <= 4)
		ܦܢܐ -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	ܐܢ ((r = sshbuf_put_string(c->input, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ܦܢܐ (0);
}

u_char *
sys_tun_outfilter(بنية ssh *ssh, بنية Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	صحيح r;

	/* XXX new API is incompatible with this signature. */
	ܐܢ ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ܐܢ (*dlen < حجم(af))
		ܦܢܐ (عدم);
	buf = *data;

#ܐܢ defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= حجم(af);
	buf = *data + حجم(af);
#وإلاإذا defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	ܦܢܐ (buf);
}
#endif /* SSH_TUN_FILTER */
