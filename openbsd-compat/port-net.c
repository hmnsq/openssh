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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>
#شامل <netinet/ip.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "openbsd-compat/sys-queue.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "channels.h"
#شامل "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#اگر defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#شامل <linux/if.h>
#endif

#اگر defined(SYS_RDOMAIN_LINUX)
نویسه *
sys_get_rdomain(صحیح fd)
{
	نویسه dev[IFNAMSIZ + 1];
	socklen_t len = اندازه(dev) - 1;

	اگر (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		بازگشت پوچ;
	}
	dev[len] = '\0';
	بازگشت strdup(dev);
}

صحیح
sys_set_rdomain(صحیح fd, ثابت نویسه *name)
{
	اگر (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		بازگشت -1;
	}
	بازگشت 0;
}

صحیح
sys_valid_rdomain(ثابت نویسه *name)
{
	صحیح fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	اگر ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		بازگشت 0;
	اگر (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		بازگشت 0;
	}
	close(fd);
	بازگشت 1;
}
#وگرنهاگر defined(SYS_RDOMAIN_XXX)
/* XXX examples */
نویسه *
sys_get_rdomain(صحیح fd)
{
	بازگشت پوچ;
}

صحیح
sys_set_rdomain(صحیح fd, ثابت نویسه *name)
{
	بازگشت -1;
}

صحیح
valid_rdomain(ثابت نویسه *name)
{
	بازگشت 0;
}

تهی
sys_set_process_rdomain(ثابت نویسه *name)
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

#اگر defined(SSH_TUN_LINUX)
#شامل <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

صحیح
sys_tun_open(صحیح tun, صحیح mode, نویسه **ifname)
{
	ساختار ifreq ifr;
	صحیح fd = -1;
	ثابت نویسه *name = پوچ;

	اگر (ifname != پوچ)
		*ifname = پوچ;
	اگر ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		بازگشت (-1);
	}

	bzero(&ifr, اندازه(ifr));

	اگر (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} وگرنه {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	اگر (tun != SSH_TUNID_ANY) {
		اگر (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			برو failed;
		}
		snprintf(ifr.ifr_name, اندازه(ifr.ifr_name), name, tun);
	}

	اگر (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		برو failed;
	}

	اگر (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	وگرنه
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	اگر (ifname != پوچ && (*ifname = strdup(ifr.ifr_name)) == پوچ)
		برو failed;

	بازگشت (fd);

 failed:
	close(fd);
	بازگشت (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#شامل <sys/socket.h>
#شامل <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#شامل <net/if_tun.h>
#endif

صحیح
sys_tun_open(صحیح tun, صحیح mode, نویسه **ifname)
{
	ساختار ifreq ifr;
	نویسه name[100];
	صحیح fd = -1, sock;
	ثابت نویسه *tunbase = "tun";
#اگر defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	صحیح flag;
#endif

	اگر (ifname != پوچ)
		*ifname = پوچ;

	اگر (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		بازگشت (-1);
#وگرنه
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	اگر (tun <= SSH_TUNID_MAX) {
		snprintf(name, اندازه(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} وگرنه اگر (tun == SSH_TUNID_ANY) {
		برای (tun = 100; tun >= 0; tun--) {
			snprintf(name, اندازه(name), "/dev/%s%d",
			    tunbase, tun);
			اگر ((fd = open(name, O_RDWR)) >= 0)
				بشکن;
		}
	} وگرنه {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		بازگشت (-1);
	}

	اگر (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		بازگشت (-1);
	}

	/* Turn on tunnel headers */
#اگر defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	اگر (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, اندازه(ifr.ifr_name), "%s%d", tunbase, tun);
	اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		برو failed;

	اگر (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		برو failed;
	اگر ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		اگر (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			برو failed;
	}

	اگر (ifname != پوچ && (*ifname = strdup(ifr.ifr_name)) == پوچ)
		برو failed;

	close(sock);
	بازگشت (fd);

 failed:
	اگر (fd >= 0)
		close(fd);
	اگر (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	بازگشت (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#اگر defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

صحیح
sys_tun_infilter(ساختار ssh *ssh, ساختار Channel *c, نویسه *buf, صحیح _len)
{
	صحیح r;
	size_t len;
	نویسه *ptr = buf;
#اگر defined(SSH_TUN_PREPEND_AF)
	نویسه rbuf[CHAN_RBUF];
	ساختار ip iph;
#endif
#اگر defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	اگر (_len < 0)
		بازگشت -1;
	len = _len;

#اگر defined(SSH_TUN_PREPEND_AF)
	اگر (len <= اندازه(iph) || len > اندازه(rbuf) - 4)
		بازگشت -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, اندازه(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#وگرنهاگر defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	اگر (len <= 4)
		بازگشت -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	اگر ((r = sshbuf_put_string(c->درون_داد, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	بازگشت (0);
}

u_char *
sys_tun_outfilter(ساختار ssh *ssh, ساختار Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	صحیح r;

	/* XXX new API is incompatible with this signature. */
	اگر ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	اگر (*dlen < اندازه(af))
		بازگشت (پوچ);
	buf = *data;

#اگر defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= اندازه(af);
	buf = *data + اندازه(af);
#وگرنهاگر defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	بازگشت (buf);
}
#endif /* SSH_TUN_FILTER */
