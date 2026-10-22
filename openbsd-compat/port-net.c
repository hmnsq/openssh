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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>
#ಅನ್ತರ್ಭಾವ <netinet/ip.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "openbsd-compat/sys-queue.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#ಯದಿ defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#ಅನ್ತರ್ಭಾವ <linux/if.h>
#endif

#ಯದಿ defined(SYS_RDOMAIN_LINUX)
ವರ್ಣ *
sys_get_rdomain(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ವರ್ಣ dev[IFNAMSIZ + 1];
	socklen_t len = ಪರಿಮಾಣ(dev) - 1;

	ಯದಿ (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	dev[len] = '\0';
	ಪ್ರತ್ಯಾಗಮ strdup(dev);
}

ಪೂರ್ಣಾಙ್ಕ
sys_set_rdomain(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *name)
{
	ಯದಿ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sys_valid_rdomain(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	ಯದಿ ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	close(fd);
	ಪ್ರತ್ಯಾಗಮ 1;
}
#ನೋಚೇದ್ಯದಿ defined(SYS_RDOMAIN_XXX)
/* XXX examples */
ವರ್ಣ *
sys_get_rdomain(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
sys_set_rdomain(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *name)
{
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಪೂರ್ಣಾಙ್ಕ
valid_rdomain(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
sys_set_process_rdomain(ಧ್ರುವ ವರ್ಣ *name)
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

#ಯದಿ defined(SSH_TUN_LINUX)
#ಅನ್ತರ್ಭಾವ <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

ಪೂರ್ಣಾಙ್ಕ
sys_tun_open(ಪೂರ್ಣಾಙ್ಕ tun, ಪೂರ್ಣಾಙ್ಕ mode, ವರ್ಣ **ifname)
{
	ಸಂರಚನಾ ifreq ifr;
	ಪೂರ್ಣಾಙ್ಕ fd = -1;
	ಧ್ರುವ ವರ್ಣ *name = ರಿಕ್ತ;

	ಯದಿ (ifname != ರಿಕ್ತ)
		*ifname = ರಿಕ್ತ;
	ಯದಿ ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	bzero(&ifr, ಪರಿಮಾಣ(ifr));

	ಯದಿ (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} ಅನ್ಯಥಾ {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	ಯದಿ (tun != SSH_TUNID_ANY) {
		ಯದಿ (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			ಗಚ್ಛ failed;
		}
		snprintf(ifr.ifr_name, ಪರಿಮಾಣ(ifr.ifr_name), name, tun);
	}

	ಯದಿ (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		ಗಚ್ಛ failed;
	}

	ಯದಿ (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	ಅನ್ಯಥಾ
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	ಯದಿ (ifname != ರಿಕ್ತ && (*ifname = strdup(ifr.ifr_name)) == ರಿಕ್ತ)
		ಗಚ್ಛ failed;

	ಪ್ರತ್ಯಾಗಮ (fd);

 failed:
	close(fd);
	ಪ್ರತ್ಯಾಗಮ (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#ಅನ್ತರ್ಭಾವ <net/if_tun.h>
#endif

ಪೂರ್ಣಾಙ್ಕ
sys_tun_open(ಪೂರ್ಣಾಙ್ಕ tun, ಪೂರ್ಣಾಙ್ಕ mode, ವರ್ಣ **ifname)
{
	ಸಂರಚನಾ ifreq ifr;
	ವರ್ಣ name[100];
	ಪೂರ್ಣಾಙ್ಕ fd = -1, sock;
	ಧ್ರುವ ವರ್ಣ *tunbase = "tun";
#ಯದಿ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	ಪೂರ್ಣಾಙ್ಕ flag;
#endif

	ಯದಿ (ifname != ರಿಕ್ತ)
		*ifname = ರಿಕ್ತ;

	ಯದಿ (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ಪ್ರತ್ಯಾಗಮ (-1);
#ಅನ್ಯಥಾ
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	ಯದಿ (tun <= SSH_TUNID_MAX) {
		snprintf(name, ಪರಿಮಾಣ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ಅನ್ಯಥಾ ಯದಿ (tun == SSH_TUNID_ANY) {
		ಪ್ರತಿ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ಪರಿಮಾಣ(name), "/dev/%s%d",
			    tunbase, tun);
			ಯದಿ ((fd = open(name, O_RDWR)) >= 0)
				ಭಙ್ಗ;
		}
	} ಅನ್ಯಥಾ {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	ಯದಿ (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	/* Turn on tunnel headers */
#ಯದಿ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	ಯದಿ (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, ಪರಿಮಾಣ(ifr.ifr_name), "%s%d", tunbase, tun);
	ಯದಿ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ಗಚ್ಛ failed;

	ಯದಿ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		ಗಚ್ಛ failed;
	ಯದಿ ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		ಯದಿ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			ಗಚ್ಛ failed;
	}

	ಯದಿ (ifname != ರಿಕ್ತ && (*ifname = strdup(ifr.ifr_name)) == ರಿಕ್ತ)
		ಗಚ್ಛ failed;

	close(sock);
	ಪ್ರತ್ಯಾಗಮ (fd);

 failed:
	ಯದಿ (fd >= 0)
		close(fd);
	ಯದಿ (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	ಪ್ರತ್ಯಾಗಮ (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#ಯದಿ defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

ಪೂರ್ಣಾಙ್ಕ
sys_tun_infilter(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Channel *c, ವರ್ಣ *buf, ಪೂರ್ಣಾಙ್ಕ _len)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t len;
	ವರ್ಣ *ptr = buf;
#ಯದಿ defined(SSH_TUN_PREPEND_AF)
	ವರ್ಣ rbuf[CHAN_RBUF];
	ಸಂರಚನಾ ip iph;
#endif
#ಯದಿ defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	ಯದಿ (_len < 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	len = _len;

#ಯದಿ defined(SSH_TUN_PREPEND_AF)
	ಯದಿ (len <= ಪರಿಮಾಣ(iph) || len > ಪರಿಮಾಣ(rbuf) - 4)
		ಪ್ರತ್ಯಾಗಮ -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, ಪರಿಮಾಣ(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#ನೋಚೇದ್ಯದಿ defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	ಯದಿ (len <= 4)
		ಪ್ರತ್ಯಾಗಮ -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	ಯದಿ ((r = sshbuf_put_string(c->ಒಳಹರಿವು, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ಪ್ರತ್ಯಾಗಮ (0);
}

u_char *
sys_tun_outfilter(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* XXX new API is incompatible with this signature. */
	ಯದಿ ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ಯದಿ (*dlen < ಪರಿಮಾಣ(af))
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	buf = *data;

#ಯದಿ defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= ಪರಿಮಾಣ(af);
	buf = *data + ಪರಿಮಾಣ(af);
#ನೋಚೇದ್ಯದಿ defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	ಪ್ರತ್ಯಾಗಮ (buf);
}
#endif /* SSH_TUN_FILTER */
