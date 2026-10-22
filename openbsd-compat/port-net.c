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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/ip.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/sys-queue.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#ਜੇ defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#ਅਨ੍ਤਰ੍ਭਾਵ <linux/if.h>
#ਜੇ_ਅੰਤ

#ਜੇ defined(SYS_RDOMAIN_LINUX)
ਅੱਖਰ *
sys_get_rdomain(ਪੂਰਨ fd)
{
	ਅੱਖਰ dev[IFNAMSIZ + 1];
	socklen_t len = ਆਕਾਰ(dev) - 1;

	ਜੇ (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
	dev[len] = '\0';
	ਵਾਪਸ strdup(dev);
}

ਪੂਰਨ
sys_ਸੈੱਟ_rdomain(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *name)
{
	ਜੇ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, ਲੜੀ_ਲੰਬਾਈ(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sys_valid_rdomain(ਅਚਲ ਅੱਖਰ *name)
{
	ਪੂਰਨ fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	ਜੇ ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ਵਾਪਸ 0;
	ਜੇ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, ਲੜੀ_ਲੰਬਾਈ(name)) == -1) {
		close(fd);
		ਵਾਪਸ 0;
	}
	close(fd);
	ਵਾਪਸ 1;
}
#ਜਾਂਜੇ defined(SYS_RDOMAIN_XXX)
/* XXX examples */
ਅੱਖਰ *
sys_get_rdomain(ਪੂਰਨ fd)
{
	ਵਾਪਸ ਨਿਰਾ;
}

ਪੂਰਨ
sys_ਸੈੱਟ_rdomain(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *name)
{
	ਵਾਪਸ -1;
}

ਪੂਰਨ
valid_rdomain(ਅਚਲ ਅੱਖਰ *name)
{
	ਵਾਪਸ 0;
}

ਖਾਲੀ
sys_ਸੈੱਟ_process_rdomain(ਅਚਲ ਅੱਖਰ *name)
{
	fatal("%s: not supported", __func__);
}
#ਜੇ_ਅੰਤ /* defined(SYS_RDOMAIN_XXX) */

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

#ਜੇ defined(SSH_TUN_LINUX)
#ਅਨ੍ਤਰ੍ਭਾਵ <linux/if_tun.h>
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TUN_CTRL_DEV "/dev/net/tun"

ਪੂਰਨ
sys_tun_open(ਪੂਰਨ tun, ਪੂਰਨ ਬਹੁਲਕ, ਅੱਖਰ **ifname)
{
	ਬਣਤਰ ifreq ifr;
	ਪੂਰਨ fd = -1;
	ਅਚਲ ਅੱਖਰ *name = ਨਿਰਾ;

	ਜੇ (ifname != ਨਿਰਾ)
		*ifname = ਨਿਰਾ;
	ਜੇ ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ਵਾਪਸ (-1);
	}

	bzero(&ifr, ਆਕਾਰ(ifr));

	ਜੇ (ਬਹੁਲਕ == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} ਨਹੀਂਤਾਂ {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	ਜੇ (tun != SSH_TUNID_ANY) {
		ਜੇ (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			ਜਾਓ failed;
		}
		snprintf(ifr.ifr_name, ਆਕਾਰ(ifr.ifr_name), name, tun);
	}

	ਜੇ (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    ਬਹੁਲਕ, strerror(errno));
		ਜਾਓ failed;
	}

	ਜੇ (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, ਬਹੁਲਕ, fd);
	ਨਹੀਂਤਾਂ
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, ਬਹੁਲਕ, fd);

	ਜੇ (ifname != ਨਿਰਾ && (*ifname = strdup(ifr.ifr_name)) == ਨਿਰਾ)
		ਜਾਓ failed;

	ਵਾਪਸ (fd);

 failed:
	close(fd);
	ਵਾਪਸ (-1);
}
#ਜੇ_ਅੰਤ /* SSH_TUN_LINUX */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_TUN_FREEBSD
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <net/if.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_NET_IF_TUN_H
#ਅਨ੍ਤਰ੍ਭਾਵ <net/if_tun.h>
#ਜੇ_ਅੰਤ

ਪੂਰਨ
sys_tun_open(ਪੂਰਨ tun, ਪੂਰਨ ਬਹੁਲਕ, ਅੱਖਰ **ifname)
{
	ਬਣਤਰ ifreq ifr;
	ਅੱਖਰ name[100];
	ਪੂਰਨ fd = -1, sock;
	ਅਚਲ ਅੱਖਰ *tunbase = "tun";
#ਜੇ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	ਪੂਰਨ flag;
#ਜੇ_ਅੰਤ

	ਜੇ (ifname != ਨਿਰਾ)
		*ifname = ਨਿਰਾ;

	ਜੇ (ਬਹੁਲਕ == SSH_TUNMODE_ETHERNET) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ਵਾਪਸ (-1);
#ਨਹੀਂਤਾਂ
		tunbase = "tap";
#ਜੇ_ਅੰਤ
	}

	/* Open the tunnel device */
	ਜੇ (tun <= SSH_TUNID_MAX) {
		snprintf(name, ਆਕਾਰ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ਨਹੀਂਤਾਂ ਜੇ (tun == SSH_TUNID_ANY) {
		ਲਈ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ਆਕਾਰ(name), "/dev/%s%d",
			    tunbase, tun);
			ਜੇ ((fd = open(name, O_RDWR)) >= 0)
				ਰੋਕੋ;
		}
	} ਨਹੀਂਤਾਂ {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ਵਾਪਸ (-1);
	}

	ਜੇ (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ਵਾਪਸ (-1);
	}

	/* Turn on tunnel headers */
#ਜੇ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	ਜੇ (ਬਹੁਲਕ != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#ਜੇ_ਅੰਤ

	debug("%s: %s mode %d fd %d", __func__, name, ਬਹੁਲਕ, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, ਆਕਾਰ(ifr.ifr_name), "%s%d", tunbase, tun);
	ਜੇ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ਜਾਓ failed;

	ਜੇ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		ਜਾਓ failed;
	ਜੇ ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		ਜੇ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			ਜਾਓ failed;
	}

	ਜੇ (ifname != ਨਿਰਾ && (*ifname = strdup(ifr.ifr_name)) == ਨਿਰਾ)
		ਜਾਓ failed;

	close(sock);
	ਵਾਪਸ (fd);

 failed:
	ਜੇ (fd >= 0)
		close(fd);
	ਜੇ (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    ਬਹੁਲਕ, strerror(errno));
	ਵਾਪਸ (-1);
}
#ਜੇ_ਅੰਤ /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#ਜੇ defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPENBSD_AF_INET		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPENBSD_AF_INET6	24

ਪੂਰਨ
sys_tun_infilter(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Channel *c, ਅੱਖਰ *buf, ਪੂਰਨ _len)
{
	ਪੂਰਨ r;
	ਮਾਪ_t len;
	ਅੱਖਰ *ptr = buf;
#ਜੇ defined(SSH_TUN_PREPEND_AF)
	ਅੱਖਰ rbuf[CHAN_RBUF];
	ਬਣਤਰ ip iph;
#ਜੇ_ਅੰਤ
#ਜੇ defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#ਜੇ_ਅੰਤ

	/* XXX update channel input filter API to use unsigned length */
	ਜੇ (_len < 0)
		ਵਾਪਸ -1;
	len = _len;

#ਜੇ defined(SSH_TUN_PREPEND_AF)
	ਜੇ (len <= ਆਕਾਰ(iph) || len > ਆਕਾਰ(rbuf) - 4)
		ਵਾਪਸ -1;
	/* Determine address family from packet IP header. */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(&iph, buf, ਆਕਾਰ(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#ਜਾਂਜੇ defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	ਜੇ (len <= 4)
		ਵਾਪਸ -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#ਜੇ_ਅੰਤ

	ਜੇ ((r = sshbuf_put_string(c->ਨਿਵੇਸ਼, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ਵਾਪਸ (0);
}

u_char *
sys_tun_outfilter(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Channel *c,
    u_char **ਅੰਕੜੇ, ਮਾਪ_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	ਪੂਰਨ r;

	/* XXX new API is incompatible with this signature. */
	ਜੇ ((r = sshbuf_get_string(c->output, ਅੰਕੜੇ, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ਜੇ (*dlen < ਆਕਾਰ(af))
		ਵਾਪਸ (ਨਿਰਾ);
	buf = *ਅੰਕੜੇ;

#ਜੇ defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= ਆਕਾਰ(af);
	buf = *ਅੰਕੜੇ + ਆਕਾਰ(af);
#ਜਾਂਜੇ defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ (buf);
}
#ਜੇ_ਅੰਤ /* SSH_TUN_FILTER */
