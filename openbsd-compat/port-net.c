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

#ಆದರೆ defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#ಅನ್ತರ್ಭಾವ <linux/if.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(SYS_RDOMAIN_LINUX)
ಅಕ್ಷರ *
sys_get_rdomain(ಪೂರ್ಣಾಂಕ fd)
{
	ಅಕ್ಷರ dev[IFNAMSIZ + 1];
	socklen_t len = ಗಾತ್ರ(dev) - 1;

	ಆದರೆ (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	dev[len] = '\0';
	ಹಿಂತಿರುಗಿ strdup(dev);
}

ಪೂರ್ಣಾಂಕ
sys_ಗಣ_rdomain(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಆದರೆ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sys_valid_rdomain(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	ಆದರೆ ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name)) == -1) {
		close(fd);
		ಹಿಂತಿರುಗಿ 0;
	}
	close(fd);
	ಹಿಂತಿರುಗಿ 1;
}
#ಅಥವಾಆದರೆ defined(SYS_RDOMAIN_XXX)
/* XXX examples */
ಅಕ್ಷರ *
sys_get_rdomain(ಪೂರ್ಣಾಂಕ fd)
{
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
sys_ಗಣ_rdomain(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಹಿಂತಿರುಗಿ -1;
}

ಪೂರ್ಣಾಂಕ
valid_rdomain(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
sys_ಗಣ_process_rdomain(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	fatal("%s: not supported", __func__);
}
#ಆದರೆ_ಅಂತ್ಯ /* defined(SYS_RDOMAIN_XXX) */

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

#ಆದರೆ defined(SSH_TUN_LINUX)
#ಅನ್ತರ್ಭಾವ <linux/if_tun.h>
#ವ್ಯಾಖ್ಯಾನಿಸು TUN_CTRL_DEV "/dev/net/tun"

ಪೂರ್ಣಾಂಕ
sys_tun_open(ಪೂರ್ಣಾಂಕ tun, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, ಅಕ್ಷರ **ifname)
{
	ರಚನೆ ifreq ifr;
	ಪೂರ್ಣಾಂಕ fd = -1;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name = ಖಾಲಿ;

	ಆದರೆ (ifname != ಖಾಲಿ)
		*ifname = ಖಾಲಿ;
	ಆದರೆ ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}

	bzero(&ifr, ಗಾತ್ರ(ifr));

	ಆದರೆ (ಬಹುಲಕ == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} ಇಲ್ಲದಿದ್ದರೆ {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	ಆದರೆ (tun != SSH_TUNID_ANY) {
		ಆದರೆ (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			ಹೋಗು failed;
		}
		snprintf(ifr.ifr_name, ಗಾತ್ರ(ifr.ifr_name), name, tun);
	}

	ಆದರೆ (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    ಬಹುಲಕ, strerror(errno));
		ಹೋಗು failed;
	}

	ಆದರೆ (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, ಬಹುಲಕ, fd);
	ಇಲ್ಲದಿದ್ದರೆ
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, ಬಹುಲಕ, fd);

	ಆದರೆ (ifname != ಖಾಲಿ && (*ifname = strdup(ifr.ifr_name)) == ಖಾಲಿ)
		ಹೋಗು failed;

	ಹಿಂತಿರುಗಿ (fd);

 failed:
	close(fd);
	ಹಿಂತಿರುಗಿ (-1);
}
#ಆದರೆ_ಅಂತ್ಯ /* SSH_TUN_LINUX */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_TUN_FREEBSD
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <net/if.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_NET_IF_TUN_H
#ಅನ್ತರ್ಭಾವ <net/if_tun.h>
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
sys_tun_open(ಪೂರ್ಣಾಂಕ tun, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, ಅಕ್ಷರ **ifname)
{
	ರಚನೆ ifreq ifr;
	ಅಕ್ಷರ name[100];
	ಪೂರ್ಣಾಂಕ fd = -1, sock;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tunbase = "tun";
#ಆದರೆ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	ಪೂರ್ಣಾಂಕ flag;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (ifname != ಖಾಲಿ)
		*ifname = ಖಾಲಿ;

	ಆದರೆ (ಬಹುಲಕ == SSH_TUNMODE_ETHERNET) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ಹಿಂತಿರುಗಿ (-1);
#ಇಲ್ಲದಿದ್ದರೆ
		tunbase = "tap";
#ಆದರೆ_ಅಂತ್ಯ
	}

	/* Open the tunnel device */
	ಆದರೆ (tun <= SSH_TUNID_MAX) {
		snprintf(name, ಗಾತ್ರ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (tun == SSH_TUNID_ANY) {
		ಗಾಗಿ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ಗಾತ್ರ(name), "/dev/%s%d",
			    tunbase, tun);
			ಆದರೆ ((fd = open(name, O_RDWR)) >= 0)
				ನಿಲ್ಲಿಸು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ಹಿಂತಿರುಗಿ (-1);
	}

	ಆದರೆ (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}

	/* Turn on tunnel headers */
#ಆದರೆ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	ಆದರೆ (ಬಹುಲಕ != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#ಆದರೆ_ಅಂತ್ಯ

	debug("%s: %s mode %d fd %d", __func__, name, ಬಹುಲಕ, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, ಗಾತ್ರ(ifr.ifr_name), "%s%d", tunbase, tun);
	ಆದರೆ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ಹೋಗು failed;

	ಆದರೆ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		ಹೋಗು failed;
	ಆದರೆ ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		ಆದರೆ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			ಹೋಗು failed;
	}

	ಆದರೆ (ifname != ಖಾಲಿ && (*ifname = strdup(ifr.ifr_name)) == ಖಾಲಿ)
		ಹೋಗು failed;

	close(sock);
	ಹಿಂತಿರುಗಿ (fd);

 failed:
	ಆದರೆ (fd >= 0)
		close(fd);
	ಆದರೆ (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    ಬಹುಲಕ, strerror(errno));
	ಹಿಂತಿರುಗಿ (-1);
}
#ಆದರೆ_ಅಂತ್ಯ /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#ಆದರೆ defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು OPENBSD_AF_INET		2
#ವ್ಯಾಖ್ಯಾನಿಸು OPENBSD_AF_INET6	24

ಪೂರ್ಣಾಂಕ
sys_tun_infilter(ರಚನೆ ssh *ssh, ರಚನೆ Channel *c, ಅಕ್ಷರ *buf, ಪೂರ್ಣಾಂಕ _len)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t len;
	ಅಕ್ಷರ *ptr = buf;
#ಆದರೆ defined(SSH_TUN_PREPEND_AF)
	ಅಕ್ಷರ rbuf[CHAN_RBUF];
	ರಚನೆ ip iph;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#ಆದರೆ_ಅಂತ್ಯ

	/* XXX update channel input filter API to use unsigned length */
	ಆದರೆ (_len < 0)
		ಹಿಂತಿರುಗಿ -1;
	len = _len;

#ಆದರೆ defined(SSH_TUN_PREPEND_AF)
	ಆದರೆ (len <= ಗಾತ್ರ(iph) || len > ಗಾತ್ರ(rbuf) - 4)
		ಹಿಂತಿರುಗಿ -1;
	/* Determine address family from packet IP header. */
	ಸ್ಮರಣೆ_ನಕಲು(&iph, buf, ಗಾತ್ರ(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	ಸ್ಮರಣೆ_ನಕಲು(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#ಅಥವಾಆದರೆ defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	ಆದರೆ (len <= 4)
		ಹಿಂತಿರುಗಿ -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((r = sshbuf_put_string(c->ಒಳಹರಿವು, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ಹಿಂತಿರುಗಿ (0);
}

u_char *
sys_tun_outfilter(ರಚನೆ ssh *ssh, ರಚನೆ Channel *c,
    u_char **ದತ್ತಾಂಶ, ಗಾತ್ರ_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	ಪೂರ್ಣಾಂಕ r;

	/* XXX new API is incompatible with this signature. */
	ಆದರೆ ((r = sshbuf_get_string(c->output, ದತ್ತಾಂಶ, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ಆದರೆ (*dlen < ಗಾತ್ರ(af))
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	buf = *ದತ್ತಾಂಶ;

#ಆದರೆ defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= ಗಾತ್ರ(af);
	buf = *ದತ್ತಾಂಶ + ಗಾತ್ರ(af);
#ಅಥವಾಆದರೆ defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ (buf);
}
#ಆದರೆ_ಅಂತ್ಯ /* SSH_TUN_FILTER */
