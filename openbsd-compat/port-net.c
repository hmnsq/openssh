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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>
#அந்தர்பாவ <netinet/ip.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "openbsd-compat/sys-queue.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#எனில் defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#அந்தர்பாவ <linux/if.h>
#endif

#எனில் defined(SYS_RDOMAIN_LINUX)
எழுத்து *
sys_get_rdomain(முழு fd)
{
	எழுத்து dev[IFNAMSIZ + 1];
	socklen_t len = அளவு(dev) - 1;

	எனில் (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		திரும்பு வெற்று;
	}
	dev[len] = '\0';
	திரும்பு strdup(dev);
}

முழு
sys_set_rdomain(முழு fd, மாறிலி எழுத்து *name)
{
	எனில் (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		திரும்பு -1;
	}
	திரும்பு 0;
}

முழு
sys_valid_rdomain(மாறிலி எழுத்து *name)
{
	முழு fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	எனில் ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		திரும்பு 0;
	எனில் (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		திரும்பு 0;
	}
	close(fd);
	திரும்பு 1;
}
#அல்லதெனில் defined(SYS_RDOMAIN_XXX)
/* XXX examples */
எழுத்து *
sys_get_rdomain(முழு fd)
{
	திரும்பு வெற்று;
}

முழு
sys_set_rdomain(முழு fd, மாறிலி எழுத்து *name)
{
	திரும்பு -1;
}

முழு
valid_rdomain(மாறிலி எழுத்து *name)
{
	திரும்பு 0;
}

வெறுமை
sys_set_process_rdomain(மாறிலி எழுத்து *name)
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

#எனில் defined(SSH_TUN_LINUX)
#அந்தர்பாவ <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

முழு
sys_tun_open(முழு tun, முழு mode, எழுத்து **ifname)
{
	கட்டமைப்பு ifreq ifr;
	முழு fd = -1;
	மாறிலி எழுத்து *name = வெற்று;

	எனில் (ifname != வெற்று)
		*ifname = வெற்று;
	எனில் ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		திரும்பு (-1);
	}

	bzero(&ifr, அளவு(ifr));

	எனில் (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} இல்லையெனில் {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	எனில் (tun != SSH_TUNID_ANY) {
		எனில் (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			செல் failed;
		}
		snprintf(ifr.ifr_name, அளவு(ifr.ifr_name), name, tun);
	}

	எனில் (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		செல் failed;
	}

	எனில் (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	இல்லையெனில்
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	எனில் (ifname != வெற்று && (*ifname = strdup(ifr.ifr_name)) == வெற்று)
		செல் failed;

	திரும்பு (fd);

 failed:
	close(fd);
	திரும்பு (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#அந்தர்பாவ <net/if_tun.h>
#endif

முழு
sys_tun_open(முழு tun, முழு mode, எழுத்து **ifname)
{
	கட்டமைப்பு ifreq ifr;
	எழுத்து name[100];
	முழு fd = -1, sock;
	மாறிலி எழுத்து *tunbase = "tun";
#எனில் defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	முழு flag;
#endif

	எனில் (ifname != வெற்று)
		*ifname = வெற்று;

	எனில் (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		திரும்பு (-1);
#இல்லையெனில்
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	எனில் (tun <= SSH_TUNID_MAX) {
		snprintf(name, அளவு(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} இல்லையெனில் எனில் (tun == SSH_TUNID_ANY) {
		க்கு (tun = 100; tun >= 0; tun--) {
			snprintf(name, அளவு(name), "/dev/%s%d",
			    tunbase, tun);
			எனில் ((fd = open(name, O_RDWR)) >= 0)
				நிறுத்து;
		}
	} இல்லையெனில் {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		திரும்பு (-1);
	}

	எனில் (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		திரும்பு (-1);
	}

	/* Turn on tunnel headers */
#எனில் defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	எனில் (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, அளவு(ifr.ifr_name), "%s%d", tunbase, tun);
	எனில் ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		செல் failed;

	எனில் (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		செல் failed;
	எனில் ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		எனில் (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			செல் failed;
	}

	எனில் (ifname != வெற்று && (*ifname = strdup(ifr.ifr_name)) == வெற்று)
		செல் failed;

	close(sock);
	திரும்பு (fd);

 failed:
	எனில் (fd >= 0)
		close(fd);
	எனில் (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	திரும்பு (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#எனில் defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

முழு
sys_tun_infilter(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Channel *c, எழுத்து *buf, முழு _len)
{
	முழு r;
	size_t len;
	எழுத்து *ptr = buf;
#எனில் defined(SSH_TUN_PREPEND_AF)
	எழுத்து rbuf[CHAN_RBUF];
	கட்டமைப்பு ip iph;
#endif
#எனில் defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	எனில் (_len < 0)
		திரும்பு -1;
	len = _len;

#எனில் defined(SSH_TUN_PREPEND_AF)
	எனில் (len <= அளவு(iph) || len > அளவு(rbuf) - 4)
		திரும்பு -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, அளவு(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#அல்லதெனில் defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	எனில் (len <= 4)
		திரும்பு -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	எனில் ((r = sshbuf_put_string(c->உள்ளீடு, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	திரும்பு (0);
}

u_char *
sys_tun_outfilter(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	முழு r;

	/* XXX new API is incompatible with this signature. */
	எனில் ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	எனில் (*dlen < அளவு(af))
		திரும்பு (வெற்று);
	buf = *data;

#எனில் defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= அளவு(af);
	buf = *data + அளவு(af);
#அல்லதெனில் defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	திரும்பு (buf);
}
#endif /* SSH_TUN_FILTER */
