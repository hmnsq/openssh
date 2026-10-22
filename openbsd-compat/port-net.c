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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>
#અન્તર્ભાવ <netinet/ip.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "openbsd-compat/sys-queue.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#જો defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#અન્તર્ભાવ <linux/if.h>
#endif

#જો defined(SYS_RDOMAIN_LINUX)
અક્ષર *
sys_get_rdomain(પૂર્ણાંક fd)
{
	અક્ષર dev[IFNAMSIZ + 1];
	socklen_t len = કદ(dev) - 1;

	જો (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		પાછા ખાલી;
	}
	dev[len] = '\0';
	પાછા strdup(dev);
}

પૂર્ણાંક
sys_set_rdomain(પૂર્ણાંક fd, અચલ અક્ષર *name)
{
	જો (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		પાછા -1;
	}
	પાછા 0;
}

પૂર્ણાંક
sys_valid_rdomain(અચલ અક્ષર *name)
{
	પૂર્ણાંક fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	જો ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		પાછા 0;
	જો (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		પાછા 0;
	}
	close(fd);
	પાછા 1;
}
#અથવાજો defined(SYS_RDOMAIN_XXX)
/* XXX examples */
અક્ષર *
sys_get_rdomain(પૂર્ણાંક fd)
{
	પાછા ખાલી;
}

પૂર્ણાંક
sys_set_rdomain(પૂર્ણાંક fd, અચલ અક્ષર *name)
{
	પાછા -1;
}

પૂર્ણાંક
valid_rdomain(અચલ અક્ષર *name)
{
	પાછા 0;
}

શૂન્ય
sys_set_process_rdomain(અચલ અક્ષર *name)
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

#જો defined(SSH_TUN_LINUX)
#અન્તર્ભાવ <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

પૂર્ણાંક
sys_tun_open(પૂર્ણાંક tun, પૂર્ણાંક mode, અક્ષર **ifname)
{
	સંરચના ifreq ifr;
	પૂર્ણાંક fd = -1;
	અચલ અક્ષર *name = ખાલી;

	જો (ifname != ખાલી)
		*ifname = ખાલી;
	જો ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		પાછા (-1);
	}

	bzero(&ifr, કદ(ifr));

	જો (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} નહીંતર {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	જો (tun != SSH_TUNID_ANY) {
		જો (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			જાઓ failed;
		}
		snprintf(ifr.ifr_name, કદ(ifr.ifr_name), name, tun);
	}

	જો (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		જાઓ failed;
	}

	જો (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	નહીંતર
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	જો (ifname != ખાલી && (*ifname = strdup(ifr.ifr_name)) == ખાલી)
		જાઓ failed;

	પાછા (fd);

 failed:
	close(fd);
	પાછા (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#અન્તર્ભાવ <net/if_tun.h>
#endif

પૂર્ણાંક
sys_tun_open(પૂર્ણાંક tun, પૂર્ણાંક mode, અક્ષર **ifname)
{
	સંરચના ifreq ifr;
	અક્ષર name[100];
	પૂર્ણાંક fd = -1, sock;
	અચલ અક્ષર *tunbase = "tun";
#જો defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	પૂર્ણાંક flag;
#endif

	જો (ifname != ખાલી)
		*ifname = ખાલી;

	જો (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		પાછા (-1);
#નહીંતર
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	જો (tun <= SSH_TUNID_MAX) {
		snprintf(name, કદ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} નહીંતર જો (tun == SSH_TUNID_ANY) {
		માટે (tun = 100; tun >= 0; tun--) {
			snprintf(name, કદ(name), "/dev/%s%d",
			    tunbase, tun);
			જો ((fd = open(name, O_RDWR)) >= 0)
				તોડો;
		}
	} નહીંતર {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		પાછા (-1);
	}

	જો (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		પાછા (-1);
	}

	/* Turn on tunnel headers */
#જો defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	જો (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, કદ(ifr.ifr_name), "%s%d", tunbase, tun);
	જો ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		જાઓ failed;

	જો (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		જાઓ failed;
	જો ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		જો (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			જાઓ failed;
	}

	જો (ifname != ખાલી && (*ifname = strdup(ifr.ifr_name)) == ખાલી)
		જાઓ failed;

	close(sock);
	પાછા (fd);

 failed:
	જો (fd >= 0)
		close(fd);
	જો (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	પાછા (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#જો defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

પૂર્ણાંક
sys_tun_infilter(સંરચના ssh *ssh, સંરચના Channel *c, અક્ષર *buf, પૂર્ણાંક _len)
{
	પૂર્ણાંક r;
	size_t len;
	અક્ષર *ptr = buf;
#જો defined(SSH_TUN_PREPEND_AF)
	અક્ષર rbuf[CHAN_RBUF];
	સંરચના ip iph;
#endif
#જો defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	જો (_len < 0)
		પાછા -1;
	len = _len;

#જો defined(SSH_TUN_PREPEND_AF)
	જો (len <= કદ(iph) || len > કદ(rbuf) - 4)
		પાછા -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, કદ(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#અથવાજો defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	જો (len <= 4)
		પાછા -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	જો ((r = sshbuf_put_string(c->આગત, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	પાછા (0);
}

u_char *
sys_tun_outfilter(સંરચના ssh *ssh, સંરચના Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	પૂર્ણાંક r;

	/* XXX new API is incompatible with this signature. */
	જો ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	જો (*dlen < કદ(af))
		પાછા (ખાલી);
	buf = *data;

#જો defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= કદ(af);
	buf = *data + કદ(af);
#અથવાજો defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	પાછા (buf);
}
#endif /* SSH_TUN_FILTER */
