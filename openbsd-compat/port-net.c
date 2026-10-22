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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>
#അന്തര്ഭാവ <netinet/ip.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "openbsd-compat/sys-queue.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#എങ്കിൽ defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#അന്തര്ഭാവ <linux/if.h>
#endif

#എങ്കിൽ defined(SYS_RDOMAIN_LINUX)
അക്ഷരം *
sys_get_rdomain(പൂർണ്ണസംഖ്യ fd)
{
	അക്ഷരം dev[IFNAMSIZ + 1];
	socklen_t len = വലുപ്പം(dev) - 1;

	എങ്കിൽ (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		തിരികെ ശൂന്യ;
	}
	dev[len] = '\0';
	തിരികെ strdup(dev);
}

പൂർണ്ണസംഖ്യ
sys_set_rdomain(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *name)
{
	എങ്കിൽ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		തിരികെ -1;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sys_valid_rdomain(സ്ഥിരം അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	എങ്കിൽ ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		തിരികെ 0;
	എങ്കിൽ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		തിരികെ 0;
	}
	close(fd);
	തിരികെ 1;
}
#അല്ലെങ്കിലെങ്കിൽ defined(SYS_RDOMAIN_XXX)
/* XXX examples */
അക്ഷരം *
sys_get_rdomain(പൂർണ്ണസംഖ്യ fd)
{
	തിരികെ ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
sys_set_rdomain(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *name)
{
	തിരികെ -1;
}

പൂർണ്ണസംഖ്യ
valid_rdomain(സ്ഥിരം അക്ഷരം *name)
{
	തിരികെ 0;
}

ശൂന്യം
sys_set_process_rdomain(സ്ഥിരം അക്ഷരം *name)
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

#എങ്കിൽ defined(SSH_TUN_LINUX)
#അന്തര്ഭാവ <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

പൂർണ്ണസംഖ്യ
sys_tun_open(പൂർണ്ണസംഖ്യ tun, പൂർണ്ണസംഖ്യ mode, അക്ഷരം **ifname)
{
	ഘടന ifreq ifr;
	പൂർണ്ണസംഖ്യ fd = -1;
	സ്ഥിരം അക്ഷരം *name = ശൂന്യ;

	എങ്കിൽ (ifname != ശൂന്യ)
		*ifname = ശൂന്യ;
	എങ്കിൽ ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		തിരികെ (-1);
	}

	bzero(&ifr, വലുപ്പം(ifr));

	എങ്കിൽ (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} അല്ലെങ്കിൽ {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	എങ്കിൽ (tun != SSH_TUNID_ANY) {
		എങ്കിൽ (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			പോകുക failed;
		}
		snprintf(ifr.ifr_name, വലുപ്പം(ifr.ifr_name), name, tun);
	}

	എങ്കിൽ (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		പോകുക failed;
	}

	എങ്കിൽ (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	അല്ലെങ്കിൽ
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	എങ്കിൽ (ifname != ശൂന്യ && (*ifname = strdup(ifr.ifr_name)) == ശൂന്യ)
		പോകുക failed;

	തിരികെ (fd);

 failed:
	close(fd);
	തിരികെ (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#അന്തര്ഭാവ <net/if_tun.h>
#endif

പൂർണ്ണസംഖ്യ
sys_tun_open(പൂർണ്ണസംഖ്യ tun, പൂർണ്ണസംഖ്യ mode, അക്ഷരം **ifname)
{
	ഘടന ifreq ifr;
	അക്ഷരം name[100];
	പൂർണ്ണസംഖ്യ fd = -1, sock;
	സ്ഥിരം അക്ഷരം *tunbase = "tun";
#എങ്കിൽ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	പൂർണ്ണസംഖ്യ flag;
#endif

	എങ്കിൽ (ifname != ശൂന്യ)
		*ifname = ശൂന്യ;

	എങ്കിൽ (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		തിരികെ (-1);
#അല്ലെങ്കിൽ
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	എങ്കിൽ (tun <= SSH_TUNID_MAX) {
		snprintf(name, വലുപ്പം(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} അല്ലെങ്കിൽ എങ്കിൽ (tun == SSH_TUNID_ANY) {
		വേണ്ടി (tun = 100; tun >= 0; tun--) {
			snprintf(name, വലുപ്പം(name), "/dev/%s%d",
			    tunbase, tun);
			എങ്കിൽ ((fd = open(name, O_RDWR)) >= 0)
				നിർത്തുക;
		}
	} അല്ലെങ്കിൽ {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		തിരികെ (-1);
	}

	എങ്കിൽ (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		തിരികെ (-1);
	}

	/* Turn on tunnel headers */
#എങ്കിൽ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	എങ്കിൽ (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, വലുപ്പം(ifr.ifr_name), "%s%d", tunbase, tun);
	എങ്കിൽ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		പോകുക failed;

	എങ്കിൽ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		പോകുക failed;
	എങ്കിൽ ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		എങ്കിൽ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			പോകുക failed;
	}

	എങ്കിൽ (ifname != ശൂന്യ && (*ifname = strdup(ifr.ifr_name)) == ശൂന്യ)
		പോകുക failed;

	close(sock);
	തിരികെ (fd);

 failed:
	എങ്കിൽ (fd >= 0)
		close(fd);
	എങ്കിൽ (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	തിരികെ (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#എങ്കിൽ defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

പൂർണ്ണസംഖ്യ
sys_tun_infilter(ഘടന ssh *ssh, ഘടന Channel *c, അക്ഷരം *buf, പൂർണ്ണസംഖ്യ _len)
{
	പൂർണ്ണസംഖ്യ r;
	size_t len;
	അക്ഷരം *ptr = buf;
#എങ്കിൽ defined(SSH_TUN_PREPEND_AF)
	അക്ഷരം rbuf[CHAN_RBUF];
	ഘടന ip iph;
#endif
#എങ്കിൽ defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	എങ്കിൽ (_len < 0)
		തിരികെ -1;
	len = _len;

#എങ്കിൽ defined(SSH_TUN_PREPEND_AF)
	എങ്കിൽ (len <= വലുപ്പം(iph) || len > വലുപ്പം(rbuf) - 4)
		തിരികെ -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, വലുപ്പം(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#അല്ലെങ്കിലെങ്കിൽ defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	എങ്കിൽ (len <= 4)
		തിരികെ -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	എങ്കിൽ ((r = sshbuf_put_string(c->നിവേശം, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	തിരികെ (0);
}

u_char *
sys_tun_outfilter(ഘടന ssh *ssh, ഘടന Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	പൂർണ്ണസംഖ്യ r;

	/* XXX new API is incompatible with this signature. */
	എങ്കിൽ ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	എങ്കിൽ (*dlen < വലുപ്പം(af))
		തിരികെ (ശൂന്യ);
	buf = *data;

#എങ്കിൽ defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= വലുപ്പം(af);
	buf = *data + വലുപ്പം(af);
#അല്ലെങ്കിലെങ്കിൽ defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	തിരികെ (buf);
}
#endif /* SSH_TUN_FILTER */
