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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/ioctl.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>
#অন্তর্ভাব <netinet/ip.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "openbsd-compat/sys-queue.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#যদি defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#অন্তর্ভাব <linux/if.h>
#endif

#যদি defined(SYS_RDOMAIN_LINUX)
অক্ষর *
sys_get_rdomain(পূর্ণসংখ্যা fd)
{
	অক্ষর dev[IFNAMSIZ + 1];
	socklen_t len = আকার(dev) - 1;

	যদি (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ফেরত ফাঁকা;
	}
	dev[len] = '\0';
	ফেরত strdup(dev);
}

পূর্ণসংখ্যা
sys_set_rdomain(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *name)
{
	যদি (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ফেরত -1;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sys_valid_rdomain(ধ্রুবক অক্ষর *name)
{
	পূর্ণসংখ্যা fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	যদি ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ফেরত 0;
	যদি (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		ফেরত 0;
	}
	close(fd);
	ফেরত 1;
}
#নতুবা_যদি defined(SYS_RDOMAIN_XXX)
/* XXX examples */
অক্ষর *
sys_get_rdomain(পূর্ণসংখ্যা fd)
{
	ফেরত ফাঁকা;
}

পূর্ণসংখ্যা
sys_set_rdomain(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *name)
{
	ফেরত -1;
}

পূর্ণসংখ্যা
valid_rdomain(ধ্রুবক অক্ষর *name)
{
	ফেরত 0;
}

শূন্য
sys_set_process_rdomain(ধ্রুবক অক্ষর *name)
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

#যদি defined(SSH_TUN_LINUX)
#অন্তর্ভাব <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

পূর্ণসংখ্যা
sys_tun_open(পূর্ণসংখ্যা tun, পূর্ণসংখ্যা mode, অক্ষর **ifname)
{
	কাঠামো ifreq ifr;
	পূর্ণসংখ্যা fd = -1;
	ধ্রুবক অক্ষর *name = ফাঁকা;

	যদি (ifname != ফাঁকা)
		*ifname = ফাঁকা;
	যদি ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ফেরত (-1);
	}

	bzero(&ifr, আকার(ifr));

	যদি (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} অন্যথা {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	যদি (tun != SSH_TUNID_ANY) {
		যদি (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			যাও failed;
		}
		snprintf(ifr.ifr_name, আকার(ifr.ifr_name), name, tun);
	}

	যদি (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		যাও failed;
	}

	যদি (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	অন্যথা
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	যদি (ifname != ফাঁকা && (*ifname = strdup(ifr.ifr_name)) == ফাঁকা)
		যাও failed;

	ফেরত (fd);

 failed:
	close(fd);
	ফেরত (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#অন্তর্ভাব <net/if_tun.h>
#endif

পূর্ণসংখ্যা
sys_tun_open(পূর্ণসংখ্যা tun, পূর্ণসংখ্যা mode, অক্ষর **ifname)
{
	কাঠামো ifreq ifr;
	অক্ষর name[100];
	পূর্ণসংখ্যা fd = -1, sock;
	ধ্রুবক অক্ষর *tunbase = "tun";
#যদি defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	পূর্ণসংখ্যা flag;
#endif

	যদি (ifname != ফাঁকা)
		*ifname = ফাঁকা;

	যদি (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ফেরত (-1);
#অন্যথা
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	যদি (tun <= SSH_TUNID_MAX) {
		snprintf(name, আকার(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} অন্যথা যদি (tun == SSH_TUNID_ANY) {
		জন্য (tun = 100; tun >= 0; tun--) {
			snprintf(name, আকার(name), "/dev/%s%d",
			    tunbase, tun);
			যদি ((fd = open(name, O_RDWR)) >= 0)
				বিরতি;
		}
	} অন্যথা {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ফেরত (-1);
	}

	যদি (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ফেরত (-1);
	}

	/* Turn on tunnel headers */
#যদি defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	যদি (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, আকার(ifr.ifr_name), "%s%d", tunbase, tun);
	যদি ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		যাও failed;

	যদি (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		যাও failed;
	যদি ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		যদি (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			যাও failed;
	}

	যদি (ifname != ফাঁকা && (*ifname = strdup(ifr.ifr_name)) == ফাঁকা)
		যাও failed;

	close(sock);
	ফেরত (fd);

 failed:
	যদি (fd >= 0)
		close(fd);
	যদি (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	ফেরত (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#যদি defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

পূর্ণসংখ্যা
sys_tun_infilter(কাঠামো ssh *ssh, কাঠামো Channel *c, অক্ষর *buf, পূর্ণসংখ্যা _len)
{
	পূর্ণসংখ্যা r;
	আকার_t len;
	অক্ষর *ptr = buf;
#যদি defined(SSH_TUN_PREPEND_AF)
	অক্ষর rbuf[CHAN_RBUF];
	কাঠামো ip iph;
#endif
#যদি defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	যদি (_len < 0)
		ফেরত -1;
	len = _len;

#যদি defined(SSH_TUN_PREPEND_AF)
	যদি (len <= আকার(iph) || len > আকার(rbuf) - 4)
		ফেরত -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, আকার(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#নতুবা_যদি defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	যদি (len <= 4)
		ফেরত -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	যদি ((r = sshbuf_put_string(c->প্রবেশ, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ফেরত (0);
}

u_char *
sys_tun_outfilter(কাঠামো ssh *ssh, কাঠামো Channel *c,
    u_char **তথ্য, আকার_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	পূর্ণসংখ্যা r;

	/* XXX new API is incompatible with this signature. */
	যদি ((r = sshbuf_get_string(c->output, তথ্য, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	যদি (*dlen < আকার(af))
		ফেরত (ফাঁকা);
	buf = *তথ্য;

#যদি defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= আকার(af);
	buf = *তথ্য + আকার(af);
#নতুবা_যদি defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	ফেরত (buf);
}
#endif /* SSH_TUN_FILTER */
