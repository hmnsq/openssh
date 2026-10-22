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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>
#ଅନ୍ତର୍ଭାଵ <netinet/ip.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/sys-queue.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#ଯଦି defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#ଅନ୍ତର୍ଭାଵ <linux/if.h>
#endif

#ଯଦି defined(SYS_RDOMAIN_LINUX)
ଅକ୍ଷର *
sys_get_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ଅକ୍ଷର dev[IFNAMSIZ + 1];
	socklen_t len = ଆକାର(dev) - 1;

	ଯଦି (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	dev[len] = '\0';
	ଫେରନ୍ତୁ strdup(dev);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_set_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *name)
{
	ଯଦି (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_valid_rdomain(ଅଚଳ ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	ଯଦି ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ଫେରନ୍ତୁ 0;
	ଯଦି (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		ଫେରନ୍ତୁ 0;
	}
	close(fd);
	ଫେରନ୍ତୁ 1;
}
#ନଚେତଯଦି defined(SYS_RDOMAIN_XXX)
/* XXX examples */
ଅକ୍ଷର *
sys_get_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ଫେରନ୍ତୁ ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_set_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *name)
{
	ଫେରନ୍ତୁ -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
valid_rdomain(ଅଚଳ ଅକ୍ଷର *name)
{
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
sys_set_process_rdomain(ଅଚଳ ଅକ୍ଷର *name)
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

#ଯଦି defined(SSH_TUN_LINUX)
#ଅନ୍ତର୍ଭାଵ <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_tun_open(ପୂର୍ଣ୍ଣସଂଖ୍ୟା tun, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, ଅକ୍ଷର **ifname)
{
	ସଂରଚନା ifreq ifr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = -1;
	ଅଚଳ ଅକ୍ଷର *name = ଖାଲି;

	ଯଦି (ifname != ଖାଲି)
		*ifname = ଖାଲି;
	ଯଦି ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}

	bzero(&ifr, ଆକାର(ifr));

	ଯଦି (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} ଅନ୍ୟଥା {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	ଯଦି (tun != SSH_TUNID_ANY) {
		ଯଦି (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			ଯାଅ failed;
		}
		snprintf(ifr.ifr_name, ଆକାର(ifr.ifr_name), name, tun);
	}

	ଯଦି (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		ଯାଅ failed;
	}

	ଯଦି (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	ଅନ୍ୟଥା
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	ଯଦି (ifname != ଖାଲି && (*ifname = strdup(ifr.ifr_name)) == ଖାଲି)
		ଯାଅ failed;

	ଫେରନ୍ତୁ (fd);

 failed:
	close(fd);
	ଫେରନ୍ତୁ (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#ଅନ୍ତର୍ଭାଵ <net/if_tun.h>
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_tun_open(ପୂର୍ଣ୍ଣସଂଖ୍ୟା tun, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, ଅକ୍ଷର **ifname)
{
	ସଂରଚନା ifreq ifr;
	ଅକ୍ଷର name[100];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = -1, sock;
	ଅଚଳ ଅକ୍ଷର *tunbase = "tun";
#ଯଦି defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag;
#endif

	ଯଦି (ifname != ଖାଲି)
		*ifname = ଖାଲି;

	ଯଦି (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ଫେରନ୍ତୁ (-1);
#ଅନ୍ୟଥା
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	ଯଦି (tun <= SSH_TUNID_MAX) {
		snprintf(name, ଆକାର(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ଅନ୍ୟଥା ଯଦି (tun == SSH_TUNID_ANY) {
		ପାଇଁ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ଆକାର(name), "/dev/%s%d",
			    tunbase, tun);
			ଯଦି ((fd = open(name, O_RDWR)) >= 0)
				ଭାଙ୍ଗ;
		}
	} ଅନ୍ୟଥା {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ଫେରନ୍ତୁ (-1);
	}

	ଯଦି (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}

	/* Turn on tunnel headers */
#ଯଦି defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	ଯଦି (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, ଆକାର(ifr.ifr_name), "%s%d", tunbase, tun);
	ଯଦି ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ଯାଅ failed;

	ଯଦି (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		ଯାଅ failed;
	ଯଦି ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		ଯଦି (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			ଯାଅ failed;
	}

	ଯଦି (ifname != ଖାଲି && (*ifname = strdup(ifr.ifr_name)) == ଖାଲି)
		ଯାଅ failed;

	close(sock);
	ଫେରନ୍ତୁ (fd);

 failed:
	ଯଦି (fd >= 0)
		close(fd);
	ଯଦି (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	ଫେରନ୍ତୁ (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#ଯଦି defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_tun_infilter(ସଂରଚନା ssh *ssh, ସଂରଚନା Channel *c, ଅକ୍ଷର *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା _len)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t len;
	ଅକ୍ଷର *ptr = buf;
#ଯଦି defined(SSH_TUN_PREPEND_AF)
	ଅକ୍ଷର rbuf[CHAN_RBUF];
	ସଂରଚନା ip iph;
#endif
#ଯଦି defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	ଯଦି (_len < 0)
		ଫେରନ୍ତୁ -1;
	len = _len;

#ଯଦି defined(SSH_TUN_PREPEND_AF)
	ଯଦି (len <= ଆକାର(iph) || len > ଆକାର(rbuf) - 4)
		ଫେରନ୍ତୁ -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, ଆକାର(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#ନଚେତଯଦି defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	ଯଦି (len <= 4)
		ଫେରନ୍ତୁ -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	ଯଦି ((r = sshbuf_put_string(c->ନିବେଶ, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ଫେରନ୍ତୁ (0);
}

u_char *
sys_tun_outfilter(ସଂରଚନା ssh *ssh, ସଂରଚନା Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* XXX new API is incompatible with this signature. */
	ଯଦି ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ଯଦି (*dlen < ଆକାର(af))
		ଫେରନ୍ତୁ (ଖାଲି);
	buf = *data;

#ଯଦି defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= ଆକାର(af);
	buf = *data + ଆକାର(af);
#ନଚେତଯଦି defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	ଫେରନ୍ତୁ (buf);
}
#endif /* SSH_TUN_FILTER */
