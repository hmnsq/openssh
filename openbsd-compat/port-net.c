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

#إذا defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#ضمن <linux/if.h>
#د_که_پای

#إذا defined(SYS_RDOMAIN_LINUX)
حرف *
sys_get_rdomain(صحيح fd)
{
	حرف dev[IFNAMSIZ + 1];
	socklen_t len = حجم(dev) - 1;

	إذا (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		أرجع عدم;
	}
	dev[len] = '\0';
	أرجع strdup(dev);
}

صحيح
sys_سېټ_rdomain(صحيح fd, ثابت حرف *name)
{
	إذا (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, مزي_اوږدوالی(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		أرجع -1;
	}
	أرجع 0;
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
	إذا ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		أرجع 0;
	إذا (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, مزي_اوږدوالی(name)) == -1) {
		close(fd);
		أرجع 0;
	}
	close(fd);
	أرجع 1;
}
#وإلاإذا defined(SYS_RDOMAIN_XXX)
/* XXX examples */
حرف *
sys_get_rdomain(صحيح fd)
{
	أرجع عدم;
}

صحيح
sys_سېټ_rdomain(صحيح fd, ثابت حرف *name)
{
	أرجع -1;
}

صحيح
valid_rdomain(ثابت حرف *name)
{
	أرجع 0;
}

فراغ
sys_سېټ_process_rdomain(ثابت حرف *name)
{
	fatal("%s: not supported", __func__);
}
#د_که_پای /* defined(SYS_RDOMAIN_XXX) */

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

#إذا defined(SSH_TUN_LINUX)
#ضمن <linux/if_tun.h>
#تعریف_کړه TUN_CTRL_DEV "/dev/net/tun"

صحيح
sys_tun_open(صحيح tun, صحيح ډېرپېښ, حرف **ifname)
{
	بنية ifreq ifr;
	صحيح fd = -1;
	ثابت حرف *name = عدم;

	إذا (ifname != عدم)
		*ifname = عدم;
	إذا ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		أرجع (-1);
	}

	bzero(&ifr, حجم(ifr));

	إذا (ډېرپېښ == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} وإلا {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	إذا (tun != SSH_TUNID_ANY) {
		إذا (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			اذهب failed;
		}
		snprintf(ifr.ifr_name, حجم(ifr.ifr_name), name, tun);
	}

	إذا (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    ډېرپېښ, strerror(errno));
		اذهب failed;
	}

	إذا (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, ډېرپېښ, fd);
	وإلا
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, ډېرپېښ, fd);

	إذا (ifname != عدم && (*ifname = strdup(ifr.ifr_name)) == عدم)
		اذهب failed;

	أرجع (fd);

 failed:
	close(fd);
	أرجع (-1);
}
#د_که_پای /* SSH_TUN_LINUX */

#که_تعریف_شوی SSH_TUN_FREEBSD
#ضمن <sys/socket.h>
#ضمن <net/if.h>

#که_تعریف_شوی HAVE_NET_IF_TUN_H
#ضمن <net/if_tun.h>
#د_که_پای

صحيح
sys_tun_open(صحيح tun, صحيح ډېرپېښ, حرف **ifname)
{
	بنية ifreq ifr;
	حرف name[100];
	صحيح fd = -1, sock;
	ثابت حرف *tunbase = "tun";
#إذا defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	صحيح flag;
#د_که_پای

	إذا (ifname != عدم)
		*ifname = عدم;

	إذا (ډېرپېښ == SSH_TUNMODE_ETHERNET) {
#که_تعریف_شوی SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		أرجع (-1);
#وإلا
		tunbase = "tap";
#د_که_پای
	}

	/* Open the tunnel device */
	إذا (tun <= SSH_TUNID_MAX) {
		snprintf(name, حجم(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} وإلا إذا (tun == SSH_TUNID_ANY) {
		لكل (tun = 100; tun >= 0; tun--) {
			snprintf(name, حجم(name), "/dev/%s%d",
			    tunbase, tun);
			إذا ((fd = open(name, O_RDWR)) >= 0)
				اكسر;
		}
	} وإلا {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		أرجع (-1);
	}

	إذا (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		أرجع (-1);
	}

	/* Turn on tunnel headers */
#إذا defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	إذا (ډېرپېښ != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#د_که_پای

	debug("%s: %s mode %d fd %d", __func__, name, ډېرپېښ, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, حجم(ifr.ifr_name), "%s%d", tunbase, tun);
	إذا ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		اذهب failed;

	إذا (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		اذهب failed;
	إذا ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		إذا (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			اذهب failed;
	}

	إذا (ifname != عدم && (*ifname = strdup(ifr.ifr_name)) == عدم)
		اذهب failed;

	close(sock);
	أرجع (fd);

 failed:
	إذا (fd >= 0)
		close(fd);
	إذا (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    ډېرپېښ, strerror(errno));
	أرجع (-1);
}
#د_که_پای /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#إذا defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#تعریف_کړه OPENBSD_AF_INET		2
#تعریف_کړه OPENBSD_AF_INET6	24

صحيح
sys_tun_infilter(بنية ssh *ssh, بنية Channel *c, حرف *buf, صحيح _len)
{
	صحيح r;
	اندازه_t len;
	حرف *ptr = buf;
#إذا defined(SSH_TUN_PREPEND_AF)
	حرف rbuf[CHAN_RBUF];
	بنية ip iph;
#د_که_پای
#إذا defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#د_که_پای

	/* XXX update channel input filter API to use unsigned length */
	إذا (_len < 0)
		أرجع -1;
	len = _len;

#إذا defined(SSH_TUN_PREPEND_AF)
	إذا (len <= حجم(iph) || len > حجم(rbuf) - 4)
		أرجع -1;
	/* Determine address family from packet IP header. */
	حافظه_نقل(&iph, buf, حجم(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	حافظه_نقل(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#وإلاإذا defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	إذا (len <= 4)
		أرجع -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#د_که_پای

	إذا ((r = sshbuf_put_string(c->ننوت, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	أرجع (0);
}

u_char *
sys_tun_outfilter(بنية ssh *ssh, بنية Channel *c,
    u_char **معلومات, اندازه_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	صحيح r;

	/* XXX new API is incompatible with this signature. */
	إذا ((r = sshbuf_get_string(c->output, معلومات, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	إذا (*dlen < حجم(af))
		أرجع (عدم);
	buf = *معلومات;

#إذا defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= حجم(af);
	buf = *معلومات + حجم(af);
#وإلاإذا defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#د_که_پای
	أرجع (buf);
}
#د_که_پای /* SSH_TUN_FILTER */
