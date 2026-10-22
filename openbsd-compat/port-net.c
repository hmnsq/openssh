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
#اگر_ختم

#اگر defined(SYS_RDOMAIN_LINUX)
حرف *
sys_get_rdomain(صحیح fd)
{
	حرف dev[IFNAMSIZ + 1];
	socklen_t len = حجم(dev) - 1;

	اگر (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		واپس تہی;
	}
	dev[len] = '\0';
	واپس strdup(dev);
}

صحیح
sys_سیٹ_rdomain(صحیح fd, ثابت حرف *name)
{
	اگر (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, لڑی_لمبائی(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		واپس -1;
	}
	واپس 0;
}

صحیح
sys_valid_rdomain(ثابت حرف *name)
{
	صحیح fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	اگر ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		واپس 0;
	اگر (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, لڑی_لمبائی(name)) == -1) {
		close(fd);
		واپس 0;
	}
	close(fd);
	واپس 1;
}
#وگرنہ_اگر defined(SYS_RDOMAIN_XXX)
/* XXX examples */
حرف *
sys_get_rdomain(صحیح fd)
{
	واپس تہی;
}

صحیح
sys_سیٹ_rdomain(صحیح fd, ثابت حرف *name)
{
	واپس -1;
}

صحیح
valid_rdomain(ثابت حرف *name)
{
	واپس 0;
}

خالی
sys_سیٹ_process_rdomain(ثابت حرف *name)
{
	fatal("%s: not supported", __func__);
}
#اگر_ختم /* defined(SYS_RDOMAIN_XXX) */

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
#تعریف_کرو TUN_CTRL_DEV "/dev/net/tun"

صحیح
sys_tun_open(صحیح tun, صحیح منوال, حرف **ifname)
{
	ساخت ifreq ifr;
	صحیح fd = -1;
	ثابت حرف *name = تہی;

	اگر (ifname != تہی)
		*ifname = تہی;
	اگر ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		واپس (-1);
	}

	bzero(&ifr, حجم(ifr));

	اگر (منوال == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} ورنہ {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	اگر (tun != SSH_TUNID_ANY) {
		اگر (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			جاؤ failed;
		}
		snprintf(ifr.ifr_name, حجم(ifr.ifr_name), name, tun);
	}

	اگر (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    منوال, strerror(errno));
		جاؤ failed;
	}

	اگر (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, منوال, fd);
	ورنہ
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, منوال, fd);

	اگر (ifname != تہی && (*ifname = strdup(ifr.ifr_name)) == تہی)
		جاؤ failed;

	واپس (fd);

 failed:
	close(fd);
	واپس (-1);
}
#اگر_ختم /* SSH_TUN_LINUX */

#اگر_تعریف_شدہ SSH_TUN_FREEBSD
#شامل <sys/socket.h>
#شامل <net/if.h>

#اگر_تعریف_شدہ HAVE_NET_IF_TUN_H
#شامل <net/if_tun.h>
#اگر_ختم

صحیح
sys_tun_open(صحیح tun, صحیح منوال, حرف **ifname)
{
	ساخت ifreq ifr;
	حرف name[100];
	صحیح fd = -1, sock;
	ثابت حرف *tunbase = "tun";
#اگر defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	صحیح flag;
#اگر_ختم

	اگر (ifname != تہی)
		*ifname = تہی;

	اگر (منوال == SSH_TUNMODE_ETHERNET) {
#اگر_تعریف_شدہ SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		واپس (-1);
#ورنہ
		tunbase = "tap";
#اگر_ختم
	}

	/* Open the tunnel device */
	اگر (tun <= SSH_TUNID_MAX) {
		snprintf(name, حجم(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ورنہ اگر (tun == SSH_TUNID_ANY) {
		برائے (tun = 100; tun >= 0; tun--) {
			snprintf(name, حجم(name), "/dev/%s%d",
			    tunbase, tun);
			اگر ((fd = open(name, O_RDWR)) >= 0)
				توڑو;
		}
	} ورنہ {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		واپس (-1);
	}

	اگر (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		واپس (-1);
	}

	/* Turn on tunnel headers */
#اگر defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	اگر (منوال != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#اگر_ختم

	debug("%s: %s mode %d fd %d", __func__, name, منوال, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, حجم(ifr.ifr_name), "%s%d", tunbase, tun);
	اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		جاؤ failed;

	اگر (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		جاؤ failed;
	اگر ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		اگر (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			جاؤ failed;
	}

	اگر (ifname != تہی && (*ifname = strdup(ifr.ifr_name)) == تہی)
		جاؤ failed;

	close(sock);
	واپس (fd);

 failed:
	اگر (fd >= 0)
		close(fd);
	اگر (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    منوال, strerror(errno));
	واپس (-1);
}
#اگر_ختم /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#اگر defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#تعریف_کرو OPENBSD_AF_INET		2
#تعریف_کرو OPENBSD_AF_INET6	24

صحیح
sys_tun_infilter(ساخت ssh *ssh, ساخت Channel *c, حرف *buf, صحیح _len)
{
	صحیح r;
	سائز_t len;
	حرف *ptr = buf;
#اگر defined(SSH_TUN_PREPEND_AF)
	حرف rbuf[CHAN_RBUF];
	ساخت ip iph;
#اگر_ختم
#اگر defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#اگر_ختم

	/* XXX update channel input filter API to use unsigned length */
	اگر (_len < 0)
		واپس -1;
	len = _len;

#اگر defined(SSH_TUN_PREPEND_AF)
	اگر (len <= حجم(iph) || len > حجم(rbuf) - 4)
		واپس -1;
	/* Determine address family from packet IP header. */
	حافظہ_نقل(&iph, buf, حجم(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	حافظہ_نقل(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#وگرنہ_اگر defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	اگر (len <= 4)
		واپس -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#اگر_ختم

	اگر ((r = sshbuf_put_string(c->داخلہ, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	واپس (0);
}

u_char *
sys_tun_outfilter(ساخت ssh *ssh, ساخت Channel *c,
    u_char **ڈیٹا, سائز_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	صحیح r;

	/* XXX new API is incompatible with this signature. */
	اگر ((r = sshbuf_get_string(c->output, ڈیٹا, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	اگر (*dlen < حجم(af))
		واپس (تہی);
	buf = *ڈیٹا;

#اگر defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= حجم(af);
	buf = *ڈیٹا + حجم(af);
#وگرنہ_اگر defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#اگر_ختم
	واپس (buf);
}
#اگر_ختم /* SSH_TUN_FILTER */
