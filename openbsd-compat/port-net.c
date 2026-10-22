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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>
#अन्तर्भाव <netinet/ip.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "openbsd-compat/sys-queue.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#यदि defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#अन्तर्भाव <linux/if.h>
#यदि_अन्तः

#यदि defined(SYS_RDOMAIN_LINUX)
वर्ण *
sys_get_rdomain(पूर्णाङ्क fd)
{
	वर्ण dev[IFNAMSIZ + 1];
	socklen_t len = परिमाण(dev) - 1;

	यदि (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		प्रत्यागम रिक्त;
	}
	dev[len] = '\0';
	प्रत्यागम strdup(dev);
}

पूर्णाङ्क
sys_समुच्चयः_rdomain(पूर्णाङ्क fd, ध्रुव वर्ण *name)
{
	यदि (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, वाक्यदैर्घ्यम्(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		प्रत्यागम -1;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sys_valid_rdomain(ध्रुव वर्ण *name)
{
	पूर्णाङ्क fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	यदि ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		प्रत्यागम 0;
	यदि (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, वाक्यदैर्घ्यम्(name)) == -1) {
		close(fd);
		प्रत्यागम 0;
	}
	close(fd);
	प्रत्यागम 1;
}
#नोचेद्यदि defined(SYS_RDOMAIN_XXX)
/* XXX examples */
वर्ण *
sys_get_rdomain(पूर्णाङ्क fd)
{
	प्रत्यागम रिक्त;
}

पूर्णाङ्क
sys_समुच्चयः_rdomain(पूर्णाङ्क fd, ध्रुव वर्ण *name)
{
	प्रत्यागम -1;
}

पूर्णाङ्क
valid_rdomain(ध्रुव वर्ण *name)
{
	प्रत्यागम 0;
}

शून्य
sys_समुच्चयः_process_rdomain(ध्रुव वर्ण *name)
{
	fatal("%s: not supported", __func__);
}
#यदि_अन्तः /* defined(SYS_RDOMAIN_XXX) */

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

#यदि defined(SSH_TUN_LINUX)
#अन्तर्भाव <linux/if_tun.h>
#परिभाषय TUN_CTRL_DEV "/dev/net/tun"

पूर्णाङ्क
sys_tun_open(पूर्णाङ्क tun, पूर्णाङ्क बहुलकम्, वर्ण **ifname)
{
	संरचना ifreq ifr;
	पूर्णाङ्क fd = -1;
	ध्रुव वर्ण *name = रिक्त;

	यदि (ifname != रिक्त)
		*ifname = रिक्त;
	यदि ((fd = उद्घाटय(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		प्रत्यागम (-1);
	}

	bzero(&ifr, परिमाण(ifr));

	यदि (बहुलकम् == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} अन्यथा {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	यदि (tun != SSH_TUNID_ANY) {
		यदि (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			गच्छ failed;
		}
		snprintf(ifr.ifr_name, परिमाण(ifr.ifr_name), name, tun);
	}

	यदि (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    बहुलकम्, strerror(errno));
		गच्छ failed;
	}

	यदि (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, बहुलकम्, fd);
	अन्यथा
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, बहुलकम्, fd);

	यदि (ifname != रिक्त && (*ifname = strdup(ifr.ifr_name)) == रिक्त)
		गच्छ failed;

	प्रत्यागम (fd);

 failed:
	close(fd);
	प्रत्यागम (-1);
}
#यदि_अन्तः /* SSH_TUN_LINUX */

#यदि_परिभाषितम् SSH_TUN_FREEBSD
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <net/if.h>

#यदि_परिभाषितम् HAVE_NET_IF_TUN_H
#अन्तर्भाव <net/if_tun.h>
#यदि_अन्तः

पूर्णाङ्क
sys_tun_open(पूर्णाङ्क tun, पूर्णाङ्क बहुलकम्, वर्ण **ifname)
{
	संरचना ifreq ifr;
	वर्ण name[100];
	पूर्णाङ्क fd = -1, sock;
	ध्रुव वर्ण *tunbase = "tun";
#यदि defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	पूर्णाङ्क flag;
#यदि_अन्तः

	यदि (ifname != रिक्त)
		*ifname = रिक्त;

	यदि (बहुलकम् == SSH_TUNMODE_ETHERNET) {
#यदि_परिभाषितम् SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		प्रत्यागम (-1);
#अन्यथा
		tunbase = "tap";
#यदि_अन्तः
	}

	/* Open the tunnel device */
	यदि (tun <= SSH_TUNID_MAX) {
		snprintf(name, परिमाण(name), "/dev/%s%d", tunbase, tun);
		fd = उद्घाटय(name, O_RDWR);
	} अन्यथा यदि (tun == SSH_TUNID_ANY) {
		प्रति (tun = 100; tun >= 0; tun--) {
			snprintf(name, परिमाण(name), "/dev/%s%d",
			    tunbase, tun);
			यदि ((fd = उद्घाटय(name, O_RDWR)) >= 0)
				भङ्ग;
		}
	} अन्यथा {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		प्रत्यागम (-1);
	}

	यदि (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		प्रत्यागम (-1);
	}

	/* Turn on tunnel headers */
#यदि defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	यदि (बहुलकम् != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#यदि_अन्तः

	debug("%s: %s mode %d fd %d", __func__, name, बहुलकम्, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, परिमाण(ifr.ifr_name), "%s%d", tunbase, tun);
	यदि ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		गच्छ failed;

	यदि (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		गच्छ failed;
	यदि ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		यदि (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			गच्छ failed;
	}

	यदि (ifname != रिक्त && (*ifname = strdup(ifr.ifr_name)) == रिक्त)
		गच्छ failed;

	close(sock);
	प्रत्यागम (fd);

 failed:
	यदि (fd >= 0)
		close(fd);
	यदि (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    बहुलकम्, strerror(errno));
	प्रत्यागम (-1);
}
#यदि_अन्तः /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#यदि defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#परिभाषय OPENBSD_AF_INET		2
#परिभाषय OPENBSD_AF_INET6	24

पूर्णाङ्क
sys_tun_infilter(संरचना ssh *ssh, संरचना Channel *c, वर्ण *buf, पूर्णाङ्क _len)
{
	पूर्णाङ्क r;
	आकार_t len;
	वर्ण *ptr = buf;
#यदि defined(SSH_TUN_PREPEND_AF)
	वर्ण rbuf[CHAN_RBUF];
	संरचना ip iph;
#यदि_अन्तः
#यदि defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#यदि_अन्तः

	/* XXX update channel input filter API to use unsigned length */
	यदि (_len < 0)
		प्रत्यागम -1;
	len = _len;

#यदि defined(SSH_TUN_PREPEND_AF)
	यदि (len <= परिमाण(iph) || len > परिमाण(rbuf) - 4)
		प्रत्यागम -1;
	/* Determine address family from packet IP header. */
	स्मृतिं_प्रतिलिख(&iph, buf, परिमाण(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	स्मृतिं_प्रतिलिख(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#नोचेद्यदि defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	यदि (len <= 4)
		प्रत्यागम -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#यदि_अन्तः

	यदि ((r = sshbuf_put_string(c->निवेशः, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	प्रत्यागम (0);
}

u_char *
sys_tun_outfilter(संरचना ssh *ssh, संरचना Channel *c,
    u_char **दत्त, आकार_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	पूर्णाङ्क r;

	/* XXX new API is incompatible with this signature. */
	यदि ((r = sshbuf_get_string(c->output, दत्त, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	यदि (*dlen < परिमाण(af))
		प्रत्यागम (रिक्त);
	buf = *दत्त;

#यदि defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= परिमाण(af);
	buf = *दत्त + परिमाण(af);
#नोचेद्यदि defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#यदि_अन्तः
	प्रत्यागम (buf);
}
#यदि_अन्तः /* SSH_TUN_FILTER */
