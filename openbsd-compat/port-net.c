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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>
#అన్తర్భావ <netinet/ip.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "openbsd-compat/sys-queue.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#ఒకవేళ defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#అన్తర్భావ <linux/if.h>
#అయితే_ముగింపు

#ఒకవేళ defined(SYS_RDOMAIN_LINUX)
అక్షరం *
sys_get_rdomain(పూర్ణాంకం fd)
{
	అక్షరం dev[IFNAMSIZ + 1];
	socklen_t len = పరిమాణం(dev) - 1;

	ఒకవేళ (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		తిరిగి ఖాళీ;
	}
	dev[len] = '\0';
	తిరిగి strdup(dev);
}

పూర్ణాంకం
sys_సమితి_rdomain(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *name)
{
	ఒకవేళ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, అక్షరశ్రేణి_పొడవు(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		తిరిగి -1;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sys_valid_rdomain(స్థిరరాశి అక్షరం *name)
{
	పూర్ణాంకం fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	ఒకవేళ ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		తిరిగి 0;
	ఒకవేళ (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, అక్షరశ్రేణి_పొడవు(name)) == -1) {
		close(fd);
		తిరిగి 0;
	}
	close(fd);
	తిరిగి 1;
}
#లేదావేళ defined(SYS_RDOMAIN_XXX)
/* XXX examples */
అక్షరం *
sys_get_rdomain(పూర్ణాంకం fd)
{
	తిరిగి ఖాళీ;
}

పూర్ణాంకం
sys_సమితి_rdomain(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *name)
{
	తిరిగి -1;
}

పూర్ణాంకం
valid_rdomain(స్థిరరాశి అక్షరం *name)
{
	తిరిగి 0;
}

శూన్య
sys_సమితి_process_rdomain(స్థిరరాశి అక్షరం *name)
{
	fatal("%s: not supported", __func__);
}
#అయితే_ముగింపు /* defined(SYS_RDOMAIN_XXX) */

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

#ఒకవేళ defined(SSH_TUN_LINUX)
#అన్తర్భావ <linux/if_tun.h>
#నిర్వచించు TUN_CTRL_DEV "/dev/net/tun"

పూర్ణాంకం
sys_tun_open(పూర్ణాంకం tun, పూర్ణాంకం బహుళకం, అక్షరం **ifname)
{
	నిర్మాణం ifreq ifr;
	పూర్ణాంకం fd = -1;
	స్థిరరాశి అక్షరం *name = ఖాళీ;

	ఒకవేళ (ifname != ఖాళీ)
		*ifname = ఖాళీ;
	ఒకవేళ ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		తిరిగి (-1);
	}

	bzero(&ifr, పరిమాణం(ifr));

	ఒకవేళ (బహుళకం == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} లేకపోతే {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	ఒకవేళ (tun != SSH_TUNID_ANY) {
		ఒకవేళ (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			వెళ్ళు failed;
		}
		snprintf(ifr.ifr_name, పరిమాణం(ifr.ifr_name), name, tun);
	}

	ఒకవేళ (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    బహుళకం, strerror(errno));
		వెళ్ళు failed;
	}

	ఒకవేళ (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, బహుళకం, fd);
	లేకపోతే
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, బహుళకం, fd);

	ఒకవేళ (ifname != ఖాళీ && (*ifname = strdup(ifr.ifr_name)) == ఖాళీ)
		వెళ్ళు failed;

	తిరిగి (fd);

 failed:
	close(fd);
	తిరిగి (-1);
}
#అయితే_ముగింపు /* SSH_TUN_LINUX */

#నిర్వచితమైతే SSH_TUN_FREEBSD
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <net/if.h>

#నిర్వచితమైతే HAVE_NET_IF_TUN_H
#అన్తర్భావ <net/if_tun.h>
#అయితే_ముగింపు

పూర్ణాంకం
sys_tun_open(పూర్ణాంకం tun, పూర్ణాంకం బహుళకం, అక్షరం **ifname)
{
	నిర్మాణం ifreq ifr;
	అక్షరం name[100];
	పూర్ణాంకం fd = -1, sock;
	స్థిరరాశి అక్షరం *tunbase = "tun";
#ఒకవేళ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	పూర్ణాంకం flag;
#అయితే_ముగింపు

	ఒకవేళ (ifname != ఖాళీ)
		*ifname = ఖాళీ;

	ఒకవేళ (బహుళకం == SSH_TUNMODE_ETHERNET) {
#నిర్వచితమైతే SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		తిరిగి (-1);
#లేకపోతే
		tunbase = "tap";
#అయితే_ముగింపు
	}

	/* Open the tunnel device */
	ఒకవేళ (tun <= SSH_TUNID_MAX) {
		snprintf(name, పరిమాణం(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} లేకపోతే ఒకవేళ (tun == SSH_TUNID_ANY) {
		కొరకు (tun = 100; tun >= 0; tun--) {
			snprintf(name, పరిమాణం(name), "/dev/%s%d",
			    tunbase, tun);
			ఒకవేళ ((fd = open(name, O_RDWR)) >= 0)
				ఆపు;
		}
	} లేకపోతే {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		తిరిగి (-1);
	}

	ఒకవేళ (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		తిరిగి (-1);
	}

	/* Turn on tunnel headers */
#ఒకవేళ defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	ఒకవేళ (బహుళకం != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#అయితే_ముగింపు

	debug("%s: %s mode %d fd %d", __func__, name, బహుళకం, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, పరిమాణం(ifr.ifr_name), "%s%d", tunbase, tun);
	ఒకవేళ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		వెళ్ళు failed;

	ఒకవేళ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		వెళ్ళు failed;
	ఒకవేళ ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		ఒకవేళ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			వెళ్ళు failed;
	}

	ఒకవేళ (ifname != ఖాళీ && (*ifname = strdup(ifr.ifr_name)) == ఖాళీ)
		వెళ్ళు failed;

	close(sock);
	తిరిగి (fd);

 failed:
	ఒకవేళ (fd >= 0)
		close(fd);
	ఒకవేళ (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    బహుళకం, strerror(errno));
	తిరిగి (-1);
}
#అయితే_ముగింపు /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#ఒకవేళ defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#నిర్వచించు OPENBSD_AF_INET		2
#నిర్వచించు OPENBSD_AF_INET6	24

పూర్ణాంకం
sys_tun_infilter(నిర్మాణం ssh *ssh, నిర్మాణం Channel *c, అక్షరం *buf, పూర్ణాంకం _len)
{
	పూర్ణాంకం r;
	కొలత_t len;
	అక్షరం *ptr = buf;
#ఒకవేళ defined(SSH_TUN_PREPEND_AF)
	అక్షరం rbuf[CHAN_RBUF];
	నిర్మాణం ip iph;
#అయితే_ముగింపు
#ఒకవేళ defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#అయితే_ముగింపు

	/* XXX update channel input filter API to use unsigned length */
	ఒకవేళ (_len < 0)
		తిరిగి -1;
	len = _len;

#ఒకవేళ defined(SSH_TUN_PREPEND_AF)
	ఒకవేళ (len <= పరిమాణం(iph) || len > పరిమాణం(rbuf) - 4)
		తిరిగి -1;
	/* Determine address family from packet IP header. */
	జ్ఞాపకం_నకలు(&iph, buf, పరిమాణం(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	జ్ఞాపకం_నకలు(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#లేదావేళ defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	ఒకవేళ (len <= 4)
		తిరిగి -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#అయితే_ముగింపు

	ఒకవేళ ((r = sshbuf_put_string(c->ఆదానం, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	తిరిగి (0);
}

u_char *
sys_tun_outfilter(నిర్మాణం ssh *ssh, నిర్మాణం Channel *c,
    u_char **దత్తాంశం, కొలత_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	పూర్ణాంకం r;

	/* XXX new API is incompatible with this signature. */
	ఒకవేళ ((r = sshbuf_get_string(c->output, దత్తాంశం, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ఒకవేళ (*dlen < పరిమాణం(af))
		తిరిగి (ఖాళీ);
	buf = *దత్తాంశం;

#ఒకవేళ defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= పరిమాణం(af);
	buf = *దత్తాంశం + పరిమాణం(af);
#లేదావేళ defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#అయితే_ముగింపు
	తిరిగి (buf);
}
#అయితే_ముగింపు /* SSH_TUN_FILTER */
