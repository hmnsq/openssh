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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "openbsd-compat/sys-queue.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "channels.h"
#include "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#නම් defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#include <linux/if.h>
#endif

#නම් defined(SYS_RDOMAIN_LINUX)
var_na *
sys_get_rdomain(පූර්ණ_සංඛ්‍යා fd)
{
	var_na dev[IFNAMSIZ + 1];
	socklen_t len = parimaa_na(dev) - 1;

	නම් (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		ආපසු NULL;
	}
	dev[len] = '\0';
	ආපසු strdup(dev);
}

පූර්ණ_සංඛ්‍යා
sys_set_rdomain(පූර්ණ_සංඛ්‍යා fd, const var_na *name)
{
	නම් (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		ආපසු -1;
	}
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sys_valid_rdomain(const var_na *name)
{
	පූර්ණ_සංඛ්‍යා fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	නම් ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		ආපසු 0;
	නම් (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		ආපසු 0;
	}
	close(fd);
	ආපසු 1;
}
#elif defined(SYS_RDOMAIN_XXX)
/* XXX examples */
var_na *
sys_get_rdomain(පූර්ණ_සංඛ්‍යා fd)
{
	ආපසු NULL;
}

පූර්ණ_සංඛ්‍යා
sys_set_rdomain(පූර්ණ_සංඛ්‍යා fd, const var_na *name)
{
	ආපසු -1;
}

පූර්ණ_සංඛ්‍යා
valid_rdomain(const var_na *name)
{
	ආපසු 0;
}

void
sys_set_process_rdomain(const var_na *name)
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

#නම් defined(SSH_TUN_LINUX)
#include <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

පූර්ණ_සංඛ්‍යා
sys_tun_open(පූර්ණ_සංඛ්‍යා tun, පූර්ණ_සංඛ්‍යා mode, var_na **ifname)
{
	sa_nracanaa ifreq ifr;
	පූර්ණ_සංඛ්‍යා fd = -1;
	const var_na *name = NULL;

	නම් (ifname != NULL)
		*ifname = NULL;
	නම් ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		ආපසු (-1);
	}

	bzero(&ifr, parimaa_na(ifr));

	නම් (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} නැතහොත් {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	නම් (tun != SSH_TUNID_ANY) {
		නම් (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			goto failed;
		}
		snprintf(ifr.ifr_name, parimaa_na(ifr.ifr_name), name, tun);
	}

	නම් (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		goto failed;
	}

	නම් (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	නැතහොත්
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	නම් (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	ආපසු (fd);

 failed:
	close(fd);
	ආපසු (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#include <sys/socket.h>
#include <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

පූර්ණ_සංඛ්‍යා
sys_tun_open(පූර්ණ_සංඛ්‍යා tun, පූර්ණ_සංඛ්‍යා mode, var_na **ifname)
{
	sa_nracanaa ifreq ifr;
	var_na name[100];
	පූර්ණ_සංඛ්‍යා fd = -1, sock;
	const var_na *tunbase = "tun";
#නම් defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	පූර්ණ_සංඛ්‍යා flag;
#endif

	නම් (ifname != NULL)
		*ifname = NULL;

	නම් (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		ආපසු (-1);
#නැතහොත්
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	නම් (tun <= SSH_TUNID_MAX) {
		snprintf(name, parimaa_na(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} නැතහොත් නම් (tun == SSH_TUNID_ANY) {
		සඳහා (tun = 100; tun >= 0; tun--) {
			snprintf(name, parimaa_na(name), "/dev/%s%d",
			    tunbase, tun);
			නම් ((fd = open(name, O_RDWR)) >= 0)
				bha_nga;
		}
	} නැතහොත් {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		ආපසු (-1);
	}

	නම් (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		ආපසු (-1);
	}

	/* Turn on tunnel headers */
#නම් defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	නම් (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, parimaa_na(ifr.ifr_name), "%s%d", tunbase, tun);
	නම් ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	නම් (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		goto failed;
	නම් ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		නම් (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			goto failed;
	}

	නම් (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	close(sock);
	ආපසු (fd);

 failed:
	නම් (fd >= 0)
		close(fd);
	නම් (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	ආපසු (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#නම් defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

පූර්ණ_සංඛ්‍යා
sys_tun_infilter(sa_nracanaa ssh *ssh, sa_nracanaa Channel *c, var_na *buf, පූර්ණ_සංඛ්‍යා _len)
{
	පූර්ණ_සංඛ්‍යා r;
	size_t len;
	var_na *ptr = buf;
#නම් defined(SSH_TUN_PREPEND_AF)
	var_na rbuf[CHAN_RBUF];
	sa_nracanaa ip iph;
#endif
#නම් defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	නම් (_len < 0)
		ආපසු -1;
	len = _len;

#නම් defined(SSH_TUN_PREPEND_AF)
	නම් (len <= parimaa_na(iph) || len > parimaa_na(rbuf) - 4)
		ආපසු -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, parimaa_na(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#elif defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	නම් (len <= 4)
		ආපසු -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	නම් ((r = sshbuf_put_string(c->input, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ආපසු (0);
}

u_char *
sys_tun_outfilter(sa_nracanaa ssh *ssh, sa_nracanaa Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	පූර්ණ_සංඛ්‍යා r;

	/* XXX new API is incompatible with this signature. */
	නම් ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	නම් (*dlen < parimaa_na(af))
		ආපසු (NULL);
	buf = *data;

#නම් defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= parimaa_na(af);
	buf = *data + parimaa_na(af);
#elif defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	ආපසු (buf);
}
#endif /* SSH_TUN_FILTER */
