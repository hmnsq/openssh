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

#जर defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#अन्तर्भाव <linux/if.h>
#endif

#जर defined(SYS_RDOMAIN_LINUX)
अक्षर *
sys_get_rdomain(पूर्णांक fd)
{
	अक्षर dev[IFNAMSIZ + 1];
	socklen_t len = आकार(dev) - 1;

	जर (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, म_त्रुटि(त्रुटि_सं));
		परत रिक्त;
	}
	dev[len] = '\0';
	परत strdup(dev);
}

पूर्णांक
sys_set_rdomain(पूर्णांक fd, स्थिरांक अक्षर *name)
{
	जर (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, म_माप(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	परत 0;
}

पूर्णांक
sys_valid_rdomain(स्थिरांक अक्षर *name)
{
	पूर्णांक fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	जर ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		परत 0;
	जर (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, म_माप(name)) == -1) {
		बंद(fd);
		परत 0;
	}
	बंद(fd);
	परत 1;
}
#किंवाजर defined(SYS_RDOMAIN_XXX)
/* XXX examples */
अक्षर *
sys_get_rdomain(पूर्णांक fd)
{
	परत रिक्त;
}

पूर्णांक
sys_set_rdomain(पूर्णांक fd, स्थिरांक अक्षर *name)
{
	परत -1;
}

पूर्णांक
valid_rdomain(स्थिरांक अक्षर *name)
{
	परत 0;
}

शून्य
sys_set_process_rdomain(स्थिरांक अक्षर *name)
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

#जर defined(SSH_TUN_LINUX)
#अन्तर्भाव <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

पूर्णांक
sys_tun_open(पूर्णांक tun, पूर्णांक mode, अक्षर **ifname)
{
	संरचना ifreq ifr;
	पूर्णांक fd = -1;
	स्थिरांक अक्षर *name = रिक्त;

	जर (ifname != रिक्त)
		*ifname = रिक्त;
	जर ((fd = खोलो(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, म_त्रुटि(त्रुटि_सं));
		परत (-1);
	}

	bzero(&ifr, आकार(ifr));

	जर (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} अन्यथा {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	जर (tun != SSH_TUNID_ANY) {
		जर (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, म_त्रुटि(त्रुटि_सं));
			जा failed;
		}
		snprintf(ifr.ifr_name, आकार(ifr.ifr_name), name, tun);
	}

	जर (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, म_त्रुटि(त्रुटि_सं));
		जा failed;
	}

	जर (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	अन्यथा
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	जर (ifname != रिक्त && (*ifname = strdup(ifr.ifr_name)) == रिक्त)
		जा failed;

	परत (fd);

 failed:
	बंद(fd);
	परत (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#अन्तर्भाव <net/if_tun.h>
#endif

पूर्णांक
sys_tun_open(पूर्णांक tun, पूर्णांक mode, अक्षर **ifname)
{
	संरचना ifreq ifr;
	अक्षर name[100];
	पूर्णांक fd = -1, sock;
	स्थिरांक अक्षर *tunbase = "tun";
#जर defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	पूर्णांक flag;
#endif

	जर (ifname != रिक्त)
		*ifname = रिक्त;

	जर (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		परत (-1);
#अन्यथा
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	जर (tun <= SSH_TUNID_MAX) {
		snprintf(name, आकार(name), "/dev/%s%d", tunbase, tun);
		fd = खोलो(name, O_RDWR);
	} अन्यथा जर (tun == SSH_TUNID_ANY) {
		साठी (tun = 100; tun >= 0; tun--) {
			snprintf(name, आकार(name), "/dev/%s%d",
			    tunbase, tun);
			जर ((fd = खोलो(name, O_RDWR)) >= 0)
				थांबा;
		}
	} अन्यथा {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		परत (-1);
	}

	जर (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    म_त्रुटि(त्रुटि_सं));
		परत (-1);
	}

	/* Turn on tunnel headers */
#जर defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	जर (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    म_त्रुटि(त्रुटि_सं));
		बंद(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, आकार(ifr.ifr_name), "%s%d", tunbase, tun);
	जर ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		जा failed;

	जर (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		जा failed;
	जर ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		जर (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			जा failed;
	}

	जर (ifname != रिक्त && (*ifname = strdup(ifr.ifr_name)) == रिक्त)
		जा failed;

	बंद(sock);
	परत (fd);

 failed:
	जर (fd >= 0)
		बंद(fd);
	जर (sock >= 0)
		बंद(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, म_त्रुटि(त्रुटि_सं));
	परत (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#जर defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

पूर्णांक
sys_tun_infilter(संरचना ssh *ssh, संरचना Channel *c, अक्षर *buf, पूर्णांक _len)
{
	पूर्णांक r;
	माप_प्रकार len;
	अक्षर *ptr = buf;
#जर defined(SSH_TUN_PREPEND_AF)
	अक्षर rbuf[CHAN_RBUF];
	संरचना ip iph;
#endif
#जर defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	जर (_len < 0)
		परत -1;
	len = _len;

#जर defined(SSH_TUN_PREPEND_AF)
	जर (len <= आकार(iph) || len > आकार(rbuf) - 4)
		परत -1;
	/* Determine address family from packet IP header. */
	स_नकल(&iph, buf, आकार(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	स_नकल(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#किंवाजर defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	जर (len <= 4)
		परत -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	जर ((r = sshbuf_put_string(c->आदान, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	परत (0);
}

u_char *
sys_tun_outfilter(संरचना ssh *ssh, संरचना Channel *c,
    u_char **data, माप_प्रकार *dlen)
{
	u_char *buf;
	u_int32_t af;
	पूर्णांक r;

	/* XXX new API is incompatible with this signature. */
	जर ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	जर (*dlen < आकार(af))
		परत (रिक्त);
	buf = *data;

#जर defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= आकार(af);
	buf = *data + आकार(af);
#किंवाजर defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	परत (buf);
}
#endif /* SSH_TUN_FILTER */
