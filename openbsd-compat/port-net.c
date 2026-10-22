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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>
#समावेश <netinet/ip.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "openbsd-compat/sys-queue.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "channels.h"
#समावेश "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#अगर defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#समावेश <linux/if.h>
#पूर्ण_अगर

#अगर defined(SYS_RDOMAIN_LINUX)
अक्षर *
sys_get_rdomain(पूर्णांक fd)
{
	अक्षर dev[IFNAMSIZ + 1];
	socklen_t len = माप(dev) - 1;

	अगर (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
	dev[len] = '\0';
	वापस strdup(dev);
}

पूर्णांक
sys_set_rdomain(पूर्णांक fd, स्थिर अक्षर *name)
{
	अगर (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, म_माप(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	वापस 0;
}

पूर्णांक
sys_valid_rdomain(स्थिर अक्षर *name)
{
	पूर्णांक fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	अगर ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		वापस 0;
	अगर (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, म_माप(name)) == -1) {
		बंद(fd);
		वापस 0;
	}
	बंद(fd);
	वापस 1;
}
#या_अगर defined(SYS_RDOMAIN_XXX)
/* XXX examples */
अक्षर *
sys_get_rdomain(पूर्णांक fd)
{
	वापस शून्य;
}

पूर्णांक
sys_set_rdomain(पूर्णांक fd, स्थिर अक्षर *name)
{
	वापस -1;
}

पूर्णांक
valid_rdomain(स्थिर अक्षर *name)
{
	वापस 0;
}

व्योम
sys_set_process_rdomain(स्थिर अक्षर *name)
{
	fatal("%s: not supported", __func__);
}
#पूर्ण_अगर /* defined(SYS_RDOMAIN_XXX) */

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

#अगर defined(SSH_TUN_LINUX)
#समावेश <linux/if_tun.h>
#घोषणा TUN_CTRL_DEV "/dev/net/tun"

पूर्णांक
sys_tun_open(पूर्णांक tun, पूर्णांक mode, अक्षर **ifname)
{
	काष्ठा ifreq ifr;
	पूर्णांक fd = -1;
	स्थिर अक्षर *name = शून्य;

	अगर (ifname != शून्य)
		*ifname = शून्य;
	अगर ((fd = खोलो(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}

	bzero(&ifr, माप(ifr));

	अगर (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} अन्यथा {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	अगर (tun != SSH_TUNID_ANY) {
		अगर (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, म_त्रुटि(त्रुटि_सं));
			जाओ failed;
		}
		snprintf(ifr.ifr_name, माप(ifr.ifr_name), name, tun);
	}

	अगर (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, म_त्रुटि(त्रुटि_सं));
		जाओ failed;
	}

	अगर (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	अन्यथा
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	अगर (ifname != शून्य && (*ifname = strdup(ifr.ifr_name)) == शून्य)
		जाओ failed;

	वापस (fd);

 failed:
	बंद(fd);
	वापस (-1);
}
#पूर्ण_अगर /* SSH_TUN_LINUX */

#अगर_घोषित SSH_TUN_FREEBSD
#समावेश <sys/socket.h>
#समावेश <net/if.h>

#अगर_घोषित HAVE_NET_IF_TUN_H
#समावेश <net/if_tun.h>
#पूर्ण_अगर

पूर्णांक
sys_tun_open(पूर्णांक tun, पूर्णांक mode, अक्षर **ifname)
{
	काष्ठा ifreq ifr;
	अक्षर name[100];
	पूर्णांक fd = -1, sock;
	स्थिर अक्षर *tunbase = "tun";
#अगर defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	पूर्णांक flag;
#पूर्ण_अगर

	अगर (ifname != शून्य)
		*ifname = शून्य;

	अगर (mode == SSH_TUNMODE_ETHERNET) {
#अगर_घोषित SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		वापस (-1);
#अन्यथा
		tunbase = "tap";
#पूर्ण_अगर
	}

	/* Open the tunnel device */
	अगर (tun <= SSH_TUNID_MAX) {
		snprintf(name, माप(name), "/dev/%s%d", tunbase, tun);
		fd = खोलो(name, O_RDWR);
	} अन्यथा अगर (tun == SSH_TUNID_ANY) {
		क्रम (tun = 100; tun >= 0; tun--) {
			snprintf(name, माप(name), "/dev/%s%d",
			    tunbase, tun);
			अगर ((fd = खोलो(name, O_RDWR)) >= 0)
				अवरोध;
		}
	} अन्यथा {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		वापस (-1);
	}

	अगर (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}

	/* Turn on tunnel headers */
#अगर defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	अगर (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    म_त्रुटि(त्रुटि_सं));
		बंद(fd);
	}
#पूर्ण_अगर

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, माप(ifr.ifr_name), "%s%d", tunbase, tun);
	अगर ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		जाओ failed;

	अगर (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		जाओ failed;
	अगर ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		अगर (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			जाओ failed;
	}

	अगर (ifname != शून्य && (*ifname = strdup(ifr.ifr_name)) == शून्य)
		जाओ failed;

	बंद(sock);
	वापस (fd);

 failed:
	अगर (fd >= 0)
		बंद(fd);
	अगर (sock >= 0)
		बंद(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, म_त्रुटि(त्रुटि_सं));
	वापस (-1);
}
#पूर्ण_अगर /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#अगर defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#घोषणा OPENBSD_AF_INET		2
#घोषणा OPENBSD_AF_INET6	24

पूर्णांक
sys_tun_infilter(काष्ठा ssh *ssh, काष्ठा Channel *c, अक्षर *buf, पूर्णांक _len)
{
	पूर्णांक r;
	माप_प्रकार len;
	अक्षर *ptr = buf;
#अगर defined(SSH_TUN_PREPEND_AF)
	अक्षर rbuf[CHAN_RBUF];
	काष्ठा ip iph;
#पूर्ण_अगर
#अगर defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#पूर्ण_अगर

	/* XXX update channel input filter API to use unsigned length */
	अगर (_len < 0)
		वापस -1;
	len = _len;

#अगर defined(SSH_TUN_PREPEND_AF)
	अगर (len <= माप(iph) || len > माप(rbuf) - 4)
		वापस -1;
	/* Determine address family from packet IP header. */
	स_नकल(&iph, buf, माप(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	स_नकल(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#या_अगर defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	अगर (len <= 4)
		वापस -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#पूर्ण_अगर

	अगर ((r = sshbuf_put_string(c->निवेश, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	वापस (0);
}

u_char *
sys_tun_outfilter(काष्ठा ssh *ssh, काष्ठा Channel *c,
    u_char **तथ्य, माप_प्रकार *dlen)
{
	u_char *buf;
	u_int32_t af;
	पूर्णांक r;

	/* XXX new API is incompatible with this signature. */
	अगर ((r = sshbuf_get_string(c->output, तथ्य, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	अगर (*dlen < माप(af))
		वापस (शून्य);
	buf = *तथ्य;

#अगर defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= माप(af);
	buf = *तथ्य + माप(af);
#या_अगर defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#पूर्ण_अगर
	वापस (buf);
}
#पूर्ण_अगर /* SSH_TUN_FILTER */
