/*
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/un.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <errno.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <stddef.h> /* for offsetof */

#ضمن "atomicio.h"
#ضمن "misc.h"
#ضمن "log.h"

#إذا defined(PRNGD_پورت) || defined(PRNGD_SOCKET)
/*
 * EGD/PRNGD interface.
 *
 * Collect 'len' bytes of entropy into 'buf' from PRNGD/EGD daemon
 * listening either on 'tcp_port', or via Unix domain socket at *
 * 'socket_path'.
 * Either a non-zero tcp_port or a non-null socket_path must be
 * supplied.
 * Returns 0 on success, -1 on error
 */
ساكن صحيح
get_random_بایتها_prngd(بیعلامت حرف *buf, صحيح len,
    بیعلامت کوتاه tcp_پورت, حرف *socket_مسیر)
{
	صحيح fd, addr_len, rval, errors;
	u_char پیام[2];
	بنية sockaddr_storage addr;
	بنية sockaddr_in *addr_درون = (بنية sockaddr_in *)&addr;
	بنية sockaddr_un *addr_un = (بنية sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	إذا (socket_مسیر == عدم && tcp_پورت == 0)
		fatal("You must specify a port or a socket");
	إذا (socket_مسیر != عدم &&
	    طول_رشته(socket_مسیر) >= حجم(addr_un->sun_مسیر))
		fatal("Random pool path is too long");
	إذا (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', حجم(addr));

	إذا (tcp_پورت != 0) {
		addr_درون->sin_family = AF_INET;
		addr_درون->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_درون->sin_port = htons(tcp_پورت);
		addr_len = حجم(*addr_درون);
	} وإلا {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_مسیر, socket_مسیر,
		    حجم(addr_un->sun_مسیر));
		addr_len = offsetof(بنية sockaddr_un, sun_مسیر) +
		    طول_رشته(socket_مسیر) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	إذا (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		اذهب انجامشده;
	}

	إذا (connect(fd, (بنية sockaddr*)&addr, addr_len) == -1) {
		إذا (tcp_پورت != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_پورت, strerror(errno));
		} وإلا {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_مسیر, strerror(errno));
		}
		اذهب انجامشده;
	}

	/* Send blocking read request to PRNGD */
	پیام[0] = 0x02;
	پیام[1] = len;

	إذا (atomicio(vwrite, fd, پیام, حجم(پیام)) != حجم(پیام)) {
		إذا (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			اذهب reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		اذهب انجامشده;
	}

	إذا (atomicio(اقرأ, fd, buf, len) != (اندازه_t)len) {
		إذا (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			اذهب reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		اذهب انجامشده;
	}

	rval = 0;
انجامشده:
	ssh_signal(SIGPIPE, old_sigpipe);
	إذا (fd != -1)
		close(fd);
	أرجع rval;
}
#پایان_اگر /* PRNGD_PORT || PRNGD_SOCKET */

صحيح
دانه_from_prngd(بیعلامت حرف *buf, اندازه_t بایتها)
{
#اگر_تعریف_شده PRNGD_پورت
	debug("trying egd/prngd port %d", PRNGD_پورت);
	إذا (get_random_بایتها_prngd(buf, بایتها, PRNGD_پورت, عدم) == 0)
		أرجع 0;
#پایان_اگر
#اگر_تعریف_شده PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	إذا (get_random_بایتها_prngd(buf, بایتها, 0, PRNGD_SOCKET) == 0)
		أرجع 0;
#پایان_اگر
	أرجع -1;
}
