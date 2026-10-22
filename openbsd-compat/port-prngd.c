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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/un.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <stddef.h> /* for offsetof */

#شامل "atomicio.h"
#شامل "misc.h"
#شامل "log.h"

#اگر defined(PRNGD_پورٹ) || defined(PRNGD_SOCKET)
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
ساکن صحیح
get_random_بائٹیں_prngd(غیرعلامتی حرف *buf, صحیح len,
    غیرعلامتی مختصر tcp_پورٹ, حرف *socket_راستہ)
{
	صحیح fd, addr_len, rval, errors;
	u_char پیغام[2];
	ساخت sockaddr_storage addr;
	ساخت sockaddr_in *addr_اندر = (ساخت sockaddr_in *)&addr;
	ساخت sockaddr_un *addr_un = (ساخت sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	اگر (socket_راستہ == تہی && tcp_پورٹ == 0)
		fatal("You must specify a port or a socket");
	اگر (socket_راستہ != تہی &&
	    لڑی_لمبائی(socket_راستہ) >= حجم(addr_un->sun_راستہ))
		fatal("Random pool path is too long");
	اگر (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', حجم(addr));

	اگر (tcp_پورٹ != 0) {
		addr_اندر->sin_family = AF_INET;
		addr_اندر->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_اندر->sin_port = htons(tcp_پورٹ);
		addr_len = حجم(*addr_اندر);
	} ورنہ {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_راستہ, socket_راستہ,
		    حجم(addr_un->sun_راستہ));
		addr_len = offsetof(ساخت sockaddr_un, sun_راستہ) +
		    لڑی_لمبائی(socket_راستہ) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	اگر (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		جاؤ مکمل;
	}

	اگر (connect(fd, (ساخت sockaddr*)&addr, addr_len) == -1) {
		اگر (tcp_پورٹ != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_پورٹ, strerror(errno));
		} ورنہ {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_راستہ, strerror(errno));
		}
		جاؤ مکمل;
	}

	/* Send blocking read request to PRNGD */
	پیغام[0] = 0x02;
	پیغام[1] = len;

	اگر (atomicio(vwrite, fd, پیغام, حجم(پیغام)) != حجم(پیغام)) {
		اگر (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			جاؤ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		جاؤ مکمل;
	}

	اگر (atomicio(اقرأ, fd, buf, len) != (سائز_t)len) {
		اگر (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			جاؤ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		جاؤ مکمل;
	}

	rval = 0;
مکمل:
	ssh_signal(SIGPIPE, old_sigpipe);
	اگر (fd != -1)
		close(fd);
	واپس rval;
}
#اگر_ختم /* PRNGD_PORT || PRNGD_SOCKET */

صحیح
بیج_from_prngd(غیرعلامتی حرف *buf, سائز_t بائٹیں)
{
#اگر_تعریف_شدہ PRNGD_پورٹ
	debug("trying egd/prngd port %d", PRNGD_پورٹ);
	اگر (get_random_بائٹیں_prngd(buf, بائٹیں, PRNGD_پورٹ, تہی) == 0)
		واپس 0;
#اگر_ختم
#اگر_تعریف_شدہ PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	اگر (get_random_بائٹیں_prngd(buf, بائٹیں, 0, PRNGD_SOCKET) == 0)
		واپس 0;
#اگر_ختم
	واپس -1;
}
