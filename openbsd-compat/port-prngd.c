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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h> /* for offsetof */

#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ defined(PRNGD_ਪੋਰਟ) || defined(PRNGD_SOCKET)
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
ਸਥਿਰ ਪੂਰਨ
get_random_ਬਾਈਟਾਂ_prngd(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *buf, ਪੂਰਨ len,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ tcp_ਪੋਰਟ, ਅੱਖਰ *socket_ਰਸਤਾ)
{
	ਪੂਰਨ fd, addr_len, rval, errors;
	u_char ਸੁਨੇਹਾ[2];
	ਬਣਤਰ sockaddr_storage addr;
	ਬਣਤਰ sockaddr_in *addr_ਵਿੱਚ = (ਬਣਤਰ sockaddr_in *)&addr;
	ਬਣਤਰ sockaddr_un *addr_un = (ਬਣਤਰ sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	ਜੇ (socket_ਰਸਤਾ == ਨਿਰਾ && tcp_ਪੋਰਟ == 0)
		fatal("You must specify a port or a socket");
	ਜੇ (socket_ਰਸਤਾ != ਨਿਰਾ &&
	    ਲੜੀ_ਲੰਬਾਈ(socket_ਰਸਤਾ) >= ਆਕਾਰ(addr_un->sun_ਰਸਤਾ))
		fatal("Random pool path is too long");
	ਜੇ (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', ਆਕਾਰ(addr));

	ਜੇ (tcp_ਪੋਰਟ != 0) {
		addr_ਵਿੱਚ->sin_family = AF_INET;
		addr_ਵਿੱਚ->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_ਵਿੱਚ->sin_port = htons(tcp_ਪੋਰਟ);
		addr_len = ਆਕਾਰ(*addr_ਵਿੱਚ);
	} ਨਹੀਂਤਾਂ {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_ਰਸਤਾ, socket_ਰਸਤਾ,
		    ਆਕਾਰ(addr_un->sun_ਰਸਤਾ));
		addr_len = offsetof(ਬਣਤਰ sockaddr_un, sun_ਰਸਤਾ) +
		    ਲੜੀ_ਲੰਬਾਈ(socket_ਰਸਤਾ) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	ਜੇ (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (connect(fd, (ਬਣਤਰ sockaddr*)&addr, addr_len) == -1) {
		ਜੇ (tcp_ਪੋਰਟ != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_ਪੋਰਟ, strerror(errno));
		} ਨਹੀਂਤਾਂ {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_ਰਸਤਾ, strerror(errno));
		}
		ਜਾਓ ਪੂਰਾ;
	}

	/* Send blocking read request to PRNGD */
	ਸੁਨੇਹਾ[0] = 0x02;
	ਸੁਨੇਹਾ[1] = len;

	ਜੇ (atomicio(vwrite, fd, ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ)) != ਆਕਾਰ(ਸੁਨੇਹਾ)) {
		ਜੇ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ਜਾਓ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (atomicio(ਪਠ, fd, buf, len) != (ਮਾਪ_t)len) {
		ਜੇ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ਜਾਓ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		ਜਾਓ ਪੂਰਾ;
	}

	rval = 0;
ਪੂਰਾ:
	ssh_signal(SIGPIPE, old_sigpipe);
	ਜੇ (fd != -1)
		close(fd);
	ਵਾਪਸ rval;
}
#ਜੇ_ਅੰਤ /* PRNGD_PORT || PRNGD_SOCKET */

ਪੂਰਨ
ਬੀਜ_from_prngd(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *buf, ਮਾਪ_t ਬਾਈਟਾਂ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRNGD_ਪੋਰਟ
	debug("trying egd/prngd port %d", PRNGD_ਪੋਰਟ);
	ਜੇ (get_random_ਬਾਈਟਾਂ_prngd(buf, ਬਾਈਟਾਂ, PRNGD_ਪੋਰਟ, ਨਿਰਾ) == 0)
		ਵਾਪਸ 0;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	ਜੇ (get_random_ਬਾਈਟਾਂ_prngd(buf, ਬਾਈਟਾਂ, 0, PRNGD_SOCKET) == 0)
		ਵਾਪਸ 0;
#ਜੇ_ਅੰਤ
	ਵਾਪਸ -1;
}
