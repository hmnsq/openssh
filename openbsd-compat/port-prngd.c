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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stddef.h> /* for offsetof */

#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "log.h"

#જો defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
સ્થિર પૂર્ણાંક
get_random_bytes_prngd(unsigned અક્ષર *buf, પૂર્ણાંક len,
    unsigned short tcp_port, અક્ષર *socket_path)
{
	પૂર્ણાંક fd, addr_len, rval, errors;
	u_char સંદેશ[2];
	સંરચના sockaddr_storage addr;
	સંરચના sockaddr_in *addr_in = (સંરચના sockaddr_in *)&addr;
	સંરચના sockaddr_un *addr_un = (સંરચના sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	જો (socket_path == ખાલી && tcp_port == 0)
		fatal("You must specify a port or a socket");
	જો (socket_path != ખાલી &&
	    strlen(socket_path) >= કદ(addr_un->sun_path))
		fatal("Random pool path is too long");
	જો (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', કદ(addr));

	જો (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = કદ(*addr_in);
	} નહીંતર {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    કદ(addr_un->sun_path));
		addr_len = offsetof(સંરચના sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	જો (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		જાઓ done;
	}

	જો (connect(fd, (સંરચના sockaddr*)&addr, addr_len) == -1) {
		જો (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} નહીંતર {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		જાઓ done;
	}

	/* Send blocking read request to PRNGD */
	સંદેશ[0] = 0x02;
	સંદેશ[1] = len;

	જો (atomicio(vwrite, fd, સંદેશ, કદ(સંદેશ)) != કદ(સંદેશ)) {
		જો (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			જાઓ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		જાઓ done;
	}

	જો (atomicio(પઠ, fd, buf, len) != (size_t)len) {
		જો (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			જાઓ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		જાઓ done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	જો (fd != -1)
		close(fd);
	પાછા rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

પૂર્ણાંક
seed_from_prngd(unsigned અક્ષર *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	જો (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, ખાલી) == 0)
		પાછા 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	જો (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		પાછા 0;
#endif
	પાછા -1;
}
