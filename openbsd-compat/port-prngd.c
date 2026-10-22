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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stddef.h> /* for offsetof */

#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "log.h"

#എങ്കിൽ defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
get_random_bytes_prngd(unsigned അക്ഷരം *buf, പൂർണ്ണസംഖ്യ len,
    unsigned short tcp_port, അക്ഷരം *socket_path)
{
	പൂർണ്ണസംഖ്യ fd, addr_len, rval, errors;
	u_char സന്ദേശം[2];
	ഘടന sockaddr_storage addr;
	ഘടന sockaddr_in *addr_in = (ഘടന sockaddr_in *)&addr;
	ഘടന sockaddr_un *addr_un = (ഘടന sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	എങ്കിൽ (socket_path == ശൂന്യ && tcp_port == 0)
		fatal("You must specify a port or a socket");
	എങ്കിൽ (socket_path != ശൂന്യ &&
	    strlen(socket_path) >= വലുപ്പം(addr_un->sun_path))
		fatal("Random pool path is too long");
	എങ്കിൽ (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', വലുപ്പം(addr));

	എങ്കിൽ (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = വലുപ്പം(*addr_in);
	} അല്ലെങ്കിൽ {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    വലുപ്പം(addr_un->sun_path));
		addr_len = offsetof(ഘടന sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	എങ്കിൽ (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		പോകുക done;
	}

	എങ്കിൽ (connect(fd, (ഘടന sockaddr*)&addr, addr_len) == -1) {
		എങ്കിൽ (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} അല്ലെങ്കിൽ {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		പോകുക done;
	}

	/* Send blocking read request to PRNGD */
	സന്ദേശം[0] = 0x02;
	സന്ദേശം[1] = len;

	എങ്കിൽ (atomicio(vwrite, fd, സന്ദേശം, വലുപ്പം(സന്ദേശം)) != വലുപ്പം(സന്ദേശം)) {
		എങ്കിൽ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			പോകുക reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		പോകുക done;
	}

	എങ്കിൽ (atomicio(പഠ, fd, buf, len) != (size_t)len) {
		എങ്കിൽ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			പോകുക reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		പോകുക done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	എങ്കിൽ (fd != -1)
		close(fd);
	തിരികെ rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

പൂർണ്ണസംഖ്യ
seed_from_prngd(unsigned അക്ഷരം *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	എങ്കിൽ (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, ശൂന്യ) == 0)
		തിരികെ 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	എങ്കിൽ (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		തിരികെ 0;
#endif
	തിരികെ -1;
}
