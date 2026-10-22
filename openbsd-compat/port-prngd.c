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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stddef.h> /* for offsetof */

#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಯದಿ defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_random_bytes_prngd(unsigned ವರ್ಣ *buf, ಪೂರ್ಣಾಙ್ಕ len,
    unsigned short tcp_port, ವರ್ಣ *socket_path)
{
	ಪೂರ್ಣಾಙ್ಕ fd, addr_len, rval, errors;
	u_char ಸಂದೇಶ[2];
	ಸಂರಚನಾ sockaddr_storage addr;
	ಸಂರಚನಾ sockaddr_in *addr_in = (ಸಂರಚನಾ sockaddr_in *)&addr;
	ಸಂರಚನಾ sockaddr_un *addr_un = (ಸಂರಚನಾ sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	ಯದಿ (socket_path == ರಿಕ್ತ && tcp_port == 0)
		fatal("You must specify a port or a socket");
	ಯದಿ (socket_path != ರಿಕ್ತ &&
	    strlen(socket_path) >= ಪರಿಮಾಣ(addr_un->sun_path))
		fatal("Random pool path is too long");
	ಯದಿ (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', ಪರಿಮಾಣ(addr));

	ಯದಿ (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = ಪರಿಮಾಣ(*addr_in);
	} ಅನ್ಯಥಾ {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    ಪರಿಮಾಣ(addr_un->sun_path));
		addr_len = offsetof(ಸಂರಚನಾ sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	ಯದಿ (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		ಗಚ್ಛ done;
	}

	ಯದಿ (connect(fd, (ಸಂರಚನಾ sockaddr*)&addr, addr_len) == -1) {
		ಯದಿ (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} ಅನ್ಯಥಾ {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		ಗಚ್ಛ done;
	}

	/* Send blocking read request to PRNGD */
	ಸಂದೇಶ[0] = 0x02;
	ಸಂದೇಶ[1] = len;

	ಯದಿ (atomicio(vwrite, fd, ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ)) != ಪರಿಮಾಣ(ಸಂದೇಶ)) {
		ಯದಿ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ಗಚ್ಛ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		ಗಚ್ಛ done;
	}

	ಯದಿ (atomicio(ಪಠ, fd, buf, len) != (size_t)len) {
		ಯದಿ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ಗಚ್ಛ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		ಗಚ್ಛ done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	ಯದಿ (fd != -1)
		close(fd);
	ಪ್ರತ್ಯಾಗಮ rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

ಪೂರ್ಣಾಙ್ಕ
seed_from_prngd(unsigned ವರ್ಣ *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	ಯದಿ (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, ರಿಕ್ತ) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	ಯದಿ (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
#endif
	ಪ್ರತ್ಯಾಗಮ -1;
}
