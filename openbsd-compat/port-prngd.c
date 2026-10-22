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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stddef.h> /* for offsetof */

#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "log.h"

#எனில் defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
நிலையான முழு
get_random_bytes_prngd(unsigned எழுத்து *buf, முழு len,
    unsigned short tcp_port, எழுத்து *socket_path)
{
	முழு fd, addr_len, rval, errors;
	u_char செய்தி[2];
	கட்டமைப்பு sockaddr_storage addr;
	கட்டமைப்பு sockaddr_in *addr_in = (கட்டமைப்பு sockaddr_in *)&addr;
	கட்டமைப்பு sockaddr_un *addr_un = (கட்டமைப்பு sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	எனில் (socket_path == வெற்று && tcp_port == 0)
		fatal("You must specify a port or a socket");
	எனில் (socket_path != வெற்று &&
	    strlen(socket_path) >= அளவு(addr_un->sun_path))
		fatal("Random pool path is too long");
	எனில் (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', அளவு(addr));

	எனில் (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = அளவு(*addr_in);
	} இல்லையெனில் {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    அளவு(addr_un->sun_path));
		addr_len = offsetof(கட்டமைப்பு sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	எனில் (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		செல் done;
	}

	எனில் (connect(fd, (கட்டமைப்பு sockaddr*)&addr, addr_len) == -1) {
		எனில் (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} இல்லையெனில் {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		செல் done;
	}

	/* Send blocking read request to PRNGD */
	செய்தி[0] = 0x02;
	செய்தி[1] = len;

	எனில் (atomicio(vwrite, fd, செய்தி, அளவு(செய்தி)) != அளவு(செய்தி)) {
		எனில் (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			செல் reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		செல் done;
	}

	எனில் (atomicio(பட, fd, buf, len) != (size_t)len) {
		எனில் (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			செல் reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		செல் done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	எனில் (fd != -1)
		close(fd);
	திரும்பு rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

முழு
seed_from_prngd(unsigned எழுத்து *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	எனில் (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, வெற்று) == 0)
		திரும்பு 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	எனில் (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		திரும்பு 0;
#endif
	திரும்பு -1;
}
