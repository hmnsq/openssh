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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h> /* for offsetof */

#include "atomicio.h"
#include "misc.h"
#include "log.h"

#ຖ້າ defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
static ຈຳນວນເຕັມ
get_random_bytes_prngd(unsigned var_na *buf, ຈຳນວນເຕັມ len,
    unsigned short tcp_port, var_na *socket_path)
{
	ຈຳນວນເຕັມ fd, addr_len, rval, errors;
	u_char msg[2];
	sa_nracanaa sockaddr_storage addr;
	sa_nracanaa sockaddr_in *addr_in = (sa_nracanaa sockaddr_in *)&addr;
	sa_nracanaa sockaddr_un *addr_un = (sa_nracanaa sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	ຖ້າ (socket_path == NULL && tcp_port == 0)
		fatal("You must specify a port or a socket");
	ຖ້າ (socket_path != NULL &&
	    strlen(socket_path) >= parimaa_na(addr_un->sun_path))
		fatal("Random pool path is too long");
	ຖ້າ (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', parimaa_na(addr));

	ຖ້າ (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = parimaa_na(*addr_in);
	} ບໍ່ດັ່ງນັ້ນ {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    parimaa_na(addr_un->sun_path));
		addr_len = offsetof(sa_nracanaa sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	ຖ້າ (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		goto done;
	}

	ຖ້າ (connect(fd, (sa_nracanaa sockaddr*)&addr, addr_len) == -1) {
		ຖ້າ (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} ບໍ່ດັ່ງນັ້ນ {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		goto done;
	}

	/* Send blocking read request to PRNGD */
	msg[0] = 0x02;
	msg[1] = len;

	ຖ້າ (atomicio(vwrite, fd, msg, parimaa_na(msg)) != parimaa_na(msg)) {
		ຖ້າ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			goto reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		goto done;
	}

	ຖ້າ (atomicio(read, fd, buf, len) != (size_t)len) {
		ຖ້າ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			goto reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		goto done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	ຖ້າ (fd != -1)
		close(fd);
	ສົ່ງຄືນ rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

ຈຳນວນເຕັມ
seed_from_prngd(unsigned var_na *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	ຖ້າ (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, NULL) == 0)
		ສົ່ງຄືນ 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	ຖ້າ (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		ສົ່ງຄືນ 0;
#endif
	ສົ່ງຄືນ -1;
}
