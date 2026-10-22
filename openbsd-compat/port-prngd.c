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

#𐡄𐡍 defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
get_random_bytes_prngd(unsigned حرف *buf, صحيح len,
    unsigned short tcp_port, حرف *socket_path)
{
	صحيح fd, addr_len, rval, errors;
	u_char msg[2];
	بنية sockaddr_storage addr;
	بنية sockaddr_in *addr_in = (بنية sockaddr_in *)&addr;
	بنية sockaddr_un *addr_un = (بنية sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	𐡄𐡍 (socket_path == عدم && tcp_port == 0)
		fatal("You must specify a port or a socket");
	𐡄𐡍 (socket_path != عدم &&
	    strlen(socket_path) >= حجم(addr_un->sun_path))
		fatal("Random pool path is too long");
	𐡄𐡍 (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', حجم(addr));

	𐡄𐡍 (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = حجم(*addr_in);
	} وإلا {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    حجم(addr_un->sun_path));
		addr_len = offsetof(بنية sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	𐡄𐡍 (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		اذهب done;
	}

	𐡄𐡍 (connect(fd, (بنية sockaddr*)&addr, addr_len) == -1) {
		𐡄𐡍 (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} وإلا {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		اذهب done;
	}

	/* Send blocking read request to PRNGD */
	msg[0] = 0x02;
	msg[1] = len;

	𐡄𐡍 (atomicio(vwrite, fd, msg, حجم(msg)) != حجم(msg)) {
		𐡄𐡍 (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			اذهب reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		اذهب done;
	}

	𐡄𐡍 (atomicio(اقرأ, fd, buf, len) != (size_t)len) {
		𐡄𐡍 (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			اذهب reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		اذهب done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	𐡄𐡍 (fd != -1)
		close(fd);
	أرجع rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

صحيح
seed_from_prngd(unsigned حرف *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	𐡄𐡍 (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, عدم) == 0)
		أرجع 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	𐡄𐡍 (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		أرجع 0;
#endif
	أرجع -1;
}
