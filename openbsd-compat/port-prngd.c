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

#اگر defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
ایستا صحیح
get_random_bytes_prngd(unsigned نویسه *buf, صحیح len,
    unsigned short tcp_port, نویسه *socket_path)
{
	صحیح fd, addr_len, rval, errors;
	u_char پیام[2];
	ساختار sockaddr_storage addr;
	ساختار sockaddr_in *addr_in = (ساختار sockaddr_in *)&addr;
	ساختار sockaddr_un *addr_un = (ساختار sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	اگر (socket_path == پوچ && tcp_port == 0)
		fatal("You must specify a port or a socket");
	اگر (socket_path != پوچ &&
	    strlen(socket_path) >= اندازه(addr_un->sun_path))
		fatal("Random pool path is too long");
	اگر (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', اندازه(addr));

	اگر (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = اندازه(*addr_in);
	} وگرنه {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    اندازه(addr_un->sun_path));
		addr_len = offsetof(ساختار sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	اگر (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		برو done;
	}

	اگر (connect(fd, (ساختار sockaddr*)&addr, addr_len) == -1) {
		اگر (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} وگرنه {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		برو done;
	}

	/* Send blocking read request to PRNGD */
	پیام[0] = 0x02;
	پیام[1] = len;

	اگر (atomicio(vwrite, fd, پیام, اندازه(پیام)) != اندازه(پیام)) {
		اگر (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			برو reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		برو done;
	}

	اگر (atomicio(اقرأ, fd, buf, len) != (size_t)len) {
		اگر (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			برو reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		برو done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	اگر (fd != -1)
		close(fd);
	بازگشت rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

صحیح
seed_from_prngd(unsigned نویسه *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	اگر (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, پوچ) == 0)
		بازگشت 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	اگر (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		بازگشت 0;
#endif
	بازگشت -1;
}
