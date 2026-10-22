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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h> /* for offsetof */

#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ଯଦି defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_random_bytes_prngd(unsigned ଅକ୍ଷର *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା len,
    unsigned short tcp_port, ଅକ୍ଷର *socket_path)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, addr_len, rval, errors;
	u_char ସନ୍ଦେଶ[2];
	ସଂରଚନା sockaddr_storage addr;
	ସଂରଚନା sockaddr_in *addr_in = (ସଂରଚନା sockaddr_in *)&addr;
	ସଂରଚନା sockaddr_un *addr_un = (ସଂରଚନା sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	ଯଦି (socket_path == ଖାଲି && tcp_port == 0)
		fatal("You must specify a port or a socket");
	ଯଦି (socket_path != ଖାଲି &&
	    strlen(socket_path) >= ଆକାର(addr_un->sun_path))
		fatal("Random pool path is too long");
	ଯଦି (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', ଆକାର(addr));

	ଯଦି (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = ଆକାର(*addr_in);
	} ଅନ୍ୟଥା {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    ଆକାର(addr_un->sun_path));
		addr_len = offsetof(ସଂରଚନା sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	ଯଦି (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		ଯାଅ done;
	}

	ଯଦି (connect(fd, (ସଂରଚନା sockaddr*)&addr, addr_len) == -1) {
		ଯଦି (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} ଅନ୍ୟଥା {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		ଯାଅ done;
	}

	/* Send blocking read request to PRNGD */
	ସନ୍ଦେଶ[0] = 0x02;
	ସନ୍ଦେଶ[1] = len;

	ଯଦି (atomicio(vwrite, fd, ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ)) != ଆକାର(ସନ୍ଦେଶ)) {
		ଯଦି (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ଯାଅ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		ଯାଅ done;
	}

	ଯଦି (atomicio(ପଠ, fd, buf, len) != (size_t)len) {
		ଯଦି (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ଯାଅ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		ଯାଅ done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	ଯଦି (fd != -1)
		close(fd);
	ଫେରନ୍ତୁ rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
seed_from_prngd(unsigned ଅକ୍ଷର *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	ଯଦି (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, ଖାଲି) == 0)
		ଫେରନ୍ତୁ 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	ଯଦି (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		ଫେରନ୍ତୁ 0;
#endif
	ଫେରନ୍ତୁ -1;
}
