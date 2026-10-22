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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/un.h>

#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <arpa/inet.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <stddef.h> /* for offsetof */

#অন্তর্ভাৱ "atomicio.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "log.h"

#যদি defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
স্থির পূর্ণাঙ্ক
get_random_bytes_prngd(unsigned ৱর্ণ *buf, পূর্ণাঙ্ক len,
    unsigned short tcp_port, ৱর্ণ *socket_path)
{
	পূর্ণাঙ্ক fd, addr_len, rval, errors;
	u_char বাৰ্তা[2];
	সংরচনা sockaddr_storage addr;
	সংরচনা sockaddr_in *addr_in = (সংরচনা sockaddr_in *)&addr;
	সংরচনা sockaddr_un *addr_un = (সংরচনা sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	যদি (socket_path == রিক্ত && tcp_port == 0)
		fatal("You must specify a port or a socket");
	যদি (socket_path != রিক্ত &&
	    strlen(socket_path) >= পরিমাণ(addr_un->sun_path))
		fatal("Random pool path is too long");
	যদি (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', পরিমাণ(addr));

	যদি (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = পরিমাণ(*addr_in);
	} অন্যথা {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    পরিমাণ(addr_un->sun_path));
		addr_len = offsetof(সংরচনা sockaddr_un, sun_path) +
		    strlen(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	যদি (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		গচ্ছ done;
	}

	যদি (connect(fd, (সংরচনা sockaddr*)&addr, addr_len) == -1) {
		যদি (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, strerror(errno));
		} অন্যথা {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, strerror(errno));
		}
		গচ্ছ done;
	}

	/* Send blocking read request to PRNGD */
	বাৰ্তা[0] = 0x02;
	বাৰ্তা[1] = len;

	যদি (atomicio(vwrite, fd, বাৰ্তা, পরিমাণ(বাৰ্তা)) != পরিমাণ(বাৰ্তা)) {
		যদি (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			গচ্ছ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		গচ্ছ done;
	}

	যদি (atomicio(পঠ, fd, buf, len) != (size_t)len) {
		যদি (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			গচ্ছ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		গচ্ছ done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	যদি (fd != -1)
		close(fd);
	ঘূৰাই rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

পূর্ণাঙ্ক
seed_from_prngd(unsigned ৱর্ণ *buf, size_t bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	যদি (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, রিক্ত) == 0)
		ঘূৰাই 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	যদি (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		ঘূৰাই 0;
#endif
	ঘূৰাই -1;
}
