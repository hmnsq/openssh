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

#ಆದರೆ defined(PRNGD_ಪೋರ್ಟ್) || defined(PRNGD_SOCKET)
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_random_ಬೈಟುಗಳು_prngd(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *buf, ಪೂರ್ಣಾಂಕ len,
    ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ tcp_ಪೋರ್ಟ್, ಅಕ್ಷರ *socket_ಮಾರ್ಗ)
{
	ಪೂರ್ಣಾಂಕ fd, addr_len, rval, errors;
	u_char ಸಂದೇಶ[2];
	ರಚನೆ sockaddr_storage addr;
	ರಚನೆ sockaddr_in *addr_ಒಳ = (ರಚನೆ sockaddr_in *)&addr;
	ರಚನೆ sockaddr_un *addr_un = (ರಚನೆ sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	ಆದರೆ (socket_ಮಾರ್ಗ == ಖಾಲಿ && tcp_ಪೋರ್ಟ್ == 0)
		fatal("You must specify a port or a socket");
	ಆದರೆ (socket_ಮಾರ್ಗ != ಖಾಲಿ &&
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(socket_ಮಾರ್ಗ) >= ಗಾತ್ರ(addr_un->sun_ಮಾರ್ಗ))
		fatal("Random pool path is too long");
	ಆದರೆ (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', ಗಾತ್ರ(addr));

	ಆದರೆ (tcp_ಪೋರ್ಟ್ != 0) {
		addr_ಒಳ->sin_family = AF_INET;
		addr_ಒಳ->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_ಒಳ->sin_port = htons(tcp_ಪೋರ್ಟ್);
		addr_len = ಗಾತ್ರ(*addr_ಒಳ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_ಮಾರ್ಗ, socket_ಮಾರ್ಗ,
		    ಗಾತ್ರ(addr_un->sun_ಮಾರ್ಗ));
		addr_len = offsetof(ರಚನೆ sockaddr_un, sun_ಮಾರ್ಗ) +
		    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(socket_ಮಾರ್ಗ) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	ಆದರೆ (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (connect(fd, (ರಚನೆ sockaddr*)&addr, addr_len) == -1) {
		ಆದರೆ (tcp_ಪೋರ್ಟ್ != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_ಪೋರ್ಟ್, strerror(errno));
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_ಮಾರ್ಗ, strerror(errno));
		}
		ಹೋಗು ಮುಗಿದ;
	}

	/* Send blocking read request to PRNGD */
	ಸಂದೇಶ[0] = 0x02;
	ಸಂದೇಶ[1] = len;

	ಆದರೆ (atomicio(vwrite, fd, ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ)) != ಗಾತ್ರ(ಸಂದೇಶ)) {
		ಆದರೆ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ಹೋಗು reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (atomicio(ಪಠ, fd, buf, len) != (ಗಾತ್ರ_t)len) {
		ಆದರೆ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			ಹೋಗು reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		ಹೋಗು ಮುಗಿದ;
	}

	rval = 0;
ಮುಗಿದ:
	ssh_signal(SIGPIPE, old_sigpipe);
	ಆದರೆ (fd != -1)
		close(fd);
	ಹಿಂತಿರುಗಿ rval;
}
#ಆದರೆ_ಅಂತ್ಯ /* PRNGD_PORT || PRNGD_SOCKET */

ಪೂರ್ಣಾಂಕ
ಬೀಜ_from_prngd(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *buf, ಗಾತ್ರ_t ಬೈಟುಗಳು)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRNGD_ಪೋರ್ಟ್
	debug("trying egd/prngd port %d", PRNGD_ಪೋರ್ಟ್);
	ಆದರೆ (get_random_ಬೈಟುಗಳು_prngd(buf, ಬೈಟುಗಳು, PRNGD_ಪೋರ್ಟ್, ಖಾಲಿ) == 0)
		ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	ಆದರೆ (get_random_ಬೈಟುಗಳು_prngd(buf, ಬೈಟುಗಳು, 0, PRNGD_SOCKET) == 0)
		ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ -1;
}
