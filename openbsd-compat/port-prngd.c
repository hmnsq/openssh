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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stddef.h> /* for offsetof */

#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "log.h"

#यदि defined(PRNGD_पत्तनम्) || defined(PRNGD_SOCKET)
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
स्थिर पूर्णाङ्क
get_random_अष्टकानि_prngd(अचिह्नित वर्ण *buf, पूर्णाङ्क len,
    अचिह्नित ह्रस्व tcp_पत्तनम्, वर्ण *socket_मार्गः)
{
	पूर्णाङ्क fd, addr_len, rval, errors;
	u_char सन्देशः[2];
	संरचना sockaddr_storage addr;
	संरचना sockaddr_in *addr_अन्तर् = (संरचना sockaddr_in *)&addr;
	संरचना sockaddr_un *addr_un = (संरचना sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	यदि (socket_मार्गः == रिक्त && tcp_पत्तनम् == 0)
		fatal("You must specify a port or a socket");
	यदि (socket_मार्गः != रिक्त &&
	    वाक्यदैर्घ्यम्(socket_मार्गः) >= परिमाण(addr_un->sun_मार्गः))
		fatal("Random pool path is too long");
	यदि (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	स्मृतिं_पूरय(&addr, '\0', परिमाण(addr));

	यदि (tcp_पत्तनम् != 0) {
		addr_अन्तर्->sin_family = AF_INET;
		addr_अन्तर्->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_अन्तर्->sin_port = htons(tcp_पत्तनम्);
		addr_len = परिमाण(*addr_अन्तर्);
	} अन्यथा {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_मार्गः, socket_मार्गः,
		    परिमाण(addr_un->sun_मार्गः));
		addr_len = offsetof(संरचना sockaddr_un, sun_मार्गः) +
		    वाक्यदैर्घ्यम्(socket_मार्गः) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	यदि (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		गच्छ समाप्तम्;
	}

	यदि (connect(fd, (संरचना sockaddr*)&addr, addr_len) == -1) {
		यदि (tcp_पत्तनम् != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_पत्तनम्, strerror(errno));
		} अन्यथा {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_मार्गः, strerror(errno));
		}
		गच्छ समाप्तम्;
	}

	/* Send blocking read request to PRNGD */
	सन्देशः[0] = 0x02;
	सन्देशः[1] = len;

	यदि (atomicio(vwrite, fd, सन्देशः, परिमाण(सन्देशः)) != परिमाण(सन्देशः)) {
		यदि (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			गच्छ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		गच्छ समाप्तम्;
	}

	यदि (atomicio(पठ, fd, buf, len) != (आकार_t)len) {
		यदि (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			गच्छ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		गच्छ समाप्तम्;
	}

	rval = 0;
समाप्तम्:
	ssh_signal(SIGPIPE, old_sigpipe);
	यदि (fd != -1)
		close(fd);
	प्रत्यागम rval;
}
#यदि_अन्तः /* PRNGD_PORT || PRNGD_SOCKET */

पूर्णाङ्क
बीजम्_from_prngd(अचिह्नित वर्ण *buf, आकार_t अष्टकानि)
{
#यदि_परिभाषितम् PRNGD_पत्तनम्
	debug("trying egd/prngd port %d", PRNGD_पत्तनम्);
	यदि (get_random_अष्टकानि_prngd(buf, अष्टकानि, PRNGD_पत्तनम्, रिक्त) == 0)
		प्रत्यागम 0;
#यदि_अन्तः
#यदि_परिभाषितम् PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	यदि (get_random_अष्टकानि_prngd(buf, अष्टकानि, 0, PRNGD_SOCKET) == 0)
		प्रत्यागम 0;
#यदि_अन्तः
	प्रत्यागम -1;
}
