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

#यदि defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
get_random_bytes_prngd(अचिन्हित वर्ण *buf, पूर्णाङ्क len,
    अचिन्हित लघु tcp_port, वर्ण *socket_path)
{
	पूर्णाङ्क fd, addr_len, rval, errors;
	u_char सन्देश[2];
	संरचना sockaddr_storage addr;
	संरचना sockaddr_in *addr_in = (संरचना sockaddr_in *)&addr;
	संरचना sockaddr_un *addr_un = (संरचना sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	यदि (socket_path == रिक्त && tcp_port == 0)
		fatal("You must specify a port or a socket");
	यदि (socket_path != रिक्त &&
	    म_माप(socket_path) >= परिमाण(addr_un->sun_path))
		fatal("Random pool path is too long");
	यदि (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	स_रखो(&addr, '\0', परिमाण(addr));

	यदि (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = परिमाण(*addr_in);
	} अन्यथा {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    परिमाण(addr_un->sun_path));
		addr_len = दुरत्व(संरचना sockaddr_un, sun_path) +
		    म_माप(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, संक_छोड़ो);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	यदि (fd == -1) {
		error("Couldn't create socket: %s", म_त्रुटि(त्रुटि_सं));
		गच्छ done;
	}

	यदि (connect(fd, (संरचना sockaddr*)&addr, addr_len) == -1) {
		यदि (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, म_त्रुटि(त्रुटि_सं));
		} अन्यथा {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, म_त्रुटि(त्रुटि_सं));
		}
		गच्छ done;
	}

	/* Send blocking read request to PRNGD */
	सन्देश[0] = 0x02;
	सन्देश[1] = len;

	यदि (atomicio(vwrite, fd, सन्देश, परिमाण(सन्देश)) != परिमाण(सन्देश)) {
		यदि (त्रुटि_सं == EPIPE && errors < 10) {
			बंद(fd);
			errors++;
			गच्छ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    म_त्रुटि(त्रुटि_सं));
		गच्छ done;
	}

	यदि (atomicio(पठ, fd, buf, len) != (माप_प्रकार)len) {
		यदि (त्रुटि_सं == EPIPE && errors < 10) {
			बंद(fd);
			errors++;
			गच्छ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    म_त्रुटि(त्रुटि_सं));
		गच्छ done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	यदि (fd != -1)
		बंद(fd);
	फर्काऊ rval;
}
#endif /* PRNGD_PORT || PRNGD_SOCKET */

पूर्णाङ्क
seed_from_prngd(अचिन्हित वर्ण *buf, माप_प्रकार bytes)
{
#ifdef PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	यदि (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, रिक्त) == 0)
		फर्काऊ 0;
#endif
#ifdef PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	यदि (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		फर्काऊ 0;
#endif
	फर्काऊ -1;
}
