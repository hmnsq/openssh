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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/un.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <signal.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <stddef.h> /* for offsetof */

#समावेश "atomicio.h"
#समावेश "misc.h"
#समावेश "log.h"

#अगर defined(PRNGD_PORT) || defined(PRNGD_SOCKET)
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
अटल पूर्णांक
get_random_bytes_prngd(अचिन्हित अक्षर *buf, पूर्णांक len,
    अचिन्हित लघु tcp_port, अक्षर *socket_path)
{
	पूर्णांक fd, addr_len, rval, errors;
	u_char संदेश[2];
	काष्ठा sockaddr_storage addr;
	काष्ठा sockaddr_in *addr_in = (काष्ठा sockaddr_in *)&addr;
	काष्ठा sockaddr_un *addr_un = (काष्ठा sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	अगर (socket_path == शून्य && tcp_port == 0)
		fatal("You must specify a port or a socket");
	अगर (socket_path != शून्य &&
	    म_माप(socket_path) >= माप(addr_un->sun_path))
		fatal("Random pool path is too long");
	अगर (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	स_रखो(&addr, '\0', माप(addr));

	अगर (tcp_port != 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_in->sin_port = htons(tcp_port);
		addr_len = माप(*addr_in);
	} अन्यथा {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_path, socket_path,
		    माप(addr_un->sun_path));
		addr_len = दुरत्व(काष्ठा sockaddr_un, sun_path) +
		    म_माप(socket_path) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, संक_छोड़ो);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	अगर (fd == -1) {
		error("Couldn't create socket: %s", म_त्रुटि(त्रुटि_सं));
		जाओ done;
	}

	अगर (connect(fd, (काष्ठा sockaddr*)&addr, addr_len) == -1) {
		अगर (tcp_port != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_port, म_त्रुटि(त्रुटि_सं));
		} अन्यथा {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_path, म_त्रुटि(त्रुटि_सं));
		}
		जाओ done;
	}

	/* Send blocking read request to PRNGD */
	संदेश[0] = 0x02;
	संदेश[1] = len;

	अगर (atomicio(vwrite, fd, संदेश, माप(संदेश)) != माप(संदेश)) {
		अगर (त्रुटि_सं == EPIPE && errors < 10) {
			बंद(fd);
			errors++;
			जाओ reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    म_त्रुटि(त्रुटि_सं));
		जाओ done;
	}

	अगर (atomicio(पढ़ो, fd, buf, len) != (माप_प्रकार)len) {
		अगर (त्रुटि_सं == EPIPE && errors < 10) {
			बंद(fd);
			errors++;
			जाओ reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    म_त्रुटि(त्रुटि_सं));
		जाओ done;
	}

	rval = 0;
done:
	ssh_signal(SIGPIPE, old_sigpipe);
	अगर (fd != -1)
		बंद(fd);
	वापस rval;
}
#पूर्ण_अगर /* PRNGD_PORT || PRNGD_SOCKET */

पूर्णांक
seed_from_prngd(अचिन्हित अक्षर *buf, माप_प्रकार bytes)
{
#अगर_घोषित PRNGD_PORT
	debug("trying egd/prngd port %d", PRNGD_PORT);
	अगर (get_random_bytes_prngd(buf, bytes, PRNGD_PORT, शून्य) == 0)
		वापस 0;
#पूर्ण_अगर
#अगर_घोषित PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	अगर (get_random_bytes_prngd(buf, bytes, 0, PRNGD_SOCKET) == 0)
		वापस 0;
#पूर्ण_अगर
	वापस -1;
}
