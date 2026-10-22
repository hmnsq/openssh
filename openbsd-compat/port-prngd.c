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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stddef.h> /* for offsetof */

#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "log.h"

#ఒకవేళ defined(PRNGD_పోర్టు) || defined(PRNGD_SOCKET)
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
స్థిర పూర్ణాంకం
get_random_బైట్లు_prngd(గుర్తులేని అక్షరం *buf, పూర్ణాంకం len,
    గుర్తులేని పొట్టి tcp_పోర్టు, అక్షరం *socket_మార్గం)
{
	పూర్ణాంకం fd, addr_len, rval, errors;
	u_char సందేశం[2];
	నిర్మాణం sockaddr_storage addr;
	నిర్మాణం sockaddr_in *addr_లోపల = (నిర్మాణం sockaddr_in *)&addr;
	నిర్మాణం sockaddr_un *addr_un = (నిర్మాణం sockaddr_un *)&addr;
	sshsig_t old_sigpipe;

	/* Sanity checks */
	ఒకవేళ (socket_మార్గం == ఖాళీ && tcp_పోర్టు == 0)
		fatal("You must specify a port or a socket");
	ఒకవేళ (socket_మార్గం != ఖాళీ &&
	    అక్షరశ్రేణి_పొడవు(socket_మార్గం) >= పరిమాణం(addr_un->sun_మార్గం))
		fatal("Random pool path is too long");
	ఒకవేళ (len <= 0 || len > 255)
		fatal("Too many bytes (%d) to read from PRNGD", len);

	memset(&addr, '\0', పరిమాణం(addr));

	ఒకవేళ (tcp_పోర్టు != 0) {
		addr_లోపల->sin_family = AF_INET;
		addr_లోపల->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_లోపల->sin_port = htons(tcp_పోర్టు);
		addr_len = పరిమాణం(*addr_లోపల);
	} లేకపోతే {
		addr_un->sun_family = AF_UNIX;
		strlcpy(addr_un->sun_మార్గం, socket_మార్గం,
		    పరిమాణం(addr_un->sun_మార్గం));
		addr_len = offsetof(నిర్మాణం sockaddr_un, sun_మార్గం) +
		    అక్షరశ్రేణి_పొడవు(socket_మార్గం) + 1;
	}

	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);

	errors = 0;
	rval = -1;
reopen:
	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	ఒకవేళ (fd == -1) {
		error("Couldn't create socket: %s", strerror(errno));
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (connect(fd, (నిర్మాణం sockaddr*)&addr, addr_len) == -1) {
		ఒకవేళ (tcp_పోర్టు != 0) {
			error("Couldn't connect to PRNGD port %d: %s",
			    tcp_పోర్టు, strerror(errno));
		} లేకపోతే {
			error("Couldn't connect to PRNGD socket \"%s\": %s",
			    addr_un->sun_మార్గం, strerror(errno));
		}
		వెళ్ళు పూర్తి;
	}

	/* Send blocking read request to PRNGD */
	సందేశం[0] = 0x02;
	సందేశం[1] = len;

	ఒకవేళ (atomicio(vwrite, fd, సందేశం, పరిమాణం(సందేశం)) != పరిమాణం(సందేశం)) {
		ఒకవేళ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			వెళ్ళు reopen;
		}
		error("Couldn't write to PRNGD socket: %s",
		    strerror(errno));
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (atomicio(పఠ, fd, buf, len) != (కొలత_t)len) {
		ఒకవేళ (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			వెళ్ళు reopen;
		}
		error("Couldn't read from PRNGD socket: %s",
		    strerror(errno));
		వెళ్ళు పూర్తి;
	}

	rval = 0;
పూర్తి:
	ssh_signal(SIGPIPE, old_sigpipe);
	ఒకవేళ (fd != -1)
		close(fd);
	తిరిగి rval;
}
#అయితే_ముగింపు /* PRNGD_PORT || PRNGD_SOCKET */

పూర్ణాంకం
విత్తనం_from_prngd(గుర్తులేని అక్షరం *buf, కొలత_t బైట్లు)
{
#నిర్వచితమైతే PRNGD_పోర్టు
	debug("trying egd/prngd port %d", PRNGD_పోర్టు);
	ఒకవేళ (get_random_బైట్లు_prngd(buf, బైట్లు, PRNGD_పోర్టు, ఖాళీ) == 0)
		తిరిగి 0;
#అయితే_ముగింపు
#నిర్వచితమైతే PRNGD_SOCKET
	debug("trying egd/prngd socket %s", PRNGD_SOCKET);
	ఒకవేళ (get_random_బైట్లు_prngd(buf, బైట్లు, 0, PRNGD_SOCKET) == 0)
		తిరిగి 0;
#అయితే_ముగింపు
	తిరిగి -1;
}
