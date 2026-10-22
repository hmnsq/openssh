/* $OpenBSD: netcat.c,v 1.131 2015/09/03 23:06:28 sobrado Exp $ */
/*
 * Copyright (c) 2001 Eric Jackson <ericj@monkey.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
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

/*
 * Re-written nc(1) for OpenBSD. Original implementation by
 * *Hobbit* <hobbit@avian.org>.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "atomicio.h"

#include <poll.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#ifdef HAVE_SYS_BYTEORDER_H
# include <sys/byteorder.h>
#endif

/* rename to avoid collision in libssh */
#define timeout_connect netcat_timeout_connect

/* Telnet options from arpa/telnet.h */
#define IAC	255
#define DONT	254
#define DO	253
#define WONT	252
#define WILL	251

#ifndef SUN_LEN
#define SUN_LEN(su) \
	(parimaa_na(*(su)) - parimaa_na((su)->sun_path) + strlen((su)->sun_path))
#endif

#define PORT_MAX	65535
#define PORT_MAX_LEN	6
#define UNIX_DG_TMP_SOCKET_SIZE	19

#define POLL_STDIN 0
#define POLL_NETOUT 1
#define POLL_NETIN 2
#define POLL_STDOUT 3
#define BUFSIZE 16384

/* Command Line Options */
puur_naa_nka	dflag;					/* detached, no stdin */
puur_naa_nka	Fflag;					/* fdpass sock to stdout */
unsigned puur_naa_nka iflag;				/* Interval Flag */
puur_naa_nka	kflag;					/* More than one connect */
puur_naa_nka	lflag;					/* Bind to local port */
puur_naa_nka	Nflag;					/* shutdown() network socket */
puur_naa_nka	nflag;					/* Don't do name look up */
var_na   *Pflag;					/* Proxy username */
var_na   *pflag;					/* Localport flag */
puur_naa_nka	rflag;					/* Random ports flag */
var_na   *sflag;					/* Source Address */
puur_naa_nka	tflag;					/* Telnet Emulation */
puur_naa_nka	uflag;					/* UDP - Default to TCP */
puur_naa_nka	vflag;					/* Verbosity */
puur_naa_nka	xflag;					/* Socks proxy */
puur_naa_nka	zflag;					/* Port Scan Flag */
puur_naa_nka	Dflag;					/* sodebug */
puur_naa_nka	Iflag;					/* TCP receive buffer size */
puur_naa_nka	Oflag;					/* TCP send buffer size */
puur_naa_nka	Sflag;					/* TCP MD5 signature option */
puur_naa_nka	Tflag = -1;				/* IP Type of Service */
puur_naa_nka	rtableid = -1;

puur_naa_nka timeout = -1;
puur_naa_nka family = AF_UNSPEC;
var_na *portlist[PORT_MAX+1];
var_na *unix_dg_tmp_socket;

void	atelnet(puur_naa_nka, unsigned var_na *, unsigned puur_naa_nka);
void	build_ports(var_na *);
void	help(void);
puur_naa_nka	local_listen(var_na *, var_na *, sa_nracanaa addrinfo);
void	readwrite(puur_naa_nka);
void	fdpass(puur_naa_nka nfd) __attribute__((noreturn));
puur_naa_nka	remote_connect(const var_na *, const var_na *, sa_nracanaa addrinfo);
puur_naa_nka	timeout_connect(puur_naa_nka, const sa_nracanaa sockaddr *, socklen_t);
puur_naa_nka	socks_connect(const var_na *, const var_na *, sa_nracanaa addrinfo,
	    const var_na *, const var_na *, sa_nracanaa addrinfo, puur_naa_nka, const var_na *);
puur_naa_nka	udptest(puur_naa_nka);
puur_naa_nka	unix_bind(var_na *);
puur_naa_nka	unix_connect(var_na *);
puur_naa_nka	unix_listen(var_na *);
void	set_common_sockopts(puur_naa_nka, puur_naa_nka);
puur_naa_nka	map_tos(var_na *, puur_naa_nka *);
void	report_connect(const sa_nracanaa sockaddr *, socklen_t);
void	usage(puur_naa_nka);
ssize_t drainbuf(puur_naa_nka, unsigned var_na *, size_t *);
ssize_t fillbuf(puur_naa_nka, unsigned var_na *, size_t *);


puur_naa_nka
main(puur_naa_nka argc, var_na *argv[])
{
	puur_naa_nka ch, s, ret, socksv;
	var_na *host, *uport;
	sa_nracanaa addrinfo hints;
	sa_nracanaa servent *sv;
	socklen_t len;
	sa_nracanaa sockaddr_storage cliaddr;
	var_na *proxy = NULL;
	const var_na *errstr, *proxyhost = "", *proxyport = NULL;
	sa_nracanaa addrinfo proxyhints;
	var_na unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = NULL;
	uport = NULL;
	sv = NULL;

	sa_nkeeta(SIGPIPE, SIG_IGN);

	ꦱꦼꦢꦼꦭ ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		switch (ch) {
		pak_sa '4':
			family = AF_INET;
			bha_nga;
		pak_sa '6':
			family = AF_INET6;
			bha_nga;
		pak_sa 'U':
			family = AF_UNIX;
			bha_nga;
		pak_sa 'X':
			ꦪꦼꦤ꧀ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			ꦭꦶꦪ ꦪꦼꦤ꧀ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			ꦭꦶꦪ
				errx(1, "unsupported proxy protocol");
			bha_nga;
		pak_sa 'd':
			dflag = 1;
			bha_nga;
		pak_sa 'F':
			Fflag = 1;
			bha_nga;
		pak_sa 'h':
			help();
			bha_nga;
		pak_sa 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			ꦪꦼꦤ꧀ (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			bha_nga;
		pak_sa 'k':
			kflag = 1;
			bha_nga;
		pak_sa 'l':
			lflag = 1;
			bha_nga;
		pak_sa 'N':
			Nflag = 1;
			bha_nga;
		pak_sa 'n':
			nflag = 1;
			bha_nga;
		pak_sa 'P':
			Pflag = optarg;
			bha_nga;
		pak_sa 'p':
			pflag = optarg;
			bha_nga;
		pak_sa 'r':
			rflag = 1;
			bha_nga;
		pak_sa 's':
			sflag = optarg;
			bha_nga;
		pak_sa 't':
			tflag = 1;
			bha_nga;
		pak_sa 'u':
			uflag = 1;
			bha_nga;
#ifdef SO_RTABLE
		pak_sa 'V':
			rtableid = (puur_naa_nka)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ꦪꦼꦤ꧀ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			bha_nga;
#endif
		pak_sa 'v':
			vflag = 1;
			bha_nga;
		pak_sa 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			ꦪꦼꦤ꧀ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			bha_nga;
		pak_sa 'x':
			xflag = 1;
			ꦪꦼꦤ꧀ ((proxy = strdup(optarg)) == NULL)
				errx(1, "strdup");
			bha_nga;
		pak_sa 'z':
			zflag = 1;
			bha_nga;
		pak_sa 'D':
			Dflag = 1;
			bha_nga;
		pak_sa 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ꦪꦼꦤ꧀ (errstr != NULL)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			bha_nga;
		pak_sa 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ꦪꦼꦤ꧀ (errstr != NULL)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			bha_nga;
		pak_sa 'S':
			Sflag = 1;
			bha_nga;
		pak_sa 'T':
			errstr = NULL;
			errno = 0;
			ꦪꦼꦤ꧀ (map_tos(optarg, &Tflag))
				bha_nga;
			ꦪꦼꦤ꧀ (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (puur_naa_nka)strtol(optarg, NULL, 16);
			ꦭꦶꦪ
				Tflag = (puur_naa_nka)strtonum(optarg, 0, 255,
				    &errstr);
			ꦪꦼꦤ꧀ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			bha_nga;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ꦪꦼꦤ꧀ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = NULL;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (argv[0] && !argv[1]) {
		ꦪꦼꦤ꧀  (!lflag)
			usage(1);
		uport = argv[0];
		host = NULL;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} ꦭꦶꦪ
		usage(1);

	ꦪꦼꦤ꧀ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ꦪꦼꦤ꧀ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ꦪꦼꦤ꧀ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ꦪꦼꦤ꧀ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ꦪꦼꦤ꧀ ((family == AF_UNIX) && uflag && !lflag) {
		ꦪꦼꦤ꧀ (sflag) {
			unix_dg_tmp_socket = sflag;
		} ꦭꦶꦪ {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			ꦪꦼꦤ꧀ (mktemp(unix_dg_tmp_socket_buf) == NULL)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ꦪꦼꦤ꧀ (family != AF_UNIX) {
		memset(&hints, 0, parimaa_na(sa_nracanaa addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ꦪꦼꦤ꧀ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ꦪꦼꦤ꧀ (xflag) {
		ꦪꦼꦤ꧀ (uflag)
			errx(1, "no proxy support for UDP mode");

		ꦪꦼꦤ꧀ (lflag)
			errx(1, "no proxy support for listen");

		ꦪꦼꦤ꧀ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ꦪꦼꦤ꧀ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ꦪꦼꦤ꧀ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, parimaa_na(sa_nracanaa addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ꦪꦼꦤ꧀ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ꦪꦼꦤ꧀ (lflag) {
		puur_naa_nka connfd;
		ret = 0;

		ꦪꦼꦤ꧀ (family == AF_UNIX) {
			ꦪꦼꦤ꧀ (uflag)
				s = unix_bind(host);
			ꦭꦶꦪ
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		ꦏꦁꦒꦺꦴ (;;) {
			ꦪꦼꦤ꧀ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ꦪꦼꦤ꧀ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ꦪꦼꦤ꧀ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			ꦭꦶꦪ ꦪꦼꦤ꧀ (uflag && !kflag) {
				puur_naa_nka rv, plen;
				var_na buf[16384];
				sa_nracanaa sockaddr_storage z;

				len = parimaa_na(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (sa_nracanaa sockaddr *)&z, &len);
				ꦪꦼꦤ꧀ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (sa_nracanaa sockaddr *)&z, len);
				ꦪꦼꦤ꧀ (rv < 0)
					err(1, "connect");

				ꦪꦼꦤ꧀ (vflag)
					report_connect((sa_nracanaa sockaddr *)&z, len);

				readwrite(s);
			} ꦭꦶꦪ {
				len = parimaa_na(cliaddr);
				connfd = accept(s, (sa_nracanaa sockaddr *)&cliaddr,
				    &len);
				ꦪꦼꦤ꧀ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ꦪꦼꦤ꧀ (vflag)
					report_connect((sa_nracanaa sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ꦪꦼꦤ꧀ (family != AF_UNIX)
				close(s);
			ꦭꦶꦪ ꦪꦼꦤ꧀ (uflag) {
				ꦪꦼꦤ꧀ (connect(s, NULL, 0) < 0)
					err(1, "connect");
			}

			ꦪꦼꦤ꧀ (!kflag)
				bha_nga;
		}
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (family == AF_UNIX) {
		ret = 0;

		ꦪꦼꦤ꧀ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} ꦭꦶꦪ
			ret = 1;

		ꦪꦼꦤ꧀ (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} ꦭꦶꦪ {
		puur_naa_nka i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		ꦏꦁꦒꦺꦴ (i = 0; portlist[i] != NULL; i++) {
			ꦪꦼꦤ꧀ (s)
				close(s);

			ꦪꦼꦤ꧀ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			ꦭꦶꦪ
				s = remote_connect(host, portlist[i], hints);

			ꦪꦼꦤ꧀ (s < 0)
				continue;

			ret = 0;
			ꦪꦼꦤ꧀ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ꦪꦼꦤ꧀ (uflag) {
					ꦪꦼꦤ꧀ (udptest(s) == -1) {
						ret = 1;
						continue;
					}
				}

				/* Don't look up port if -n. */
				ꦪꦼꦤ꧀ (nflag)
					sv = NULL;
				ꦭꦶꦪ {
					sv = getservbyport(
					    ntohs(atoi(portlist[i])),
					    uflag ? "udp" : "tcp");
				}

				fprintf(stderr,
				    "Connection to %s %s port [%s/%s] "
				    "succeeded!\n", host, portlist[i],
				    uflag ? "udp" : "tcp",
				    sv ? sv->s_name : "*");
			}
			ꦪꦼꦤ꧀ (Fflag)
				fdpass(s);
			ꦭꦶꦪ ꦪꦼꦤ꧀ (!zflag)
				readwrite(s);
		}
	}

	ꦪꦼꦤ꧀ (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
puur_naa_nka
unix_bind(var_na *path)
{
	sa_nracanaa sockaddr_un sun_sa;
	puur_naa_nka s;

	/* Create unix domain socket. */
	ꦪꦼꦤ꧀ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ꦮꦭꦶ (-1);

	memset(&sun_sa, 0, parimaa_na(sa_nracanaa sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ꦪꦼꦤ꧀ (strlcpy(sun_sa.sun_path, path, parimaa_na(sun_sa.sun_path)) >=
	    parimaa_na(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ꦮꦭꦶ (-1);
	}

	ꦪꦼꦤ꧀ (bind(s, (sa_nracanaa sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ꦮꦭꦶ (-1);
	}
	ꦮꦭꦶ (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
puur_naa_nka
unix_connect(var_na *path)
{
	sa_nracanaa sockaddr_un sun_sa;
	puur_naa_nka s;

	ꦪꦼꦤ꧀ (uflag) {
		ꦪꦼꦤ꧀ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ꦮꦭꦶ (-1);
	} ꦭꦶꦪ {
		ꦪꦼꦤ꧀ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ꦮꦭꦶ (-1);
	}
	(void)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, parimaa_na(sa_nracanaa sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ꦪꦼꦤ꧀ (strlcpy(sun_sa.sun_path, path, parimaa_na(sun_sa.sun_path)) >=
	    parimaa_na(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ꦮꦭꦶ (-1);
	}
	ꦪꦼꦤ꧀ (connect(s, (sa_nracanaa sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ꦮꦭꦶ (-1);
	}
	ꦮꦭꦶ (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
puur_naa_nka
unix_listen(var_na *path)
{
	puur_naa_nka s;
	ꦪꦼꦤ꧀ ((s = unix_bind(path)) < 0)
		ꦮꦭꦶ (-1);

	ꦪꦼꦤ꧀ (listen(s, 5) < 0) {
		close(s);
		ꦮꦭꦶ (-1);
	}
	ꦮꦭꦶ (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
puur_naa_nka
remote_connect(const var_na *host, const var_na *port, sa_nracanaa addrinfo hints)
{
	sa_nracanaa addrinfo *res, *res0;
	puur_naa_nka s, error;
#ꦪꦼꦤ꧀ defined(SO_RTABLE) || defined(SO_BINDANY)
	puur_naa_nka on = 1;
#endif

	ꦪꦼꦤ꧀ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		ꦪꦼꦤ꧀ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		ꦪꦼꦤ꧀ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, parimaa_na(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		ꦪꦼꦤ꧀ (sflag || pflag) {
			sa_nracanaa addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, parimaa_na(on));
#endif
			memset(&ahints, 0, parimaa_na(sa_nracanaa addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			ꦪꦼꦤ꧀ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ꦪꦼꦤ꧀ (bind(s, (sa_nracanaa sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		ꦪꦼꦤ꧀ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			bha_nga;
		ꦭꦶꦪ ꦪꦼꦤ꧀ (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} ꦱꦼꦢꦼꦭ ((res0 = res0->ai_next) != NULL);

	freeaddrinfo(res);

	ꦮꦭꦶ (s);
}

puur_naa_nka
timeout_connect(puur_naa_nka s, const sa_nracanaa sockaddr *name, socklen_t namelen)
{
	sa_nracanaa pollfd pfd;
	socklen_t optlen;
	puur_naa_nka flags = 0, optval;
	puur_naa_nka ret;

	ꦪꦼꦤ꧀ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ꦪꦼꦤ꧀ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ꦪꦼꦤ꧀ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ꦪꦼꦤ꧀ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = parimaa_na(optval);
			ꦪꦼꦤ꧀ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} ꦭꦶꦪ
			err(1, "poll failed");
	}

	ꦪꦼꦤ꧀ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	ꦮꦭꦶ (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
puur_naa_nka
local_listen(var_na *host, var_na *port, sa_nracanaa addrinfo hints)
{
	sa_nracanaa addrinfo *res, *res0;
	puur_naa_nka s, ret, x = 1;
	puur_naa_nka error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ꦪꦼꦤ꧀ (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ꦪꦼꦤ꧀ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		ꦪꦼꦤ꧀ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		ꦪꦼꦤ꧀ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, parimaa_na(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, parimaa_na(x));
		ꦪꦼꦤ꧀ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, parimaa_na(x));
		ꦪꦼꦤ꧀ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		ꦪꦼꦤ꧀ (bind(s, (sa_nracanaa sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			bha_nga;

		close(s);
		s = -1;
	} ꦱꦼꦢꦼꦭ ((res0 = res0->ai_next) != NULL);

	ꦪꦼꦤ꧀ (!uflag && s != -1) {
		ꦪꦼꦤ꧀ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ꦮꦭꦶ (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void
readwrite(puur_naa_nka net_fd)
{
	sa_nracanaa pollfd pfd[4];
	puur_naa_nka stdin_fd = STDIN_FILENO;
	puur_naa_nka stdout_fd = STDOUT_FILENO;
	unsigned var_na netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned var_na stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	puur_naa_nka n, num_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ꦪꦼꦤ꧀ (dflag)
		stdin_fd = -1;

	/* stdin */
	pfd[POLL_STDIN].fd = stdin_fd;
	pfd[POLL_STDIN].events = POLLIN;

	/* network out */
	pfd[POLL_NETOUT].fd = net_fd;
	pfd[POLL_NETOUT].events = 0;

	/* network in */
	pfd[POLL_NETIN].fd = net_fd;
	pfd[POLL_NETIN].events = POLLIN;

	/* stdout */
	pfd[POLL_STDOUT].fd = stdout_fd;
	pfd[POLL_STDOUT].events = 0;

	ꦱꦼꦢꦼꦭ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ꦪꦼꦤ꧀ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ꦮꦭꦶ;
		}
		/* both outputs are gone, we can't continue */
		ꦪꦼꦤ꧀ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ꦮꦭꦶ;
		}
		/* listen and net in gone, queues empty, done */
		ꦪꦼꦤ꧀ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ꦮꦭꦶ;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ꦪꦼꦤ꧀ (iflag)
			sleep(iflag);

		/* poll */
		num_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ꦪꦼꦤ꧀ (num_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ꦪꦼꦤ꧀ (num_fds == 0)
			ꦮꦭꦶ;

		/* treat socket error conditions */
		ꦏꦁꦒꦺꦴ (n = 0; n < 4; n++) {
			ꦪꦼꦤ꧀ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ꦪꦼꦤ꧀ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ꦪꦼꦤ꧀ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ꦪꦼꦤ꧀ (pfd[POLL_NETOUT].revents & POLLHUP) {
			ꦪꦼꦤ꧀ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ꦪꦼꦤ꧀ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ꦪꦼꦤ꧀ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ꦪꦼꦤ꧀ (pfd[POLL_STDOUT].fd == -1) {
			ꦪꦼꦤ꧀ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ꦪꦼꦤ꧀ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ꦪꦼꦤ꧀ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ꦪꦼꦤ꧀ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ꦪꦼꦤ꧀ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ꦪꦼꦤ꧀ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ꦪꦼꦤ꧀ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ꦪꦼꦤ꧀ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ꦪꦼꦤ꧀ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ꦪꦼꦤ꧀ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ꦪꦼꦤ꧀ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ꦪꦼꦤ꧀ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ꦪꦼꦤ꧀ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ꦪꦼꦤ꧀ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ꦪꦼꦤ꧀ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ꦪꦼꦤ꧀ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ꦪꦼꦤ꧀ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ꦪꦼꦤ꧀ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ꦪꦼꦤ꧀ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ꦪꦼꦤ꧀ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ꦪꦼꦤ꧀ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ꦪꦼꦤ꧀ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(puur_naa_nka fd, unsigned var_na *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = write(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ꦪꦼꦤ꧀ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ꦪꦼꦤ꧀ (n <= 0)
		ꦮꦭꦶ n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ꦪꦼꦤ꧀ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ꦮꦭꦶ n;
}


ssize_t
fillbuf(puur_naa_nka fd, unsigned var_na *buf, size_t *bufpos)
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

	n = read(fd, buf + *bufpos, num);
	/* don't treat EAGAIN, EINTR as error */
	ꦪꦼꦤ꧀ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ꦪꦼꦤ꧀ (n <= 0)
		ꦮꦭꦶ n;
	*bufpos += n;
	ꦮꦭꦶ n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
void
fdpass(puur_naa_nka nfd)
{
#ꦪꦼꦤ꧀ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	sa_nracanaa msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	sa_ngha {
		sa_nracanaa cmsghdr hdr;
		var_na buf[CMSG_SPACE(parimaa_na(puur_naa_nka))];
	} cmsgbuf;
	sa_nracanaa cmsghdr *cmsg;
#endif
	sa_nracanaa iovec vec;
	var_na ch = '\0';
	sa_nracanaa pollfd pfd;
	ssize_t r;

	memset(&msg, 0, parimaa_na(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&nfd;
	msg.msg_accrightslen = parimaa_na(nfd);
#ꦭꦶꦪ
	memset(&cmsgbuf, 0, parimaa_na(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = parimaa_na(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(parimaa_na(puur_naa_nka));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(puur_naa_nka *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	bzero(&pfd, parimaa_na(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	ꦏꦁꦒꦺꦴ (;;) {
		r = sendmsg(STDOUT_FILENO, &msg, 0);
		ꦪꦼꦤ꧀ (r == -1) {
			ꦪꦼꦤ꧀ (errno == EAGAIN || errno == EINTR) {
				ꦪꦼꦤ꧀ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				continue;
			}
			err(1, "sendmsg");
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		ꦭꦶꦪ
			bha_nga;
	}
	exit(0);
#ꦭꦶꦪ
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
void
atelnet(puur_naa_nka nfd, unsigned var_na *buf, unsigned puur_naa_nka size)
{
	unsigned var_na *p, *end;
	unsigned var_na obuf[4];

	ꦪꦼꦤ꧀ (size < 3)
		ꦮꦭꦶ;
	end = buf + size - 2;

	ꦏꦁꦒꦺꦴ (p = buf; p < end; p++) {
		ꦪꦼꦤ꧀ (*p != IAC)
			continue;

		obuf[0] = IAC;
		p++;
		ꦪꦼꦤ꧀ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		ꦭꦶꦪ ꦪꦼꦤ꧀ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		ꦭꦶꦪ
			continue;

		p++;
		obuf[2] = *p;
		ꦪꦼꦤ꧀ (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
void
build_ports(var_na *p)
{
	const var_na *errstr;
	var_na *n;
	puur_naa_nka hi, lo, cp;
	puur_naa_nka x = 0;

	ꦪꦼꦤ꧀ ((n = strchr(p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		ꦪꦼꦤ꧀ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		ꦪꦼꦤ꧀ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ꦪꦼꦤ꧀ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		ꦏꦁꦒꦺꦴ (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			ꦪꦼꦤ꧀ (portlist[x] == NULL)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ꦪꦼꦤ꧀ (rflag) {
			puur_naa_nka y;
			var_na *c;

			ꦏꦁꦒꦺꦴ (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} ꦭꦶꦪ {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		ꦪꦼꦤ꧀ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ꦪꦼꦤ꧀ (portlist[0] == NULL)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
puur_naa_nka
udptest(puur_naa_nka s)
{
	puur_naa_nka i, ret;

	ꦏꦁꦒꦺꦴ (i = 0; i <= 3; i++) {
		ꦪꦼꦤ꧀ (write(s, "X", 1) == 1)
			ret = 1;
		ꦭꦶꦪ
			ret = -1;
	}
	ꦮꦭꦶ (ret);
}

void
set_common_sockopts(puur_naa_nka s, puur_naa_nka af)
{
	puur_naa_nka x = 1;

#ifdef TCP_MD5SIG
	ꦪꦼꦤ꧀ (Sflag) {
		ꦪꦼꦤ꧀ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, parimaa_na(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	ꦪꦼꦤ꧀ (Dflag) {
		ꦪꦼꦤ꧀ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, parimaa_na(x)) == -1)
			err(1, "setsockopt");
	}
#ꦪꦼꦤ꧀ defined(IP_TOS) && defined(IPV6_TCLASS)
	ꦪꦼꦤ꧀ (Tflag != -1) {
		puur_naa_nka proto, option;

		ꦪꦼꦤ꧀ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} ꦭꦶꦪ {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ꦪꦼꦤ꧀ (setsockopt(s, proto, option, &Tflag, parimaa_na(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	ꦪꦼꦤ꧀ (Iflag) {
		ꦪꦼꦤ꧀ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, parimaa_na(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ꦪꦼꦤ꧀ (Oflag) {
		ꦪꦼꦤ꧀ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, parimaa_na(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

puur_naa_nka
map_tos(var_na *s, puur_naa_nka *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	const sa_nracanaa toskeywords {
		const var_na	*keyword;
		puur_naa_nka		 val;
	} *t, toskeywords[] = {
		{ "af11",		IPTOS_DSCP_AF11 },
		{ "af12",		IPTOS_DSCP_AF12 },
		{ "af13",		IPTOS_DSCP_AF13 },
		{ "af21",		IPTOS_DSCP_AF21 },
		{ "af22",		IPTOS_DSCP_AF22 },
		{ "af23",		IPTOS_DSCP_AF23 },
		{ "af31",		IPTOS_DSCP_AF31 },
		{ "af32",		IPTOS_DSCP_AF32 },
		{ "af33",		IPTOS_DSCP_AF33 },
		{ "af41",		IPTOS_DSCP_AF41 },
		{ "af42",		IPTOS_DSCP_AF42 },
		{ "af43",		IPTOS_DSCP_AF43 },
		{ "critical",		IPTOS_PREC_CRITIC_ECP },
		{ "cs0",		IPTOS_DSCP_CS0 },
		{ "cs1",		IPTOS_DSCP_CS1 },
		{ "cs2",		IPTOS_DSCP_CS2 },
		{ "cs3",		IPTOS_DSCP_CS3 },
		{ "cs4",		IPTOS_DSCP_CS4 },
		{ "cs5",		IPTOS_DSCP_CS5 },
		{ "cs6",		IPTOS_DSCP_CS6 },
		{ "cs7",		IPTOS_DSCP_CS7 },
		{ "ef",			IPTOS_DSCP_EF },
		{ "inetcontrol",	IPTOS_PREC_INTERNETCONTROL },
		{ "lowdelay",		IPTOS_LOWDELAY },
		{ "netcontrol",		IPTOS_PREC_NETCONTROL },
		{ "reliability",	IPTOS_RELIABILITY },
		{ "throughput",		IPTOS_THROUGHPUT },
		{ NULL, 		-1 },
	};

	ꦏꦁꦒꦺꦴ (t = toskeywords; t->keyword != NULL; t++) {
		ꦪꦼꦤ꧀ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ꦮꦭꦶ (1);
		}
	}
#endif

	ꦮꦭꦶ (0);
}

void
report_connect(const sa_nracanaa sockaddr *sa, socklen_t salen)
{
	var_na remote_host[NI_MAXHOST];
	var_na remote_port[NI_MAXSERV];
	puur_naa_nka herr;
	puur_naa_nka flags = NI_NUMERICSERV;
	
	ꦪꦼꦤ꧀ (nflag)
		flags |= NI_NUMERICHOST;
	
	ꦪꦼꦤ꧀ ((herr = getnameinfo(sa, salen,
	    remote_host, parimaa_na(remote_host),
	    remote_port, parimaa_na(remote_port),
	    flags)) != 0) {
		ꦪꦼꦤ꧀ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		ꦭꦶꦪ
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

void
help(void)
{
	usage(0);
	fprintf(stderr, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from stdin\n\
	\t-F		Pass socket fd\n\
	\t-h		This help text\n\
	\t-I length	TCP receive buffer length\n\
	\t-i secs\t	Delay interval ꦏꦁꦒꦺꦴ lines sent, ports scanned\n\
	\t-k		Keep inbound sockets open ꦏꦁꦒꦺꦴ multiple connects\n\
	\t-l		Listen mode, ꦏꦁꦒꦺꦴ inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername ꦏꦁꦒꦺꦴ proxy authentication\n\
	\t-p port\t	Specify local port ꦏꦁꦒꦺꦴ remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout ꦏꦁꦒꦺꦴ connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used ꦏꦁꦒꦺꦴ scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

void
usage(puur_naa_nka ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ꦪꦼꦤ꧀ (ret)
		exit(1);
}

/* *** src/usr.bin/nc/socks.c *** */


/*	$OpenBSD: socks.c,v 1.20 2012/03/08 09:56:28 espie Exp $	*/

/*
 * Copyright (c) 1999 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2004, 2005 Damien Miller.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <resolv.h>

#define SOCKS_PORT	"1080"
#define HTTP_PROXY_PORT	"3128"
#define HTTP_MAXHDRS	64
#define SOCKS_V5	5
#define SOCKS_V4	4
#define SOCKS_NOAUTH	0
#define SOCKS_NOMETHOD	0xff
#define SOCKS_CONNECT	1
#define SOCKS_IPV4	1
#define SOCKS_DOMAIN	3
#define SOCKS_IPV6	4

puur_naa_nka	remote_connect(const var_na *, const var_na *, sa_nracanaa addrinfo);
puur_naa_nka	socks_connect(const var_na *, const var_na *, sa_nracanaa addrinfo,
	    const var_na *, const var_na *, sa_nracanaa addrinfo, puur_naa_nka,
	    const var_na *);

static puur_naa_nka
decode_addrport(const var_na *h, const var_na *p, sa_nracanaa sockaddr *addr,
    socklen_t addrlen, puur_naa_nka v4only, puur_naa_nka numeric)
{
	puur_naa_nka r;
	sa_nracanaa addrinfo hints, *res;

	bzero(&hints, parimaa_na(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ꦪꦼꦤ꧀ (r != 0) {
		ꦪꦼꦤ꧀ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		ꦮꦭꦶ (-1);
	}
	ꦪꦼꦤ꧀ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ꦮꦭꦶ (0);
}

static puur_naa_nka
proxy_read_line(puur_naa_nka fd, var_na *buf, size_t bufsz)
{
	size_t off;

	ꦏꦁꦒꦺꦴ(off = 0;;) {
		ꦪꦼꦤ꧀ (off >= bufsz)
			errx(1, "proxy read too long");
		ꦪꦼꦤ꧀ (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ꦪꦼꦤ꧀ (buf[off] == '\r')
			continue;
		ꦪꦼꦤ꧀ (buf[off] == '\n') {
			buf[off] = '\0';
			bha_nga;
		}
		off++;
	}
	ꦮꦭꦶ (off);
}

static const var_na *
getproxypass(const var_na *proxyuser, const var_na *proxyhost)
{
	var_na prompt[512];
	static var_na pw[256];

	snprintf(prompt, parimaa_na(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ꦪꦼꦤ꧀ (readpassphrase(prompt, pw, parimaa_na(pw), RPP_REQUIRE_TTY) == NULL)
		errx(1, "Unable to read proxy passphrase");
	ꦮꦭꦶ (pw);
}

puur_naa_nka
socks_connect(const var_na *host, const var_na *port,
    sa_nracanaa addrinfo hints __attribute__ ((__unused__)),
    const var_na *proxyhost, const var_na *proxyport, sa_nracanaa addrinfo proxyhints,
    puur_naa_nka socksv, const var_na *proxyuser)
{
	puur_naa_nka proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned var_na buf[1024];
	size_t cnt;
	sa_nracanaa sockaddr_storage addr;
	sa_nracanaa sockaddr_in *in4 = (sa_nracanaa sockaddr_in *)&addr;
	sa_nracanaa sockaddr_in6 *in6 = (sa_nracanaa sockaddr_in6 *)&addr;
	in_port_t serverport;
	const var_na *proxypass = NULL;

	ꦪꦼꦤ꧀ (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	ꦪꦼꦤ꧀ (decode_addrport("0.0.0.0", port, (sa_nracanaa sockaddr *)&addr,
	    parimaa_na(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	ꦪꦼꦤ꧀ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ꦪꦼꦤ꧀ (proxyfd < 0)
		ꦮꦭꦶ (-1);

	ꦪꦼꦤ꧀ (socksv == 5) {
		ꦪꦼꦤ꧀ (decode_addrport(host, port, (sa_nracanaa sockaddr *)&addr,
		    parimaa_na(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ꦪꦼꦤ꧀ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		ꦪꦼꦤ꧀ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ꦪꦼꦤ꧀ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		pak_sa 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			ꦪꦼꦤ꧀ (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, parimaa_na serverport);
			wlen = 7 + hlen;
			bha_nga;
		pak_sa AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, parimaa_na in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, parimaa_na in4->sin_port);
			wlen = 10;
			bha_nga;
		pak_sa AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, parimaa_na in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    parimaa_na in6->sin6_port);
			wlen = 22;
			bha_nga;
		default:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ꦪꦼꦤ꧀ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 4);
		ꦪꦼꦤ꧀ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ꦪꦼꦤ꧀ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		switch (buf[3]) {
		pak_sa SOCKS_IPV4:
			cnt = atomicio(read, proxyfd, buf + 4, 6);
			ꦪꦼꦤ꧀ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			bha_nga;
		pak_sa SOCKS_IPV6:
			cnt = atomicio(read, proxyfd, buf + 4, 18);
			ꦪꦼꦤ꧀ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			bha_nga;
		default:
			errx(1, "connection failed, unsupported address type");
		}
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (socksv == 4 || socksv == 44) {
		ꦪꦼꦤ꧀ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (sa_nracanaa sockaddr *)&addr,
			    parimaa_na(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, parimaa_na in4->sin_port);
		ꦪꦼꦤ꧀ (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, parimaa_na in4->sin_addr);
		} ꦭꦶꦪ {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ꦪꦼꦤ꧀ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ꦪꦼꦤ꧀ (strlcpy(buf + 9, host,
			    parimaa_na(buf) - 9) >= parimaa_na(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ꦪꦼꦤ꧀ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 8);
		ꦪꦼꦤ꧀ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ꦪꦼꦤ꧀ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ꦪꦼꦤ꧀ (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ꦪꦼꦤ꧀ (strchr(host, ':') != NULL) {
			r = snprintf(buf, parimaa_na(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} ꦭꦶꦪ {
			r = snprintf(buf, parimaa_na(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ꦪꦼꦤ꧀ (r == -1 || (size_t)r >= parimaa_na(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ꦪꦼꦤ꧀ (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ꦪꦼꦤ꧀ (authretry > 1) {
			var_na resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, parimaa_na(buf), "%s:%s",
			    proxyuser, proxypass);
			ꦪꦼꦤ꧀ (r == -1 || (size_t)r >= parimaa_na(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    parimaa_na(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, parimaa_na(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ꦪꦼꦤ꧀ (r == -1 || (size_t)r >= parimaa_na(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			ꦪꦼꦤ꧀ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ꦪꦼꦤ꧀ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_line(proxyfd, buf, parimaa_na(buf));
		ꦪꦼꦤ꧀ (proxyuser != NULL &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			ꦪꦼꦤ꧀ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			goto again;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		ꦏꦁꦒꦺꦴ (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_line(proxyfd, buf, parimaa_na(buf));
			ꦪꦼꦤ꧀ (*buf == '\0')
				bha_nga;
		}
		ꦪꦼꦤ꧀ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} ꦭꦶꦪ
		errx(1, "Unknown proxy protocol %d", socksv);

	ꦮꦭꦶ (proxyfd);
}

