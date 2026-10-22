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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/uio.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/tcp.h>
#अन्तर्भाव <netinet/ip.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव "atomicio.h"

#अन्तर्भाव <poll.h>
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
	(परिमाण(*(su)) - परिमाण((su)->sun_path) + strlen((su)->sun_path))
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
पूर्णाङ्क	dflag;					/* detached, no stdin */
पूर्णाङ्क	Fflag;					/* fdpass sock to stdout */
unsigned पूर्णाङ्क iflag;				/* Interval Flag */
पूर्णाङ्क	kflag;					/* More than one connect */
पूर्णाङ्क	lflag;					/* Bind to local port */
पूर्णाङ्क	Nflag;					/* shutdown() network socket */
पूर्णाङ्क	nflag;					/* Don't do name look up */
वर्ण   *Pflag;					/* Proxy username */
वर्ण   *pflag;					/* Localport flag */
पूर्णाङ्क	rflag;					/* Random ports flag */
वर्ण   *sflag;					/* Source Address */
पूर्णाङ्क	tflag;					/* Telnet Emulation */
पूर्णाङ्क	uflag;					/* UDP - Default to TCP */
पूर्णाङ्क	vflag;					/* Verbosity */
पूर्णाङ्क	xflag;					/* Socks proxy */
पूर्णाङ्क	zflag;					/* Port Scan Flag */
पूर्णाङ्क	Dflag;					/* sodebug */
पूर्णाङ्क	Iflag;					/* TCP receive buffer size */
पूर्णाङ्क	Oflag;					/* TCP send buffer size */
पूर्णाङ्क	Sflag;					/* TCP MD5 signature option */
पूर्णाङ्क	Tflag = -1;				/* IP Type of Service */
पूर्णाङ्क	rtableid = -1;

पूर्णाङ्क timeout = -1;
पूर्णाङ्क family = AF_UNSPEC;
वर्ण *portlist[PORT_MAX+1];
वर्ण *unix_dg_tmp_socket;

शून्य	atelnet(पूर्णाङ्क, unsigned वर्ण *, unsigned पूर्णाङ्क);
शून्य	build_ports(वर्ण *);
शून्य	help(शून्य);
पूर्णाङ्क	local_listen(वर्ण *, वर्ण *, संरचना addrinfo);
शून्य	readwrite(पूर्णाङ्क);
शून्य	fdpass(पूर्णाङ्क nfd) __attribute__((noreturn));
पूर्णाङ्क	remote_connect(ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना addrinfo);
पूर्णाङ्क	timeout_connect(पूर्णाङ्क, ध्रुव संरचना sockaddr *, socklen_t);
पूर्णाङ्क	socks_connect(ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना addrinfo,
	    ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना addrinfo, पूर्णाङ्क, ध्रुव वर्ण *);
पूर्णाङ्क	udptest(पूर्णाङ्क);
पूर्णाङ्क	unix_bind(वर्ण *);
पूर्णाङ्क	unix_connect(वर्ण *);
पूर्णाङ्क	unix_listen(वर्ण *);
शून्य	set_common_sockopts(पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	map_tos(वर्ण *, पूर्णाङ्क *);
शून्य	report_connect(ध्रुव संरचना sockaddr *, socklen_t);
शून्य	usage(पूर्णाङ्क);
ssize_t drainbuf(पूर्णाङ्क, unsigned वर्ण *, size_t *);
ssize_t fillbuf(पूर्णाङ्क, unsigned वर्ण *, size_t *);


पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण *argv[])
{
	पूर्णाङ्क ch, s, ret, socksv;
	वर्ण *host, *uport;
	संरचना addrinfo hints;
	संरचना servent *sv;
	socklen_t len;
	संरचना sockaddr_storage cliaddr;
	वर्ण *proxy = रिक्त;
	ध्रुव वर्ण *errstr, *proxyhost = "", *proxyport = रिक्त;
	संरचना addrinfo proxyhints;
	वर्ण unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = रिक्त;
	uport = रिक्त;
	sv = रिक्त;

	सङ्केत(SIGPIPE, SIG_IGN);

	यावत् ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		विकल्प (ch) {
		पक्ष '4':
			family = AF_INET;
			भङ्ग;
		पक्ष '6':
			family = AF_INET6;
			भङ्ग;
		पक्ष 'U':
			family = AF_UNIX;
			भङ्ग;
		पक्ष 'X':
			यदि (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			अन्यथा यदि (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			अन्यथा यदि (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			अन्यथा यदि (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			अन्यथा
				errx(1, "unsupported proxy protocol");
			भङ्ग;
		पक्ष 'd':
			dflag = 1;
			भङ्ग;
		पक्ष 'F':
			Fflag = 1;
			भङ्ग;
		पक्ष 'h':
			help();
			भङ्ग;
		पक्ष 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			यदि (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			भङ्ग;
		पक्ष 'k':
			kflag = 1;
			भङ्ग;
		पक्ष 'l':
			lflag = 1;
			भङ्ग;
		पक्ष 'N':
			Nflag = 1;
			भङ्ग;
		पक्ष 'n':
			nflag = 1;
			भङ्ग;
		पक्ष 'P':
			Pflag = optarg;
			भङ्ग;
		पक्ष 'p':
			pflag = optarg;
			भङ्ग;
		पक्ष 'r':
			rflag = 1;
			भङ्ग;
		पक्ष 's':
			sflag = optarg;
			भङ्ग;
		पक्ष 't':
			tflag = 1;
			भङ्ग;
		पक्ष 'u':
			uflag = 1;
			भङ्ग;
#ifdef SO_RTABLE
		पक्ष 'V':
			rtableid = (पूर्णाङ्क)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			यदि (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			भङ्ग;
#endif
		पक्ष 'v':
			vflag = 1;
			भङ्ग;
		पक्ष 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			यदि (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			भङ्ग;
		पक्ष 'x':
			xflag = 1;
			यदि ((proxy = strdup(optarg)) == रिक्त)
				errx(1, "strdup");
			भङ्ग;
		पक्ष 'z':
			zflag = 1;
			भङ्ग;
		पक्ष 'D':
			Dflag = 1;
			भङ्ग;
		पक्ष 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			यदि (errstr != रिक्त)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			भङ्ग;
		पक्ष 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			यदि (errstr != रिक्त)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			भङ्ग;
		पक्ष 'S':
			Sflag = 1;
			भङ्ग;
		पक्ष 'T':
			errstr = रिक्त;
			errno = 0;
			यदि (map_tos(optarg, &Tflag))
				भङ्ग;
			यदि (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (पूर्णाङ्क)strtol(optarg, रिक्त, 16);
			अन्यथा
				Tflag = (पूर्णाङ्क)strtonum(optarg, 0, 255,
				    &errstr);
			यदि (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			भङ्ग;
		स्वभाव:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	यदि (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = रिक्त;
	} अन्यथा यदि (argv[0] && !argv[1]) {
		यदि  (!lflag)
			usage(1);
		uport = argv[0];
		host = रिक्त;
	} अन्यथा यदि (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} अन्यथा
		usage(1);

	यदि (lflag && sflag)
		errx(1, "cannot use -s and -l");
	यदि (lflag && pflag)
		errx(1, "cannot use -p and -l");
	यदि (lflag && zflag)
		errx(1, "cannot use -z and -l");
	यदि (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	यदि ((family == AF_UNIX) && uflag && !lflag) {
		यदि (sflag) {
			unix_dg_tmp_socket = sflag;
		} अन्यथा {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			यदि (mktemp(unix_dg_tmp_socket_buf) == रिक्त)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	यदि (family != AF_UNIX) {
		memset(&hints, 0, परिमाण(संरचना addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		यदि (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	यदि (xflag) {
		यदि (uflag)
			errx(1, "no proxy support for UDP mode");

		यदि (lflag)
			errx(1, "no proxy support for listen");

		यदि (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		यदि (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		यदि (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, परिमाण(संरचना addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		यदि (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	यदि (lflag) {
		पूर्णाङ्क connfd;
		ret = 0;

		यदि (family == AF_UNIX) {
			यदि (uflag)
				s = unix_bind(host);
			अन्यथा
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		प्रति (;;) {
			यदि (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			यदि (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			यदि (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			अन्यथा यदि (uflag && !kflag) {
				पूर्णाङ्क rv, plen;
				वर्ण buf[16384];
				संरचना sockaddr_storage z;

				len = परिमाण(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (संरचना sockaddr *)&z, &len);
				यदि (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (संरचना sockaddr *)&z, len);
				यदि (rv < 0)
					err(1, "connect");

				यदि (vflag)
					report_connect((संरचना sockaddr *)&z, len);

				readwrite(s);
			} अन्यथा {
				len = परिमाण(cliaddr);
				connfd = accept(s, (संरचना sockaddr *)&cliaddr,
				    &len);
				यदि (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				यदि (vflag)
					report_connect((संरचना sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			यदि (family != AF_UNIX)
				close(s);
			अन्यथा यदि (uflag) {
				यदि (connect(s, रिक्त, 0) < 0)
					err(1, "connect");
			}

			यदि (!kflag)
				भङ्ग;
		}
	} अन्यथा यदि (family == AF_UNIX) {
		ret = 0;

		यदि ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} अन्यथा
			ret = 1;

		यदि (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} अन्यथा {
		पूर्णाङ्क i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		प्रति (i = 0; portlist[i] != रिक्त; i++) {
			यदि (s)
				close(s);

			यदि (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			अन्यथा
				s = remote_connect(host, portlist[i], hints);

			यदि (s < 0)
				अनुवर्त;

			ret = 0;
			यदि (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				यदि (uflag) {
					यदि (udptest(s) == -1) {
						ret = 1;
						अनुवर्त;
					}
				}

				/* Don't look up port if -n. */
				यदि (nflag)
					sv = रिक्त;
				अन्यथा {
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
			यदि (Fflag)
				fdpass(s);
			अन्यथा यदि (!zflag)
				readwrite(s);
		}
	}

	यदि (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
पूर्णाङ्क
unix_bind(वर्ण *path)
{
	संरचना sockaddr_un sun_sa;
	पूर्णाङ्क s;

	/* Create unix domain socket. */
	यदि ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		प्रत्यागम (-1);

	memset(&sun_sa, 0, परिमाण(संरचना sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	यदि (strlcpy(sun_sa.sun_path, path, परिमाण(sun_sa.sun_path)) >=
	    परिमाण(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		प्रत्यागम (-1);
	}

	यदि (bind(s, (संरचना sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		प्रत्यागम (-1);
	}
	प्रत्यागम (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
पूर्णाङ्क
unix_connect(वर्ण *path)
{
	संरचना sockaddr_un sun_sa;
	पूर्णाङ्क s;

	यदि (uflag) {
		यदि ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			प्रत्यागम (-1);
	} अन्यथा {
		यदि ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			प्रत्यागम (-1);
	}
	(शून्य)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, परिमाण(संरचना sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	यदि (strlcpy(sun_sa.sun_path, path, परिमाण(sun_sa.sun_path)) >=
	    परिमाण(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		प्रत्यागम (-1);
	}
	यदि (connect(s, (संरचना sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		प्रत्यागम (-1);
	}
	प्रत्यागम (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
पूर्णाङ्क
unix_listen(वर्ण *path)
{
	पूर्णाङ्क s;
	यदि ((s = unix_bind(path)) < 0)
		प्रत्यागम (-1);

	यदि (listen(s, 5) < 0) {
		close(s);
		प्रत्यागम (-1);
	}
	प्रत्यागम (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
पूर्णाङ्क
remote_connect(ध्रुव वर्ण *host, ध्रुव वर्ण *port, संरचना addrinfo hints)
{
	संरचना addrinfo *res, *res0;
	पूर्णाङ्क s, error;
#यदि defined(SO_RTABLE) || defined(SO_BINDANY)
	पूर्णाङ्क on = 1;
#endif

	यदि ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	कुरु {
		यदि ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			अनुवर्त;

#ifdef SO_RTABLE
		यदि (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, परिमाण(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		यदि (sflag || pflag) {
			संरचना addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, परिमाण(on));
#endif
			memset(&ahints, 0, परिमाण(संरचना addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			यदि ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			यदि (bind(s, (संरचना sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		यदि (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			भङ्ग;
		अन्यथा यदि (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} यावत् ((res0 = res0->ai_next) != रिक्त);

	freeaddrinfo(res);

	प्रत्यागम (s);
}

पूर्णाङ्क
timeout_connect(पूर्णाङ्क s, ध्रुव संरचना sockaddr *name, socklen_t namelen)
{
	संरचना pollfd pfd;
	socklen_t optlen;
	पूर्णाङ्क flags = 0, optval;
	पूर्णाङ्क ret;

	यदि (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		यदि (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	यदि ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		यदि ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = परिमाण(optval);
			यदि ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} अन्यथा यदि (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} अन्यथा
			err(1, "poll failed");
	}

	यदि (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	प्रत्यागम (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
पूर्णाङ्क
local_listen(वर्ण *host, वर्ण *port, संरचना addrinfo hints)
{
	संरचना addrinfo *res, *res0;
	पूर्णाङ्क s, ret, x = 1;
	पूर्णाङ्क error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	यदि (host == रिक्त && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	यदि ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	कुरु {
		यदि ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			अनुवर्त;

#ifdef SO_RTABLE
		यदि (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, परिमाण(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, परिमाण(x));
		यदि (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, परिमाण(x));
		यदि (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		यदि (bind(s, (संरचना sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			भङ्ग;

		close(s);
		s = -1;
	} यावत् ((res0 = res0->ai_next) != रिक्त);

	यदि (!uflag && s != -1) {
		यदि (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	प्रत्यागम (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
शून्य
readwrite(पूर्णाङ्क net_fd)
{
	संरचना pollfd pfd[4];
	पूर्णाङ्क stdin_fd = STDIN_FILENO;
	पूर्णाङ्क stdout_fd = STDOUT_FILENO;
	unsigned वर्ण netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned वर्ण stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	पूर्णाङ्क n, अंक_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	यदि (dflag)
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

	यावत् (1) {
		/* both inputs are gone, buffers are empty, we are done */
		यदि (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			प्रत्यागम;
		}
		/* both outputs are gone, we can't continue */
		यदि (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			प्रत्यागम;
		}
		/* listen and net in gone, queues empty, done */
		यदि (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			प्रत्यागम;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		यदि (iflag)
			sleep(iflag);

		/* poll */
		अंक_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		यदि (अंक_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		यदि (अंक_fds == 0)
			प्रत्यागम;

		/* treat socket error conditions */
		प्रति (n = 0; n < 4; n++) {
			यदि (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		यदि (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		यदि (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		यदि (pfd[POLL_NETOUT].revents & POLLHUP) {
			यदि (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		यदि (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		यदि (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		यदि (pfd[POLL_STDOUT].fd == -1) {
			यदि (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		यदि (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			यदि (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			यदि (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			यदि (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		यदि (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			यदि (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			यदि (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			यदि (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		यदि (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			यदि (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			यदि (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			यदि (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			यदि (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			यदि (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		यदि (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			यदि (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			यदि (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			यदि (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		यदि (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			यदि (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		यदि (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(पूर्णाङ्क fd, unsigned वर्ण *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = लिख(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	यदि (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	यदि (n <= 0)
		प्रत्यागम n;
	/* adjust buffer */
	adjust = *bufpos - n;
	यदि (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	प्रत्यागम n;
}


ssize_t
fillbuf(पूर्णाङ्क fd, unsigned वर्ण *buf, size_t *bufpos)
{
	size_t अंक = BUFSIZE - *bufpos;
	ssize_t n;

	n = पठ(fd, buf + *bufpos, अंक);
	/* don't treat EAGAIN, EINTR as error */
	यदि (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	यदि (n <= 0)
		प्रत्यागम n;
	*bufpos += n;
	प्रत्यागम n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
शून्य
fdpass(पूर्णाङ्क nfd)
{
#यदि defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	संरचना msghdr संदेश;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	सङ्घ {
		संरचना cmsghdr hdr;
		वर्ण buf[CMSG_SPACE(परिमाण(पूर्णाङ्क))];
	} cmsgbuf;
	संरचना cmsghdr *cmsg;
#endif
	संरचना iovec vec;
	वर्ण ch = '\0';
	संरचना pollfd pfd;
	ssize_t r;

	memset(&संदेश, 0, परिमाण(संदेश));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	संदेश.संदेश_accrights = (caddr_t)&nfd;
	संदेश.संदेश_accrightslen = परिमाण(nfd);
#अन्यथा
	memset(&cmsgbuf, 0, परिमाण(cmsgbuf));
	संदेश.msg_control = (caddr_t)&cmsgbuf.buf;
	संदेश.msg_controllen = परिमाण(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&संदेश);
	cmsg->cmsg_len = CMSG_LEN(परिमाण(पूर्णाङ्क));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(पूर्णाङ्क *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	संदेश.msg_iov = &vec;
	संदेश.msg_iovlen = 1;

	bzero(&pfd, परिमाण(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	प्रति (;;) {
		r = sendmsg(STDOUT_FILENO, &संदेश, 0);
		यदि (r == -1) {
			यदि (errno == EAGAIN || errno == EINTR) {
				यदि (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				अनुवर्त;
			}
			err(1, "sendmsg");
		} अन्यथा यदि (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		अन्यथा
			भङ्ग;
	}
	exit(0);
#अन्यथा
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
शून्य
atelnet(पूर्णाङ्क nfd, unsigned वर्ण *buf, unsigned पूर्णाङ्क size)
{
	unsigned वर्ण *p, *end;
	unsigned वर्ण obuf[4];

	यदि (size < 3)
		प्रत्यागम;
	end = buf + size - 2;

	प्रति (p = buf; p < end; p++) {
		यदि (*p != IAC)
			अनुवर्त;

		obuf[0] = IAC;
		p++;
		यदि ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		अन्यथा यदि ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		अन्यथा
			अनुवर्त;

		p++;
		obuf[2] = *p;
		यदि (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
शून्य
build_ports(वर्ण *p)
{
	ध्रुव वर्ण *errstr;
	वर्ण *n;
	पूर्णाङ्क hi, lo, cp;
	पूर्णाङ्क x = 0;

	यदि ((n = strchr(p, '-')) != रिक्त) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		यदि (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		यदि (errstr)
			errx(1, "port number %s: %s", errstr, p);

		यदि (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		प्रति (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			यदि (portlist[x] == रिक्त)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		यदि (rflag) {
			पूर्णाङ्क y;
			वर्ण *c;

			प्रति (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} अन्यथा {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		यदि (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		यदि (portlist[0] == रिक्त)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
पूर्णाङ्क
udptest(पूर्णाङ्क s)
{
	पूर्णाङ्क i, ret;

	प्रति (i = 0; i <= 3; i++) {
		यदि (लिख(s, "X", 1) == 1)
			ret = 1;
		अन्यथा
			ret = -1;
	}
	प्रत्यागम (ret);
}

शून्य
set_common_sockopts(पूर्णाङ्क s, पूर्णाङ्क af)
{
	पूर्णाङ्क x = 1;

#ifdef TCP_MD5SIG
	यदि (Sflag) {
		यदि (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, परिमाण(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	यदि (Dflag) {
		यदि (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, परिमाण(x)) == -1)
			err(1, "setsockopt");
	}
#यदि defined(IP_TOS) && defined(IPV6_TCLASS)
	यदि (Tflag != -1) {
		पूर्णाङ्क proto, option;

		यदि (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} अन्यथा {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		यदि (setsockopt(s, proto, option, &Tflag, परिमाण(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	यदि (Iflag) {
		यदि (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, परिमाण(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	यदि (Oflag) {
		यदि (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, परिमाण(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

पूर्णाङ्क
map_tos(वर्ण *s, पूर्णाङ्क *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ध्रुव संरचना toskeywords {
		ध्रुव वर्ण	*keyword;
		पूर्णाङ्क		 val;
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
		{ रिक्त, 		-1 },
	};

	प्रति (t = toskeywords; t->keyword != रिक्त; t++) {
		यदि (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			प्रत्यागम (1);
		}
	}
#endif

	प्रत्यागम (0);
}

शून्य
report_connect(ध्रुव संरचना sockaddr *sa, socklen_t salen)
{
	वर्ण remote_host[NI_MAXHOST];
	वर्ण remote_port[NI_MAXSERV];
	पूर्णाङ्क herr;
	पूर्णाङ्क flags = NI_NUMERICSERV;
	
	यदि (nflag)
		flags |= NI_NUMERICHOST;
	
	यदि ((herr = getnameinfo(sa, salen,
	    remote_host, परिमाण(remote_host),
	    remote_port, परिमाण(remote_port),
	    flags)) != 0) {
		यदि (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		अन्यथा
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

शून्य
help(शून्य)
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
	\t-i secs\t	Delay interval प्रति ओळी sent, ports scanned\n\
	\t-k		Keep inbound sockets open प्रति multiple connects\n\
	\t-l		Listen mode, प्रति inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername प्रति proxy authentication\n\
	\t-p port\t	Specify local port प्रति remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout प्रति connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used प्रति scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

शून्य
usage(पूर्णाङ्क ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	यदि (ret)
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

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <resolv.h>

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

पूर्णाङ्क	remote_connect(ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना addrinfo);
पूर्णाङ्क	socks_connect(ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना addrinfo,
	    ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना addrinfo, पूर्णाङ्क,
	    ध्रुव वर्ण *);

स्थिर पूर्णाङ्क
decode_addrport(ध्रुव वर्ण *h, ध्रुव वर्ण *p, संरचना sockaddr *addr,
    socklen_t addrlen, पूर्णाङ्क v4only, पूर्णाङ्क numeric)
{
	पूर्णाङ्क r;
	संरचना addrinfo hints, *res;

	bzero(&hints, परिमाण(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	यदि (r != 0) {
		यदि (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		प्रत्यागम (-1);
	}
	यदि (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
proxy_read_ओळ(पूर्णाङ्क fd, वर्ण *buf, size_t bufsz)
{
	size_t off;

	प्रति(off = 0;;) {
		यदि (off >= bufsz)
			errx(1, "proxy read too long");
		यदि (atomicio(पठ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		यदि (buf[off] == '\r')
			अनुवर्त;
		यदि (buf[off] == '\n') {
			buf[off] = '\0';
			भङ्ग;
		}
		off++;
	}
	प्रत्यागम (off);
}

स्थिर ध्रुव वर्ण *
getproxypass(ध्रुव वर्ण *proxyuser, ध्रुव वर्ण *proxyhost)
{
	वर्ण prompt[512];
	स्थिर वर्ण pw[256];

	snprintf(prompt, परिमाण(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	यदि (readpassphrase(prompt, pw, परिमाण(pw), RPP_REQUIRE_TTY) == रिक्त)
		errx(1, "Unable to read proxy passphrase");
	प्रत्यागम (pw);
}

पूर्णाङ्क
socks_connect(ध्रुव वर्ण *host, ध्रुव वर्ण *port,
    संरचना addrinfo hints __attribute__ ((__unused__)),
    ध्रुव वर्ण *proxyhost, ध्रुव वर्ण *proxyport, संरचना addrinfo proxyhints,
    पूर्णाङ्क socksv, ध्रुव वर्ण *proxyuser)
{
	पूर्णाङ्क proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned वर्ण buf[1024];
	size_t cnt;
	संरचना sockaddr_storage addr;
	संरचना sockaddr_in *in4 = (संरचना sockaddr_in *)&addr;
	संरचना sockaddr_in6 *in6 = (संरचना sockaddr_in6 *)&addr;
	in_port_t serverport;
	ध्रुव वर्ण *proxypass = रिक्त;

	यदि (proxyport == रिक्त)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	यदि (decode_addrport("0.0.0.0", port, (संरचना sockaddr *)&addr,
	    परिमाण(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	यदि (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	यदि (proxyfd < 0)
		प्रत्यागम (-1);

	यदि (socksv == 5) {
		यदि (decode_addrport(host, port, (संरचना sockaddr *)&addr,
		    परिमाण(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		यदि (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(पठ, proxyfd, buf, 2);
		यदि (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		यदि (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		विकल्प (addr.ss_family) {
		पक्ष 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			यदि (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, परिमाण serverport);
			wlen = 7 + hlen;
			भङ्ग;
		पक्ष AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, परिमाण in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, परिमाण in4->sin_port);
			wlen = 10;
			भङ्ग;
		पक्ष AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, परिमाण in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    परिमाण in6->sin6_port);
			wlen = 22;
			भङ्ग;
		स्वभाव:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		यदि (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(पठ, proxyfd, buf, 4);
		यदि (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		यदि (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		विकल्प (buf[3]) {
		पक्ष SOCKS_IPV4:
			cnt = atomicio(पठ, proxyfd, buf + 4, 6);
			यदि (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			भङ्ग;
		पक्ष SOCKS_IPV6:
			cnt = atomicio(पठ, proxyfd, buf + 4, 18);
			यदि (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			भङ्ग;
		स्वभाव:
			errx(1, "connection failed, unsupported address type");
		}
	} अन्यथा यदि (socksv == 4 || socksv == 44) {
		यदि (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (संरचना sockaddr *)&addr,
			    परिमाण(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, परिमाण in4->sin_port);
		यदि (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, परिमाण in4->sin_addr);
		} अन्यथा {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		यदि (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			यदि (strlcpy(buf + 9, host,
			    परिमाण(buf) - 9) >= परिमाण(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		यदि (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(पठ, proxyfd, buf, 8);
		यदि (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		यदि (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} अन्यथा यदि (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		यदि (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		यदि (strchr(host, ':') != रिक्त) {
			r = snprintf(buf, परिमाण(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} अन्यथा {
			r = snprintf(buf, परिमाण(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		यदि (r == -1 || (size_t)r >= परिमाण(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		यदि (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		यदि (authretry > 1) {
			वर्ण resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, परिमाण(buf), "%s:%s",
			    proxyuser, proxypass);
			यदि (r == -1 || (size_t)r >= परिमाण(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    परिमाण(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, परिमाण(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			यदि (r == -1 || (size_t)r >= परिमाण(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			यदि ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		यदि ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_ओळ(proxyfd, buf, परिमाण(buf));
		यदि (proxyuser != रिक्त &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			यदि (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			गच्छ again;
		} अन्यथा यदि (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		प्रति (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_ओळ(proxyfd, buf, परिमाण(buf));
			यदि (*buf == '\0')
				भङ्ग;
		}
		यदि (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} अन्यथा
		errx(1, "Unknown proxy protocol %d", socksv);

	प्रत्यागम (proxyfd);
}

