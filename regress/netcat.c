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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/uio.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <netinet/tcp.h>
#અન્તર્ભાવ <netinet/ip.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ "atomicio.h"

#અન્તર્ભાવ <poll.h>
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
	(કદ(*(su)) - કદ((su)->sun_path) + strlen((su)->sun_path))
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
પૂર્ણાંક	dflag;					/* detached, no stdin */
પૂર્ણાંક	Fflag;					/* fdpass sock to stdout */
unsigned પૂર્ણાંક iflag;				/* Interval Flag */
પૂર્ણાંક	kflag;					/* More than one connect */
પૂર્ણાંક	lflag;					/* Bind to local port */
પૂર્ણાંક	Nflag;					/* shutdown() network socket */
પૂર્ણાંક	nflag;					/* Don't do name look up */
અક્ષર   *Pflag;					/* Proxy username */
અક્ષર   *pflag;					/* Localport flag */
પૂર્ણાંક	rflag;					/* Random ports flag */
અક્ષર   *sflag;					/* Source Address */
પૂર્ણાંક	tflag;					/* Telnet Emulation */
પૂર્ણાંક	uflag;					/* UDP - Default to TCP */
પૂર્ણાંક	vflag;					/* Verbosity */
પૂર્ણાંક	xflag;					/* Socks proxy */
પૂર્ણાંક	zflag;					/* Port Scan Flag */
પૂર્ણાંક	Dflag;					/* sodebug */
પૂર્ણાંક	Iflag;					/* TCP receive buffer size */
પૂર્ણાંક	Oflag;					/* TCP send buffer size */
પૂર્ણાંક	Sflag;					/* TCP MD5 signature option */
પૂર્ણાંક	Tflag = -1;				/* IP Type of Service */
પૂર્ણાંક	rtableid = -1;

પૂર્ણાંક timeout = -1;
પૂર્ણાંક family = AF_UNSPEC;
અક્ષર *portlist[PORT_MAX+1];
અક્ષર *unix_dg_tmp_socket;

શૂન્ય	atelnet(પૂર્ણાંક, unsigned અક્ષર *, unsigned પૂર્ણાંક);
શૂન્ય	build_ports(અક્ષર *);
શૂન્ય	help(શૂન્ય);
પૂર્ણાંક	local_listen(અક્ષર *, અક્ષર *, સંરચના addrinfo);
શૂન્ય	readwrite(પૂર્ણાંક);
શૂન્ય	fdpass(પૂર્ણાંક nfd) __attribute__((noreturn));
પૂર્ણાંક	remote_connect(અચલ અક્ષર *, અચલ અક્ષર *, સંરચના addrinfo);
પૂર્ણાંક	timeout_connect(પૂર્ણાંક, અચલ સંરચના sockaddr *, socklen_t);
પૂર્ણાંક	socks_connect(અચલ અક્ષર *, અચલ અક્ષર *, સંરચના addrinfo,
	    અચલ અક્ષર *, અચલ અક્ષર *, સંરચના addrinfo, પૂર્ણાંક, અચલ અક્ષર *);
પૂર્ણાંક	udptest(પૂર્ણાંક);
પૂર્ણાંક	unix_bind(અક્ષર *);
પૂર્ણાંક	unix_connect(અક્ષર *);
પૂર્ણાંક	unix_listen(અક્ષર *);
શૂન્ય	set_common_sockopts(પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	map_tos(અક્ષર *, પૂર્ણાંક *);
શૂન્ય	report_connect(અચલ સંરચના sockaddr *, socklen_t);
શૂન્ય	usage(પૂર્ણાંક);
ssize_t drainbuf(પૂર્ણાંક, unsigned અક્ષર *, size_t *);
ssize_t fillbuf(પૂર્ણાંક, unsigned અક્ષર *, size_t *);


પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર *argv[])
{
	પૂર્ણાંક ch, s, ret, socksv;
	અક્ષર *host, *uport;
	સંરચના addrinfo hints;
	સંરચના servent *sv;
	socklen_t len;
	સંરચના sockaddr_storage cliaddr;
	અક્ષર *proxy = ખાલી;
	અચલ અક્ષર *errstr, *proxyhost = "", *proxyport = ખાલી;
	સંરચના addrinfo proxyhints;
	અક્ષર unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ખાલી;
	uport = ખાલી;
	sv = ખાલી;

	સંકેત(SIGPIPE, SIG_IGN);

	જ્યારે ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ '4':
			family = AF_INET;
			તોડો;
		સ્થિતિ '6':
			family = AF_INET6;
			તોડો;
		સ્થિતિ 'U':
			family = AF_UNIX;
			તોડો;
		સ્થિતિ 'X':
			જો (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			નહીંતર જો (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			નહીંતર જો (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			નહીંતર જો (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			નહીંતર
				errx(1, "unsupported proxy protocol");
			તોડો;
		સ્થિતિ 'd':
			dflag = 1;
			તોડો;
		સ્થિતિ 'F':
			Fflag = 1;
			તોડો;
		સ્થિતિ 'h':
			help();
			તોડો;
		સ્થિતિ 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			જો (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			તોડો;
		સ્થિતિ 'k':
			kflag = 1;
			તોડો;
		સ્થિતિ 'l':
			lflag = 1;
			તોડો;
		સ્થિતિ 'N':
			Nflag = 1;
			તોડો;
		સ્થિતિ 'n':
			nflag = 1;
			તોડો;
		સ્થિતિ 'P':
			Pflag = optarg;
			તોડો;
		સ્થિતિ 'p':
			pflag = optarg;
			તોડો;
		સ્થિતિ 'r':
			rflag = 1;
			તોડો;
		સ્થિતિ 's':
			sflag = optarg;
			તોડો;
		સ્થિતિ 't':
			tflag = 1;
			તોડો;
		સ્થિતિ 'u':
			uflag = 1;
			તોડો;
#ifdef SO_RTABLE
		સ્થિતિ 'V':
			rtableid = (પૂર્ણાંક)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			જો (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			તોડો;
#endif
		સ્થિતિ 'v':
			vflag = 1;
			તોડો;
		સ્થિતિ 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			જો (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			તોડો;
		સ્થિતિ 'x':
			xflag = 1;
			જો ((proxy = strdup(optarg)) == ખાલી)
				errx(1, "strdup");
			તોડો;
		સ્થિતિ 'z':
			zflag = 1;
			તોડો;
		સ્થિતિ 'D':
			Dflag = 1;
			તોડો;
		સ્થિતિ 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			જો (errstr != ખાલી)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			તોડો;
		સ્થિતિ 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			જો (errstr != ખાલી)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			તોડો;
		સ્થિતિ 'S':
			Sflag = 1;
			તોડો;
		સ્થિતિ 'T':
			errstr = ખાલી;
			errno = 0;
			જો (map_tos(optarg, &Tflag))
				તોડો;
			જો (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (પૂર્ણાંક)strtol(optarg, ખાલી, 16);
			નહીંતર
				Tflag = (પૂર્ણાંક)strtonum(optarg, 0, 255,
				    &errstr);
			જો (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			તોડો;
		મૂળભૂત:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	જો (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ખાલી;
	} નહીંતર જો (argv[0] && !argv[1]) {
		જો  (!lflag)
			usage(1);
		uport = argv[0];
		host = ખાલી;
	} નહીંતર જો (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} નહીંતર
		usage(1);

	જો (lflag && sflag)
		errx(1, "cannot use -s and -l");
	જો (lflag && pflag)
		errx(1, "cannot use -p and -l");
	જો (lflag && zflag)
		errx(1, "cannot use -z and -l");
	જો (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	જો ((family == AF_UNIX) && uflag && !lflag) {
		જો (sflag) {
			unix_dg_tmp_socket = sflag;
		} નહીંતર {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			જો (mktemp(unix_dg_tmp_socket_buf) == ખાલી)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	જો (family != AF_UNIX) {
		memset(&hints, 0, કદ(સંરચના addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		જો (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	જો (xflag) {
		જો (uflag)
			errx(1, "no proxy support for UDP mode");

		જો (lflag)
			errx(1, "no proxy support for listen");

		જો (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		જો (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		જો (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, કદ(સંરચના addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		જો (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	જો (lflag) {
		પૂર્ણાંક connfd;
		ret = 0;

		જો (family == AF_UNIX) {
			જો (uflag)
				s = unix_bind(host);
			નહીંતર
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		માટે (;;) {
			જો (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			જો (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			જો (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			નહીંતર જો (uflag && !kflag) {
				પૂર્ણાંક rv, plen;
				અક્ષર buf[16384];
				સંરચના sockaddr_storage z;

				len = કદ(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (સંરચના sockaddr *)&z, &len);
				જો (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (સંરચના sockaddr *)&z, len);
				જો (rv < 0)
					err(1, "connect");

				જો (vflag)
					report_connect((સંરચના sockaddr *)&z, len);

				readwrite(s);
			} નહીંતર {
				len = કદ(cliaddr);
				connfd = accept(s, (સંરચના sockaddr *)&cliaddr,
				    &len);
				જો (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				જો (vflag)
					report_connect((સંરચના sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			જો (family != AF_UNIX)
				close(s);
			નહીંતર જો (uflag) {
				જો (connect(s, ખાલી, 0) < 0)
					err(1, "connect");
			}

			જો (!kflag)
				તોડો;
		}
	} નહીંતર જો (family == AF_UNIX) {
		ret = 0;

		જો ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} નહીંતર
			ret = 1;

		જો (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} નહીંતર {
		પૂર્ણાંક i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		માટે (i = 0; portlist[i] != ખાલી; i++) {
			જો (s)
				close(s);

			જો (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			નહીંતર
				s = remote_connect(host, portlist[i], hints);

			જો (s < 0)
				ચાલુ;

			ret = 0;
			જો (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				જો (uflag) {
					જો (udptest(s) == -1) {
						ret = 1;
						ચાલુ;
					}
				}

				/* Don't look up port if -n. */
				જો (nflag)
					sv = ખાલી;
				નહીંતર {
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
			જો (Fflag)
				fdpass(s);
			નહીંતર જો (!zflag)
				readwrite(s);
		}
	}

	જો (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
પૂર્ણાંક
unix_bind(અક્ષર *path)
{
	સંરચના sockaddr_un sun_sa;
	પૂર્ણાંક s;

	/* Create unix domain socket. */
	જો ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		પાછા (-1);

	memset(&sun_sa, 0, કદ(સંરચના sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	જો (strlcpy(sun_sa.sun_path, path, કદ(sun_sa.sun_path)) >=
	    કદ(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		પાછા (-1);
	}

	જો (bind(s, (સંરચના sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		પાછા (-1);
	}
	પાછા (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
પૂર્ણાંક
unix_connect(અક્ષર *path)
{
	સંરચના sockaddr_un sun_sa;
	પૂર્ણાંક s;

	જો (uflag) {
		જો ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			પાછા (-1);
	} નહીંતર {
		જો ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			પાછા (-1);
	}
	(શૂન્ય)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, કદ(સંરચના sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	જો (strlcpy(sun_sa.sun_path, path, કદ(sun_sa.sun_path)) >=
	    કદ(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		પાછા (-1);
	}
	જો (connect(s, (સંરચના sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		પાછા (-1);
	}
	પાછા (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
પૂર્ણાંક
unix_listen(અક્ષર *path)
{
	પૂર્ણાંક s;
	જો ((s = unix_bind(path)) < 0)
		પાછા (-1);

	જો (listen(s, 5) < 0) {
		close(s);
		પાછા (-1);
	}
	પાછા (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
પૂર્ણાંક
remote_connect(અચલ અક્ષર *host, અચલ અક્ષર *port, સંરચના addrinfo hints)
{
	સંરચના addrinfo *res, *res0;
	પૂર્ણાંક s, error;
#જો defined(SO_RTABLE) || defined(SO_BINDANY)
	પૂર્ણાંક on = 1;
#endif

	જો ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	કરો {
		જો ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ચાલુ;

#ifdef SO_RTABLE
		જો (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, કદ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		જો (sflag || pflag) {
			સંરચના addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, કદ(on));
#endif
			memset(&ahints, 0, કદ(સંરચના addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			જો ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			જો (bind(s, (સંરચના sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		જો (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			તોડો;
		નહીંતર જો (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} જ્યારે ((res0 = res0->ai_next) != ખાલી);

	freeaddrinfo(res);

	પાછા (s);
}

પૂર્ણાંક
timeout_connect(પૂર્ણાંક s, અચલ સંરચના sockaddr *name, socklen_t namelen)
{
	સંરચના pollfd pfd;
	socklen_t optlen;
	પૂર્ણાંક flags = 0, optval;
	પૂર્ણાંક ret;

	જો (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		જો (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	જો ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		જો ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = કદ(optval);
			જો ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} નહીંતર જો (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} નહીંતર
			err(1, "poll failed");
	}

	જો (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	પાછા (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
પૂર્ણાંક
local_listen(અક્ષર *host, અક્ષર *port, સંરચના addrinfo hints)
{
	સંરચના addrinfo *res, *res0;
	પૂર્ણાંક s, ret, x = 1;
	પૂર્ણાંક error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	જો (host == ખાલી && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	જો ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	કરો {
		જો ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ચાલુ;

#ifdef SO_RTABLE
		જો (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, કદ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, કદ(x));
		જો (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, કદ(x));
		જો (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		જો (bind(s, (સંરચના sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			તોડો;

		close(s);
		s = -1;
	} જ્યારે ((res0 = res0->ai_next) != ખાલી);

	જો (!uflag && s != -1) {
		જો (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	પાછા (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
શૂન્ય
readwrite(પૂર્ણાંક net_fd)
{
	સંરચના pollfd pfd[4];
	પૂર્ણાંક stdin_fd = STDIN_FILENO;
	પૂર્ણાંક stdout_fd = STDOUT_FILENO;
	unsigned અક્ષર netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned અક્ષર stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	પૂર્ણાંક n, અંક_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	જો (dflag)
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

	જ્યારે (1) {
		/* both inputs are gone, buffers are empty, we are done */
		જો (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			પાછા;
		}
		/* both outputs are gone, we can't continue */
		જો (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			પાછા;
		}
		/* listen and net in gone, queues empty, done */
		જો (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			પાછા;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		જો (iflag)
			sleep(iflag);

		/* poll */
		અંક_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		જો (અંક_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		જો (અંક_fds == 0)
			પાછા;

		/* treat socket error conditions */
		માટે (n = 0; n < 4; n++) {
			જો (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		જો (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		જો (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		જો (pfd[POLL_NETOUT].revents & POLLHUP) {
			જો (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		જો (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		જો (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		જો (pfd[POLL_STDOUT].fd == -1) {
			જો (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		જો (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			જો (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			જો (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			જો (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		જો (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			જો (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			જો (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			જો (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		જો (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			જો (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			જો (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			જો (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			જો (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			જો (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		જો (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			જો (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			જો (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			જો (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		જો (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			જો (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		જો (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(પૂર્ણાંક fd, unsigned અક્ષર *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = લિખ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	જો (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	જો (n <= 0)
		પાછા n;
	/* adjust buffer */
	adjust = *bufpos - n;
	જો (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	પાછા n;
}


ssize_t
fillbuf(પૂર્ણાંક fd, unsigned અક્ષર *buf, size_t *bufpos)
{
	size_t અંક = BUFSIZE - *bufpos;
	ssize_t n;

	n = પઠ(fd, buf + *bufpos, અંક);
	/* don't treat EAGAIN, EINTR as error */
	જો (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	જો (n <= 0)
		પાછા n;
	*bufpos += n;
	પાછા n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
શૂન્ય
fdpass(પૂર્ણાંક nfd)
{
#જો defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	સંરચના msghdr સંદેશ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	સંઘ {
		સંરચના cmsghdr hdr;
		અક્ષર buf[CMSG_SPACE(કદ(પૂર્ણાંક))];
	} cmsgbuf;
	સંરચના cmsghdr *cmsg;
#endif
	સંરચના iovec vec;
	અક્ષર ch = '\0';
	સંરચના pollfd pfd;
	ssize_t r;

	memset(&સંદેશ, 0, કદ(સંદેશ));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	સંદેશ.સંદેશ_accrights = (caddr_t)&nfd;
	સંદેશ.સંદેશ_accrightslen = કદ(nfd);
#નહીંતર
	memset(&cmsgbuf, 0, કદ(cmsgbuf));
	સંદેશ.msg_control = (caddr_t)&cmsgbuf.buf;
	સંદેશ.msg_controllen = કદ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&સંદેશ);
	cmsg->cmsg_len = CMSG_LEN(કદ(પૂર્ણાંક));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(પૂર્ણાંક *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	સંદેશ.msg_iov = &vec;
	સંદેશ.msg_iovlen = 1;

	bzero(&pfd, કદ(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	માટે (;;) {
		r = sendmsg(STDOUT_FILENO, &સંદેશ, 0);
		જો (r == -1) {
			જો (errno == EAGAIN || errno == EINTR) {
				જો (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				ચાલુ;
			}
			err(1, "sendmsg");
		} નહીંતર જો (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		નહીંતર
			તોડો;
	}
	exit(0);
#નહીંતર
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
શૂન્ય
atelnet(પૂર્ણાંક nfd, unsigned અક્ષર *buf, unsigned પૂર્ણાંક size)
{
	unsigned અક્ષર *p, *end;
	unsigned અક્ષર obuf[4];

	જો (size < 3)
		પાછા;
	end = buf + size - 2;

	માટે (p = buf; p < end; p++) {
		જો (*p != IAC)
			ચાલુ;

		obuf[0] = IAC;
		p++;
		જો ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		નહીંતર જો ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		નહીંતર
			ચાલુ;

		p++;
		obuf[2] = *p;
		જો (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
શૂન્ય
build_ports(અક્ષર *p)
{
	અચલ અક્ષર *errstr;
	અક્ષર *n;
	પૂર્ણાંક hi, lo, cp;
	પૂર્ણાંક x = 0;

	જો ((n = strchr(p, '-')) != ખાલી) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		જો (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		જો (errstr)
			errx(1, "port number %s: %s", errstr, p);

		જો (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		માટે (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			જો (portlist[x] == ખાલી)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		જો (rflag) {
			પૂર્ણાંક y;
			અક્ષર *c;

			માટે (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} નહીંતર {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		જો (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		જો (portlist[0] == ખાલી)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
પૂર્ણાંક
udptest(પૂર્ણાંક s)
{
	પૂર્ણાંક i, ret;

	માટે (i = 0; i <= 3; i++) {
		જો (લિખ(s, "X", 1) == 1)
			ret = 1;
		નહીંતર
			ret = -1;
	}
	પાછા (ret);
}

શૂન્ય
set_common_sockopts(પૂર્ણાંક s, પૂર્ણાંક af)
{
	પૂર્ણાંક x = 1;

#ifdef TCP_MD5SIG
	જો (Sflag) {
		જો (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, કદ(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	જો (Dflag) {
		જો (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, કદ(x)) == -1)
			err(1, "setsockopt");
	}
#જો defined(IP_TOS) && defined(IPV6_TCLASS)
	જો (Tflag != -1) {
		પૂર્ણાંક proto, option;

		જો (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} નહીંતર {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		જો (setsockopt(s, proto, option, &Tflag, કદ(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	જો (Iflag) {
		જો (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, કદ(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	જો (Oflag) {
		જો (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, કદ(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

પૂર્ણાંક
map_tos(અક્ષર *s, પૂર્ણાંક *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	અચલ સંરચના toskeywords {
		અચલ અક્ષર	*keyword;
		પૂર્ણાંક		 val;
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
		{ ખાલી, 		-1 },
	};

	માટે (t = toskeywords; t->keyword != ખાલી; t++) {
		જો (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			પાછા (1);
		}
	}
#endif

	પાછા (0);
}

શૂન્ય
report_connect(અચલ સંરચના sockaddr *sa, socklen_t salen)
{
	અક્ષર remote_host[NI_MAXHOST];
	અક્ષર remote_port[NI_MAXSERV];
	પૂર્ણાંક herr;
	પૂર્ણાંક flags = NI_NUMERICSERV;
	
	જો (nflag)
		flags |= NI_NUMERICHOST;
	
	જો ((herr = getnameinfo(sa, salen,
	    remote_host, કદ(remote_host),
	    remote_port, કદ(remote_port),
	    flags)) != 0) {
		જો (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		નહીંતર
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

શૂન્ય
help(શૂન્ય)
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
	\t-i secs\t	Delay interval માટે લીટીઓ sent, ports scanned\n\
	\t-k		Keep inbound sockets open માટે multiple connects\n\
	\t-l		Listen mode, માટે inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername માટે proxy authentication\n\
	\t-p port\t	Specify local port માટે remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout માટે connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used માટે scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

શૂન્ય
usage(પૂર્ણાંક ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	જો (ret)
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

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <resolv.h>

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

પૂર્ણાંક	remote_connect(અચલ અક્ષર *, અચલ અક્ષર *, સંરચના addrinfo);
પૂર્ણાંક	socks_connect(અચલ અક્ષર *, અચલ અક્ષર *, સંરચના addrinfo,
	    અચલ અક્ષર *, અચલ અક્ષર *, સંરચના addrinfo, પૂર્ણાંક,
	    અચલ અક્ષર *);

સ્થિર પૂર્ણાંક
decode_addrport(અચલ અક્ષર *h, અચલ અક્ષર *p, સંરચના sockaddr *addr,
    socklen_t addrlen, પૂર્ણાંક v4only, પૂર્ણાંક numeric)
{
	પૂર્ણાંક r;
	સંરચના addrinfo hints, *res;

	bzero(&hints, કદ(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	જો (r != 0) {
		જો (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		પાછા (-1);
	}
	જો (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	પાછા (0);
}

સ્થિર પૂર્ણાંક
proxy_read_લીટી(પૂર્ણાંક fd, અક્ષર *buf, size_t bufsz)
{
	size_t off;

	માટે(off = 0;;) {
		જો (off >= bufsz)
			errx(1, "proxy read too long");
		જો (atomicio(પઠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		જો (buf[off] == '\r')
			ચાલુ;
		જો (buf[off] == '\n') {
			buf[off] = '\0';
			તોડો;
		}
		off++;
	}
	પાછા (off);
}

સ્થિર અચલ અક્ષર *
getproxypass(અચલ અક્ષર *proxyuser, અચલ અક્ષર *proxyhost)
{
	અક્ષર prompt[512];
	સ્થિર અક્ષર pw[256];

	snprintf(prompt, કદ(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	જો (readpassphrase(prompt, pw, કદ(pw), RPP_REQUIRE_TTY) == ખાલી)
		errx(1, "Unable to read proxy passphrase");
	પાછા (pw);
}

પૂર્ણાંક
socks_connect(અચલ અક્ષર *host, અચલ અક્ષર *port,
    સંરચના addrinfo hints __attribute__ ((__unused__)),
    અચલ અક્ષર *proxyhost, અચલ અક્ષર *proxyport, સંરચના addrinfo proxyhints,
    પૂર્ણાંક socksv, અચલ અક્ષર *proxyuser)
{
	પૂર્ણાંક proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned અક્ષર buf[1024];
	size_t cnt;
	સંરચના sockaddr_storage addr;
	સંરચના sockaddr_in *in4 = (સંરચના sockaddr_in *)&addr;
	સંરચના sockaddr_in6 *in6 = (સંરચના sockaddr_in6 *)&addr;
	in_port_t serverport;
	અચલ અક્ષર *proxypass = ખાલી;

	જો (proxyport == ખાલી)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	જો (decode_addrport("0.0.0.0", port, (સંરચના sockaddr *)&addr,
	    કદ(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	જો (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	જો (proxyfd < 0)
		પાછા (-1);

	જો (socksv == 5) {
		જો (decode_addrport(host, port, (સંરચના sockaddr *)&addr,
		    કદ(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		જો (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(પઠ, proxyfd, buf, 2);
		જો (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		જો (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		પસંદગી (addr.ss_family) {
		સ્થિતિ 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			જો (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, કદ serverport);
			wlen = 7 + hlen;
			તોડો;
		સ્થિતિ AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, કદ in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, કદ in4->sin_port);
			wlen = 10;
			તોડો;
		સ્થિતિ AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, કદ in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    કદ in6->sin6_port);
			wlen = 22;
			તોડો;
		મૂળભૂત:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		જો (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(પઠ, proxyfd, buf, 4);
		જો (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		જો (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		પસંદગી (buf[3]) {
		સ્થિતિ SOCKS_IPV4:
			cnt = atomicio(પઠ, proxyfd, buf + 4, 6);
			જો (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			તોડો;
		સ્થિતિ SOCKS_IPV6:
			cnt = atomicio(પઠ, proxyfd, buf + 4, 18);
			જો (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			તોડો;
		મૂળભૂત:
			errx(1, "connection failed, unsupported address type");
		}
	} નહીંતર જો (socksv == 4 || socksv == 44) {
		જો (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (સંરચના sockaddr *)&addr,
			    કદ(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, કદ in4->sin_port);
		જો (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, કદ in4->sin_addr);
		} નહીંતર {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		જો (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			જો (strlcpy(buf + 9, host,
			    કદ(buf) - 9) >= કદ(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		જો (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(પઠ, proxyfd, buf, 8);
		જો (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		જો (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} નહીંતર જો (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		જો (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		જો (strchr(host, ':') != ખાલી) {
			r = snprintf(buf, કદ(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} નહીંતર {
			r = snprintf(buf, કદ(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		જો (r == -1 || (size_t)r >= કદ(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		જો (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		જો (authretry > 1) {
			અક્ષર resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, કદ(buf), "%s:%s",
			    proxyuser, proxypass);
			જો (r == -1 || (size_t)r >= કદ(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    કદ(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, કદ(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			જો (r == -1 || (size_t)r >= કદ(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			જો ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		જો ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_લીટી(proxyfd, buf, કદ(buf));
		જો (proxyuser != ખાલી &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			જો (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			જાઓ again;
		} નહીંતર જો (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		માટે (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_લીટી(proxyfd, buf, કદ(buf));
			જો (*buf == '\0')
				તોડો;
		}
		જો (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} નહીંતર
		errx(1, "Unknown proxy protocol %d", socksv);

	પાછા (proxyfd);
}

