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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/uio.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <netinet/tcp.h>
#അന്തര്ഭാവ <netinet/ip.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ "atomicio.h"

#അന്തര്ഭാവ <poll.h>
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
	(വലുപ്പം(*(su)) - വലുപ്പം((su)->sun_path) + strlen((su)->sun_path))
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
പൂർണ്ണസംഖ്യ	dflag;					/* detached, no stdin */
പൂർണ്ണസംഖ്യ	Fflag;					/* fdpass sock to stdout */
unsigned പൂർണ്ണസംഖ്യ iflag;				/* Interval Flag */
പൂർണ്ണസംഖ്യ	kflag;					/* More than one connect */
പൂർണ്ണസംഖ്യ	lflag;					/* Bind to local port */
പൂർണ്ണസംഖ്യ	Nflag;					/* shutdown() network socket */
പൂർണ്ണസംഖ്യ	nflag;					/* Don't do name look up */
അക്ഷരം   *Pflag;					/* Proxy username */
അക്ഷരം   *pflag;					/* Localport flag */
പൂർണ്ണസംഖ്യ	rflag;					/* Random ports flag */
അക്ഷരം   *sflag;					/* Source Address */
പൂർണ്ണസംഖ്യ	tflag;					/* Telnet Emulation */
പൂർണ്ണസംഖ്യ	uflag;					/* UDP - Default to TCP */
പൂർണ്ണസംഖ്യ	vflag;					/* Verbosity */
പൂർണ്ണസംഖ്യ	xflag;					/* Socks proxy */
പൂർണ്ണസംഖ്യ	zflag;					/* Port Scan Flag */
പൂർണ്ണസംഖ്യ	Dflag;					/* sodebug */
പൂർണ്ണസംഖ്യ	Iflag;					/* TCP receive buffer size */
പൂർണ്ണസംഖ്യ	Oflag;					/* TCP send buffer size */
പൂർണ്ണസംഖ്യ	Sflag;					/* TCP MD5 signature option */
പൂർണ്ണസംഖ്യ	Tflag = -1;				/* IP Type of Service */
പൂർണ്ണസംഖ്യ	rtableid = -1;

പൂർണ്ണസംഖ്യ timeout = -1;
പൂർണ്ണസംഖ്യ family = AF_UNSPEC;
അക്ഷരം *portlist[PORT_MAX+1];
അക്ഷരം *unix_dg_tmp_socket;

ശൂന്യം	atelnet(പൂർണ്ണസംഖ്യ, unsigned അക്ഷരം *, unsigned പൂർണ്ണസംഖ്യ);
ശൂന്യം	build_ports(അക്ഷരം *);
ശൂന്യം	help(ശൂന്യം);
പൂർണ്ണസംഖ്യ	local_listen(അക്ഷരം *, അക്ഷരം *, ഘടന addrinfo);
ശൂന്യം	readwrite(പൂർണ്ണസംഖ്യ);
ശൂന്യം	fdpass(പൂർണ്ണസംഖ്യ nfd) __attribute__((noreturn));
പൂർണ്ണസംഖ്യ	remote_connect(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന addrinfo);
പൂർണ്ണസംഖ്യ	timeout_connect(പൂർണ്ണസംഖ്യ, സ്ഥിരം ഘടന sockaddr *, socklen_t);
പൂർണ്ണസംഖ്യ	socks_connect(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന addrinfo,
	    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന addrinfo, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	udptest(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	unix_bind(അക്ഷരം *);
പൂർണ്ണസംഖ്യ	unix_connect(അക്ഷരം *);
പൂർണ്ണസംഖ്യ	unix_listen(അക്ഷരം *);
ശൂന്യം	set_common_sockopts(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	map_tos(അക്ഷരം *, പൂർണ്ണസംഖ്യ *);
ശൂന്യം	report_connect(സ്ഥിരം ഘടന sockaddr *, socklen_t);
ശൂന്യം	usage(പൂർണ്ണസംഖ്യ);
ssize_t drainbuf(പൂർണ്ണസംഖ്യ, unsigned അക്ഷരം *, size_t *);
ssize_t fillbuf(പൂർണ്ണസംഖ്യ, unsigned അക്ഷരം *, size_t *);


പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം *argv[])
{
	പൂർണ്ണസംഖ്യ ch, s, ret, socksv;
	അക്ഷരം *host, *uport;
	ഘടന addrinfo hints;
	ഘടന servent *sv;
	socklen_t len;
	ഘടന sockaddr_storage cliaddr;
	അക്ഷരം *proxy = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *errstr, *proxyhost = "", *proxyport = ശൂന്യ;
	ഘടന addrinfo proxyhints;
	അക്ഷരം unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ശൂന്യ;
	uport = ശൂന്യ;
	sv = ശൂന്യ;

	സൂചന(SIGPIPE, SIG_IGN);

	ആകുമ്പോൾ ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ '4':
			family = AF_INET;
			നിർത്തുക;
		അവസ്ഥ '6':
			family = AF_INET6;
			നിർത്തുക;
		അവസ്ഥ 'U':
			family = AF_UNIX;
			നിർത്തുക;
		അവസ്ഥ 'X':
			എങ്കിൽ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			അല്ലെങ്കിൽ
				errx(1, "unsupported proxy protocol");
			നിർത്തുക;
		അവസ്ഥ 'd':
			dflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'F':
			Fflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'h':
			help();
			നിർത്തുക;
		അവസ്ഥ 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			എങ്കിൽ (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			നിർത്തുക;
		അവസ്ഥ 'k':
			kflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'l':
			lflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'N':
			Nflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'n':
			nflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'P':
			Pflag = optarg;
			നിർത്തുക;
		അവസ്ഥ 'p':
			pflag = optarg;
			നിർത്തുക;
		അവസ്ഥ 'r':
			rflag = 1;
			നിർത്തുക;
		അവസ്ഥ 's':
			sflag = optarg;
			നിർത്തുക;
		അവസ്ഥ 't':
			tflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'u':
			uflag = 1;
			നിർത്തുക;
#ifdef SO_RTABLE
		അവസ്ഥ 'V':
			rtableid = (പൂർണ്ണസംഖ്യ)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			എങ്കിൽ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			നിർത്തുക;
#endif
		അവസ്ഥ 'v':
			vflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			എങ്കിൽ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			നിർത്തുക;
		അവസ്ഥ 'x':
			xflag = 1;
			എങ്കിൽ ((proxy = strdup(optarg)) == ശൂന്യ)
				errx(1, "strdup");
			നിർത്തുക;
		അവസ്ഥ 'z':
			zflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'D':
			Dflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			എങ്കിൽ (errstr != ശൂന്യ)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			നിർത്തുക;
		അവസ്ഥ 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			എങ്കിൽ (errstr != ശൂന്യ)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			നിർത്തുക;
		അവസ്ഥ 'S':
			Sflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'T':
			errstr = ശൂന്യ;
			errno = 0;
			എങ്കിൽ (map_tos(optarg, &Tflag))
				നിർത്തുക;
			എങ്കിൽ (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (പൂർണ്ണസംഖ്യ)strtol(optarg, ശൂന്യ, 16);
			അല്ലെങ്കിൽ
				Tflag = (പൂർണ്ണസംഖ്യ)strtonum(optarg, 0, 255,
				    &errstr);
			എങ്കിൽ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	എങ്കിൽ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (argv[0] && !argv[1]) {
		എങ്കിൽ  (!lflag)
			usage(1);
		uport = argv[0];
		host = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} അല്ലെങ്കിൽ
		usage(1);

	എങ്കിൽ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	എങ്കിൽ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	എങ്കിൽ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	എങ്കിൽ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	എങ്കിൽ ((family == AF_UNIX) && uflag && !lflag) {
		എങ്കിൽ (sflag) {
			unix_dg_tmp_socket = sflag;
		} അല്ലെങ്കിൽ {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			എങ്കിൽ (mktemp(unix_dg_tmp_socket_buf) == ശൂന്യ)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	എങ്കിൽ (family != AF_UNIX) {
		memset(&hints, 0, വലുപ്പം(ഘടന addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		എങ്കിൽ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	എങ്കിൽ (xflag) {
		എങ്കിൽ (uflag)
			errx(1, "no proxy support for UDP mode");

		എങ്കിൽ (lflag)
			errx(1, "no proxy support for listen");

		എങ്കിൽ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		എങ്കിൽ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		എങ്കിൽ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, വലുപ്പം(ഘടന addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		എങ്കിൽ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	എങ്കിൽ (lflag) {
		പൂർണ്ണസംഖ്യ connfd;
		ret = 0;

		എങ്കിൽ (family == AF_UNIX) {
			എങ്കിൽ (uflag)
				s = unix_bind(host);
			അല്ലെങ്കിൽ
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		വേണ്ടി (;;) {
			എങ്കിൽ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			എങ്കിൽ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			എങ്കിൽ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			അല്ലെങ്കിൽ എങ്കിൽ (uflag && !kflag) {
				പൂർണ്ണസംഖ്യ rv, plen;
				അക്ഷരം buf[16384];
				ഘടന sockaddr_storage z;

				len = വലുപ്പം(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (ഘടന sockaddr *)&z, &len);
				എങ്കിൽ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (ഘടന sockaddr *)&z, len);
				എങ്കിൽ (rv < 0)
					err(1, "connect");

				എങ്കിൽ (vflag)
					report_connect((ഘടന sockaddr *)&z, len);

				readwrite(s);
			} അല്ലെങ്കിൽ {
				len = വലുപ്പം(cliaddr);
				connfd = accept(s, (ഘടന sockaddr *)&cliaddr,
				    &len);
				എങ്കിൽ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				എങ്കിൽ (vflag)
					report_connect((ഘടന sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			എങ്കിൽ (family != AF_UNIX)
				close(s);
			അല്ലെങ്കിൽ എങ്കിൽ (uflag) {
				എങ്കിൽ (connect(s, ശൂന്യ, 0) < 0)
					err(1, "connect");
			}

			എങ്കിൽ (!kflag)
				നിർത്തുക;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (family == AF_UNIX) {
		ret = 0;

		എങ്കിൽ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} അല്ലെങ്കിൽ
			ret = 1;

		എങ്കിൽ (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} അല്ലെങ്കിൽ {
		പൂർണ്ണസംഖ്യ i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		വേണ്ടി (i = 0; portlist[i] != ശൂന്യ; i++) {
			എങ്കിൽ (s)
				close(s);

			എങ്കിൽ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			അല്ലെങ്കിൽ
				s = remote_connect(host, portlist[i], hints);

			എങ്കിൽ (s < 0)
				തുടരുക;

			ret = 0;
			എങ്കിൽ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				എങ്കിൽ (uflag) {
					എങ്കിൽ (udptest(s) == -1) {
						ret = 1;
						തുടരുക;
					}
				}

				/* Don't look up port if -n. */
				എങ്കിൽ (nflag)
					sv = ശൂന്യ;
				അല്ലെങ്കിൽ {
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
			എങ്കിൽ (Fflag)
				fdpass(s);
			അല്ലെങ്കിൽ എങ്കിൽ (!zflag)
				readwrite(s);
		}
	}

	എങ്കിൽ (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
പൂർണ്ണസംഖ്യ
unix_bind(അക്ഷരം *path)
{
	ഘടന sockaddr_un sun_sa;
	പൂർണ്ണസംഖ്യ s;

	/* Create unix domain socket. */
	എങ്കിൽ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		തിരികെ (-1);

	memset(&sun_sa, 0, വലുപ്പം(ഘടന sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	എങ്കിൽ (strlcpy(sun_sa.sun_path, path, വലുപ്പം(sun_sa.sun_path)) >=
	    വലുപ്പം(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		തിരികെ (-1);
	}

	എങ്കിൽ (bind(s, (ഘടന sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		തിരികെ (-1);
	}
	തിരികെ (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
പൂർണ്ണസംഖ്യ
unix_connect(അക്ഷരം *path)
{
	ഘടന sockaddr_un sun_sa;
	പൂർണ്ണസംഖ്യ s;

	എങ്കിൽ (uflag) {
		എങ്കിൽ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			തിരികെ (-1);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			തിരികെ (-1);
	}
	(ശൂന്യം)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, വലുപ്പം(ഘടന sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	എങ്കിൽ (strlcpy(sun_sa.sun_path, path, വലുപ്പം(sun_sa.sun_path)) >=
	    വലുപ്പം(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		തിരികെ (-1);
	}
	എങ്കിൽ (connect(s, (ഘടന sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		തിരികെ (-1);
	}
	തിരികെ (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
പൂർണ്ണസംഖ്യ
unix_listen(അക്ഷരം *path)
{
	പൂർണ്ണസംഖ്യ s;
	എങ്കിൽ ((s = unix_bind(path)) < 0)
		തിരികെ (-1);

	എങ്കിൽ (listen(s, 5) < 0) {
		close(s);
		തിരികെ (-1);
	}
	തിരികെ (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
പൂർണ്ണസംഖ്യ
remote_connect(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *port, ഘടന addrinfo hints)
{
	ഘടന addrinfo *res, *res0;
	പൂർണ്ണസംഖ്യ s, error;
#എങ്കിൽ defined(SO_RTABLE) || defined(SO_BINDANY)
	പൂർണ്ണസംഖ്യ on = 1;
#endif

	എങ്കിൽ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ചെയ്യുക {
		എങ്കിൽ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			തുടരുക;

#ifdef SO_RTABLE
		എങ്കിൽ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, വലുപ്പം(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		എങ്കിൽ (sflag || pflag) {
			ഘടന addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, വലുപ്പം(on));
#endif
			memset(&ahints, 0, വലുപ്പം(ഘടന addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			എങ്കിൽ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			എങ്കിൽ (bind(s, (ഘടന sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		എങ്കിൽ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			നിർത്തുക;
		അല്ലെങ്കിൽ എങ്കിൽ (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} ആകുമ്പോൾ ((res0 = res0->ai_next) != ശൂന്യ);

	freeaddrinfo(res);

	തിരികെ (s);
}

പൂർണ്ണസംഖ്യ
timeout_connect(പൂർണ്ണസംഖ്യ s, സ്ഥിരം ഘടന sockaddr *name, socklen_t namelen)
{
	ഘടന pollfd pfd;
	socklen_t optlen;
	പൂർണ്ണസംഖ്യ flags = 0, optval;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		എങ്കിൽ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	എങ്കിൽ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		എങ്കിൽ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = വലുപ്പം(optval);
			എങ്കിൽ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} അല്ലെങ്കിൽ
			err(1, "poll failed");
	}

	എങ്കിൽ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	തിരികെ (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
പൂർണ്ണസംഖ്യ
local_listen(അക്ഷരം *host, അക്ഷരം *port, ഘടന addrinfo hints)
{
	ഘടന addrinfo *res, *res0;
	പൂർണ്ണസംഖ്യ s, ret, x = 1;
	പൂർണ്ണസംഖ്യ error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	എങ്കിൽ (host == ശൂന്യ && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	എങ്കിൽ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ചെയ്യുക {
		എങ്കിൽ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			തുടരുക;

#ifdef SO_RTABLE
		എങ്കിൽ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, വലുപ്പം(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, വലുപ്പം(x));
		എങ്കിൽ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, വലുപ്പം(x));
		എങ്കിൽ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		എങ്കിൽ (bind(s, (ഘടന sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			നിർത്തുക;

		close(s);
		s = -1;
	} ആകുമ്പോൾ ((res0 = res0->ai_next) != ശൂന്യ);

	എങ്കിൽ (!uflag && s != -1) {
		എങ്കിൽ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	തിരികെ (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
ശൂന്യം
readwrite(പൂർണ്ണസംഖ്യ net_fd)
{
	ഘടന pollfd pfd[4];
	പൂർണ്ണസംഖ്യ stdin_fd = STDIN_FILENO;
	പൂർണ്ണസംഖ്യ stdout_fd = STDOUT_FILENO;
	unsigned അക്ഷരം netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned അക്ഷരം stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	പൂർണ്ണസംഖ്യ n, അക്കം_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	എങ്കിൽ (dflag)
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

	ആകുമ്പോൾ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		എങ്കിൽ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			തിരികെ;
		}
		/* both outputs are gone, we can't continue */
		എങ്കിൽ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			തിരികെ;
		}
		/* listen and net in gone, queues empty, done */
		എങ്കിൽ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			തിരികെ;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		എങ്കിൽ (iflag)
			sleep(iflag);

		/* poll */
		അക്കം_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		എങ്കിൽ (അക്കം_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		എങ്കിൽ (അക്കം_fds == 0)
			തിരികെ;

		/* treat socket error conditions */
		വേണ്ടി (n = 0; n < 4; n++) {
			എങ്കിൽ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		എങ്കിൽ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		എങ്കിൽ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		എങ്കിൽ (pfd[POLL_NETOUT].revents & POLLHUP) {
			എങ്കിൽ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		എങ്കിൽ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		എങ്കിൽ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		എങ്കിൽ (pfd[POLL_STDOUT].fd == -1) {
			എങ്കിൽ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		എങ്കിൽ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			എങ്കിൽ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			എങ്കിൽ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			എങ്കിൽ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		എങ്കിൽ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			എങ്കിൽ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			എങ്കിൽ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			എങ്കിൽ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		എങ്കിൽ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			എങ്കിൽ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			എങ്കിൽ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			എങ്കിൽ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			എങ്കിൽ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			എങ്കിൽ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		എങ്കിൽ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			എങ്കിൽ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			എങ്കിൽ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			എങ്കിൽ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		എങ്കിൽ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			എങ്കിൽ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		എങ്കിൽ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(പൂർണ്ണസംഖ്യ fd, unsigned അക്ഷരം *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = ലിഖ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	എങ്കിൽ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	എങ്കിൽ (n <= 0)
		തിരികെ n;
	/* adjust buffer */
	adjust = *bufpos - n;
	എങ്കിൽ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	തിരികെ n;
}


ssize_t
fillbuf(പൂർണ്ണസംഖ്യ fd, unsigned അക്ഷരം *buf, size_t *bufpos)
{
	size_t അക്കം = BUFSIZE - *bufpos;
	ssize_t n;

	n = പഠ(fd, buf + *bufpos, അക്കം);
	/* don't treat EAGAIN, EINTR as error */
	എങ്കിൽ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	എങ്കിൽ (n <= 0)
		തിരികെ n;
	*bufpos += n;
	തിരികെ n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
ശൂന്യം
fdpass(പൂർണ്ണസംഖ്യ nfd)
{
#എങ്കിൽ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ഘടന msghdr സന്ദേശം;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	സംഘം {
		ഘടന cmsghdr hdr;
		അക്ഷരം buf[CMSG_SPACE(വലുപ്പം(പൂർണ്ണസംഖ്യ))];
	} cmsgbuf;
	ഘടന cmsghdr *cmsg;
#endif
	ഘടന iovec vec;
	അക്ഷരം ch = '\0';
	ഘടന pollfd pfd;
	ssize_t r;

	memset(&സന്ദേശം, 0, വലുപ്പം(സന്ദേശം));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	സന്ദേശം.സന്ദേശം_accrights = (caddr_t)&nfd;
	സന്ദേശം.സന്ദേശം_accrightslen = വലുപ്പം(nfd);
#അല്ലെങ്കിൽ
	memset(&cmsgbuf, 0, വലുപ്പം(cmsgbuf));
	സന്ദേശം.msg_control = (caddr_t)&cmsgbuf.buf;
	സന്ദേശം.msg_controllen = വലുപ്പം(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&സന്ദേശം);
	cmsg->cmsg_len = CMSG_LEN(വലുപ്പം(പൂർണ്ണസംഖ്യ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(പൂർണ്ണസംഖ്യ *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	സന്ദേശം.msg_iov = &vec;
	സന്ദേശം.msg_iovlen = 1;

	bzero(&pfd, വലുപ്പം(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	വേണ്ടി (;;) {
		r = sendmsg(STDOUT_FILENO, &സന്ദേശം, 0);
		എങ്കിൽ (r == -1) {
			എങ്കിൽ (errno == EAGAIN || errno == EINTR) {
				എങ്കിൽ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				തുടരുക;
			}
			err(1, "sendmsg");
		} അല്ലെങ്കിൽ എങ്കിൽ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		അല്ലെങ്കിൽ
			നിർത്തുക;
	}
	exit(0);
#അല്ലെങ്കിൽ
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
ശൂന്യം
atelnet(പൂർണ്ണസംഖ്യ nfd, unsigned അക്ഷരം *buf, unsigned പൂർണ്ണസംഖ്യ size)
{
	unsigned അക്ഷരം *p, *end;
	unsigned അക്ഷരം obuf[4];

	എങ്കിൽ (size < 3)
		തിരികെ;
	end = buf + size - 2;

	വേണ്ടി (p = buf; p < end; p++) {
		എങ്കിൽ (*p != IAC)
			തുടരുക;

		obuf[0] = IAC;
		p++;
		എങ്കിൽ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		അല്ലെങ്കിൽ എങ്കിൽ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		അല്ലെങ്കിൽ
			തുടരുക;

		p++;
		obuf[2] = *p;
		എങ്കിൽ (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
ശൂന്യം
build_ports(അക്ഷരം *p)
{
	സ്ഥിരം അക്ഷരം *errstr;
	അക്ഷരം *n;
	പൂർണ്ണസംഖ്യ hi, lo, cp;
	പൂർണ്ണസംഖ്യ x = 0;

	എങ്കിൽ ((n = strchr(p, '-')) != ശൂന്യ) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		എങ്കിൽ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		എങ്കിൽ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		എങ്കിൽ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		വേണ്ടി (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			എങ്കിൽ (portlist[x] == ശൂന്യ)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		എങ്കിൽ (rflag) {
			പൂർണ്ണസംഖ്യ y;
			അക്ഷരം *c;

			വേണ്ടി (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} അല്ലെങ്കിൽ {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		എങ്കിൽ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		എങ്കിൽ (portlist[0] == ശൂന്യ)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
പൂർണ്ണസംഖ്യ
udptest(പൂർണ്ണസംഖ്യ s)
{
	പൂർണ്ണസംഖ്യ i, ret;

	വേണ്ടി (i = 0; i <= 3; i++) {
		എങ്കിൽ (ലിഖ(s, "X", 1) == 1)
			ret = 1;
		അല്ലെങ്കിൽ
			ret = -1;
	}
	തിരികെ (ret);
}

ശൂന്യം
set_common_sockopts(പൂർണ്ണസംഖ്യ s, പൂർണ്ണസംഖ്യ af)
{
	പൂർണ്ണസംഖ്യ x = 1;

#ifdef TCP_MD5SIG
	എങ്കിൽ (Sflag) {
		എങ്കിൽ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, വലുപ്പം(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	എങ്കിൽ (Dflag) {
		എങ്കിൽ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, വലുപ്പം(x)) == -1)
			err(1, "setsockopt");
	}
#എങ്കിൽ defined(IP_TOS) && defined(IPV6_TCLASS)
	എങ്കിൽ (Tflag != -1) {
		പൂർണ്ണസംഖ്യ proto, option;

		എങ്കിൽ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} അല്ലെങ്കിൽ {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		എങ്കിൽ (setsockopt(s, proto, option, &Tflag, വലുപ്പം(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	എങ്കിൽ (Iflag) {
		എങ്കിൽ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, വലുപ്പം(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	എങ്കിൽ (Oflag) {
		എങ്കിൽ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, വലുപ്പം(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

പൂർണ്ണസംഖ്യ
map_tos(അക്ഷരം *s, പൂർണ്ണസംഖ്യ *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	സ്ഥിരം ഘടന toskeywords {
		സ്ഥിരം അക്ഷരം	*keyword;
		പൂർണ്ണസംഖ്യ		 val;
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
		{ ശൂന്യ, 		-1 },
	};

	വേണ്ടി (t = toskeywords; t->keyword != ശൂന്യ; t++) {
		എങ്കിൽ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			തിരികെ (1);
		}
	}
#endif

	തിരികെ (0);
}

ശൂന്യം
report_connect(സ്ഥിരം ഘടന sockaddr *sa, socklen_t salen)
{
	അക്ഷരം remote_host[NI_MAXHOST];
	അക്ഷരം remote_port[NI_MAXSERV];
	പൂർണ്ണസംഖ്യ herr;
	പൂർണ്ണസംഖ്യ flags = NI_NUMERICSERV;
	
	എങ്കിൽ (nflag)
		flags |= NI_NUMERICHOST;
	
	എങ്കിൽ ((herr = getnameinfo(sa, salen,
	    remote_host, വലുപ്പം(remote_host),
	    remote_port, വലുപ്പം(remote_port),
	    flags)) != 0) {
		എങ്കിൽ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		അല്ലെങ്കിൽ
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

ശൂന്യം
help(ശൂന്യം)
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
	\t-i secs\t	Delay interval വേണ്ടി വരികൾ sent, ports scanned\n\
	\t-k		Keep inbound sockets open വേണ്ടി multiple connects\n\
	\t-l		Listen mode, വേണ്ടി inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername വേണ്ടി proxy authentication\n\
	\t-p port\t	Specify local port വേണ്ടി remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout വേണ്ടി connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used വേണ്ടി scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

ശൂന്യം
usage(പൂർണ്ണസംഖ്യ ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	എങ്കിൽ (ret)
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

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <resolv.h>

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

പൂർണ്ണസംഖ്യ	remote_connect(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന addrinfo);
പൂർണ്ണസംഖ്യ	socks_connect(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന addrinfo,
	    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന addrinfo, പൂർണ്ണസംഖ്യ,
	    സ്ഥിരം അക്ഷരം *);

സ്ഥിതം പൂർണ്ണസംഖ്യ
decode_addrport(സ്ഥിരം അക്ഷരം *h, സ്ഥിരം അക്ഷരം *p, ഘടന sockaddr *addr,
    socklen_t addrlen, പൂർണ്ണസംഖ്യ v4only, പൂർണ്ണസംഖ്യ numeric)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന addrinfo hints, *res;

	bzero(&hints, വലുപ്പം(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	എങ്കിൽ (r != 0) {
		എങ്കിൽ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		തിരികെ (-1);
	}
	എങ്കിൽ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	തിരികെ (0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
proxy_read_വരി(പൂർണ്ണസംഖ്യ fd, അക്ഷരം *buf, size_t bufsz)
{
	size_t off;

	വേണ്ടി(off = 0;;) {
		എങ്കിൽ (off >= bufsz)
			errx(1, "proxy read too long");
		എങ്കിൽ (atomicio(പഠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		എങ്കിൽ (buf[off] == '\r')
			തുടരുക;
		എങ്കിൽ (buf[off] == '\n') {
			buf[off] = '\0';
			നിർത്തുക;
		}
		off++;
	}
	തിരികെ (off);
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
getproxypass(സ്ഥിരം അക്ഷരം *proxyuser, സ്ഥിരം അക്ഷരം *proxyhost)
{
	അക്ഷരം prompt[512];
	സ്ഥിതം അക്ഷരം pw[256];

	snprintf(prompt, വലുപ്പം(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	എങ്കിൽ (readpassphrase(prompt, pw, വലുപ്പം(pw), RPP_REQUIRE_TTY) == ശൂന്യ)
		errx(1, "Unable to read proxy passphrase");
	തിരികെ (pw);
}

പൂർണ്ണസംഖ്യ
socks_connect(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *port,
    ഘടന addrinfo hints __attribute__ ((__unused__)),
    സ്ഥിരം അക്ഷരം *proxyhost, സ്ഥിരം അക്ഷരം *proxyport, ഘടന addrinfo proxyhints,
    പൂർണ്ണസംഖ്യ socksv, സ്ഥിരം അക്ഷരം *proxyuser)
{
	പൂർണ്ണസംഖ്യ proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned അക്ഷരം buf[1024];
	size_t cnt;
	ഘടന sockaddr_storage addr;
	ഘടന sockaddr_in *in4 = (ഘടന sockaddr_in *)&addr;
	ഘടന sockaddr_in6 *in6 = (ഘടന sockaddr_in6 *)&addr;
	in_port_t serverport;
	സ്ഥിരം അക്ഷരം *proxypass = ശൂന്യ;

	എങ്കിൽ (proxyport == ശൂന്യ)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	എങ്കിൽ (decode_addrport("0.0.0.0", port, (ഘടന sockaddr *)&addr,
	    വലുപ്പം(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	എങ്കിൽ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	എങ്കിൽ (proxyfd < 0)
		തിരികെ (-1);

	എങ്കിൽ (socksv == 5) {
		എങ്കിൽ (decode_addrport(host, port, (ഘടന sockaddr *)&addr,
		    വലുപ്പം(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		എങ്കിൽ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(പഠ, proxyfd, buf, 2);
		എങ്കിൽ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		എങ്കിൽ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		തിരഞ്ഞെടുപ്പ് (addr.ss_family) {
		അവസ്ഥ 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			എങ്കിൽ (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, വലുപ്പം serverport);
			wlen = 7 + hlen;
			നിർത്തുക;
		അവസ്ഥ AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, വലുപ്പം in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, വലുപ്പം in4->sin_port);
			wlen = 10;
			നിർത്തുക;
		അവസ്ഥ AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, വലുപ്പം in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    വലുപ്പം in6->sin6_port);
			wlen = 22;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		എങ്കിൽ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(പഠ, proxyfd, buf, 4);
		എങ്കിൽ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		എങ്കിൽ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		തിരഞ്ഞെടുപ്പ് (buf[3]) {
		അവസ്ഥ SOCKS_IPV4:
			cnt = atomicio(പഠ, proxyfd, buf + 4, 6);
			എങ്കിൽ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			നിർത്തുക;
		അവസ്ഥ SOCKS_IPV6:
			cnt = atomicio(പഠ, proxyfd, buf + 4, 18);
			എങ്കിൽ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			errx(1, "connection failed, unsupported address type");
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (socksv == 4 || socksv == 44) {
		എങ്കിൽ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (ഘടന sockaddr *)&addr,
			    വലുപ്പം(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, വലുപ്പം in4->sin_port);
		എങ്കിൽ (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, വലുപ്പം in4->sin_addr);
		} അല്ലെങ്കിൽ {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		എങ്കിൽ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			എങ്കിൽ (strlcpy(buf + 9, host,
			    വലുപ്പം(buf) - 9) >= വലുപ്പം(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		എങ്കിൽ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(പഠ, proxyfd, buf, 8);
		എങ്കിൽ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		എങ്കിൽ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} അല്ലെങ്കിൽ എങ്കിൽ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		എങ്കിൽ (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		എങ്കിൽ (strchr(host, ':') != ശൂന്യ) {
			r = snprintf(buf, വലുപ്പം(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} അല്ലെങ്കിൽ {
			r = snprintf(buf, വലുപ്പം(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		എങ്കിൽ (r == -1 || (size_t)r >= വലുപ്പം(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		എങ്കിൽ (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		എങ്കിൽ (authretry > 1) {
			അക്ഷരം resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, വലുപ്പം(buf), "%s:%s",
			    proxyuser, proxypass);
			എങ്കിൽ (r == -1 || (size_t)r >= വലുപ്പം(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    വലുപ്പം(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, വലുപ്പം(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			എങ്കിൽ (r == -1 || (size_t)r >= വലുപ്പം(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			എങ്കിൽ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		എങ്കിൽ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_വരി(proxyfd, buf, വലുപ്പം(buf));
		എങ്കിൽ (proxyuser != ശൂന്യ &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			എങ്കിൽ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			പോകുക again;
		} അല്ലെങ്കിൽ എങ്കിൽ (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		വേണ്ടി (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_വരി(proxyfd, buf, വലുപ്പം(buf));
			എങ്കിൽ (*buf == '\0')
				നിർത്തുക;
		}
		എങ്കിൽ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} അല്ലെങ്കിൽ
		errx(1, "Unknown proxy protocol %d", socksv);

	തിരികെ (proxyfd);
}

