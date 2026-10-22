/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#అన్తర్భావ "includes.h"
 
#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/resource.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "dns.h"
#అన్తర్భావ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
పూర్ణాంకం IPv4or6 = AF_UNSPEC;

పూర్ణాంకం ssh_పోర్టు = SSH_DEFAULT_పోర్టు;

#నిర్వచించు KT_RSA		(1)
#నిర్వచించు KT_ECDSA	(1<<1)
#నిర్వచించు KT_ED25519	(1<<2)
#నిర్వచించు KT_ECDSA_SK	(1<<4)
#నిర్వచించు KT_ED25519_SK	(1<<5)
#నిర్వచించు KT_MLDSA44_ED25519 (1<<6)

#నిర్వచించు KT_MIN		KT_RSA
#నిర్వచించు KT_MAX		KT_MLDSA44_ED25519

పూర్ణాంకం get_cert = 0;
పూర్ణాంకం get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

పూర్ణాంకం hash_hosts = 0;		/* Hash hostname on output */

పూర్ణాంకం print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

పూర్ణాంకం దొరికింది_one = 0;		/* Successfully found a key */

పూర్ణాంకం hashalg = -1;		/* Hash for SSHFP records or -1 for all */

పూర్ణాంకం quiet = 0;			/* Don't print key comment lines */

#నిర్వచించు MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
పూర్ణాంకం timeout = 5;

పూర్ణాంకం maxfd;
#నిర్వచించు MAXCON (maxfd - 10)

బాహ్య అక్షరం *__progname;
నిర్మాణం pollfd *read_wait;
పూర్ణాంకం ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
రకనిర్వచనం నిర్మాణం Connection {
	u_char c_స్థితి;	/* State of connection on this file desc. */
#నిర్వచించు CS_వాడని 0		/* File descriptor unused */
#నిర్వచించు CS_CON 1		/* Waiting to connect/read greeting */
	పూర్ణాంకం c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	పూర్ణాంకం c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_పూర్తి;	/* SSH2 done */
	అక్షరం *c_namebase;	/* Address to free for c_name and c_namelist */
	అక్షరం *c_name;		/* Hostname of connection for errors */
	అక్షరం *c_namelist;	/* Pointer to other possible addresses */
	అక్షరం *c_output_name;	/* Hostname of connection for output */
	నిర్మాణం ssh *c_ssh;	/* SSH-connection */
	అక్షరం c_banner[256];	/* Partial server greeting */
	కొలత_t c_banner_len;	/* Length of partial server greeting */
	పూర్ణాంకం c_banner_పంపిన;	/* Client greeting has been sent */
	నిర్మాణం timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

స్థిర శూన్య keyprint(con *c, నిర్మాణం sshkey *కీలకం);

స్థిర పూర్ణాంకం
fdlim_get(పూర్ణాంకం hard)
{
#ఒకవేళ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	నిర్మాణం rlimit rlfd;
	rlim_t lim;

	ఒకవేళ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		తిరిగి -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	ఒకవేళ (lim <= 0)
		తిరిగి -1;
	ఒకవేళ (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	ఒకవేళ (lim >= గరిష్ఠ_పూర్ణాంకం)
		lim = గరిష్ఠ_పూర్ణాంకం;
	తిరిగి lim;
#లేకపోతే
	తిరిగి (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= గరిష్ఠ_పూర్ణాంకం) ? గరిష్ఠ_పూర్ణాంకం : SSH_SYSFDMAX);
#అయితే_ముగింపు
}

స్థిర పూర్ణాంకం
fdlim_సమితి(పూర్ణాంకం lim)
{
#ఒకవేళ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	నిర్మాణం rlimit rlfd;
#అయితే_ముగింపు

	ఒకవేళ (lim <= 0)
		తిరిగి (-1);
#ఒకవేళ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ఒకవేళ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		తిరిగి (-1);
	rlfd.rlim_cur = lim;
	ఒకవేళ (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		తిరిగి (-1);
#లేదావేళ defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#అయితే_ముగింపు
	తిరిగి (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
స్థిర అక్షరం *
xstrsep(అక్షరం **str, స్థిరరాశి అక్షరం *delim)
{
	అక్షరం *s, *e;

	ఒకవేళ (!**str)
		తిరిగి (ఖాళీ);

	s = *str;
	e = s + strcspn(s, delim);

	ఒకవేళ (*e != '\0')
		*e++ = '\0';
	*str = e;

	తిరిగి (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
స్థిర అక్షరం *
strnnsep(అక్షరం **stringp, అక్షరం *delim)
{
	అక్షరం *tok;

	చేయి {
		tok = xstrsep(stringp, delim);
	} అయితే (tok && *tok == '\0');
	తిరిగి (tok);
}


స్థిర పూర్ణాంకం
కీలకం_print_wrapper(నిర్మాణం sshkey *hostkey, నిర్మాణం ssh *ssh)
{
	con *c;

	ఒకవేళ ((c = ssh_get_app_దత్తాంశం(ssh)) != ఖాళీ)
		keyprint(c, hostkey);
	/* always abort key exchange */
	తిరిగి -1;
}

స్థిర పూర్ణాంకం
ssh2_capable(పూర్ణాంకం remote_major, పూర్ణాంకం remote_minor)
{
	ఎంపిక (remote_major) {
	స్థితి 1:
		ఒకవేళ (remote_minor == 99)
			తిరిగి 1;
		ఆపు;
	స్థితి 2:
		తిరిగి 1;
	అప్రమేయ:
		ఆపు;
	}
	తిరిగి 0;
}

స్థిర శూన్య
keygrab_ssh2(con *c)
{
	అక్షరం *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	పూర్ణాంకం r;

	ఎంపిక (c->c_keytype) {
	స్థితి KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		ఆపు;
	స్థితి KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		ఆపు;
	స్థితి KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		ఆపు;
	స్థితి KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		ఆపు;
	స్థితి KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		ఆపు;
	స్థితి KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		ఆపు;
	అప్రమేయ:
		fatal("unknown key type %d", c->c_keytype);
		ఆపు;
	}
	ఒకవేళ ((r = kex_అమరిక(c->c_ssh, myproposal)) != 0) {
		విడుదల(c->c_ssh);
		fprintf(stderr, "kex_setup: %s\n", ssh_err(r));
		నిష్క్రమించు(1);
	}
#నిర్వచితమైతే WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#అయితే_ముగింపు
	c->c_ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh_సమితి_verify_host_కీలకం_callback(c->c_ssh, కీలకం_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_నిరంతరం(c->c_ssh, DISPATCH_ఖండం, &c->c_పూర్తి);
}

స్థిర శూన్య
keyprint_one(స్థిరరాశి అక్షరం *host, నిర్మాణం sshkey *కీలకం)
{
	అక్షరం *hostport = ఖాళీ, *hashed = ఖాళీ;
	స్థిరరాశి అక్షరం *తెలిసిన_host;
	పూర్ణాంకం r = 0;

	దొరికింది_one = 1;

	ఒకవేళ (print_sshfp) {
		export_dns_rr(host, కీలకం, stdout, 0, hashalg);
		తిరిగి;
	}

	hostport = put_host_పోర్టు(host, ssh_పోర్టు);
	lowercase(hostport);
	ఒకవేళ (hash_hosts && (hashed = host_hash(hostport, ఖాళీ, 0)) == ఖాళీ)
		fatal("host_hash failed");
	తెలిసిన_host = hash_hosts ? hashed : hostport;
	ఒకవేళ (!get_cert)
		r = fprintf(stdout, "%s ", తెలిసిన_host);
	ఒకవేళ (r >= 0 && sshkey_write(కీలకం, stdout) == 0)
		(శూన్య)fputs("\n", stdout);
	విడుదల(hashed);
	విడుదల(hostport);
}

స్థిర శూన్య
keyprint(con *c, నిర్మాణం sshkey *కీలకం)
{
	అక్షరం *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	అక్షరం *host, *ohosts;

	ఒకవేళ (కీలకం == ఖాళీ)
		తిరిగి;
	ఒకవేళ (get_cert || (!hash_hosts && ssh_పోర్టు == SSH_DEFAULT_పోర్టు)) {
		keyprint_one(hosts, కీలకం);
		తిరిగి;
	}
	ohosts = hosts = xstrdup(hosts);
	అయితే ((host = strsep(&hosts, ",")) != ఖాళీ)
		keyprint_one(host, కీలకం);
	విడుదల(ohosts);
}

స్థిర పూర్ణాంకం
tcpconnect(అక్షరం *host)
{
	నిర్మాణం addrinfo hints, *ai, *aitop;
	అక్షరం strport[NI_MAXSERV];
	పూర్ణాంకం gaierr, s = -1;

	snprintf(strport, పరిమాణం strport, "%d", ssh_పోర్టు);
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	ఒకవేళ ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		తిరిగి -1;
	}
	కొరకు (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ఒకవేళ (s == -1) {
			error("socket: %s", strerror(errno));
			కొనసాగు;
		}
		ఒకవేళ (సమితి_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		ఒకవేళ (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		లేకపోతే
			ఆపు;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	తిరిగి s;
}

స్థిర పూర్ణాంకం
conalloc(స్థిరరాశి అక్షరం *iname, స్థిరరాశి అక్షరం *oname, పూర్ణాంకం keytype)
{
	అక్షరం *namebase, *name, *namelist;
	పూర్ణాంకం s;

	namebase = namelist = xstrdup(iname);

	చేయి {
		name = xstrsep(&namelist, ",");
		ఒకవేళ (!name) {
			విడుదల(namebase);
			తిరిగి (-1);
		}
	} అయితే ((s = tcpconnect(name)) < 0);

	ఒకవేళ (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	ఒకవేళ (fdcon[s].c_స్థితి)
		fatal("conalloc: attempt to reuse fdno %d", s);

	debug3_f("oname %s kt %d", oname, keytype);
	fdcon[s].c_fd = s;
	fdcon[s].c_స్థితి = CS_CON;
	fdcon[s].c_namebase = namebase;
	fdcon[s].c_name = name;
	fdcon[s].c_namelist = namelist;
	fdcon[s].c_output_name = xstrdup(oname);
	fdcon[s].c_keytype = keytype;
	fdcon[s].c_banner_len = 0;
	fdcon[s].c_banner_పంపిన = 0;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	తిరిగి (s);
}

స్థిర శూన్య
confree(పూర్ణాంకం s)
{
	ఒకవేళ (s >= maxfd || fdcon[s].c_స్థితి == CS_వాడని)
		fatal("confree: attempt to free bad fdno %d", s);
	విడుదల(fdcon[s].c_namebase);
	విడుదల(fdcon[s].c_output_name);
	fdcon[s].c_స్థితి = CS_వాడని;
	fdcon[s].c_keytype = 0;
	ఒకవేళ (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		విడుదల(fdcon[s].c_ssh);
		fdcon[s].c_ssh = ఖాళీ;
	} లేకపోతే
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

స్థిర పూర్ణాంకం
conrecycle(పూర్ణాంకం s)
{
	con *c = &fdcon[s];
	పూర్ణాంకం ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	తిరిగి (ret);
}

స్థిర శూన్య
congreet(పూర్ణాంకం s)
{
	పూర్ణాంకం remote_major = 0, remote_minor = 0;
	ssize_t n;
	అక్షరం buf[256], ch;
	అక్షరం remote_సంస్కరణ[పరిమాణం buf];
	con *c = &fdcon[s];

	ఒకవేళ (!c->c_banner_పంపిన) {
		/* send client banner */
		n = snprintf(buf, పరిమాణం buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		ఒకవేళ (n < 0 || (కొలత_t)n >= పరిమాణం(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			తిరిగి;
		}
		ఒకవేళ (atomicio(vwrite, s, buf, n) != (కొలత_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			తిరిగి;
		}
		c->c_banner_పంపిన = 1;
	}

	/*
	 * Read the server banner as per RFC4253 section 4.2.  The "SSH-"
	 * protocol identification string may be preceded by an arbitrarily
	 * large banner which we must read and ignore.  Read a single byte
	 * at a time so that the event loop retains control of connection
	 * timeouts.  Partial lines are retained in the connection state
	 * between calls.
	 */
	n = పఠ(s, &ch, పరిమాణం(ch));
	ఒకవేళ (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		తిరిగి;
	ఒకవేళ (n != 1) {
		ఒకవేళ (n == 0)
			errno = EPIPE;
		ఎంపిక (errno) {
		స్థితి EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			ఆపు;
		స్థితి ECONNREFUSED:
			ఆపు;
		అప్రమేయ:
			error("read (%s): %s", c->c_name, strerror(errno));
			ఆపు;
		}
		conrecycle(s);
		తిరిగి;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	ఒకవేళ (ch != '\n') {
		ఒకవేళ (c->c_banner_len < పరిమాణం(c->c_banner) - 1)
			తిరిగి; /* incomplete line */
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			తిరిగి;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		తిరిగి;
	}
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		తిరిగి;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	జ్ఞాపకం_నకలు(buf, c->c_banner, c->c_banner_len);
	ఒకవేళ ((c->c_ssh = ssh_packet_సమితి_connection(ఖాళీ, s, s)) == ఖాళీ)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_సమితి_timeout(c->c_ssh, timeout, 1);
	ssh_సమితి_app_దత్తాంశం(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	ఒకవేళ (అక్షరశ్రేణి_చదువు(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_సంస్కరణ) == 3)
		compat_banner(c->c_ssh, remote_సంస్కరణ);
	ఒకవేళ (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		తిరిగి;
	}
	ఒకవేళ (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_పోర్టు, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

స్థిర శూన్య
conread(పూర్ణాంకం s)
{
	con *c = &fdcon[s];

	ఒకవేళ (c->c_స్థితి != CS_CON)
		fatal("conread: invalid status %d", c->c_స్థితి);

	congreet(s);
}

స్థిర శూన్య
conloop(శూన్య)
{
	నిర్మాణం timespec seltime, now;
	con *c;
	పూర్ణాంకం i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	ఒకవేళ (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	లేకపోతే
		timespecclear(&seltime);

	అయితే (ppoll(read_wait, maxfd, &seltime, ఖాళీ) == -1) {
		ఒకవేళ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			కొనసాగు;
		error("poll error");
	}

	కొరకు (i = 0; i < maxfd; i++) {
		ఒకవేళ (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		లేకపోతే ఒకవేళ (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	అయితే (c && timespeccmp(&c->c_ts, &now, <)) {
		పూర్ణాంకం s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

స్థిర శూన్య
do_one_host(అక్షరం *host)
{
	అక్షరం *name = strnnsep(&host, " \t\n");
	పూర్ణాంకం j;

	ఒకవేళ (name == ఖాళీ)
		తిరిగి;
	కొరకు (j = KT_MIN; j <= KT_MAX; j *= 2) {
		ఒకవేళ (get_keytypes & j) {
			అయితే (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

స్థిర శూన్య
do_host(అక్షరం *host)
{
	అక్షరం daddr[128];
	నిర్మాణం xaddr addr, చివర_addr;
	u_int masklen;

	ఒకవేళ (host == ఖాళీ)
		తిరిగి;
	ఒకవేళ (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} లేకపోతే {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		చివర_addr = addr;
		ఒకవేళ (addr_host_గమ్యం_all1s(&చివర_addr, masklen) != 0)
			వెళ్ళు badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		కొరకు (;;) {
			ఒకవేళ (addr_ntop(&addr, daddr, పరిమాణం(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				తిరిగి;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			ఒకవేళ (addr_cmp(&addr, &చివర_addr) == 0)
				ఆపు;
			addr_increment(&addr);
		}
	}
}

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	పూర్ణాంకం opt, fopt_లెక్క = 0, j;
	అక్షరం *tname, *cp, *పంక్తి = ఖాళీ;
	కొలత_t linesize = 0;
	FILE *fp;

	బాహ్య పూర్ణాంకం optind;
	బాహ్య అక్షరం *optarg;

	__progname = ssh_get_progname(argv[0]);
	విత్తనం_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	ఒకవేళ (argc <= 1)
		usage();

	అయితే ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		ఎంపిక (opt) {
		స్థితి 'H':
			hash_hosts = 1;
			ఆపు;
		స్థితి 'c':
			get_cert = 1;
			ఆపు;
		స్థితి 'D':
			print_sshfp = 1;
			ఆపు;
		స్థితి 'p':
			ssh_పోర్టు = a2port(optarg);
			ఒకవేళ (ssh_పోర్టు <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'T':
			timeout = convtime(optarg);
			ఒకవేళ (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			ఆపు;
		స్థితి 'v':
			ఒకవేళ (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			లేకపోతే ఒకవేళ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			లేకపోతే
				fatal("Too high debugging level.");
			ఆపు;
		స్థితి 'q':
			quiet = 1;
			ఆపు;
		స్థితి 'f':
			ఒకవేళ (strcmp(optarg, "-") == 0)
				optarg = ఖాళీ;
			argv[fopt_లెక్క++] = optarg;
			ఆపు;
		స్థితి 'O':
			/* Maybe other misc options in the future too */
			ఒకవేళ (అక్షరశ్రేణి_పోలిక(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			ఒకవేళ ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			ఆపు;
		స్థితి 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			అయితే (tname) {
				పూర్ణాంకం type = sshkey_type_from_shortname(tname);

				ఎంపిక (type) {
				స్థితి కీలకం_ECDSA:
					get_keytypes |= KT_ECDSA;
					ఆపు;
				స్థితి కీలకం_RSA:
					get_keytypes |= KT_RSA;
					ఆపు;
				స్థితి కీలకం_ED25519:
					get_keytypes |= KT_ED25519;
					ఆపు;
				స్థితి కీలకం_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					ఆపు;
				స్థితి కీలకం_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					ఆపు;
				స్థితి కీలకం_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					ఆపు;
				స్థితి కీలకం_UNSPEC:
				అప్రమేయ:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(ఖాళీ, ",");
			}
			ఆపు;
		స్థితి '4':
			IPv4or6 = AF_INET;
			ఆపు;
		స్థితి '6':
			IPv4or6 = AF_INET6;
			ఆపు;
		అప్రమేయ:
			usage();
		}
	}
	ఒకవేళ (optind == argc && !fopt_లెక్క)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	ఒకవేళ (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	ఒకవేళ (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	ఒకవేళ (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	ఒకవేళ (maxfd > fdlim_get(0))
		fdlim_సమితి(maxfd);
	fdcon = xcalloc(maxfd, పరిమాణం(con));
	read_wait = xcalloc(maxfd, పరిమాణం(నిర్మాణం pollfd));
	కొరకు (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	కొరకు (j = 0; j < fopt_లెక్క; j++) {
		ఒకవేళ (argv[j] == ఖాళీ)
			fp = stdin;
		లేకపోతే ఒకవేళ ((fp = fopen(argv[j], "r")) == ఖాళీ)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		అయితే (getline(&పంక్తి, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			ఒకవేళ ((cp = strchr(పంక్తి, '#')) == ఖాళీ)
				cp = పంక్తి + అక్షరశ్రేణి_పొడవు(పంక్తి) - 1;
			అయితే (cp >= పంక్తి) {
				ఒకవేళ (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				లేకపోతే
					ఆపు;
			}

			/* Skip empty lines */
			ఒకవేళ (*పంక్తి == '\0')
				కొనసాగు;

			do_host(పంక్తి);
		}

		ఒకవేళ (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ఒకవేళ (fp != stdin)
			fclose(fp);
	}
	విడుదల(పంక్తి);

	అయితే (optind < argc)
		do_host(argv[optind++]);

	అయితే (ncon > 0)
		conloop();

	తిరిగి దొరికింది_one ? 0 : 1;
}
