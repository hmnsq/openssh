/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#ضمن "includes.h"
 
#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/queue.h>
#ضمن <sys/time.h>
#ضمن <sys/resource.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/bn.h>
#جيڪڏهن_پورو

#ضمن <errno.h>
#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <poll.h>
#ضمن <signal.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "cipher.h"
#ضمن "digest.h"
#ضمن "kex.h"
#ضمن "compat.h"
#ضمن "myproposal.h"
#ضمن "packet.h"
#ضمن "dispatch.h"
#ضمن "log.h"
#ضمن "atomicio.h"
#ضمن "misc.h"
#ضمن "hostfile.h"
#ضمن "ssherr.h"
#ضمن "ssh_api.h"
#ضمن "dns.h"
#ضمن "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
صحيح IPv4or6 = AF_UNSPEC;

صحيح ssh_پورٽ = SSH_DEFAULT_پورٽ;

#وصف_ڪريو KT_RSA		(1)
#وصف_ڪريو KT_ECDSA	(1<<1)
#وصف_ڪريو KT_ED25519	(1<<2)
#وصف_ڪريو KT_ECDSA_SK	(1<<4)
#وصف_ڪريو KT_ED25519_SK	(1<<5)
#وصف_ڪريو KT_MLDSA44_ED25519 (1<<6)

#وصف_ڪريو KT_MIN		KT_RSA
#وصف_ڪريو KT_MAX		KT_MLDSA44_ED25519

صحيح get_cert = 0;
صحيح get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

صحيح hash_hosts = 0;		/* Hash hostname on output */

صحيح print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

صحيح مليو_one = 0;		/* Successfully found a key */

صحيح hashalg = -1;		/* Hash for SSHFP records or -1 for all */

صحيح quiet = 0;			/* Don't print key comment lines */

#وصف_ڪريو MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
صحيح timeout = 5;

صحيح maxfd;
#وصف_ڪريو MAXCON (maxfd - 10)

خارجي حرف *__progname;
بنية pollfd *read_wait;
صحيح ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
تعريفنوع بنية Connection {
	u_char c_حالت;	/* State of connection on this file desc. */
#وصف_ڪريو CS_اڻ_استعمال_ٿيل 0		/* File descriptor unused */
#وصف_ڪريو CS_CON 1		/* Waiting to connect/read greeting */
	صحيح c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	صحيح c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_پورو;	/* SSH2 done */
	حرف *c_namebase;	/* Address to free for c_name and c_namelist */
	حرف *c_name;		/* Hostname of connection for errors */
	حرف *c_namelist;	/* Pointer to other possible addresses */
	حرف *c_output_name;	/* Hostname of connection for output */
	بنية ssh *c_ssh;	/* SSH-connection */
	حرف c_banner[256];	/* Partial server greeting */
	سائيز_t c_banner_len;	/* Length of partial server greeting */
	صحيح c_banner_موڪليل;	/* Client greeting has been sent */
	بنية timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

ساكن فراغ keyprint(con *c, بنية sshkey *ڪنجي);

ساكن صحيح
fdlim_get(صحيح hard)
{
#إذا defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	بنية rlimit rlfd;
	rlim_t lim;

	إذا (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		أرجع -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	إذا (lim <= 0)
		أرجع -1;
	إذا (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	إذا (lim >= وڌ_کان_وڌ_عدد)
		lim = وڌ_کان_وڌ_عدد;
	أرجع lim;
#وإلا
	أرجع (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= وڌ_کان_وڌ_عدد) ? وڌ_کان_وڌ_عدد : SSH_SYSFDMAX);
#جيڪڏهن_پورو
}

ساكن صحيح
fdlim_سيٽ(صحيح lim)
{
#إذا defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	بنية rlimit rlfd;
#جيڪڏهن_پورو

	إذا (lim <= 0)
		أرجع (-1);
#إذا defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	إذا (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		أرجع (-1);
	rlfd.rlim_cur = lim;
	إذا (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		أرجع (-1);
#وإلاإذا defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#جيڪڏهن_پورو
	أرجع (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
ساكن حرف *
xstrsep(حرف **str, ثابت حرف *delim)
{
	حرف *s, *e;

	إذا (!**str)
		أرجع (عدم);

	s = *str;
	e = s + strcspn(s, delim);

	إذا (*e != '\0')
		*e++ = '\0';
	*str = e;

	أرجع (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
ساكن حرف *
strnnsep(حرف **stringp, حرف *delim)
{
	حرف *tok;

	افعل {
		tok = xstrsep(stringp, delim);
	} طالما (tok && *tok == '\0');
	أرجع (tok);
}


ساكن صحيح
ڪنجي_print_wrapper(بنية sshkey *hostkey, بنية ssh *ssh)
{
	con *c;

	إذا ((c = ssh_get_app_معلومات(ssh)) != عدم)
		keyprint(c, hostkey);
	/* always abort key exchange */
	أرجع -1;
}

ساكن صحيح
ssh2_capable(صحيح remote_major, صحيح remote_minor)
{
	بدل (remote_major) {
	حالة 1:
		إذا (remote_minor == 99)
			أرجع 1;
		اكسر;
	حالة 2:
		أرجع 1;
	افتراضي:
		اكسر;
	}
	أرجع 0;
}

ساكن فراغ
keygrab_ssh2(con *c)
{
	حرف *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	صحيح r;

	بدل (c->c_keytype) {
	حالة KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_ڪنجي_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		اكسر;
	حالة KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ڪنجي_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		اكسر;
	حالة KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_ڪنجي_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		اكسر;
	حالة KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ڪنجي_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		اكسر;
	حالة KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_ڪنجي_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		اكسر;
	حالة KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_ڪنجي_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		اكسر;
	افتراضي:
		fatal("unknown key type %d", c->c_keytype);
		اكسر;
	}
	إذا ((r = kex_تياري(c->c_ssh, myproposal)) != 0) {
		حرر(c->c_ssh);
		fprintf(stderr, "kex_setup: %s\n", ssh_err(r));
		ٻاهر_نڪرو(1);
	}
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#جيڪڏهن_پورو
	c->c_ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh_سيٽ_verify_host_ڪنجي_callback(c->c_ssh, ڪنجي_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_لاڳيتو(c->c_ssh, DISPATCH_بلاڪ, &c->c_پورو);
}

ساكن فراغ
keyprint_one(ثابت حرف *host, بنية sshkey *ڪنجي)
{
	حرف *hostport = عدم, *hashed = عدم;
	ثابت حرف *معلوم_host;
	صحيح r = 0;

	مليو_one = 1;

	إذا (print_sshfp) {
		export_dns_rr(host, ڪنجي, stdout, 0, hashalg);
		أرجع;
	}

	hostport = put_host_پورٽ(host, ssh_پورٽ);
	lowercase(hostport);
	إذا (hash_hosts && (hashed = host_hash(hostport, عدم, 0)) == عدم)
		fatal("host_hash failed");
	معلوم_host = hash_hosts ? hashed : hostport;
	إذا (!get_cert)
		r = fprintf(stdout, "%s ", معلوم_host);
	إذا (r >= 0 && sshkey_write(ڪنجي, stdout) == 0)
		(فراغ)fputs("\n", stdout);
	حرر(hashed);
	حرر(hostport);
}

ساكن فراغ
keyprint(con *c, بنية sshkey *ڪنجي)
{
	حرف *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	حرف *host, *ohosts;

	إذا (ڪنجي == عدم)
		أرجع;
	إذا (get_cert || (!hash_hosts && ssh_پورٽ == SSH_DEFAULT_پورٽ)) {
		keyprint_one(hosts, ڪنجي);
		أرجع;
	}
	ohosts = hosts = xstrdup(hosts);
	طالما ((host = strsep(&hosts, ",")) != عدم)
		keyprint_one(host, ڪنجي);
	حرر(ohosts);
}

ساكن صحيح
tcpconnect(حرف *host)
{
	بنية addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحيح gaierr, s = -1;

	snprintf(strport, حجم strport, "%d", ssh_پورٽ);
	memset(&hints, 0, حجم(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	إذا ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		أرجع -1;
	}
	لكل (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		إذا (s == -1) {
			error("socket: %s", strerror(errno));
			استمر;
		}
		إذا (سيٽ_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		إذا (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		وإلا
			اكسر;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	أرجع s;
}

ساكن صحيح
conalloc(ثابت حرف *iname, ثابت حرف *oname, صحيح keytype)
{
	حرف *namebase, *name, *namelist;
	صحيح s;

	namebase = namelist = xstrdup(iname);

	افعل {
		name = xstrsep(&namelist, ",");
		إذا (!name) {
			حرر(namebase);
			أرجع (-1);
		}
	} طالما ((s = tcpconnect(name)) < 0);

	إذا (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	إذا (fdcon[s].c_حالت)
		fatal("conalloc: attempt to reuse fdno %d", s);

	debug3_f("oname %s kt %d", oname, keytype);
	fdcon[s].c_fd = s;
	fdcon[s].c_حالت = CS_CON;
	fdcon[s].c_namebase = namebase;
	fdcon[s].c_name = name;
	fdcon[s].c_namelist = namelist;
	fdcon[s].c_output_name = xstrdup(oname);
	fdcon[s].c_keytype = keytype;
	fdcon[s].c_banner_len = 0;
	fdcon[s].c_banner_موڪليل = 0;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	أرجع (s);
}

ساكن فراغ
confree(صحيح s)
{
	إذا (s >= maxfd || fdcon[s].c_حالت == CS_اڻ_استعمال_ٿيل)
		fatal("confree: attempt to free bad fdno %d", s);
	حرر(fdcon[s].c_namebase);
	حرر(fdcon[s].c_output_name);
	fdcon[s].c_حالت = CS_اڻ_استعمال_ٿيل;
	fdcon[s].c_keytype = 0;
	إذا (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		حرر(fdcon[s].c_ssh);
		fdcon[s].c_ssh = عدم;
	} وإلا
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

ساكن صحيح
conrecycle(صحيح s)
{
	con *c = &fdcon[s];
	صحيح ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	أرجع (ret);
}

ساكن فراغ
congreet(صحيح s)
{
	صحيح remote_major = 0, remote_minor = 0;
	ssize_t n;
	حرف buf[256], ch;
	حرف remote_نسخو[حجم buf];
	con *c = &fdcon[s];

	إذا (!c->c_banner_موڪليل) {
		/* send client banner */
		n = snprintf(buf, حجم buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		إذا (n < 0 || (سائيز_t)n >= حجم(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			أرجع;
		}
		إذا (atomicio(vwrite, s, buf, n) != (سائيز_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			أرجع;
		}
		c->c_banner_موڪليل = 1;
	}

	/*
	 * Read the server banner as per RFC4253 section 4.2.  The "SSH-"
	 * protocol identification string may be preceded by an arbitrarily
	 * large banner which we must read and ignore.  Read a single byte
	 * at a time so that the event loop retains control of connection
	 * timeouts.  Partial lines are retained in the connection state
	 * between calls.
	 */
	n = اقرأ(s, &ch, حجم(ch));
	إذا (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		أرجع;
	إذا (n != 1) {
		إذا (n == 0)
			errno = EPIPE;
		بدل (errno) {
		حالة EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			اكسر;
		حالة ECONNREFUSED:
			اكسر;
		افتراضي:
			error("read (%s): %s", c->c_name, strerror(errno));
			اكسر;
		}
		conrecycle(s);
		أرجع;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	إذا (ch != '\n') {
		إذا (c->c_banner_len < حجم(c->c_banner) - 1)
			أرجع; /* incomplete line */
		إذا (لڙي_ڀيٽ(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			أرجع;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		أرجع;
	}
	إذا (لڙي_ڀيٽ(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		أرجع;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	يادگيري_نقل(buf, c->c_banner, c->c_banner_len);
	إذا ((c->c_ssh = ssh_packet_سيٽ_connection(عدم, s, s)) == عدم)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_سيٽ_timeout(c->c_ssh, timeout, 1);
	ssh_سيٽ_app_معلومات(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	إذا (لڙي_مان_پڙهو(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_نسخو) == 3)
		compat_banner(c->c_ssh, remote_نسخو);
	إذا (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		أرجع;
	}
	إذا (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_پورٽ, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

ساكن فراغ
conread(صحيح s)
{
	con *c = &fdcon[s];

	إذا (c->c_حالت != CS_CON)
		fatal("conread: invalid status %d", c->c_حالت);

	congreet(s);
}

ساكن فراغ
conloop(فراغ)
{
	بنية timespec seltime, now;
	con *c;
	صحيح i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	إذا (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	وإلا
		timespecclear(&seltime);

	طالما (ppoll(read_wait, maxfd, &seltime, عدم) == -1) {
		إذا (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			استمر;
		error("poll error");
	}

	لكل (i = 0; i < maxfd; i++) {
		إذا (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		وإلا إذا (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	طالما (c && timespeccmp(&c->c_ts, &now, <)) {
		صحيح s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

ساكن فراغ
do_one_host(حرف *host)
{
	حرف *name = strnnsep(&host, " \t\n");
	صحيح j;

	إذا (name == عدم)
		أرجع;
	لكل (j = KT_MIN; j <= KT_MAX; j *= 2) {
		إذا (get_keytypes & j) {
			طالما (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

ساكن فراغ
do_host(حرف *host)
{
	حرف daddr[128];
	بنية xaddr addr, پڇاڙي_addr;
	u_int masklen;

	إذا (host == عدم)
		أرجع;
	إذا (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} وإلا {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		پڇاڙي_addr = addr;
		إذا (addr_host_منزل_all1s(&پڇاڙي_addr, masklen) != 0)
			اذهب badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		لكل (;;) {
			إذا (addr_ntop(&addr, daddr, حجم(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				أرجع;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			إذا (addr_cmp(&addr, &پڇاڙي_addr) == 0)
				اكسر;
			addr_increment(&addr);
		}
	}
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	ٻاهر_نڪرو(1);
}

صحيح
مکيه(صحيح argc, حرف **argv)
{
	صحيح debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	صحيح opt, fopt_ڳڻپ = 0, j;
	حرف *tname, *cp, *سٽ = عدم;
	سائيز_t linesize = 0;
	FILE *fp;

	خارجي صحيح optind;
	خارجي حرف *optarg;

	__progname = ssh_get_progname(argv[0]);
	ٻج_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	إذا (argc <= 1)
		usage();

	طالما ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		بدل (opt) {
		حالة 'H':
			hash_hosts = 1;
			اكسر;
		حالة 'c':
			get_cert = 1;
			اكسر;
		حالة 'D':
			print_sshfp = 1;
			اكسر;
		حالة 'p':
			ssh_پورٽ = a2port(optarg);
			إذا (ssh_پورٽ <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				ٻاهر_نڪرو(1);
			}
			اكسر;
		حالة 'T':
			timeout = convtime(optarg);
			إذا (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			اكسر;
		حالة 'v':
			إذا (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			وإلا إذا (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			وإلا
				fatal("Too high debugging level.");
			اكسر;
		حالة 'q':
			quiet = 1;
			اكسر;
		حالة 'f':
			إذا (strcmp(optarg, "-") == 0)
				optarg = عدم;
			argv[fopt_ڳڻپ++] = optarg;
			اكسر;
		حالة 'O':
			/* Maybe other misc options in the future too */
			إذا (لڙي_ڀيٽ(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			إذا ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			اكسر;
		حالة 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			طالما (tname) {
				صحيح type = sshkey_type_from_shortname(tname);

				بدل (type) {
				حالة ڪنجي_ECDSA:
					get_keytypes |= KT_ECDSA;
					اكسر;
				حالة ڪنجي_RSA:
					get_keytypes |= KT_RSA;
					اكسر;
				حالة ڪنجي_ED25519:
					get_keytypes |= KT_ED25519;
					اكسر;
				حالة ڪنجي_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					اكسر;
				حالة ڪنجي_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					اكسر;
				حالة ڪنجي_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					اكسر;
				حالة ڪنجي_UNSPEC:
				افتراضي:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(عدم, ",");
			}
			اكسر;
		حالة '4':
			IPv4or6 = AF_INET;
			اكسر;
		حالة '6':
			IPv4or6 = AF_INET6;
			اكسر;
		افتراضي:
			usage();
		}
	}
	إذا (optind == argc && !fopt_ڳڻپ)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	إذا (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	إذا (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	إذا (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	إذا (maxfd > fdlim_get(0))
		fdlim_سيٽ(maxfd);
	fdcon = xcalloc(maxfd, حجم(con));
	read_wait = xcalloc(maxfd, حجم(بنية pollfd));
	لكل (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	لكل (j = 0; j < fopt_ڳڻپ; j++) {
		إذا (argv[j] == عدم)
			fp = stdin;
		وإلا إذا ((fp = fopen(argv[j], "r")) == عدم)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		طالما (getline(&سٽ, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			إذا ((cp = strchr(سٽ, '#')) == عدم)
				cp = سٽ + لڙي_ڊيگهه(سٽ) - 1;
			طالما (cp >= سٽ) {
				إذا (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				وإلا
					اكسر;
			}

			/* Skip empty lines */
			إذا (*سٽ == '\0')
				استمر;

			do_host(سٽ);
		}

		إذا (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		إذا (fp != stdin)
			fclose(fp);
	}
	حرر(سٽ);

	طالما (optind < argc)
		do_host(argv[optind++]);

	طالما (ncon > 0)
		conloop();

	أرجع مليو_one ? 0 : 1;
}
