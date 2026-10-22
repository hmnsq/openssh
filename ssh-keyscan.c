/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#شامل "includes.h"
 
#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/queue.h>
#شامل <sys/time.h>
#شامل <sys/resource.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#اگر_ختم

#شامل <errno.h>
#شامل <limits.h>
#شامل <netdb.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "cipher.h"
#شامل "digest.h"
#شامل "kex.h"
#شامل "compat.h"
#شامل "myproposal.h"
#شامل "packet.h"
#شامل "dispatch.h"
#شامل "log.h"
#شامل "atomicio.h"
#شامل "misc.h"
#شامل "hostfile.h"
#شامل "ssherr.h"
#شامل "ssh_api.h"
#شامل "dns.h"
#شامل "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
صحیح IPv4or6 = AF_UNSPEC;

صحیح ssh_پورٹ = SSH_DEFAULT_پورٹ;

#تعریف_کرو KT_RSA		(1)
#تعریف_کرو KT_ECDSA	(1<<1)
#تعریف_کرو KT_ED25519	(1<<2)
#تعریف_کرو KT_ECDSA_SK	(1<<4)
#تعریف_کرو KT_ED25519_SK	(1<<5)
#تعریف_کرو KT_MLDSA44_ED25519 (1<<6)

#تعریف_کرو KT_MIN		KT_RSA
#تعریف_کرو KT_MAX		KT_MLDSA44_ED25519

صحیح get_cert = 0;
صحیح get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

صحیح hash_hosts = 0;		/* Hash hostname on output */

صحیح print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

صحیح ملا_one = 0;		/* Successfully found a key */

صحیح hashalg = -1;		/* Hash for SSHFP records or -1 for all */

صحیح quiet = 0;			/* Don't print key comment lines */

#تعریف_کرو MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
صحیح timeout = 5;

صحیح maxfd;
#تعریف_کرو MAXCON (maxfd - 10)

خارجی حرف *__progname;
ساخت pollfd *read_wait;
صحیح ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
قسمتعریف ساخت Connection {
	u_char c_حالت;	/* State of connection on this file desc. */
#تعریف_کرو CS_غیر_مستعمل 0		/* File descriptor unused */
#تعریف_کرو CS_CON 1		/* Waiting to connect/read greeting */
	صحیح c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	صحیح c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_مکمل;	/* SSH2 done */
	حرف *c_namebase;	/* Address to free for c_name and c_namelist */
	حرف *c_name;		/* Hostname of connection for errors */
	حرف *c_namelist;	/* Pointer to other possible addresses */
	حرف *c_output_name;	/* Hostname of connection for output */
	ساخت ssh *c_ssh;	/* SSH-connection */
	حرف c_banner[256];	/* Partial server greeting */
	سائز_t c_banner_len;	/* Length of partial server greeting */
	صحیح c_banner_بھیجا;	/* Client greeting has been sent */
	ساخت timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

ساکن خالی keyprint(con *c, ساخت sshkey *کلید);

ساکن صحیح
fdlim_get(صحیح hard)
{
#اگر defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ساخت rlimit rlfd;
	rlim_t lim;

	اگر (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		واپس -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	اگر (lim <= 0)
		واپس -1;
	اگر (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	اگر (lim >= زیادہ_سے_زیادہ_عدد)
		lim = زیادہ_سے_زیادہ_عدد;
	واپس lim;
#ورنہ
	واپس (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= زیادہ_سے_زیادہ_عدد) ? زیادہ_سے_زیادہ_عدد : SSH_SYSFDMAX);
#اگر_ختم
}

ساکن صحیح
fdlim_سیٹ(صحیح lim)
{
#اگر defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ساخت rlimit rlfd;
#اگر_ختم

	اگر (lim <= 0)
		واپس (-1);
#اگر defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	اگر (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		واپس (-1);
	rlfd.rlim_cur = lim;
	اگر (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		واپس (-1);
#وگرنہ_اگر defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#اگر_ختم
	واپس (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
ساکن حرف *
xstrsep(حرف **str, ثابت حرف *delim)
{
	حرف *s, *e;

	اگر (!**str)
		واپس (تہی);

	s = *str;
	e = s + strcspn(s, delim);

	اگر (*e != '\0')
		*e++ = '\0';
	*str = e;

	واپس (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
ساکن حرف *
strnnsep(حرف **stringp, حرف *delim)
{
	حرف *tok;

	کرو {
		tok = xstrsep(stringp, delim);
	} جب (tok && *tok == '\0');
	واپس (tok);
}


ساکن صحیح
کلید_print_wrapper(ساخت sshkey *hostkey, ساخت ssh *ssh)
{
	con *c;

	اگر ((c = ssh_get_app_ڈیٹا(ssh)) != تہی)
		keyprint(c, hostkey);
	/* always abort key exchange */
	واپس -1;
}

ساکن صحیح
ssh2_capable(صحیح remote_major, صحیح remote_minor)
{
	انتخاب (remote_major) {
	حالت 1:
		اگر (remote_minor == 99)
			واپس 1;
		توڑو;
	حالت 2:
		واپس 1;
	طےشدہ:
		توڑو;
	}
	واپس 0;
}

ساکن خالی
keygrab_ssh2(con *c)
{
	حرف *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	صحیح r;

	انتخاب (c->c_keytype) {
	حالت KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		توڑو;
	حالت KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		توڑو;
	حالت KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		توڑو;
	حالت KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		توڑو;
	حالت KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		توڑو;
	حالت KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		توڑو;
	طےشدہ:
		fatal("unknown key type %d", c->c_keytype);
		توڑو;
	}
	اگر ((r = kex_تیاری(c->c_ssh, myproposal)) != 0) {
		آزاد(c->c_ssh);
		fprintf(stderr, "kex_setup: %s\n", ssh_err(r));
		باہر_نکلو(1);
	}
#اگر_تعریف_شدہ WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#اگر_ختم
	c->c_ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh_سیٹ_verify_host_کلید_callback(c->c_ssh, کلید_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_تسلسل(c->c_ssh, DISPATCH_بلاک, &c->c_مکمل);
}

ساکن خالی
keyprint_one(ثابت حرف *host, ساخت sshkey *کلید)
{
	حرف *hostport = تہی, *hashed = تہی;
	ثابت حرف *معلوم_host;
	صحیح r = 0;

	ملا_one = 1;

	اگر (print_sshfp) {
		export_dns_rr(host, کلید, stdout, 0, hashalg);
		واپس;
	}

	hostport = put_host_پورٹ(host, ssh_پورٹ);
	lowercase(hostport);
	اگر (hash_hosts && (hashed = host_hash(hostport, تہی, 0)) == تہی)
		fatal("host_hash failed");
	معلوم_host = hash_hosts ? hashed : hostport;
	اگر (!get_cert)
		r = fprintf(stdout, "%s ", معلوم_host);
	اگر (r >= 0 && sshkey_write(کلید, stdout) == 0)
		(خالی)fputs("\n", stdout);
	آزاد(hashed);
	آزاد(hostport);
}

ساکن خالی
keyprint(con *c, ساخت sshkey *کلید)
{
	حرف *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	حرف *host, *ohosts;

	اگر (کلید == تہی)
		واپس;
	اگر (get_cert || (!hash_hosts && ssh_پورٹ == SSH_DEFAULT_پورٹ)) {
		keyprint_one(hosts, کلید);
		واپس;
	}
	ohosts = hosts = xstrdup(hosts);
	جب ((host = strsep(&hosts, ",")) != تہی)
		keyprint_one(host, کلید);
	آزاد(ohosts);
}

ساکن صحیح
tcpconnect(حرف *host)
{
	ساخت addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحیح gaierr, s = -1;

	snprintf(strport, حجم strport, "%d", ssh_پورٹ);
	memset(&hints, 0, حجم(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	اگر ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		واپس -1;
	}
	برائے (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		اگر (s == -1) {
			error("socket: %s", strerror(errno));
			جاری;
		}
		اگر (سیٹ_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		اگر (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		ورنہ
			توڑو;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	واپس s;
}

ساکن صحیح
conalloc(ثابت حرف *iname, ثابت حرف *oname, صحیح keytype)
{
	حرف *namebase, *name, *namelist;
	صحیح s;

	namebase = namelist = xstrdup(iname);

	کرو {
		name = xstrsep(&namelist, ",");
		اگر (!name) {
			آزاد(namebase);
			واپس (-1);
		}
	} جب ((s = tcpconnect(name)) < 0);

	اگر (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	اگر (fdcon[s].c_حالت)
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
	fdcon[s].c_banner_بھیجا = 0;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	واپس (s);
}

ساکن خالی
confree(صحیح s)
{
	اگر (s >= maxfd || fdcon[s].c_حالت == CS_غیر_مستعمل)
		fatal("confree: attempt to free bad fdno %d", s);
	آزاد(fdcon[s].c_namebase);
	آزاد(fdcon[s].c_output_name);
	fdcon[s].c_حالت = CS_غیر_مستعمل;
	fdcon[s].c_keytype = 0;
	اگر (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		آزاد(fdcon[s].c_ssh);
		fdcon[s].c_ssh = تہی;
	} ورنہ
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

ساکن صحیح
conrecycle(صحیح s)
{
	con *c = &fdcon[s];
	صحیح ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	واپس (ret);
}

ساکن خالی
congreet(صحیح s)
{
	صحیح remote_major = 0, remote_minor = 0;
	ssize_t n;
	حرف buf[256], ch;
	حرف remote_نسخہ[حجم buf];
	con *c = &fdcon[s];

	اگر (!c->c_banner_بھیجا) {
		/* send client banner */
		n = snprintf(buf, حجم buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		اگر (n < 0 || (سائز_t)n >= حجم(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			واپس;
		}
		اگر (atomicio(vwrite, s, buf, n) != (سائز_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			واپس;
		}
		c->c_banner_بھیجا = 1;
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
	اگر (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		واپس;
	اگر (n != 1) {
		اگر (n == 0)
			errno = EPIPE;
		انتخاب (errno) {
		حالت EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			توڑو;
		حالت ECONNREFUSED:
			توڑو;
		طےشدہ:
			error("read (%s): %s", c->c_name, strerror(errno));
			توڑو;
		}
		conrecycle(s);
		واپس;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	اگر (ch != '\n') {
		اگر (c->c_banner_len < حجم(c->c_banner) - 1)
			واپس; /* incomplete line */
		اگر (لڑی_موازنہ(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			واپس;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		واپس;
	}
	اگر (لڑی_موازنہ(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		واپس;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	حافظہ_نقل(buf, c->c_banner, c->c_banner_len);
	اگر ((c->c_ssh = ssh_packet_سیٹ_connection(تہی, s, s)) == تہی)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_سیٹ_timeout(c->c_ssh, timeout, 1);
	ssh_سیٹ_app_ڈیٹا(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	اگر (لڑی_سے_پڑھو(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_نسخہ) == 3)
		compat_banner(c->c_ssh, remote_نسخہ);
	اگر (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		واپس;
	}
	اگر (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_پورٹ, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

ساکن خالی
conread(صحیح s)
{
	con *c = &fdcon[s];

	اگر (c->c_حالت != CS_CON)
		fatal("conread: invalid status %d", c->c_حالت);

	congreet(s);
}

ساکن خالی
conloop(خالی)
{
	ساخت timespec seltime, now;
	con *c;
	صحیح i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	اگر (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	ورنہ
		timespecclear(&seltime);

	جب (ppoll(read_wait, maxfd, &seltime, تہی) == -1) {
		اگر (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			جاری;
		error("poll error");
	}

	برائے (i = 0; i < maxfd; i++) {
		اگر (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		ورنہ اگر (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	جب (c && timespeccmp(&c->c_ts, &now, <)) {
		صحیح s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

ساکن خالی
do_one_host(حرف *host)
{
	حرف *name = strnnsep(&host, " \t\n");
	صحیح j;

	اگر (name == تہی)
		واپس;
	برائے (j = KT_MIN; j <= KT_MAX; j *= 2) {
		اگر (get_keytypes & j) {
			جب (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

ساکن خالی
do_host(حرف *host)
{
	حرف daddr[128];
	ساخت xaddr addr, انتہا_addr;
	u_int masklen;

	اگر (host == تہی)
		واپس;
	اگر (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} ورنہ {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		انتہا_addr = addr;
		اگر (addr_host_مقصد_all1s(&انتہا_addr, masklen) != 0)
			جاؤ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		برائے (;;) {
			اگر (addr_ntop(&addr, daddr, حجم(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				واپس;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			اگر (addr_cmp(&addr, &انتہا_addr) == 0)
				توڑو;
			addr_increment(&addr);
		}
	}
}

ساکن خالی
usage(خالی)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	باہر_نکلو(1);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	صحیح debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	صحیح opt, fopt_گنتی = 0, j;
	حرف *tname, *cp, *سطر = تہی;
	سائز_t linesize = 0;
	FILE *fp;

	خارجی صحیح optind;
	خارجی حرف *optarg;

	__progname = ssh_get_progname(argv[0]);
	بیج_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	اگر (argc <= 1)
		usage();

	جب ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		انتخاب (opt) {
		حالت 'H':
			hash_hosts = 1;
			توڑو;
		حالت 'c':
			get_cert = 1;
			توڑو;
		حالت 'D':
			print_sshfp = 1;
			توڑو;
		حالت 'p':
			ssh_پورٹ = a2port(optarg);
			اگر (ssh_پورٹ <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				باہر_نکلو(1);
			}
			توڑو;
		حالت 'T':
			timeout = convtime(optarg);
			اگر (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			توڑو;
		حالت 'v':
			اگر (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			ورنہ اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ورنہ
				fatal("Too high debugging level.");
			توڑو;
		حالت 'q':
			quiet = 1;
			توڑو;
		حالت 'f':
			اگر (strcmp(optarg, "-") == 0)
				optarg = تہی;
			argv[fopt_گنتی++] = optarg;
			توڑو;
		حالت 'O':
			/* Maybe other misc options in the future too */
			اگر (لڑی_موازنہ(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			اگر ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			توڑو;
		حالت 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			جب (tname) {
				صحیح type = sshkey_type_from_shortname(tname);

				انتخاب (type) {
				حالت کلید_ECDSA:
					get_keytypes |= KT_ECDSA;
					توڑو;
				حالت کلید_RSA:
					get_keytypes |= KT_RSA;
					توڑو;
				حالت کلید_ED25519:
					get_keytypes |= KT_ED25519;
					توڑو;
				حالت کلید_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					توڑو;
				حالت کلید_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					توڑو;
				حالت کلید_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					توڑو;
				حالت کلید_UNSPEC:
				طےشدہ:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(تہی, ",");
			}
			توڑو;
		حالت '4':
			IPv4or6 = AF_INET;
			توڑو;
		حالت '6':
			IPv4or6 = AF_INET6;
			توڑو;
		طےشدہ:
			usage();
		}
	}
	اگر (optind == argc && !fopt_گنتی)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	اگر (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	اگر (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	اگر (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	اگر (maxfd > fdlim_get(0))
		fdlim_سیٹ(maxfd);
	fdcon = xcalloc(maxfd, حجم(con));
	read_wait = xcalloc(maxfd, حجم(ساخت pollfd));
	برائے (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	برائے (j = 0; j < fopt_گنتی; j++) {
		اگر (argv[j] == تہی)
			fp = stdin;
		ورنہ اگر ((fp = fopen(argv[j], "r")) == تہی)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		جب (getline(&سطر, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			اگر ((cp = strchr(سطر, '#')) == تہی)
				cp = سطر + لڑی_لمبائی(سطر) - 1;
			جب (cp >= سطر) {
				اگر (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				ورنہ
					توڑو;
			}

			/* Skip empty lines */
			اگر (*سطر == '\0')
				جاری;

			do_host(سطر);
		}

		اگر (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		اگر (fp != stdin)
			fclose(fp);
	}
	آزاد(سطر);

	جب (optind < argc)
		do_host(argv[optind++]);

	جب (ncon > 0)
		conloop();

	واپس ملا_one ? 0 : 1;
}
