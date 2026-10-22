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

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#endif

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

صحیح ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

صحیح get_cert = 0;
صحیح get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

صحیح hash_hosts = 0;		/* Hash hostname on output */

صحیح print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

صحیح found_one = 0;		/* Successfully found a key */

صحیح hashalg = -1;		/* Hash for SSHFP records or -1 for all */

صحیح quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
صحیح timeout = 5;

صحیح maxfd;
#define MAXCON (maxfd - 10)

بیرونی نویسه *__progname;
ساختار pollfd *read_wait;
صحیح ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
تعریفنوع ساختار Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	صحیح c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	صحیح c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	نویسه *c_namebase;	/* Address to free for c_name and c_namelist */
	نویسه *c_name;		/* Hostname of connection for errors */
	نویسه *c_namelist;	/* Pointer to other possible addresses */
	نویسه *c_output_name;	/* Hostname of connection for output */
	ساختار ssh *c_ssh;	/* SSH-connection */
	نویسه c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	صحیح c_banner_sent;	/* Client greeting has been sent */
	ساختار timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

ایستا تهی keyprint(con *c, ساختار sshkey *کلید);

ایستا صحیح
fdlim_get(صحیح hard)
{
#اگر defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ساختار rlimit rlfd;
	rlim_t lim;

	اگر (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		بازگشت -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	اگر (lim <= 0)
		بازگشت -1;
	اگر (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	اگر (lim >= INT_MAX)
		lim = INT_MAX;
	بازگشت lim;
#وگرنه
	بازگشت (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

ایستا صحیح
fdlim_set(صحیح lim)
{
#اگر defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ساختار rlimit rlfd;
#endif

	اگر (lim <= 0)
		بازگشت (-1);
#اگر defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	اگر (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		بازگشت (-1);
	rlfd.rlim_cur = lim;
	اگر (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		بازگشت (-1);
#وگرنهاگر defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	بازگشت (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
ایستا نویسه *
xstrsep(نویسه **str, ثابت نویسه *delim)
{
	نویسه *s, *e;

	اگر (!**str)
		بازگشت (پوچ);

	s = *str;
	e = s + strcspn(s, delim);

	اگر (*e != '\0')
		*e++ = '\0';
	*str = e;

	بازگشت (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
ایستا نویسه *
strnnsep(نویسه **stringp, نویسه *delim)
{
	نویسه *tok;

	انجامبده {
		tok = xstrsep(stringp, delim);
	} وقتی (tok && *tok == '\0');
	بازگشت (tok);
}


ایستا صحیح
کلید_print_wrapper(ساختار sshkey *hostkey, ساختار ssh *ssh)
{
	con *c;

	اگر ((c = ssh_get_app_data(ssh)) != پوچ)
		keyprint(c, hostkey);
	/* always abort key exchange */
	بازگشت -1;
}

ایستا صحیح
ssh2_capable(صحیح remote_major, صحیح remote_minor)
{
	انتخاب (remote_major) {
	حالت 1:
		اگر (remote_minor == 99)
			بازگشت 1;
		بشکن;
	حالت 2:
		بازگشت 1;
	پیشفرض:
		بشکن;
	}
	بازگشت 0;
}

ایستا تهی
keygrab_ssh2(con *c)
{
	نویسه *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
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
		بشکن;
	حالت KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		بشکن;
	حالت KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		بشکن;
	حالت KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		بشکن;
	حالت KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		بشکن;
	حالت KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		بشکن;
	پیشفرض:
		fatal("unknown key type %d", c->c_keytype);
		بشکن;
	}
	اگر ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		آزاد(c->c_ssh);
		fprintf(stderr, "kex_setup: %s\n", ssh_err(r));
		exit(1);
	}
#ifdef WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#endif
	c->c_ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh_set_verify_host_کلید_callback(c->c_ssh, کلید_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

ایستا تهی
keyprint_one(ثابت نویسه *host, ساختار sshkey *کلید)
{
	نویسه *hostport = پوچ, *hashed = پوچ;
	ثابت نویسه *known_host;
	صحیح r = 0;

	found_one = 1;

	اگر (print_sshfp) {
		export_dns_rr(host, کلید, stdout, 0, hashalg);
		بازگشت;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	اگر (hash_hosts && (hashed = host_hash(hostport, پوچ, 0)) == پوچ)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	اگر (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	اگر (r >= 0 && sshkey_write(کلید, stdout) == 0)
		(تهی)fputs("\n", stdout);
	آزاد(hashed);
	آزاد(hostport);
}

ایستا تهی
keyprint(con *c, ساختار sshkey *کلید)
{
	نویسه *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	نویسه *host, *ohosts;

	اگر (کلید == پوچ)
		بازگشت;
	اگر (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, کلید);
		بازگشت;
	}
	ohosts = hosts = xstrdup(hosts);
	وقتی ((host = strsep(&hosts, ",")) != پوچ)
		keyprint_one(host, کلید);
	آزاد(ohosts);
}

ایستا صحیح
tcpconnect(نویسه *host)
{
	ساختار addrinfo hints, *ai, *aitop;
	نویسه strport[NI_MAXSERV];
	صحیح gaierr, s = -1;

	snprintf(strport, اندازه strport, "%d", ssh_port);
	memset(&hints, 0, اندازه(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	اگر ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		بازگشت -1;
	}
	برای (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		اگر (s == -1) {
			error("socket: %s", strerror(errno));
			ادامه;
		}
		اگر (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		اگر (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		وگرنه
			بشکن;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	بازگشت s;
}

ایستا صحیح
conalloc(ثابت نویسه *iname, ثابت نویسه *oname, صحیح keytype)
{
	نویسه *namebase, *name, *namelist;
	صحیح s;

	namebase = namelist = xstrdup(iname);

	انجامبده {
		name = xstrsep(&namelist, ",");
		اگر (!name) {
			آزاد(namebase);
			بازگشت (-1);
		}
	} وقتی ((s = tcpconnect(name)) < 0);

	اگر (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	اگر (fdcon[s].c_status)
		fatal("conalloc: attempt to reuse fdno %d", s);

	debug3_f("oname %s kt %d", oname, keytype);
	fdcon[s].c_fd = s;
	fdcon[s].c_status = CS_CON;
	fdcon[s].c_namebase = namebase;
	fdcon[s].c_name = name;
	fdcon[s].c_namelist = namelist;
	fdcon[s].c_output_name = xstrdup(oname);
	fdcon[s].c_keytype = keytype;
	fdcon[s].c_banner_len = 0;
	fdcon[s].c_banner_sent = 0;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	بازگشت (s);
}

ایستا تهی
confree(صحیح s)
{
	اگر (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	آزاد(fdcon[s].c_namebase);
	آزاد(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	اگر (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		آزاد(fdcon[s].c_ssh);
		fdcon[s].c_ssh = پوچ;
	} وگرنه
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

ایستا صحیح
conrecycle(صحیح s)
{
	con *c = &fdcon[s];
	صحیح ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	بازگشت (ret);
}

ایستا تهی
congreet(صحیح s)
{
	صحیح remote_major = 0, remote_minor = 0;
	ssize_t n;
	نویسه buf[256], ch;
	نویسه remote_version[اندازه buf];
	con *c = &fdcon[s];

	اگر (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, اندازه buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		اگر (n < 0 || (size_t)n >= اندازه(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			بازگشت;
		}
		اگر (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			بازگشت;
		}
		c->c_banner_sent = 1;
	}

	/*
	 * Read the server banner as per RFC4253 section 4.2.  The "SSH-"
	 * protocol identification string may be preceded by an arbitrarily
	 * large banner which we must read and ignore.  Read a single byte
	 * at a time so that the event loop retains control of connection
	 * timeouts.  Partial lines are retained in the connection state
	 * between calls.
	 */
	n = اقرأ(s, &ch, اندازه(ch));
	اگر (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		بازگشت;
	اگر (n != 1) {
		اگر (n == 0)
			errno = EPIPE;
		انتخاب (errno) {
		حالت EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			بشکن;
		حالت ECONNREFUSED:
			بشکن;
		پیشفرض:
			error("read (%s): %s", c->c_name, strerror(errno));
			بشکن;
		}
		conrecycle(s);
		بازگشت;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	اگر (ch != '\n') {
		اگر (c->c_banner_len < اندازه(c->c_banner) - 1)
			بازگشت; /* incomplete line */
		اگر (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			بازگشت;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		بازگشت;
	}
	اگر (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		بازگشت;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	اگر ((c->c_ssh = ssh_packet_set_connection(پوچ, s, s)) == پوچ)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	اگر (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	اگر (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		بازگشت;
	}
	اگر (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

ایستا تهی
conread(صحیح s)
{
	con *c = &fdcon[s];

	اگر (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

ایستا تهی
conloop(تهی)
{
	ساختار timespec seltime, now;
	con *c;
	صحیح i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	اگر (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	وگرنه
		timespecclear(&seltime);

	وقتی (ppoll(read_wait, maxfd, &seltime, پوچ) == -1) {
		اگر (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ادامه;
		error("poll error");
	}

	برای (i = 0; i < maxfd; i++) {
		اگر (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		وگرنه اگر (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	وقتی (c && timespeccmp(&c->c_ts, &now, <)) {
		صحیح s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

ایستا تهی
do_one_host(نویسه *host)
{
	نویسه *name = strnnsep(&host, " \t\n");
	صحیح j;

	اگر (name == پوچ)
		بازگشت;
	برای (j = KT_MIN; j <= KT_MAX; j *= 2) {
		اگر (get_keytypes & j) {
			وقتی (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

ایستا تهی
do_host(نویسه *host)
{
	نویسه daddr[128];
	ساختار xaddr addr, end_addr;
	u_int masklen;

	اگر (host == پوچ)
		بازگشت;
	اگر (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} وگرنه {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		اگر (addr_host_to_all1s(&end_addr, masklen) != 0)
			برو badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		برای (;;) {
			اگر (addr_ntop(&addr, daddr, اندازه(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				بازگشت;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			اگر (addr_cmp(&addr, &end_addr) == 0)
				بشکن;
			addr_increment(&addr);
		}
	}
}

ایستا تهی
usage(تهی)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	صحیح debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	صحیح opt, fopt_شمار = 0, j;
	نویسه *tname, *cp, *سطر = پوچ;
	size_t linesize = 0;
	FILE *fp;

	بیرونی صحیح optind;
	بیرونی نویسه *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	اگر (argc <= 1)
		usage();

	وقتی ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		انتخاب (opt) {
		حالت 'H':
			hash_hosts = 1;
			بشکن;
		حالت 'c':
			get_cert = 1;
			بشکن;
		حالت 'D':
			print_sshfp = 1;
			بشکن;
		حالت 'p':
			ssh_port = a2port(optarg);
			اگر (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			بشکن;
		حالت 'T':
			timeout = convtime(optarg);
			اگر (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			بشکن;
		حالت 'v':
			اگر (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			وگرنه اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			وگرنه
				fatal("Too high debugging level.");
			بشکن;
		حالت 'q':
			quiet = 1;
			بشکن;
		حالت 'f':
			اگر (strcmp(optarg, "-") == 0)
				optarg = پوچ;
			argv[fopt_شمار++] = optarg;
			بشکن;
		حالت 'O':
			/* Maybe other misc options in the future too */
			اگر (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			اگر ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			بشکن;
		حالت 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			وقتی (tname) {
				صحیح type = sshkey_type_from_shortname(tname);

				انتخاب (type) {
				حالت کلید_ECDSA:
					get_keytypes |= KT_ECDSA;
					بشکن;
				حالت کلید_RSA:
					get_keytypes |= KT_RSA;
					بشکن;
				حالت کلید_ED25519:
					get_keytypes |= KT_ED25519;
					بشکن;
				حالت کلید_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					بشکن;
				حالت کلید_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					بشکن;
				حالت کلید_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					بشکن;
				حالت کلید_UNSPEC:
				پیشفرض:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(پوچ, ",");
			}
			بشکن;
		حالت '4':
			IPv4or6 = AF_INET;
			بشکن;
		حالت '6':
			IPv4or6 = AF_INET6;
			بشکن;
		پیشفرض:
			usage();
		}
	}
	اگر (optind == argc && !fopt_شمار)
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
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, اندازه(con));
	read_wait = xcalloc(maxfd, اندازه(ساختار pollfd));
	برای (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	برای (j = 0; j < fopt_شمار; j++) {
		اگر (argv[j] == پوچ)
			fp = stdin;
		وگرنه اگر ((fp = fopen(argv[j], "r")) == پوچ)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		وقتی (getline(&سطر, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			اگر ((cp = strchr(سطر, '#')) == پوچ)
				cp = سطر + strlen(سطر) - 1;
			وقتی (cp >= سطر) {
				اگر (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				وگرنه
					بشکن;
			}

			/* Skip empty lines */
			اگر (*سطر == '\0')
				ادامه;

			do_host(سطر);
		}

		اگر (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		اگر (fp != stdin)
			fclose(fp);
	}
	آزاد(سطر);

	وقتی (optind < argc)
		do_host(argv[optind++]);

	وقتی (ncon > 0)
		conloop();

	بازگشت found_one ? 0 : 1;
}
