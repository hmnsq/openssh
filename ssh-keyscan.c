/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#அந்தர்பாவ "includes.h"
 
#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/resource.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#endif

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "dns.h"
#அந்தர்பாவ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
முழு IPv4or6 = AF_UNSPEC;

முழு ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

முழு get_cert = 0;
முழு get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

முழு hash_hosts = 0;		/* Hash hostname on output */

முழு print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

முழு found_one = 0;		/* Successfully found a key */

முழு hashalg = -1;		/* Hash for SSHFP records or -1 for all */

முழு quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
முழு timeout = 5;

முழு maxfd;
#define MAXCON (maxfd - 10)

வெளி எழுத்து *__progname;
கட்டமைப்பு pollfd *read_wait;
முழு ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
வகைவரை கட்டமைப்பு Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	முழு c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	முழு c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	எழுத்து *c_namebase;	/* Address to free for c_name and c_namelist */
	எழுத்து *c_name;		/* Hostname of connection for errors */
	எழுத்து *c_namelist;	/* Pointer to other possible addresses */
	எழுத்து *c_output_name;	/* Hostname of connection for output */
	கட்டமைப்பு ssh *c_ssh;	/* SSH-connection */
	எழுத்து c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	முழு c_banner_sent;	/* Client greeting has been sent */
	கட்டமைப்பு timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

நிலையான வெறுமை keyprint(con *c, கட்டமைப்பு sshkey *சாவி);

நிலையான முழு
fdlim_get(முழு hard)
{
#எனில் defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	கட்டமைப்பு rlimit rlfd;
	rlim_t lim;

	எனில் (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		திரும்பு -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	எனில் (lim <= 0)
		திரும்பு -1;
	எனில் (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	எனில் (lim >= INT_MAX)
		lim = INT_MAX;
	திரும்பு lim;
#இல்லையெனில்
	திரும்பு (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

நிலையான முழு
fdlim_set(முழு lim)
{
#எனில் defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	கட்டமைப்பு rlimit rlfd;
#endif

	எனில் (lim <= 0)
		திரும்பு (-1);
#எனில் defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	எனில் (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		திரும்பு (-1);
	rlfd.rlim_cur = lim;
	எனில் (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		திரும்பு (-1);
#அல்லதெனில் defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	திரும்பு (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
நிலையான எழுத்து *
xstrsep(எழுத்து **str, மாறிலி எழுத்து *delim)
{
	எழுத்து *s, *e;

	எனில் (!**str)
		திரும்பு (வெற்று);

	s = *str;
	e = s + strcspn(s, delim);

	எனில் (*e != '\0')
		*e++ = '\0';
	*str = e;

	திரும்பு (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
நிலையான எழுத்து *
strnnsep(எழுத்து **stringp, எழுத்து *delim)
{
	எழுத்து *tok;

	செய் {
		tok = xstrsep(stringp, delim);
	} போது (tok && *tok == '\0');
	திரும்பு (tok);
}


நிலையான முழு
சாவி_print_wrapper(கட்டமைப்பு sshkey *hostkey, கட்டமைப்பு ssh *ssh)
{
	con *c;

	எனில் ((c = ssh_get_app_data(ssh)) != வெற்று)
		keyprint(c, hostkey);
	/* always abort key exchange */
	திரும்பு -1;
}

நிலையான முழு
ssh2_capable(முழு remote_major, முழு remote_minor)
{
	தேர்வு (remote_major) {
	நிலை 1:
		எனில் (remote_minor == 99)
			திரும்பு 1;
		நிறுத்து;
	நிலை 2:
		திரும்பு 1;
	இயல்பு:
		நிறுத்து;
	}
	திரும்பு 0;
}

நிலையான வெறுமை
keygrab_ssh2(con *c)
{
	எழுத்து *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	முழு r;

	தேர்வு (c->c_keytype) {
	நிலை KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_சாவி_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		நிறுத்து;
	நிலை KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_சாவி_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		நிறுத்து;
	நிலை KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_சாவி_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		நிறுத்து;
	நிலை KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_சாவி_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		நிறுத்து;
	நிலை KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_சாவி_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		நிறுத்து;
	நிலை KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_சாவி_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		நிறுத்து;
	இயல்பு:
		fatal("unknown key type %d", c->c_keytype);
		நிறுத்து;
	}
	எனில் ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		விடுவி(c->c_ssh);
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
	ssh_set_verify_host_சாவி_callback(c->c_ssh, சாவி_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

நிலையான வெறுமை
keyprint_one(மாறிலி எழுத்து *host, கட்டமைப்பு sshkey *சாவி)
{
	எழுத்து *hostport = வெற்று, *hashed = வெற்று;
	மாறிலி எழுத்து *known_host;
	முழு r = 0;

	found_one = 1;

	எனில் (print_sshfp) {
		export_dns_rr(host, சாவி, stdout, 0, hashalg);
		திரும்பு;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	எனில் (hash_hosts && (hashed = host_hash(hostport, வெற்று, 0)) == வெற்று)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	எனில் (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	எனில் (r >= 0 && sshkey_write(சாவி, stdout) == 0)
		(வெறுமை)fputs("\n", stdout);
	விடுவி(hashed);
	விடுவி(hostport);
}

நிலையான வெறுமை
keyprint(con *c, கட்டமைப்பு sshkey *சாவி)
{
	எழுத்து *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	எழுத்து *host, *ohosts;

	எனில் (சாவி == வெற்று)
		திரும்பு;
	எனில் (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, சாவி);
		திரும்பு;
	}
	ohosts = hosts = xstrdup(hosts);
	போது ((host = strsep(&hosts, ",")) != வெற்று)
		keyprint_one(host, சாவி);
	விடுவி(ohosts);
}

நிலையான முழு
tcpconnect(எழுத்து *host)
{
	கட்டமைப்பு addrinfo hints, *ai, *aitop;
	எழுத்து strport[NI_MAXSERV];
	முழு gaierr, s = -1;

	snprintf(strport, அளவு strport, "%d", ssh_port);
	memset(&hints, 0, அளவு(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	எனில் ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		திரும்பு -1;
	}
	க்கு (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		எனில் (s == -1) {
			error("socket: %s", strerror(errno));
			தொடர்;
		}
		எனில் (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		எனில் (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		இல்லையெனில்
			நிறுத்து;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	திரும்பு s;
}

நிலையான முழு
conalloc(மாறிலி எழுத்து *iname, மாறிலி எழுத்து *oname, முழு keytype)
{
	எழுத்து *namebase, *name, *namelist;
	முழு s;

	namebase = namelist = xstrdup(iname);

	செய் {
		name = xstrsep(&namelist, ",");
		எனில் (!name) {
			விடுவி(namebase);
			திரும்பு (-1);
		}
	} போது ((s = tcpconnect(name)) < 0);

	எனில் (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	எனில் (fdcon[s].c_status)
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
	திரும்பு (s);
}

நிலையான வெறுமை
confree(முழு s)
{
	எனில் (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	விடுவி(fdcon[s].c_namebase);
	விடுவி(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	எனில் (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		விடுவி(fdcon[s].c_ssh);
		fdcon[s].c_ssh = வெற்று;
	} இல்லையெனில்
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

நிலையான முழு
conrecycle(முழு s)
{
	con *c = &fdcon[s];
	முழு ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	திரும்பு (ret);
}

நிலையான வெறுமை
congreet(முழு s)
{
	முழு remote_major = 0, remote_minor = 0;
	ssize_t n;
	எழுத்து buf[256], ch;
	எழுத்து remote_version[அளவு buf];
	con *c = &fdcon[s];

	எனில் (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, அளவு buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		எனில் (n < 0 || (size_t)n >= அளவு(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			திரும்பு;
		}
		எனில் (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			திரும்பு;
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
	n = பட(s, &ch, அளவு(ch));
	எனில் (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		திரும்பு;
	எனில் (n != 1) {
		எனில் (n == 0)
			errno = EPIPE;
		தேர்வு (errno) {
		நிலை EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			நிறுத்து;
		நிலை ECONNREFUSED:
			நிறுத்து;
		இயல்பு:
			error("read (%s): %s", c->c_name, strerror(errno));
			நிறுத்து;
		}
		conrecycle(s);
		திரும்பு;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	எனில் (ch != '\n') {
		எனில் (c->c_banner_len < அளவு(c->c_banner) - 1)
			திரும்பு; /* incomplete line */
		எனில் (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			திரும்பு;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		திரும்பு;
	}
	எனில் (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		திரும்பு;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	எனில் ((c->c_ssh = ssh_packet_set_connection(வெற்று, s, s)) == வெற்று)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	எனில் (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	எனில் (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		திரும்பு;
	}
	எனில் (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

நிலையான வெறுமை
conread(முழு s)
{
	con *c = &fdcon[s];

	எனில் (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

நிலையான வெறுமை
conloop(வெறுமை)
{
	கட்டமைப்பு timespec seltime, now;
	con *c;
	முழு i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	எனில் (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	இல்லையெனில்
		timespecclear(&seltime);

	போது (ppoll(read_wait, maxfd, &seltime, வெற்று) == -1) {
		எனில் (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			தொடர்;
		error("poll error");
	}

	க்கு (i = 0; i < maxfd; i++) {
		எனில் (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		இல்லையெனில் எனில் (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	போது (c && timespeccmp(&c->c_ts, &now, <)) {
		முழு s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

நிலையான வெறுமை
do_one_host(எழுத்து *host)
{
	எழுத்து *name = strnnsep(&host, " \t\n");
	முழு j;

	எனில் (name == வெற்று)
		திரும்பு;
	க்கு (j = KT_MIN; j <= KT_MAX; j *= 2) {
		எனில் (get_keytypes & j) {
			போது (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

நிலையான வெறுமை
do_host(எழுத்து *host)
{
	எழுத்து daddr[128];
	கட்டமைப்பு xaddr addr, end_addr;
	u_int masklen;

	எனில் (host == வெற்று)
		திரும்பு;
	எனில் (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} இல்லையெனில் {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		எனில் (addr_host_to_all1s(&end_addr, masklen) != 0)
			செல் badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		க்கு (;;) {
			எனில் (addr_ntop(&addr, daddr, அளவு(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				திரும்பு;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			எனில் (addr_cmp(&addr, &end_addr) == 0)
				நிறுத்து;
			addr_increment(&addr);
		}
	}
}

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	முழு debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	முழு opt, fopt_மொத்தம் = 0, j;
	எழுத்து *tname, *cp, *வரி = வெற்று;
	size_t linesize = 0;
	FILE *fp;

	வெளி முழு optind;
	வெளி எழுத்து *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	எனில் (argc <= 1)
		usage();

	போது ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		தேர்வு (opt) {
		நிலை 'H':
			hash_hosts = 1;
			நிறுத்து;
		நிலை 'c':
			get_cert = 1;
			நிறுத்து;
		நிலை 'D':
			print_sshfp = 1;
			நிறுத்து;
		நிலை 'p':
			ssh_port = a2port(optarg);
			எனில் (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			நிறுத்து;
		நிலை 'T':
			timeout = convtime(optarg);
			எனில் (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			நிறுத்து;
		நிலை 'v':
			எனில் (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			இல்லையெனில் எனில் (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			இல்லையெனில்
				fatal("Too high debugging level.");
			நிறுத்து;
		நிலை 'q':
			quiet = 1;
			நிறுத்து;
		நிலை 'f':
			எனில் (strcmp(optarg, "-") == 0)
				optarg = வெற்று;
			argv[fopt_மொத்தம்++] = optarg;
			நிறுத்து;
		நிலை 'O':
			/* Maybe other misc options in the future too */
			எனில் (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			எனில் ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			நிறுத்து;
		நிலை 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			போது (tname) {
				முழு type = sshkey_type_from_shortname(tname);

				தேர்வு (type) {
				நிலை சாவி_ECDSA:
					get_keytypes |= KT_ECDSA;
					நிறுத்து;
				நிலை சாவி_RSA:
					get_keytypes |= KT_RSA;
					நிறுத்து;
				நிலை சாவி_ED25519:
					get_keytypes |= KT_ED25519;
					நிறுத்து;
				நிலை சாவி_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					நிறுத்து;
				நிலை சாவி_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					நிறுத்து;
				நிலை சாவி_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					நிறுத்து;
				நிலை சாவி_UNSPEC:
				இயல்பு:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(வெற்று, ",");
			}
			நிறுத்து;
		நிலை '4':
			IPv4or6 = AF_INET;
			நிறுத்து;
		நிலை '6':
			IPv4or6 = AF_INET6;
			நிறுத்து;
		இயல்பு:
			usage();
		}
	}
	எனில் (optind == argc && !fopt_மொத்தம்)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	எனில் (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	எனில் (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	எனில் (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	எனில் (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, அளவு(con));
	read_wait = xcalloc(maxfd, அளவு(கட்டமைப்பு pollfd));
	க்கு (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	க்கு (j = 0; j < fopt_மொத்தம்; j++) {
		எனில் (argv[j] == வெற்று)
			fp = stdin;
		இல்லையெனில் எனில் ((fp = fopen(argv[j], "r")) == வெற்று)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		போது (getline(&வரி, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			எனில் ((cp = strchr(வரி, '#')) == வெற்று)
				cp = வரி + strlen(வரி) - 1;
			போது (cp >= வரி) {
				எனில் (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				இல்லையெனில்
					நிறுத்து;
			}

			/* Skip empty lines */
			எனில் (*வரி == '\0')
				தொடர்;

			do_host(வரி);
		}

		எனில் (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		எனில் (fp != stdin)
			fclose(fp);
	}
	விடுவி(வரி);

	போது (optind < argc)
		do_host(argv[optind++]);

	போது (ncon > 0)
		conloop();

	திரும்பு found_one ? 0 : 1;
}
