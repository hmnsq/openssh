/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#include "includes.h"
 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#endif

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "cipher.h"
#include "digest.h"
#include "kex.h"
#include "compat.h"
#include "myproposal.h"
#include "packet.h"
#include "dispatch.h"
#include "log.h"
#include "atomicio.h"
#include "misc.h"
#include "hostfile.h"
#include "ssherr.h"
#include "ssh_api.h"
#include "dns.h"
#include "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
puur_naa_nka IPv4or6 = AF_UNSPEC;

puur_naa_nka ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

puur_naa_nka get_cert = 0;
puur_naa_nka get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

puur_naa_nka hash_hosts = 0;		/* Hash hostname on output */

puur_naa_nka print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

puur_naa_nka found_one = 0;		/* Successfully found a key */

puur_naa_nka hashalg = -1;		/* Hash for SSHFP records or -1 for all */

puur_naa_nka quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
puur_naa_nka timeout = 5;

puur_naa_nka maxfd;
#define MAXCON (maxfd - 10)

extern var_na *__progname;
sa_nracanaa pollfd *read_wait;
puur_naa_nka ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
typedef sa_nracanaa Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	puur_naa_nka c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	puur_naa_nka c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	var_na *c_namebase;	/* Address to free for c_name and c_namelist */
	var_na *c_name;		/* Hostname of connection for errors */
	var_na *c_namelist;	/* Pointer to other possible addresses */
	var_na *c_output_name;	/* Hostname of connection for output */
	sa_nracanaa ssh *c_ssh;	/* SSH-connection */
	var_na c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	puur_naa_nka c_banner_sent;	/* Client greeting has been sent */
	sa_nracanaa timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

static void keyprint(con *c, sa_nracanaa sshkey *key);

static puur_naa_nka
fdlim_get(puur_naa_nka hard)
{
#ᯀᯮᯝ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	sa_nracanaa rlimit rlfd;
	rlim_t lim;

	ᯀᯮᯝ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ᯀᯮᯞ -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	ᯀᯮᯝ (lim <= 0)
		ᯀᯮᯞ -1;
	ᯀᯮᯝ (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	ᯀᯮᯝ (lim >= INT_MAX)
		lim = INT_MAX;
	ᯀᯮᯞ lim;
#ᯀᯮᯝᯂᯪ
	ᯀᯮᯞ (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

static puur_naa_nka
fdlim_set(puur_naa_nka lim)
{
#ᯀᯮᯝ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	sa_nracanaa rlimit rlfd;
#endif

	ᯀᯮᯝ (lim <= 0)
		ᯀᯮᯞ (-1);
#ᯀᯮᯝ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ᯀᯮᯝ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ᯀᯮᯞ (-1);
	rlfd.rlim_cur = lim;
	ᯀᯮᯝ (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ᯀᯮᯞ (-1);
#elif defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	ᯀᯮᯞ (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
static var_na *
xstrsep(var_na **str, const var_na *delim)
{
	var_na *s, *e;

	ᯀᯮᯝ (!**str)
		ᯀᯮᯞ (NULL);

	s = *str;
	e = s + strcspn(s, delim);

	ᯀᯮᯝ (*e != '\0')
		*e++ = '\0';
	*str = e;

	ᯀᯮᯞ (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
static var_na *
strnnsep(var_na **stringp, var_na *delim)
{
	var_na *tok;

	do {
		tok = xstrsep(stringp, delim);
	} ᯀᯬᯝ (tok && *tok == '\0');
	ᯀᯮᯞ (tok);
}


static puur_naa_nka
key_print_wrapper(sa_nracanaa sshkey *hostkey, sa_nracanaa ssh *ssh)
{
	con *c;

	ᯀᯮᯝ ((c = ssh_get_app_data(ssh)) != NULL)
		keyprint(c, hostkey);
	/* always abort key exchange */
	ᯀᯮᯞ -1;
}

static puur_naa_nka
ssh2_capable(puur_naa_nka remote_major, puur_naa_nka remote_minor)
{
	switch (remote_major) {
	pak_sa 1:
		ᯀᯮᯝ (remote_minor == 99)
			ᯀᯮᯞ 1;
		bha_nga;
	pak_sa 2:
		ᯀᯮᯞ 1;
	default:
		bha_nga;
	}
	ᯀᯮᯞ 0;
}

static void
keygrab_ssh2(con *c)
{
	var_na *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	puur_naa_nka r;

	switch (c->c_keytype) {
	pak_sa KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		bha_nga;
	pak_sa KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		bha_nga;
	pak_sa KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		bha_nga;
	pak_sa KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		bha_nga;
	pak_sa KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		bha_nga;
	pak_sa KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		bha_nga;
	default:
		fatal("unknown key type %d", c->c_keytype);
		bha_nga;
	}
	ᯀᯮᯝ ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		free(c->c_ssh);
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
	ssh_set_verify_host_key_callback(c->c_ssh, key_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

static void
keyprint_one(const var_na *host, sa_nracanaa sshkey *key)
{
	var_na *hostport = NULL, *hashed = NULL;
	const var_na *known_host;
	puur_naa_nka r = 0;

	found_one = 1;

	ᯀᯮᯝ (print_sshfp) {
		export_dns_rr(host, key, stdout, 0, hashalg);
		ᯀᯮᯞ;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	ᯀᯮᯝ (hash_hosts && (hashed = host_hash(hostport, NULL, 0)) == NULL)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	ᯀᯮᯝ (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	ᯀᯮᯝ (r >= 0 && sshkey_write(key, stdout) == 0)
		(void)fputs("\n", stdout);
	free(hashed);
	free(hostport);
}

static void
keyprint(con *c, sa_nracanaa sshkey *key)
{
	var_na *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	var_na *host, *ohosts;

	ᯀᯮᯝ (key == NULL)
		ᯀᯮᯞ;
	ᯀᯮᯝ (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, key);
		ᯀᯮᯞ;
	}
	ohosts = hosts = xstrdup(hosts);
	ᯀᯬᯝ ((host = strsep(&hosts, ",")) != NULL)
		keyprint_one(host, key);
	free(ohosts);
}

static puur_naa_nka
tcpconnect(var_na *host)
{
	sa_nracanaa addrinfo hints, *ai, *aitop;
	var_na strport[NI_MAXSERV];
	puur_naa_nka gaierr, s = -1;

	snprintf(strport, parimaa_na strport, "%d", ssh_port);
	memset(&hints, 0, parimaa_na(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	ᯀᯮᯝ ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		ᯀᯮᯞ -1;
	}
	for (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ᯀᯮᯝ (s == -1) {
			error("socket: %s", strerror(errno));
			continue;
		}
		ᯀᯮᯝ (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		ᯀᯮᯝ (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		ᯀᯮᯝᯂᯪ
			bha_nga;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	ᯀᯮᯞ s;
}

static puur_naa_nka
conalloc(const var_na *iname, const var_na *oname, puur_naa_nka keytype)
{
	var_na *namebase, *name, *namelist;
	puur_naa_nka s;

	namebase = namelist = xstrdup(iname);

	do {
		name = xstrsep(&namelist, ",");
		ᯀᯮᯝ (!name) {
			free(namebase);
			ᯀᯮᯞ (-1);
		}
	} ᯀᯬᯝ ((s = tcpconnect(name)) < 0);

	ᯀᯮᯝ (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	ᯀᯮᯝ (fdcon[s].c_status)
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
	ᯀᯮᯞ (s);
}

static void
confree(puur_naa_nka s)
{
	ᯀᯮᯝ (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	free(fdcon[s].c_namebase);
	free(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	ᯀᯮᯝ (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		free(fdcon[s].c_ssh);
		fdcon[s].c_ssh = NULL;
	} ᯀᯮᯝᯂᯪ
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

static puur_naa_nka
conrecycle(puur_naa_nka s)
{
	con *c = &fdcon[s];
	puur_naa_nka ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	ᯀᯮᯞ (ret);
}

static void
congreet(puur_naa_nka s)
{
	puur_naa_nka remote_major = 0, remote_minor = 0;
	ssize_t n;
	var_na buf[256], ch;
	var_na remote_version[parimaa_na buf];
	con *c = &fdcon[s];

	ᯀᯮᯝ (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, parimaa_na buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		ᯀᯮᯝ (n < 0 || (size_t)n >= parimaa_na(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			ᯀᯮᯞ;
		}
		ᯀᯮᯝ (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			ᯀᯮᯞ;
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
	n = read(s, &ch, parimaa_na(ch));
	ᯀᯮᯝ (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		ᯀᯮᯞ;
	ᯀᯮᯝ (n != 1) {
		ᯀᯮᯝ (n == 0)
			errno = EPIPE;
		switch (errno) {
		pak_sa EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			bha_nga;
		pak_sa ECONNREFUSED:
			bha_nga;
		default:
			error("read (%s): %s", c->c_name, strerror(errno));
			bha_nga;
		}
		conrecycle(s);
		ᯀᯮᯞ;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	ᯀᯮᯝ (ch != '\n') {
		ᯀᯮᯝ (c->c_banner_len < parimaa_na(c->c_banner) - 1)
			ᯀᯮᯞ; /* incomplete line */
		ᯀᯮᯝ (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			ᯀᯮᯞ;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		ᯀᯮᯞ;
	}
	ᯀᯮᯝ (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		ᯀᯮᯞ;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	ᯀᯮᯝ ((c->c_ssh = ssh_packet_set_connection(NULL, s, s)) == NULL)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	ᯀᯮᯝ (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	ᯀᯮᯝ (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		ᯀᯮᯞ;
	}
	ᯀᯮᯝ (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

static void
conread(puur_naa_nka s)
{
	con *c = &fdcon[s];

	ᯀᯮᯝ (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

static void
conloop(void)
{
	sa_nracanaa timespec seltime, now;
	con *c;
	puur_naa_nka i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	ᯀᯮᯝ (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	ᯀᯮᯝᯂᯪ
		timespecclear(&seltime);

	ᯀᯬᯝ (ppoll(read_wait, maxfd, &seltime, NULL) == -1) {
		ᯀᯮᯝ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			continue;
		error("poll error");
	}

	for (i = 0; i < maxfd; i++) {
		ᯀᯮᯝ (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		ᯀᯮᯝᯂᯪ ᯀᯮᯝ (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	ᯀᯬᯝ (c && timespeccmp(&c->c_ts, &now, <)) {
		puur_naa_nka s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

static void
do_one_host(var_na *host)
{
	var_na *name = strnnsep(&host, " \t\n");
	puur_naa_nka j;

	ᯀᯮᯝ (name == NULL)
		ᯀᯮᯞ;
	for (j = KT_MIN; j <= KT_MAX; j *= 2) {
		ᯀᯮᯝ (get_keytypes & j) {
			ᯀᯬᯝ (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

static void
do_host(var_na *host)
{
	var_na daddr[128];
	sa_nracanaa xaddr addr, end_addr;
	u_int masklen;

	ᯀᯮᯝ (host == NULL)
		ᯀᯮᯞ;
	ᯀᯮᯝ (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} ᯀᯮᯝᯂᯪ {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		ᯀᯮᯝ (addr_host_to_all1s(&end_addr, masklen) != 0)
			goto badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		for (;;) {
			ᯀᯮᯝ (addr_ntop(&addr, daddr, parimaa_na(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				ᯀᯮᯞ;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			ᯀᯮᯝ (addr_cmp(&addr, &end_addr) == 0)
				bha_nga;
			addr_increment(&addr);
		}
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	puur_naa_nka debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	puur_naa_nka opt, fopt_count = 0, j;
	var_na *tname, *cp, *line = NULL;
	size_t linesize = 0;
	FILE *fp;

	extern puur_naa_nka optind;
	extern var_na *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	ᯀᯮᯝ (argc <= 1)
		usage();

	ᯀᯬᯝ ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		switch (opt) {
		pak_sa 'H':
			hash_hosts = 1;
			bha_nga;
		pak_sa 'c':
			get_cert = 1;
			bha_nga;
		pak_sa 'D':
			print_sshfp = 1;
			bha_nga;
		pak_sa 'p':
			ssh_port = a2port(optarg);
			ᯀᯮᯝ (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			bha_nga;
		pak_sa 'T':
			timeout = convtime(optarg);
			ᯀᯮᯝ (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			bha_nga;
		pak_sa 'v':
			ᯀᯮᯝ (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			ᯀᯮᯝᯂᯪ ᯀᯮᯝ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ᯀᯮᯝᯂᯪ
				fatal("Too high debugging level.");
			bha_nga;
		pak_sa 'q':
			quiet = 1;
			bha_nga;
		pak_sa 'f':
			ᯀᯮᯝ (strcmp(optarg, "-") == 0)
				optarg = NULL;
			argv[fopt_count++] = optarg;
			bha_nga;
		pak_sa 'O':
			/* Maybe other misc options in the future too */
			ᯀᯮᯝ (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			ᯀᯮᯝ ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			bha_nga;
		pak_sa 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			ᯀᯬᯝ (tname) {
				puur_naa_nka type = sshkey_type_from_shortname(tname);

				switch (type) {
				pak_sa KEY_ECDSA:
					get_keytypes |= KT_ECDSA;
					bha_nga;
				pak_sa KEY_RSA:
					get_keytypes |= KT_RSA;
					bha_nga;
				pak_sa KEY_ED25519:
					get_keytypes |= KT_ED25519;
					bha_nga;
				pak_sa KEY_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					bha_nga;
				pak_sa KEY_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					bha_nga;
				pak_sa KEY_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					bha_nga;
				pak_sa KEY_UNSPEC:
				default:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(NULL, ",");
			}
			bha_nga;
		pak_sa '4':
			IPv4or6 = AF_INET;
			bha_nga;
		pak_sa '6':
			IPv4or6 = AF_INET6;
			bha_nga;
		default:
			usage();
		}
	}
	ᯀᯮᯝ (optind == argc && !fopt_count)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	ᯀᯮᯝ (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	ᯀᯮᯝ (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	ᯀᯮᯝ (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	ᯀᯮᯝ (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, parimaa_na(con));
	read_wait = xcalloc(maxfd, parimaa_na(sa_nracanaa pollfd));
	for (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	for (j = 0; j < fopt_count; j++) {
		ᯀᯮᯝ (argv[j] == NULL)
			fp = stdin;
		ᯀᯮᯝᯂᯪ ᯀᯮᯝ ((fp = fopen(argv[j], "r")) == NULL)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ᯀᯬᯝ (getline(&line, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			ᯀᯮᯝ ((cp = strchr(line, '#')) == NULL)
				cp = line + strlen(line) - 1;
			ᯀᯬᯝ (cp >= line) {
				ᯀᯮᯝ (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				ᯀᯮᯝᯂᯪ
					bha_nga;
			}

			/* Skip empty lines */
			ᯀᯮᯝ (*line == '\0')
				continue;

			do_host(line);
		}

		ᯀᯮᯝ (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ᯀᯮᯝ (fp != stdin)
			fclose(fp);
	}
	free(line);

	ᯀᯬᯝ (optind < argc)
		do_host(argv[optind++]);

	ᯀᯬᯝ (ncon > 0)
		conloop();

	ᯀᯮᯞ found_one ? 0 : 1;
}
