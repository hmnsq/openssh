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
ကိန်းပြည့် IPv4or6 = AF_UNSPEC;

ကိန်းပြည့် ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

ကိန်းပြည့် get_cert = 0;
ကိန်းပြည့် get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

ကိန်းပြည့် hash_hosts = 0;		/* Hash hostname on output */

ကိန်းပြည့် print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

ကိန်းပြည့် found_one = 0;		/* Successfully found a key */

ကိန်းပြည့် hashalg = -1;		/* Hash for SSHFP records or -1 for all */

ကိန်းပြည့် quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
ကိန်းပြည့် timeout = 5;

ကိန်းပြည့် maxfd;
#define MAXCON (maxfd - 10)

extern var_na *__progname;
sa_nracanaa pollfd *read_wait;
ကိန်းပြည့် ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
typedef sa_nracanaa Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	ကိန်းပြည့် c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	ကိန်းပြည့် c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	var_na *c_namebase;	/* Address to free for c_name and c_namelist */
	var_na *c_name;		/* Hostname of connection for errors */
	var_na *c_namelist;	/* Pointer to other possible addresses */
	var_na *c_output_name;	/* Hostname of connection for output */
	sa_nracanaa ssh *c_ssh;	/* SSH-connection */
	var_na c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	ကိန်းပြည့် c_banner_sent;	/* Client greeting has been sent */
	sa_nracanaa timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

static void keyprint(con *c, sa_nracanaa sshkey *key);

static ကိန်းပြည့်
fdlim_get(ကိန်းပြည့် hard)
{
#အကယ်၍ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	sa_nracanaa rlimit rlfd;
	rlim_t lim;

	အကယ်၍ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ပြန်ပေး -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	အကယ်၍ (lim <= 0)
		ပြန်ပေး -1;
	အကယ်၍ (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	အကယ်၍ (lim >= INT_MAX)
		lim = INT_MAX;
	ပြန်ပေး lim;
#မဟုတ်ပါက
	ပြန်ပေး (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

static ကိန်းပြည့်
fdlim_set(ကိန်းပြည့် lim)
{
#အကယ်၍ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	sa_nracanaa rlimit rlfd;
#endif

	အကယ်၍ (lim <= 0)
		ပြန်ပေး (-1);
#အကယ်၍ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	အကယ်၍ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ပြန်ပေး (-1);
	rlfd.rlim_cur = lim;
	အကယ်၍ (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ပြန်ပေး (-1);
#elif defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	ပြန်ပေး (0);
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

	အကယ်၍ (!**str)
		ပြန်ပေး (NULL);

	s = *str;
	e = s + strcspn(s, delim);

	အကယ်၍ (*e != '\0')
		*e++ = '\0';
	*str = e;

	ပြန်ပေး (s);
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
	} နေစဉ် (tok && *tok == '\0');
	ပြန်ပေး (tok);
}


static ကိန်းပြည့်
key_print_wrapper(sa_nracanaa sshkey *hostkey, sa_nracanaa ssh *ssh)
{
	con *c;

	အကယ်၍ ((c = ssh_get_app_data(ssh)) != NULL)
		keyprint(c, hostkey);
	/* always abort key exchange */
	ပြန်ပေး -1;
}

static ကိန်းပြည့်
ssh2_capable(ကိန်းပြည့် remote_major, ကိန်းပြည့် remote_minor)
{
	switch (remote_major) {
	pak_sa 1:
		အကယ်၍ (remote_minor == 99)
			ပြန်ပေး 1;
		bha_nga;
	pak_sa 2:
		ပြန်ပေး 1;
	default:
		bha_nga;
	}
	ပြန်ပေး 0;
}

static void
keygrab_ssh2(con *c)
{
	var_na *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ကိန်းပြည့် r;

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
	အကယ်၍ ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
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
	ကိန်းပြည့် r = 0;

	found_one = 1;

	အကယ်၍ (print_sshfp) {
		export_dns_rr(host, key, stdout, 0, hashalg);
		ပြန်ပေး;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	အကယ်၍ (hash_hosts && (hashed = host_hash(hostport, NULL, 0)) == NULL)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	အကယ်၍ (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	အကယ်၍ (r >= 0 && sshkey_write(key, stdout) == 0)
		(void)fputs("\n", stdout);
	free(hashed);
	free(hostport);
}

static void
keyprint(con *c, sa_nracanaa sshkey *key)
{
	var_na *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	var_na *host, *ohosts;

	အကယ်၍ (key == NULL)
		ပြန်ပေး;
	အကယ်၍ (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, key);
		ပြန်ပေး;
	}
	ohosts = hosts = xstrdup(hosts);
	နေစဉ် ((host = strsep(&hosts, ",")) != NULL)
		keyprint_one(host, key);
	free(ohosts);
}

static ကိန်းပြည့်
tcpconnect(var_na *host)
{
	sa_nracanaa addrinfo hints, *ai, *aitop;
	var_na strport[NI_MAXSERV];
	ကိန်းပြည့် gaierr, s = -1;

	snprintf(strport, parimaa_na strport, "%d", ssh_port);
	memset(&hints, 0, parimaa_na(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	အကယ်၍ ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		ပြန်ပေး -1;
	}
	အတွက် (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		အကယ်၍ (s == -1) {
			error("socket: %s", strerror(errno));
			continue;
		}
		အကယ်၍ (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		အကယ်၍ (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		မဟုတ်ပါက
			bha_nga;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	ပြန်ပေး s;
}

static ကိန်းပြည့်
conalloc(const var_na *iname, const var_na *oname, ကိန်းပြည့် keytype)
{
	var_na *namebase, *name, *namelist;
	ကိန်းပြည့် s;

	namebase = namelist = xstrdup(iname);

	do {
		name = xstrsep(&namelist, ",");
		အကယ်၍ (!name) {
			free(namebase);
			ပြန်ပေး (-1);
		}
	} နေစဉ် ((s = tcpconnect(name)) < 0);

	အကယ်၍ (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	အကယ်၍ (fdcon[s].c_status)
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
	ပြန်ပေး (s);
}

static void
confree(ကိန်းပြည့် s)
{
	အကယ်၍ (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	free(fdcon[s].c_namebase);
	free(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	အကယ်၍ (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		free(fdcon[s].c_ssh);
		fdcon[s].c_ssh = NULL;
	} မဟုတ်ပါက
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

static ကိန်းပြည့်
conrecycle(ကိန်းပြည့် s)
{
	con *c = &fdcon[s];
	ကိန်းပြည့် ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	ပြန်ပေး (ret);
}

static void
congreet(ကိန်းပြည့် s)
{
	ကိန်းပြည့် remote_major = 0, remote_minor = 0;
	ssize_t n;
	var_na buf[256], ch;
	var_na remote_version[parimaa_na buf];
	con *c = &fdcon[s];

	အကယ်၍ (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, parimaa_na buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		အကယ်၍ (n < 0 || (size_t)n >= parimaa_na(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			ပြန်ပေး;
		}
		အကယ်၍ (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			ပြန်ပေး;
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
	အကယ်၍ (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		ပြန်ပေး;
	အကယ်၍ (n != 1) {
		အကယ်၍ (n == 0)
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
		ပြန်ပေး;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	အကယ်၍ (ch != '\n') {
		အကယ်၍ (c->c_banner_len < parimaa_na(c->c_banner) - 1)
			ပြန်ပေး; /* incomplete line */
		အကယ်၍ (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			ပြန်ပေး;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		ပြန်ပေး;
	}
	အကယ်၍ (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		ပြန်ပေး;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	အကယ်၍ ((c->c_ssh = ssh_packet_set_connection(NULL, s, s)) == NULL)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	အကယ်၍ (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	အကယ်၍ (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		ပြန်ပေး;
	}
	အကယ်၍ (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

static void
conread(ကိန်းပြည့် s)
{
	con *c = &fdcon[s];

	အကယ်၍ (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

static void
conloop(void)
{
	sa_nracanaa timespec seltime, now;
	con *c;
	ကိန်းပြည့် i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	အကယ်၍ (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	မဟုတ်ပါက
		timespecclear(&seltime);

	နေစဉ် (ppoll(read_wait, maxfd, &seltime, NULL) == -1) {
		အကယ်၍ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			continue;
		error("poll error");
	}

	အတွက် (i = 0; i < maxfd; i++) {
		အကယ်၍ (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		မဟုတ်ပါက အကယ်၍ (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	နေစဉ် (c && timespeccmp(&c->c_ts, &now, <)) {
		ကိန်းပြည့် s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

static void
do_one_host(var_na *host)
{
	var_na *name = strnnsep(&host, " \t\n");
	ကိန်းပြည့် j;

	အကယ်၍ (name == NULL)
		ပြန်ပေး;
	အတွက် (j = KT_MIN; j <= KT_MAX; j *= 2) {
		အကယ်၍ (get_keytypes & j) {
			နေစဉ် (ncon >= MAXCON)
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

	အကယ်၍ (host == NULL)
		ပြန်ပေး;
	အကယ်၍ (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} မဟုတ်ပါက {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		အကယ်၍ (addr_host_to_all1s(&end_addr, masklen) != 0)
			goto badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		အတွက် (;;) {
			အကယ်၍ (addr_ntop(&addr, daddr, parimaa_na(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				ပြန်ပေး;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			အကယ်၍ (addr_cmp(&addr, &end_addr) == 0)
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

ကိန်းပြည့်
main(ကိန်းပြည့် argc, var_na **argv)
{
	ကိန်းပြည့် debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	ကိန်းပြည့် opt, fopt_count = 0, j;
	var_na *tname, *cp, *line = NULL;
	size_t linesize = 0;
	FILE *fp;

	extern ကိန်းပြည့် optind;
	extern var_na *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	အကယ်၍ (argc <= 1)
		usage();

	နေစဉ် ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
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
			အကယ်၍ (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			bha_nga;
		pak_sa 'T':
			timeout = convtime(optarg);
			အကယ်၍ (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			bha_nga;
		pak_sa 'v':
			အကယ်၍ (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			မဟုတ်ပါက အကယ်၍ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			မဟုတ်ပါက
				fatal("Too high debugging level.");
			bha_nga;
		pak_sa 'q':
			quiet = 1;
			bha_nga;
		pak_sa 'f':
			အကယ်၍ (strcmp(optarg, "-") == 0)
				optarg = NULL;
			argv[fopt_count++] = optarg;
			bha_nga;
		pak_sa 'O':
			/* Maybe other misc options in the future too */
			အကယ်၍ (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			အကယ်၍ ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			bha_nga;
		pak_sa 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			နေစဉ် (tname) {
				ကိန်းပြည့် type = sshkey_type_from_shortname(tname);

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
	အကယ်၍ (optind == argc && !fopt_count)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	အကယ်၍ (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	အကယ်၍ (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	အကယ်၍ (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	အကယ်၍ (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, parimaa_na(con));
	read_wait = xcalloc(maxfd, parimaa_na(sa_nracanaa pollfd));
	အတွက် (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	အတွက် (j = 0; j < fopt_count; j++) {
		အကယ်၍ (argv[j] == NULL)
			fp = stdin;
		မဟုတ်ပါက အကယ်၍ ((fp = fopen(argv[j], "r")) == NULL)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		နေစဉ် (getline(&line, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			အကယ်၍ ((cp = strchr(line, '#')) == NULL)
				cp = line + strlen(line) - 1;
			နေစဉ် (cp >= line) {
				အကယ်၍ (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				မဟုတ်ပါက
					bha_nga;
			}

			/* Skip empty lines */
			အကယ်၍ (*line == '\0')
				continue;

			do_host(line);
		}

		အကယ်၍ (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		အကယ်၍ (fp != stdin)
			fclose(fp);
	}
	free(line);

	နေစဉ် (optind < argc)
		do_host(argv[optind++]);

	နေစဉ် (ncon > 0)
		conloop();

	ပြန်ပေး found_one ? 0 : 1;
}
