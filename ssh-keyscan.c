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
целое IPv4or6 = AF_UNSPEC;

целое ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

целое get_cert = 0;
целое get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

целое hash_hosts = 0;		/* Hash hostname on output */

целое print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

целое found_one = 0;		/* Successfully found a key */

целое hashalg = -1;		/* Hash for SSHFP records or -1 for all */

целое quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
целое timeout = 5;

целое maxfd;
#define MAXCON (maxfd - 10)

extern char *__progname;
struct pollfd *read_wait;
целое ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
typedef struct Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	целое c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	целое c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	char *c_namebase;	/* Address to free for c_name and c_namelist */
	char *c_name;		/* Hostname of connection for errors */
	char *c_namelist;	/* Pointer to other possible addresses */
	char *c_output_name;	/* Hostname of connection for output */
	struct ssh *c_ssh;	/* SSH-connection */
	char c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	целое c_banner_sent;	/* Client greeting has been sent */
	struct timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

static void keyprint(con *c, struct sshkey *key);

static целое
fdlim_get(целое hard)
{
#если defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlfd;
	rlim_t lim;

	если (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		вернуть -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	если (lim <= 0)
		вернуть -1;
	если (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	если (lim >= INT_MAX)
		lim = INT_MAX;
	вернуть lim;
#иначе
	вернуть (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

static целое
fdlim_set(целое lim)
{
#если defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlfd;
#endif

	если (lim <= 0)
		вернуть (-1);
#если defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	если (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		вернуть (-1);
	rlfd.rlim_cur = lim;
	если (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		вернуть (-1);
#elif defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	вернуть (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
static char *
xstrsep(char **str, const char *delim)
{
	char *s, *e;

	если (!**str)
		вернуть (NULL);

	s = *str;
	e = s + strcspn(s, delim);

	если (*e != '\0')
		*e++ = '\0';
	*str = e;

	вернуть (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
static char *
strnnsep(char **stringp, char *delim)
{
	char *tok;

	do {
		tok = xstrsep(stringp, delim);
	} пока (tok && *tok == '\0');
	вернуть (tok);
}


static целое
key_print_wrapper(struct sshkey *hostkey, struct ssh *ssh)
{
	con *c;

	если ((c = ssh_get_app_data(ssh)) != NULL)
		keyprint(c, hostkey);
	/* always abort key exchange */
	вернуть -1;
}

static целое
ssh2_capable(целое remote_major, целое remote_minor)
{
	switch (remote_major) {
	case 1:
		если (remote_minor == 99)
			вернуть 1;
		break;
	case 2:
		вернуть 1;
	default:
		break;
	}
	вернуть 0;
}

static void
keygrab_ssh2(con *c)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	целое r;

	switch (c->c_keytype) {
	case KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		break;
	case KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		break;
	case KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		break;
	case KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		break;
	case KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		break;
	case KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		break;
	default:
		fatal("unknown key type %d", c->c_keytype);
		break;
	}
	если ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
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
keyprint_one(const char *host, struct sshkey *key)
{
	char *hostport = NULL, *hashed = NULL;
	const char *known_host;
	целое r = 0;

	found_one = 1;

	если (print_sshfp) {
		export_dns_rr(host, key, stdout, 0, hashalg);
		вернуть;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	если (hash_hosts && (hashed = host_hash(hostport, NULL, 0)) == NULL)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	если (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	если (r >= 0 && sshkey_write(key, stdout) == 0)
		(void)fputs("\n", stdout);
	free(hashed);
	free(hostport);
}

static void
keyprint(con *c, struct sshkey *key)
{
	char *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	char *host, *ohosts;

	если (key == NULL)
		вернуть;
	если (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, key);
		вернуть;
	}
	ohosts = hosts = xstrdup(hosts);
	пока ((host = strsep(&hosts, ",")) != NULL)
		keyprint_one(host, key);
	free(ohosts);
}

static целое
tcpconnect(char *host)
{
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	целое gaierr, s = -1;

	snprintf(strport, sizeof strport, "%d", ssh_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	если ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		вернуть -1;
	}
	для (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		если (s == -1) {
			error("socket: %s", strerror(errno));
			continue;
		}
		если (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		если (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		иначе
			break;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	вернуть s;
}

static целое
conalloc(const char *iname, const char *oname, целое keytype)
{
	char *namebase, *name, *namelist;
	целое s;

	namebase = namelist = xstrdup(iname);

	do {
		name = xstrsep(&namelist, ",");
		если (!name) {
			free(namebase);
			вернуть (-1);
		}
	} пока ((s = tcpconnect(name)) < 0);

	если (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	если (fdcon[s].c_status)
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
	вернуть (s);
}

static void
confree(целое s)
{
	если (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	free(fdcon[s].c_namebase);
	free(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	если (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		free(fdcon[s].c_ssh);
		fdcon[s].c_ssh = NULL;
	} иначе
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

static целое
conrecycle(целое s)
{
	con *c = &fdcon[s];
	целое ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	вернуть (ret);
}

static void
congreet(целое s)
{
	целое remote_major = 0, remote_minor = 0;
	ssize_t n;
	char buf[256], ch;
	char remote_version[sizeof buf];
	con *c = &fdcon[s];

	если (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, sizeof buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		если (n < 0 || (size_t)n >= sizeof(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			вернуть;
		}
		если (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			вернуть;
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
	n = read(s, &ch, sizeof(ch));
	если (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		вернуть;
	если (n != 1) {
		если (n == 0)
			errno = EPIPE;
		switch (errno) {
		case EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			break;
		case ECONNREFUSED:
			break;
		default:
			error("read (%s): %s", c->c_name, strerror(errno));
			break;
		}
		conrecycle(s);
		вернуть;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	если (ch != '\n') {
		если (c->c_banner_len < sizeof(c->c_banner) - 1)
			вернуть; /* incomplete line */
		если (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			вернуть;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		вернуть;
	}
	если (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		вернуть;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	если ((c->c_ssh = ssh_packet_set_connection(NULL, s, s)) == NULL)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	если (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	если (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		вернуть;
	}
	если (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

static void
conread(целое s)
{
	con *c = &fdcon[s];

	если (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

static void
conloop(void)
{
	struct timespec seltime, now;
	con *c;
	целое i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	если (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	иначе
		timespecclear(&seltime);

	пока (ppoll(read_wait, maxfd, &seltime, NULL) == -1) {
		если (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			continue;
		error("poll error");
	}

	для (i = 0; i < maxfd; i++) {
		если (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		иначе если (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	пока (c && timespeccmp(&c->c_ts, &now, <)) {
		целое s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

static void
do_one_host(char *host)
{
	char *name = strnnsep(&host, " \t\n");
	целое j;

	если (name == NULL)
		вернуть;
	для (j = KT_MIN; j <= KT_MAX; j *= 2) {
		если (get_keytypes & j) {
			пока (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

static void
do_host(char *host)
{
	char daddr[128];
	struct xaddr addr, end_addr;
	u_int masklen;

	если (host == NULL)
		вернуть;
	если (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} иначе {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		если (addr_host_to_all1s(&end_addr, masklen) != 0)
			goto badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		для (;;) {
			если (addr_ntop(&addr, daddr, sizeof(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				вернуть;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			если (addr_cmp(&addr, &end_addr) == 0)
				break;
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

целое
основной(целое argc, char **argv)
{
	целое debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	целое opt, fopt_count = 0, j;
	char *tname, *cp, *line = NULL;
	size_t linesize = 0;
	FILE *fp;

	extern целое optind;
	extern char *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	если (argc <= 1)
		usage();

	пока ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		switch (opt) {
		case 'H':
			hash_hosts = 1;
			break;
		case 'c':
			get_cert = 1;
			break;
		case 'D':
			print_sshfp = 1;
			break;
		case 'p':
			ssh_port = a2port(optarg);
			если (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			break;
		case 'T':
			timeout = convtime(optarg);
			если (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			break;
		case 'v':
			если (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			иначе если (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			иначе
				fatal("Too high debugging level.");
			break;
		case 'q':
			quiet = 1;
			break;
		case 'f':
			если (strcmp(optarg, "-") == 0)
				optarg = NULL;
			argv[fopt_count++] = optarg;
			break;
		case 'O':
			/* Maybe other misc options in the future too */
			если (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			если ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			break;
		case 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			пока (tname) {
				целое type = sshkey_type_from_shortname(tname);

				switch (type) {
				case KEY_ECDSA:
					get_keytypes |= KT_ECDSA;
					break;
				case KEY_RSA:
					get_keytypes |= KT_RSA;
					break;
				case KEY_ED25519:
					get_keytypes |= KT_ED25519;
					break;
				case KEY_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					break;
				case KEY_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					break;
				case KEY_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					break;
				case KEY_UNSPEC:
				default:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(NULL, ",");
			}
			break;
		case '4':
			IPv4or6 = AF_INET;
			break;
		case '6':
			IPv4or6 = AF_INET6;
			break;
		default:
			usage();
		}
	}
	если (optind == argc && !fopt_count)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	если (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	если (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	если (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	если (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, sizeof(con));
	read_wait = xcalloc(maxfd, sizeof(struct pollfd));
	для (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	для (j = 0; j < fopt_count; j++) {
		если (argv[j] == NULL)
			fp = stdin;
		иначе если ((fp = fopen(argv[j], "r")) == NULL)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		пока (getline(&line, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			если ((cp = strchr(line, '#')) == NULL)
				cp = line + strlen(line) - 1;
			пока (cp >= line) {
				если (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				иначе
					break;
			}

			/* Skip empty lines */
			если (*line == '\0')
				continue;

			do_host(line);
		}

		если (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		если (fp != stdin)
			fclose(fp);
	}
	free(line);

	пока (optind < argc)
		do_host(argv[optind++]);

	пока (ncon > 0)
		conloop();

	вернуть found_one ? 0 : 1;
}
