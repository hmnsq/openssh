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
số_nguyên IPv4or6 = AF_UNSPEC;

số_nguyên ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

số_nguyên get_cert = 0;
số_nguyên get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

số_nguyên hash_hosts = 0;		/* Hash hostname on output */

số_nguyên print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

số_nguyên found_one = 0;		/* Successfully found a key */

số_nguyên hashalg = -1;		/* Hash for SSHFP records or -1 for all */

số_nguyên quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
số_nguyên timeout = 5;

số_nguyên maxfd;
#define MAXCON (maxfd - 10)

extern char *__progname;
struct pollfd *read_wait;
số_nguyên ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
typedef struct Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	số_nguyên c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	số_nguyên c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	char *c_namebase;	/* Address to free for c_name and c_namelist */
	char *c_name;		/* Hostname of connection for errors */
	char *c_namelist;	/* Pointer to other possible addresses */
	char *c_output_name;	/* Hostname of connection for output */
	struct ssh *c_ssh;	/* SSH-connection */
	char c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	số_nguyên c_banner_sent;	/* Client greeting has been sent */
	struct timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

static void keyprint(con *c, struct sshkey *key);

static số_nguyên
fdlim_get(số_nguyên hard)
{
#nếu defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlfd;
	rlim_t lim;

	nếu (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		trả_về -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	nếu (lim <= 0)
		trả_về -1;
	nếu (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	nếu (lim >= INT_MAX)
		lim = INT_MAX;
	trả_về lim;
#không_thì
	trả_về (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

static số_nguyên
fdlim_set(số_nguyên lim)
{
#nếu defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlfd;
#endif

	nếu (lim <= 0)
		trả_về (-1);
#nếu defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	nếu (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		trả_về (-1);
	rlfd.rlim_cur = lim;
	nếu (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		trả_về (-1);
#elif defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	trả_về (0);
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

	nếu (!**str)
		trả_về (NULL);

	s = *str;
	e = s + strcspn(s, delim);

	nếu (*e != '\0')
		*e++ = '\0';
	*str = e;

	trả_về (s);
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
	} trong_khi (tok && *tok == '\0');
	trả_về (tok);
}


static số_nguyên
key_print_wrapper(struct sshkey *hostkey, struct ssh *ssh)
{
	con *c;

	nếu ((c = ssh_get_app_data(ssh)) != NULL)
		keyprint(c, hostkey);
	/* always abort key exchange */
	trả_về -1;
}

static số_nguyên
ssh2_capable(số_nguyên remote_major, số_nguyên remote_minor)
{
	switch (remote_major) {
	case 1:
		nếu (remote_minor == 99)
			trả_về 1;
		break;
	case 2:
		trả_về 1;
	default:
		break;
	}
	trả_về 0;
}

static void
keygrab_ssh2(con *c)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	số_nguyên r;

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
	nếu ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
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
	số_nguyên r = 0;

	found_one = 1;

	nếu (print_sshfp) {
		export_dns_rr(host, key, stdout, 0, hashalg);
		trả_về;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	nếu (hash_hosts && (hashed = host_hash(hostport, NULL, 0)) == NULL)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	nếu (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	nếu (r >= 0 && sshkey_write(key, stdout) == 0)
		(void)fputs("\n", stdout);
	free(hashed);
	free(hostport);
}

static void
keyprint(con *c, struct sshkey *key)
{
	char *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	char *host, *ohosts;

	nếu (key == NULL)
		trả_về;
	nếu (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, key);
		trả_về;
	}
	ohosts = hosts = xstrdup(hosts);
	trong_khi ((host = strsep(&hosts, ",")) != NULL)
		keyprint_one(host, key);
	free(ohosts);
}

static số_nguyên
tcpconnect(char *host)
{
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	số_nguyên gaierr, s = -1;

	snprintf(strport, sizeof strport, "%d", ssh_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	nếu ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		trả_về -1;
	}
	cho (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		nếu (s == -1) {
			error("socket: %s", strerror(errno));
			continue;
		}
		nếu (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		nếu (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		không_thì
			break;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	trả_về s;
}

static số_nguyên
conalloc(const char *iname, const char *oname, số_nguyên keytype)
{
	char *namebase, *name, *namelist;
	số_nguyên s;

	namebase = namelist = xstrdup(iname);

	do {
		name = xstrsep(&namelist, ",");
		nếu (!name) {
			free(namebase);
			trả_về (-1);
		}
	} trong_khi ((s = tcpconnect(name)) < 0);

	nếu (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	nếu (fdcon[s].c_status)
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
	trả_về (s);
}

static void
confree(số_nguyên s)
{
	nếu (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	free(fdcon[s].c_namebase);
	free(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	nếu (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		free(fdcon[s].c_ssh);
		fdcon[s].c_ssh = NULL;
	} không_thì
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

static số_nguyên
conrecycle(số_nguyên s)
{
	con *c = &fdcon[s];
	số_nguyên ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	trả_về (ret);
}

static void
congreet(số_nguyên s)
{
	số_nguyên remote_major = 0, remote_minor = 0;
	ssize_t n;
	char buf[256], ch;
	char remote_version[sizeof buf];
	con *c = &fdcon[s];

	nếu (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, sizeof buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		nếu (n < 0 || (size_t)n >= sizeof(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			trả_về;
		}
		nếu (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			trả_về;
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
	nếu (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		trả_về;
	nếu (n != 1) {
		nếu (n == 0)
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
		trả_về;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	nếu (ch != '\n') {
		nếu (c->c_banner_len < sizeof(c->c_banner) - 1)
			trả_về; /* incomplete line */
		nếu (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			trả_về;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		trả_về;
	}
	nếu (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		trả_về;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	nếu ((c->c_ssh = ssh_packet_set_connection(NULL, s, s)) == NULL)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	nếu (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	nếu (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		trả_về;
	}
	nếu (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

static void
conread(số_nguyên s)
{
	con *c = &fdcon[s];

	nếu (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

static void
conloop(void)
{
	struct timespec seltime, now;
	con *c;
	số_nguyên i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	nếu (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	không_thì
		timespecclear(&seltime);

	trong_khi (ppoll(read_wait, maxfd, &seltime, NULL) == -1) {
		nếu (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			continue;
		error("poll error");
	}

	cho (i = 0; i < maxfd; i++) {
		nếu (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		không_thì nếu (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	trong_khi (c && timespeccmp(&c->c_ts, &now, <)) {
		số_nguyên s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

static void
do_one_host(char *host)
{
	char *name = strnnsep(&host, " \t\n");
	số_nguyên j;

	nếu (name == NULL)
		trả_về;
	cho (j = KT_MIN; j <= KT_MAX; j *= 2) {
		nếu (get_keytypes & j) {
			trong_khi (ncon >= MAXCON)
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

	nếu (host == NULL)
		trả_về;
	nếu (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} không_thì {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		nếu (addr_host_to_all1s(&end_addr, masklen) != 0)
			goto badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		cho (;;) {
			nếu (addr_ntop(&addr, daddr, sizeof(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				trả_về;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			nếu (addr_cmp(&addr, &end_addr) == 0)
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

số_nguyên
main(số_nguyên argc, char **argv)
{
	số_nguyên debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	số_nguyên opt, fopt_count = 0, j;
	char *tname, *cp, *line = NULL;
	size_t linesize = 0;
	FILE *fp;

	extern số_nguyên optind;
	extern char *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	nếu (argc <= 1)
		usage();

	trong_khi ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
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
			nếu (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			break;
		case 'T':
			timeout = convtime(optarg);
			nếu (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			break;
		case 'v':
			nếu (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			không_thì nếu (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			không_thì
				fatal("Too high debugging level.");
			break;
		case 'q':
			quiet = 1;
			break;
		case 'f':
			nếu (strcmp(optarg, "-") == 0)
				optarg = NULL;
			argv[fopt_count++] = optarg;
			break;
		case 'O':
			/* Maybe other misc options in the future too */
			nếu (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			nếu ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			break;
		case 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			trong_khi (tname) {
				số_nguyên type = sshkey_type_from_shortname(tname);

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
	nếu (optind == argc && !fopt_count)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	nếu (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	nếu (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	nếu (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	nếu (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, sizeof(con));
	read_wait = xcalloc(maxfd, sizeof(struct pollfd));
	cho (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	cho (j = 0; j < fopt_count; j++) {
		nếu (argv[j] == NULL)
			fp = stdin;
		không_thì nếu ((fp = fopen(argv[j], "r")) == NULL)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		trong_khi (getline(&line, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			nếu ((cp = strchr(line, '#')) == NULL)
				cp = line + strlen(line) - 1;
			trong_khi (cp >= line) {
				nếu (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				không_thì
					break;
			}

			/* Skip empty lines */
			nếu (*line == '\0')
				continue;

			do_host(line);
		}

		nếu (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		nếu (fp != stdin)
			fclose(fp);
	}
	free(line);

	trong_khi (optind < argc)
		do_host(argv[optind++]);

	trong_khi (ncon > 0)
		conloop();

	trả_về found_one ? 0 : 1;
}
