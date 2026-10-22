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
정수 IPv4or6 = AF_UNSPEC;

정수 ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

정수 get_cert = 0;
정수 get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

정수 hash_hosts = 0;		/* Hash hostname on output */

정수 print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

정수 found_one = 0;		/* Successfully found a key */

정수 hashalg = -1;		/* Hash for SSHFP records or -1 for all */

정수 quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
정수 timeout = 5;

정수 maxfd;
#define MAXCON (maxfd - 10)

extern char *__progname;
struct pollfd *read_wait;
정수 ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
typedef struct Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	정수 c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	정수 c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	char *c_namebase;	/* Address to free for c_name and c_namelist */
	char *c_name;		/* Hostname of connection for errors */
	char *c_namelist;	/* Pointer to other possible addresses */
	char *c_output_name;	/* Hostname of connection for output */
	struct ssh *c_ssh;	/* SSH-connection */
	char c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	정수 c_banner_sent;	/* Client greeting has been sent */
	struct timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

static void keyprint(con *c, struct sshkey *key);

static 정수
fdlim_get(정수 hard)
{
#만약 defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlfd;
	rlim_t lim;

	만약 (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		반환 -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	만약 (lim <= 0)
		반환 -1;
	만약 (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	만약 (lim >= INT_MAX)
		lim = INT_MAX;
	반환 lim;
#아니면
	반환 (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

static 정수
fdlim_set(정수 lim)
{
#만약 defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlfd;
#endif

	만약 (lim <= 0)
		반환 (-1);
#만약 defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	만약 (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		반환 (-1);
	rlfd.rlim_cur = lim;
	만약 (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		반환 (-1);
#elif defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	반환 (0);
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

	만약 (!**str)
		반환 (NULL);

	s = *str;
	e = s + strcspn(s, delim);

	만약 (*e != '\0')
		*e++ = '\0';
	*str = e;

	반환 (s);
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
	} 동안 (tok && *tok == '\0');
	반환 (tok);
}


static 정수
key_print_wrapper(struct sshkey *hostkey, struct ssh *ssh)
{
	con *c;

	만약 ((c = ssh_get_app_data(ssh)) != NULL)
		keyprint(c, hostkey);
	/* always abort key exchange */
	반환 -1;
}

static 정수
ssh2_capable(정수 remote_major, 정수 remote_minor)
{
	switch (remote_major) {
	case 1:
		만약 (remote_minor == 99)
			반환 1;
		break;
	case 2:
		반환 1;
	default:
		break;
	}
	반환 0;
}

static void
keygrab_ssh2(con *c)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	정수 r;

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
	만약 ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
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
	정수 r = 0;

	found_one = 1;

	만약 (print_sshfp) {
		export_dns_rr(host, key, stdout, 0, hashalg);
		반환;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	만약 (hash_hosts && (hashed = host_hash(hostport, NULL, 0)) == NULL)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	만약 (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	만약 (r >= 0 && sshkey_write(key, stdout) == 0)
		(void)fputs("\n", stdout);
	free(hashed);
	free(hostport);
}

static void
keyprint(con *c, struct sshkey *key)
{
	char *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	char *host, *ohosts;

	만약 (key == NULL)
		반환;
	만약 (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, key);
		반환;
	}
	ohosts = hosts = xstrdup(hosts);
	동안 ((host = strsep(&hosts, ",")) != NULL)
		keyprint_one(host, key);
	free(ohosts);
}

static 정수
tcpconnect(char *host)
{
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	정수 gaierr, s = -1;

	snprintf(strport, sizeof strport, "%d", ssh_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	만약 ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		반환 -1;
	}
	위해 (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		만약 (s == -1) {
			error("socket: %s", strerror(errno));
			continue;
		}
		만약 (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		만약 (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		아니면
			break;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	반환 s;
}

static 정수
conalloc(const char *iname, const char *oname, 정수 keytype)
{
	char *namebase, *name, *namelist;
	정수 s;

	namebase = namelist = xstrdup(iname);

	do {
		name = xstrsep(&namelist, ",");
		만약 (!name) {
			free(namebase);
			반환 (-1);
		}
	} 동안 ((s = tcpconnect(name)) < 0);

	만약 (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	만약 (fdcon[s].c_status)
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
	반환 (s);
}

static void
confree(정수 s)
{
	만약 (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	free(fdcon[s].c_namebase);
	free(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	만약 (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		free(fdcon[s].c_ssh);
		fdcon[s].c_ssh = NULL;
	} 아니면
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

static 정수
conrecycle(정수 s)
{
	con *c = &fdcon[s];
	정수 ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	반환 (ret);
}

static void
congreet(정수 s)
{
	정수 remote_major = 0, remote_minor = 0;
	ssize_t n;
	char buf[256], ch;
	char remote_version[sizeof buf];
	con *c = &fdcon[s];

	만약 (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, sizeof buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		만약 (n < 0 || (size_t)n >= sizeof(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			반환;
		}
		만약 (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			반환;
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
	만약 (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		반환;
	만약 (n != 1) {
		만약 (n == 0)
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
		반환;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	만약 (ch != '\n') {
		만약 (c->c_banner_len < sizeof(c->c_banner) - 1)
			반환; /* incomplete line */
		만약 (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			반환;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		반환;
	}
	만약 (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		반환;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	만약 ((c->c_ssh = ssh_packet_set_connection(NULL, s, s)) == NULL)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	만약 (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	만약 (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		반환;
	}
	만약 (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

static void
conread(정수 s)
{
	con *c = &fdcon[s];

	만약 (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

static void
conloop(void)
{
	struct timespec seltime, now;
	con *c;
	정수 i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	만약 (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	아니면
		timespecclear(&seltime);

	동안 (ppoll(read_wait, maxfd, &seltime, NULL) == -1) {
		만약 (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			continue;
		error("poll error");
	}

	위해 (i = 0; i < maxfd; i++) {
		만약 (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		아니면 만약 (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	동안 (c && timespeccmp(&c->c_ts, &now, <)) {
		정수 s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

static void
do_one_host(char *host)
{
	char *name = strnnsep(&host, " \t\n");
	정수 j;

	만약 (name == NULL)
		반환;
	위해 (j = KT_MIN; j <= KT_MAX; j *= 2) {
		만약 (get_keytypes & j) {
			동안 (ncon >= MAXCON)
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

	만약 (host == NULL)
		반환;
	만약 (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} 아니면 {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		만약 (addr_host_to_all1s(&end_addr, masklen) != 0)
			goto badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		위해 (;;) {
			만약 (addr_ntop(&addr, daddr, sizeof(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				반환;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			만약 (addr_cmp(&addr, &end_addr) == 0)
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

정수
main(정수 argc, char **argv)
{
	정수 debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	정수 opt, fopt_count = 0, j;
	char *tname, *cp, *line = NULL;
	size_t linesize = 0;
	FILE *fp;

	extern 정수 optind;
	extern char *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	만약 (argc <= 1)
		usage();

	동안 ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
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
			만약 (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			break;
		case 'T':
			timeout = convtime(optarg);
			만약 (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			break;
		case 'v':
			만약 (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			아니면 만약 (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			아니면
				fatal("Too high debugging level.");
			break;
		case 'q':
			quiet = 1;
			break;
		case 'f':
			만약 (strcmp(optarg, "-") == 0)
				optarg = NULL;
			argv[fopt_count++] = optarg;
			break;
		case 'O':
			/* Maybe other misc options in the future too */
			만약 (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			만약 ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			break;
		case 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			동안 (tname) {
				정수 type = sshkey_type_from_shortname(tname);

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
	만약 (optind == argc && !fopt_count)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	만약 (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	만약 (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	만약 (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	만약 (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, sizeof(con));
	read_wait = xcalloc(maxfd, sizeof(struct pollfd));
	위해 (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	위해 (j = 0; j < fopt_count; j++) {
		만약 (argv[j] == NULL)
			fp = stdin;
		아니면 만약 ((fp = fopen(argv[j], "r")) == NULL)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		동안 (getline(&line, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			만약 ((cp = strchr(line, '#')) == NULL)
				cp = line + strlen(line) - 1;
			동안 (cp >= line) {
				만약 (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				아니면
					break;
			}

			/* Skip empty lines */
			만약 (*line == '\0')
				continue;

			do_host(line);
		}

		만약 (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		만약 (fp != stdin)
			fclose(fp);
	}
	free(line);

	동안 (optind < argc)
		do_host(argv[optind++]);

	동안 (ncon > 0)
		conloop();

	반환 found_one ? 0 : 1;
}
