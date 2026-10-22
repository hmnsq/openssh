/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"
 
#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/resource.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#endif

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "dns.h"
#ଅନ୍ତର୍ଭାଵ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା IPv4or6 = AF_UNSPEC;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

ପୂର୍ଣ୍ଣସଂଖ୍ୟା get_cert = 0;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_hosts = 0;		/* Hash hostname on output */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା found_one = 0;		/* Successfully found a key */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା hashalg = -1;		/* Hash for SSHFP records or -1 for all */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout = 5;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା maxfd;
#define MAXCON (maxfd - 10)

ବାହ୍ୟ ଅକ୍ଷର *__progname;
ସଂରଚନା pollfd *read_wait;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	ଅକ୍ଷର *c_namebase;	/* Address to free for c_name and c_namelist */
	ଅକ୍ଷର *c_name;		/* Hostname of connection for errors */
	ଅକ୍ଷର *c_namelist;	/* Pointer to other possible addresses */
	ଅକ୍ଷର *c_output_name;	/* Hostname of connection for output */
	ସଂରଚନା ssh *c_ssh;	/* SSH-connection */
	ଅକ୍ଷର c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c_banner_sent;	/* Client greeting has been sent */
	ସଂରଚନା timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

ସ୍ଥିର ଶୂନ୍ୟ keyprint(con *c, ସଂରଚନା sshkey *ଚାବି);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fdlim_get(ପୂର୍ଣ୍ଣସଂଖ୍ୟା hard)
{
#ଯଦି defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ସଂରଚନା rlimit rlfd;
	rlim_t lim;

	ଯଦି (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ଫେରନ୍ତୁ -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	ଯଦି (lim <= 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	ଯଦି (lim >= INT_MAX)
		lim = INT_MAX;
	ଫେରନ୍ତୁ lim;
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fdlim_set(ପୂର୍ଣ୍ଣସଂଖ୍ୟା lim)
{
#ଯଦି defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ସଂରଚନା rlimit rlfd;
#endif

	ଯଦି (lim <= 0)
		ଫେରନ୍ତୁ (-1);
#ଯଦି defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ଯଦି (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ଫେରନ୍ତୁ (-1);
	rlfd.rlim_cur = lim;
	ଯଦି (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ଫେରନ୍ତୁ (-1);
#ନଚେତଯଦି defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	ଫେରନ୍ତୁ (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
ସ୍ଥିର ଅକ୍ଷର *
xstrsep(ଅକ୍ଷର **str, ଅଚଳ ଅକ୍ଷର *delim)
{
	ଅକ୍ଷର *s, *e;

	ଯଦି (!**str)
		ଫେରନ୍ତୁ (ଖାଲି);

	s = *str;
	e = s + strcspn(s, delim);

	ଯଦି (*e != '\0')
		*e++ = '\0';
	*str = e;

	ଫେରନ୍ତୁ (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
ସ୍ଥିର ଅକ୍ଷର *
strnnsep(ଅକ୍ଷର **stringp, ଅକ୍ଷର *delim)
{
	ଅକ୍ଷର *tok;

	କର {
		tok = xstrsep(stringp, delim);
	} ଯେତେବେଳେ (tok && *tok == '\0');
	ଫେରନ୍ତୁ (tok);
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଚାବି_print_wrapper(ସଂରଚନା sshkey *hostkey, ସଂରଚନା ssh *ssh)
{
	con *c;

	ଯଦି ((c = ssh_get_app_data(ssh)) != ଖାଲି)
		keyprint(c, hostkey);
	/* always abort key exchange */
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh2_capable(ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote_major, ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote_minor)
{
	ବାଛ (remote_major) {
	ସ୍ଥିତି 1:
		ଯଦି (remote_minor == 99)
			ଫେରନ୍ତୁ 1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 2:
		ଫେରନ୍ତୁ 1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
keygrab_ssh2(con *c)
{
	ଅକ୍ଷର *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ବାଛ (c->c_keytype) {
	ସ୍ଥିତି KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("unknown key type %d", c->c_keytype);
		ଭାଙ୍ଗ;
	}
	ଯଦି ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		ମୁକ୍ତ(c->c_ssh);
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
	ssh_set_verify_host_ଚାବି_callback(c->c_ssh, ଚାବି_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

ସ୍ଥିର ଶୂନ୍ୟ
keyprint_one(ଅଚଳ ଅକ୍ଷର *host, ସଂରଚନା sshkey *ଚାବି)
{
	ଅକ୍ଷର *hostport = ଖାଲି, *hashed = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *known_host;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = 0;

	found_one = 1;

	ଯଦି (print_sshfp) {
		export_dns_rr(host, ଚାବି, stdout, 0, hashalg);
		ଫେରନ୍ତୁ;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	ଯଦି (hash_hosts && (hashed = host_hash(hostport, ଖାଲି, 0)) == ଖାଲି)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	ଯଦି (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	ଯଦି (r >= 0 && sshkey_write(ଚାବି, stdout) == 0)
		(ଶୂନ୍ୟ)fputs("\n", stdout);
	ମୁକ୍ତ(hashed);
	ମୁକ୍ତ(hostport);
}

ସ୍ଥିର ଶୂନ୍ୟ
keyprint(con *c, ସଂରଚନା sshkey *ଚାବି)
{
	ଅକ୍ଷର *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	ଅକ୍ଷର *host, *ohosts;

	ଯଦି (ଚାବି == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, ଚାବି);
		ଫେରନ୍ତୁ;
	}
	ohosts = hosts = xstrdup(hosts);
	ଯେତେବେଳେ ((host = strsep(&hosts, ",")) != ଖାଲି)
		keyprint_one(host, ଚାବି);
	ମୁକ୍ତ(ohosts);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
tcpconnect(ଅକ୍ଷର *host)
{
	ସଂରଚନା addrinfo hints, *ai, *aitop;
	ଅକ୍ଷର strport[NI_MAXSERV];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr, s = -1;

	snprintf(strport, ଆକାର strport, "%d", ssh_port);
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	ଯଦି ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		ଫେରନ୍ତୁ -1;
	}
	ପାଇଁ (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ଯଦି (s == -1) {
			error("socket: %s", strerror(errno));
			ଜାରି;
		}
		ଯଦି (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		ଯଦି (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	ଫେରନ୍ତୁ s;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
conalloc(ଅଚଳ ଅକ୍ଷର *iname, ଅଚଳ ଅକ୍ଷର *oname, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype)
{
	ଅକ୍ଷର *namebase, *name, *namelist;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s;

	namebase = namelist = xstrdup(iname);

	କର {
		name = xstrsep(&namelist, ",");
		ଯଦି (!name) {
			ମୁକ୍ତ(namebase);
			ଫେରନ୍ତୁ (-1);
		}
	} ଯେତେବେଳେ ((s = tcpconnect(name)) < 0);

	ଯଦି (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	ଯଦି (fdcon[s].c_status)
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
	ଫେରନ୍ତୁ (s);
}

ସ୍ଥିର ଶୂନ୍ୟ
confree(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s)
{
	ଯଦି (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	ମୁକ୍ତ(fdcon[s].c_namebase);
	ମୁକ୍ତ(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	ଯଦି (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		ମୁକ୍ତ(fdcon[s].c_ssh);
		fdcon[s].c_ssh = ଖାଲି;
	} ଅନ୍ୟଥା
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
conrecycle(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s)
{
	con *c = &fdcon[s];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	ଫେରନ୍ତୁ (ret);
}

ସ୍ଥିର ଶୂନ୍ୟ
congreet(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote_major = 0, remote_minor = 0;
	ssize_t n;
	ଅକ୍ଷର buf[256], ch;
	ଅକ୍ଷର remote_version[ଆକାର buf];
	con *c = &fdcon[s];

	ଯଦି (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, ଆକାର buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		ଯଦି (n < 0 || (size_t)n >= ଆକାର(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			ଫେରନ୍ତୁ;
		}
		ଯଦି (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			ଫେରନ୍ତୁ;
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
	n = ପଠ(s, &ch, ଆକାର(ch));
	ଯଦି (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		ଫେରନ୍ତୁ;
	ଯଦି (n != 1) {
		ଯଦି (n == 0)
			errno = EPIPE;
		ବାଛ (errno) {
		ସ୍ଥିତି EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ECONNREFUSED:
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("read (%s): %s", c->c_name, strerror(errno));
			ଭାଙ୍ଗ;
		}
		conrecycle(s);
		ଫେରନ୍ତୁ;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	ଯଦି (ch != '\n') {
		ଯଦି (c->c_banner_len < ଆକାର(c->c_banner) - 1)
			ଫେରନ୍ତୁ; /* incomplete line */
		ଯଦି (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			ଫେରନ୍ତୁ;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		ଫେରନ୍ତୁ;
	}
	ଯଦି (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		ଫେରନ୍ତୁ;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	ଯଦି ((c->c_ssh = ssh_packet_set_connection(ଖାଲି, s, s)) == ଖାଲି)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	ଯଦି (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	ଯଦି (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

ସ୍ଥିର ଶୂନ୍ୟ
conread(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s)
{
	con *c = &fdcon[s];

	ଯଦି (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

ସ୍ଥିର ଶୂନ୍ୟ
conloop(ଶୂନ୍ୟ)
{
	ସଂରଚନା timespec seltime, now;
	con *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	ଯଦି (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	ଅନ୍ୟଥା
		timespecclear(&seltime);

	ଯେତେବେଳେ (ppoll(read_wait, maxfd, &seltime, ଖାଲି) == -1) {
		ଯଦି (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ଜାରି;
		error("poll error");
	}

	ପାଇଁ (i = 0; i < maxfd; i++) {
		ଯଦି (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		ଅନ୍ୟଥା ଯଦି (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	ଯେତେବେଳେ (c && timespeccmp(&c->c_ts, &now, <)) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
do_one_host(ଅକ୍ଷର *host)
{
	ଅକ୍ଷର *name = strnnsep(&host, " \t\n");
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା j;

	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (j = KT_MIN; j <= KT_MAX; j *= 2) {
		ଯଦି (get_keytypes & j) {
			ଯେତେବେଳେ (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
do_host(ଅକ୍ଷର *host)
{
	ଅକ୍ଷର daddr[128];
	ସଂରଚନା xaddr addr, end_addr;
	u_int masklen;

	ଯଦି (host == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} ଅନ୍ୟଥା {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		ଯଦି (addr_host_to_all1s(&end_addr, masklen) != 0)
			ଯାଅ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		ପାଇଁ (;;) {
			ଯଦି (addr_ntop(&addr, daddr, ଆକାର(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				ଫେରନ୍ତୁ;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			ଯଦି (addr_cmp(&addr, &end_addr) == 0)
				ଭାଙ୍ଗ;
			addr_increment(&addr);
		}
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା opt, fopt_ଗଣନା = 0, j;
	ଅକ୍ଷର *tname, *cp, *ଧାଡ଼ି = ଖାଲି;
	size_t linesize = 0;
	FILE *fp;

	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	ଯଦି (argc <= 1)
		usage();

	ଯେତେବେଳେ ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		ବାଛ (opt) {
		ସ୍ଥିତି 'H':
			hash_hosts = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'c':
			get_cert = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			print_sshfp = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			ssh_port = a2port(optarg);
			ଯଦି (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'T':
			timeout = convtime(optarg);
			ଯଦି (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'v':
			ଯଦି (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			ଅନ୍ୟଥା ଯଦି (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ଅନ୍ୟଥା
				fatal("Too high debugging level.");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			quiet = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			ଯଦି (strcmp(optarg, "-") == 0)
				optarg = ଖାଲି;
			argv[fopt_ଗଣନା++] = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'O':
			/* Maybe other misc options in the future too */
			ଯଦି (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			ଯଦି ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			ଯେତେବେଳେ (tname) {
				ପୂର୍ଣ୍ଣସଂଖ୍ୟା type = sshkey_type_from_shortname(tname);

				ବାଛ (type) {
				ସ୍ଥିତି ଚାବି_ECDSA:
					get_keytypes |= KT_ECDSA;
					ଭାଙ୍ଗ;
				ସ୍ଥିତି ଚାବି_RSA:
					get_keytypes |= KT_RSA;
					ଭାଙ୍ଗ;
				ସ୍ଥିତି ଚାବି_ED25519:
					get_keytypes |= KT_ED25519;
					ଭାଙ୍ଗ;
				ସ୍ଥିତି ଚାବି_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					ଭାଙ୍ଗ;
				ସ୍ଥିତି ଚାବି_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					ଭାଙ୍ଗ;
				ସ୍ଥିତି ଚାବି_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					ଭାଙ୍ଗ;
				ସ୍ଥିତି ଚାବି_UNSPEC:
				ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(ଖାଲି, ",");
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '4':
			IPv4or6 = AF_INET;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '6':
			IPv4or6 = AF_INET6;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
		}
	}
	ଯଦି (optind == argc && !fopt_ଗଣନା)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	ଯଦି (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	ଯଦି (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	ଯଦି (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	ଯଦି (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, ଆକାର(con));
	read_wait = xcalloc(maxfd, ଆକାର(ସଂରଚନା pollfd));
	ପାଇଁ (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	ପାଇଁ (j = 0; j < fopt_ଗଣନା; j++) {
		ଯଦି (argv[j] == ଖାଲି)
			fp = stdin;
		ଅନ୍ୟଥା ଯଦି ((fp = fopen(argv[j], "r")) == ଖାଲି)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			ଯଦି ((cp = strchr(ଧାଡ଼ି, '#')) == ଖାଲି)
				cp = ଧାଡ଼ି + strlen(ଧାଡ଼ି) - 1;
			ଯେତେବେଳେ (cp >= ଧାଡ଼ି) {
				ଯଦି (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				ଅନ୍ୟଥା
					ଭାଙ୍ଗ;
			}

			/* Skip empty lines */
			ଯଦି (*ଧାଡ଼ି == '\0')
				ଜାରି;

			do_host(ଧାଡ଼ି);
		}

		ଯଦି (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ଯଦି (fp != stdin)
			fclose(fp);
	}
	ମୁକ୍ତ(ଧାଡ଼ି);

	ଯେତେବେଳେ (optind < argc)
		do_host(argv[optind++]);

	ଯେତେବେଳେ (ncon > 0)
		conloop();

	ଫେରନ୍ତୁ found_one ? 0 : 1;
}
