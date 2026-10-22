/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"
 
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/resource.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#endif

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "dns.h"
#ಅನ್ತರ್ಭಾವ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
ಪೂರ್ಣಾಙ್ಕ IPv4or6 = AF_UNSPEC;

ಪೂರ್ಣಾಙ್ಕ ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

ಪೂರ್ಣಾಙ್ಕ get_cert = 0;
ಪೂರ್ಣಾಙ್ಕ get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

ಪೂರ್ಣಾಙ್ಕ hash_hosts = 0;		/* Hash hostname on output */

ಪೂರ್ಣಾಙ್ಕ print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

ಪೂರ್ಣಾಙ್ಕ found_one = 0;		/* Successfully found a key */

ಪೂರ್ಣಾಙ್ಕ hashalg = -1;		/* Hash for SSHFP records or -1 for all */

ಪೂರ್ಣಾಙ್ಕ quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
ಪೂರ್ಣಾಙ್ಕ timeout = 5;

ಪೂರ್ಣಾಙ್ಕ maxfd;
#define MAXCON (maxfd - 10)

ಬಾಹ್ಯ ವರ್ಣ *__progname;
ಸಂರಚನಾ pollfd *read_wait;
ಪೂರ್ಣಾಙ್ಕ ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	ಪೂರ್ಣಾಙ್ಕ c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	ಪೂರ್ಣಾಙ್ಕ c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	ವರ್ಣ *c_namebase;	/* Address to free for c_name and c_namelist */
	ವರ್ಣ *c_name;		/* Hostname of connection for errors */
	ವರ್ಣ *c_namelist;	/* Pointer to other possible addresses */
	ವರ್ಣ *c_output_name;	/* Hostname of connection for output */
	ಸಂರಚನಾ ssh *c_ssh;	/* SSH-connection */
	ವರ್ಣ c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	ಪೂರ್ಣಾಙ್ಕ c_banner_sent;	/* Client greeting has been sent */
	ಸಂರಚನಾ timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

ಸ್ಥಿರ ಶೂನ್ಯ keyprint(con *c, ಸಂರಚನಾ sshkey *ಕೀಲಿ);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fdlim_get(ಪೂರ್ಣಾಙ್ಕ hard)
{
#ಯದಿ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ಸಂರಚನಾ rlimit rlfd;
	rlim_t lim;

	ಯದಿ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	ಯದಿ (lim <= 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	ಯದಿ (lim >= INT_MAX)
		lim = INT_MAX;
	ಪ್ರತ್ಯಾಗಮ lim;
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fdlim_set(ಪೂರ್ಣಾಙ್ಕ lim)
{
#ಯದಿ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ಸಂರಚನಾ rlimit rlfd;
#endif

	ಯದಿ (lim <= 0)
		ಪ್ರತ್ಯಾಗಮ (-1);
#ಯದಿ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ಯದಿ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	rlfd.rlim_cur = lim;
	ಯದಿ (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
#ನೋಚೇದ್ಯದಿ defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	ಪ್ರತ್ಯಾಗಮ (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
ಸ್ಥಿರ ವರ್ಣ *
xstrsep(ವರ್ಣ **str, ಧ್ರುವ ವರ್ಣ *delim)
{
	ವರ್ಣ *s, *e;

	ಯದಿ (!**str)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

	s = *str;
	e = s + strcspn(s, delim);

	ಯದಿ (*e != '\0')
		*e++ = '\0';
	*str = e;

	ಪ್ರತ್ಯಾಗಮ (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
ಸ್ಥಿರ ವರ್ಣ *
strnnsep(ವರ್ಣ **stringp, ವರ್ಣ *delim)
{
	ವರ್ಣ *tok;

	ಕುರು {
		tok = xstrsep(stringp, delim);
	} ಯಾವತ್ (tok && *tok == '\0');
	ಪ್ರತ್ಯಾಗಮ (tok);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಕೀಲಿ_print_wrapper(ಸಂರಚನಾ sshkey *hostkey, ಸಂರಚನಾ ssh *ssh)
{
	con *c;

	ಯದಿ ((c = ssh_get_app_data(ssh)) != ರಿಕ್ತ)
		keyprint(c, hostkey);
	/* always abort key exchange */
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh2_capable(ಪೂರ್ಣಾಙ್ಕ remote_major, ಪೂರ್ಣಾಙ್ಕ remote_minor)
{
	ವಿಕಲ್ಪ (remote_major) {
	ಪಕ್ಷ 1:
		ಯದಿ (remote_minor == 99)
			ಪ್ರತ್ಯಾಗಮ 1;
		ಭಙ್ಗ;
	ಪಕ್ಷ 2:
		ಪ್ರತ್ಯಾಗಮ 1;
	ಸ್ವಭಾವ:
		ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
keygrab_ssh2(con *c)
{
	ವರ್ಣ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ಪೂರ್ಣಾಙ್ಕ r;

	ವಿಕಲ್ಪ (c->c_keytype) {
	ಪಕ್ಷ KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		ಭಙ್ಗ;
	ಪಕ್ಷ KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		ಭಙ್ಗ;
	ಪಕ್ಷ KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		ಭಙ್ಗ;
	ಪಕ್ಷ KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		ಭಙ್ಗ;
	ಪಕ್ಷ KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		ಭಙ್ಗ;
	ಪಕ್ಷ KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal("unknown key type %d", c->c_keytype);
		ಭಙ್ಗ;
	}
	ಯದಿ ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		ಮುಕ್ತ(c->c_ssh);
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
	ssh_set_verify_host_ಕೀಲಿ_callback(c->c_ssh, ಕೀಲಿ_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

ಸ್ಥಿರ ಶೂನ್ಯ
keyprint_one(ಧ್ರುವ ವರ್ಣ *host, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವರ್ಣ *hostport = ರಿಕ್ತ, *hashed = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *known_host;
	ಪೂರ್ಣಾಙ್ಕ r = 0;

	found_one = 1;

	ಯದಿ (print_sshfp) {
		export_dns_rr(host, ಕೀಲಿ, stdout, 0, hashalg);
		ಪ್ರತ್ಯಾಗಮ;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	ಯದಿ (hash_hosts && (hashed = host_hash(hostport, ರಿಕ್ತ, 0)) == ರಿಕ್ತ)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	ಯದಿ (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	ಯದಿ (r >= 0 && sshkey_write(ಕೀಲಿ, stdout) == 0)
		(ಶೂನ್ಯ)fputs("\n", stdout);
	ಮುಕ್ತ(hashed);
	ಮುಕ್ತ(hostport);
}

ಸ್ಥಿರ ಶೂನ್ಯ
keyprint(con *c, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವರ್ಣ *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	ವರ್ಣ *host, *ohosts;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, ಕೀಲಿ);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ohosts = hosts = xstrdup(hosts);
	ಯಾವತ್ ((host = strsep(&hosts, ",")) != ರಿಕ್ತ)
		keyprint_one(host, ಕೀಲಿ);
	ಮುಕ್ತ(ohosts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
tcpconnect(ವರ್ಣ *host)
{
	ಸಂರಚನಾ addrinfo hints, *ai, *aitop;
	ವರ್ಣ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಙ್ಕ gaierr, s = -1;

	snprintf(strport, ಪರಿಮಾಣ strport, "%d", ssh_port);
	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	ಯದಿ ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತಿ (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ಯದಿ (s == -1) {
			error("socket: %s", strerror(errno));
			ಅನುವರ್ತ;
		}
		ಯದಿ (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		ಯದಿ (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	ಪ್ರತ್ಯಾಗಮ s;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
conalloc(ಧ್ರುವ ವರ್ಣ *iname, ಧ್ರುವ ವರ್ಣ *oname, ಪೂರ್ಣಾಙ್ಕ keytype)
{
	ವರ್ಣ *namebase, *name, *namelist;
	ಪೂರ್ಣಾಙ್ಕ s;

	namebase = namelist = xstrdup(iname);

	ಕುರು {
		name = xstrsep(&namelist, ",");
		ಯದಿ (!name) {
			ಮುಕ್ತ(namebase);
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
	} ಯಾವತ್ ((s = tcpconnect(name)) < 0);

	ಯದಿ (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	ಯದಿ (fdcon[s].c_status)
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
	ಪ್ರತ್ಯಾಗಮ (s);
}

ಸ್ಥಿರ ಶೂನ್ಯ
confree(ಪೂರ್ಣಾಙ್ಕ s)
{
	ಯದಿ (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	ಮುಕ್ತ(fdcon[s].c_namebase);
	ಮುಕ್ತ(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	ಯದಿ (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		ಮುಕ್ತ(fdcon[s].c_ssh);
		fdcon[s].c_ssh = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
conrecycle(ಪೂರ್ಣಾಙ್ಕ s)
{
	con *c = &fdcon[s];
	ಪೂರ್ಣಾಙ್ಕ ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
congreet(ಪೂರ್ಣಾಙ್ಕ s)
{
	ಪೂರ್ಣಾಙ್ಕ remote_major = 0, remote_minor = 0;
	ssize_t n;
	ವರ್ಣ buf[256], ch;
	ವರ್ಣ remote_version[ಪರಿಮಾಣ buf];
	con *c = &fdcon[s];

	ಯದಿ (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, ಪರಿಮಾಣ buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		ಯದಿ (n < 0 || (size_t)n >= ಪರಿಮಾಣ(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			ಪ್ರತ್ಯಾಗಮ;
		}
		ಯದಿ (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			ಪ್ರತ್ಯಾಗಮ;
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
	n = ಪಠ(s, &ch, ಪರಿಮಾಣ(ch));
	ಯದಿ (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (n != 1) {
		ಯದಿ (n == 0)
			errno = EPIPE;
		ವಿಕಲ್ಪ (errno) {
		ಪಕ್ಷ EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			ಭಙ್ಗ;
		ಪಕ್ಷ ECONNREFUSED:
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("read (%s): %s", c->c_name, strerror(errno));
			ಭಙ್ಗ;
		}
		conrecycle(s);
		ಪ್ರತ್ಯಾಗಮ;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	ಯದಿ (ch != '\n') {
		ಯದಿ (c->c_banner_len < ಪರಿಮಾಣ(c->c_banner) - 1)
			ಪ್ರತ್ಯಾಗಮ; /* incomplete line */
		ಯದಿ (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			ಪ್ರತ್ಯಾಗಮ;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		ಪ್ರತ್ಯಾಗಮ;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	ಯದಿ ((c->c_ssh = ssh_packet_set_connection(ರಿಕ್ತ, s, s)) == ರಿಕ್ತ)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	ಯದಿ (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	ಯದಿ (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

ಸ್ಥಿರ ಶೂನ್ಯ
conread(ಪೂರ್ಣಾಙ್ಕ s)
{
	con *c = &fdcon[s];

	ಯದಿ (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

ಸ್ಥಿರ ಶೂನ್ಯ
conloop(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ timespec seltime, now;
	con *c;
	ಪೂರ್ಣಾಙ್ಕ i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	ಯದಿ (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	ಅನ್ಯಥಾ
		timespecclear(&seltime);

	ಯಾವತ್ (ppoll(read_wait, maxfd, &seltime, ರಿಕ್ತ) == -1) {
		ಯದಿ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ಅನುವರ್ತ;
		error("poll error");
	}

	ಪ್ರತಿ (i = 0; i < maxfd; i++) {
		ಯದಿ (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		ಅನ್ಯಥಾ ಯದಿ (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	ಯಾವತ್ (c && timespeccmp(&c->c_ts, &now, <)) {
		ಪೂರ್ಣಾಙ್ಕ s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_one_host(ವರ್ಣ *host)
{
	ವರ್ಣ *name = strnnsep(&host, " \t\n");
	ಪೂರ್ಣಾಙ್ಕ j;

	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (j = KT_MIN; j <= KT_MAX; j *= 2) {
		ಯದಿ (get_keytypes & j) {
			ಯಾವತ್ (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_host(ವರ್ಣ *host)
{
	ವರ್ಣ daddr[128];
	ಸಂರಚನಾ xaddr addr, end_addr;
	u_int masklen;

	ಯದಿ (host == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} ಅನ್ಯಥಾ {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		ಯದಿ (addr_host_to_all1s(&end_addr, masklen) != 0)
			ಗಚ್ಛ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		ಪ್ರತಿ (;;) {
			ಯದಿ (addr_ntop(&addr, daddr, ಪರಿಮಾಣ(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				ಪ್ರತ್ಯಾಗಮ;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			ಯದಿ (addr_cmp(&addr, &end_addr) == 0)
				ಭಙ್ಗ;
			addr_increment(&addr);
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	ಪೂರ್ಣಾಙ್ಕ opt, fopt_ಎಣಿಕೆ = 0, j;
	ವರ್ಣ *tname, *cp, *ಸಾಲು = ರಿಕ್ತ;
	size_t linesize = 0;
	FILE *fp;

	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	ಯದಿ (argc <= 1)
		usage();

	ಯಾವತ್ ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		ವಿಕಲ್ಪ (opt) {
		ಪಕ್ಷ 'H':
			hash_hosts = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			get_cert = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			print_sshfp = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			ssh_port = a2port(optarg);
			ಯದಿ (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'T':
			timeout = convtime(optarg);
			ಯದಿ (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'v':
			ಯದಿ (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			ಅನ್ಯಥಾ ಯದಿ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ಅನ್ಯಥಾ
				fatal("Too high debugging level.");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			quiet = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			ಯದಿ (strcmp(optarg, "-") == 0)
				optarg = ರಿಕ್ತ;
			argv[fopt_ಎಣಿಕೆ++] = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'O':
			/* Maybe other misc options in the future too */
			ಯದಿ (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			ಯದಿ ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			ಯಾವತ್ (tname) {
				ಪೂರ್ಣಾಙ್ಕ type = sshkey_type_from_shortname(tname);

				ವಿಕಲ್ಪ (type) {
				ಪಕ್ಷ ಕೀಲಿ_ECDSA:
					get_keytypes |= KT_ECDSA;
					ಭಙ್ಗ;
				ಪಕ್ಷ ಕೀಲಿ_RSA:
					get_keytypes |= KT_RSA;
					ಭಙ್ಗ;
				ಪಕ್ಷ ಕೀಲಿ_ED25519:
					get_keytypes |= KT_ED25519;
					ಭಙ್ಗ;
				ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					ಭಙ್ಗ;
				ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					ಭಙ್ಗ;
				ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					ಭಙ್ಗ;
				ಪಕ್ಷ ಕೀಲಿ_UNSPEC:
				ಸ್ವಭಾವ:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(ರಿಕ್ತ, ",");
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ '4':
			IPv4or6 = AF_INET;
			ಭಙ್ಗ;
		ಪಕ್ಷ '6':
			IPv4or6 = AF_INET6;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage();
		}
	}
	ಯದಿ (optind == argc && !fopt_ಎಣಿಕೆ)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	ಯದಿ (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	ಯದಿ (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	ಯದಿ (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	ಯದಿ (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, ಪರಿಮಾಣ(con));
	read_wait = xcalloc(maxfd, ಪರಿಮಾಣ(ಸಂರಚನಾ pollfd));
	ಪ್ರತಿ (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	ಪ್ರತಿ (j = 0; j < fopt_ಎಣಿಕೆ; j++) {
		ಯದಿ (argv[j] == ರಿಕ್ತ)
			fp = stdin;
		ಅನ್ಯಥಾ ಯದಿ ((fp = fopen(argv[j], "r")) == ರಿಕ್ತ)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ಯಾವತ್ (getline(&ಸಾಲು, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			ಯದಿ ((cp = strchr(ಸಾಲು, '#')) == ರಿಕ್ತ)
				cp = ಸಾಲು + strlen(ಸಾಲು) - 1;
			ಯಾವತ್ (cp >= ಸಾಲು) {
				ಯದಿ (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				ಅನ್ಯಥಾ
					ಭಙ್ಗ;
			}

			/* Skip empty lines */
			ಯದಿ (*ಸಾಲು == '\0')
				ಅನುವರ್ತ;

			do_host(ಸಾಲು);
		}

		ಯದಿ (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ಯದಿ (fp != stdin)
			fclose(fp);
	}
	ಮುಕ್ತ(ಸಾಲು);

	ಯಾವತ್ (optind < argc)
		do_host(argv[optind++]);

	ಯಾವತ್ (ncon > 0)
		conloop();

	ಪ್ರತ್ಯಾಗಮ found_one ? 0 : 1;
}
