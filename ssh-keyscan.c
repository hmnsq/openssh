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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಆದರೆ_ಅಂತ್ಯ

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
ಪೂರ್ಣಾಂಕ IPv4or6 = AF_UNSPEC;

ಪೂರ್ಣಾಂಕ ssh_ಪೋರ್ಟ್ = SSH_DEFAULT_ಪೋರ್ಟ್;

#ವ್ಯಾಖ್ಯಾನಿಸು KT_RSA		(1)
#ವ್ಯಾಖ್ಯಾನಿಸು KT_ECDSA	(1<<1)
#ವ್ಯಾಖ್ಯಾನಿಸು KT_ED25519	(1<<2)
#ವ್ಯಾಖ್ಯಾನಿಸು KT_ECDSA_SK	(1<<4)
#ವ್ಯಾಖ್ಯಾನಿಸು KT_ED25519_SK	(1<<5)
#ವ್ಯಾಖ್ಯಾನಿಸು KT_MLDSA44_ED25519 (1<<6)

#ವ್ಯಾಖ್ಯಾನಿಸು KT_MIN		KT_RSA
#ವ್ಯಾಖ್ಯಾನಿಸು KT_MAX		KT_MLDSA44_ED25519

ಪೂರ್ಣಾಂಕ get_cert = 0;
ಪೂರ್ಣಾಂಕ get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

ಪೂರ್ಣಾಂಕ hash_hosts = 0;		/* Hash hostname on output */

ಪೂರ್ಣಾಂಕ print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು_one = 0;		/* Successfully found a key */

ಪೂರ್ಣಾಂಕ hashalg = -1;		/* Hash for SSHFP records or -1 for all */

ಪೂರ್ಣಾಂಕ quiet = 0;			/* Don't print key comment lines */

#ವ್ಯಾಖ್ಯಾನಿಸು MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
ಪೂರ್ಣಾಂಕ timeout = 5;

ಪೂರ್ಣಾಂಕ maxfd;
#ವ್ಯಾಖ್ಯಾನಿಸು MAXCON (maxfd - 10)

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;
ರಚನೆ pollfd *read_wait;
ಪೂರ್ಣಾಂಕ ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Connection {
	u_char c_ಸ್ಥಿತಿ;	/* State of connection on this file desc. */
#ವ್ಯಾಖ್ಯಾನಿಸು CS_ಬಳಸದ 0		/* File descriptor unused */
#ವ್ಯಾಖ್ಯಾನಿಸು CS_CON 1		/* Waiting to connect/read greeting */
	ಪೂರ್ಣಾಂಕ c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	ಪೂರ್ಣಾಂಕ c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_ಮುಗಿದ;	/* SSH2 done */
	ಅಕ್ಷರ *c_namebase;	/* Address to free for c_name and c_namelist */
	ಅಕ್ಷರ *c_name;		/* Hostname of connection for errors */
	ಅಕ್ಷರ *c_namelist;	/* Pointer to other possible addresses */
	ಅಕ್ಷರ *c_output_name;	/* Hostname of connection for output */
	ರಚನೆ ssh *c_ssh;	/* SSH-connection */
	ಅಕ್ಷರ c_banner[256];	/* Partial server greeting */
	ಗಾತ್ರ_t c_banner_len;	/* Length of partial server greeting */
	ಪೂರ್ಣಾಂಕ c_banner_ಕಳುಹಿಸಿದ;	/* Client greeting has been sent */
	ರಚನೆ timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

ಸ್ಥಿರ ಶೂನ್ಯ keyprint(con *c, ರಚನೆ sshkey *ಕೀಲಿ);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fdlim_get(ಪೂರ್ಣಾಂಕ hard)
{
#ಆದರೆ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ರಚನೆ rlimit rlfd;
	rlim_t lim;

	ಆದರೆ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ಹಿಂತಿರುಗಿ -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	ಆದರೆ (lim <= 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	ಆದರೆ (lim >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		lim = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
	ಹಿಂತಿರುಗಿ lim;
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) ? ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ : SSH_SYSFDMAX);
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fdlim_ಗಣ(ಪೂರ್ಣಾಂಕ lim)
{
#ಆದರೆ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ರಚನೆ rlimit rlfd;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (lim <= 0)
		ಹಿಂತಿರುಗಿ (-1);
#ಆದರೆ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ಆದರೆ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	rlfd.rlim_cur = lim;
	ಆದರೆ (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ಹಿಂತಿರುಗಿ (-1);
#ಅಥವಾಆದರೆ defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
xstrsep(ಅಕ್ಷರ **str, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *delim)
{
	ಅಕ್ಷರ *s, *e;

	ಆದರೆ (!**str)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

	s = *str;
	e = s + strcspn(s, delim);

	ಆದರೆ (*e != '\0')
		*e++ = '\0';
	*str = e;

	ಹಿಂತಿರುಗಿ (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
strnnsep(ಅಕ್ಷರ **stringp, ಅಕ್ಷರ *delim)
{
	ಅಕ್ಷರ *tok;

	ಮಾಡು {
		tok = xstrsep(stringp, delim);
	} ಆಗ (tok && *tok == '\0');
	ಹಿಂತಿರುಗಿ (tok);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೀಲಿ_print_wrapper(ರಚನೆ sshkey *hostkey, ರಚನೆ ssh *ssh)
{
	con *c;

	ಆದರೆ ((c = ssh_get_app_ದತ್ತಾಂಶ(ssh)) != ಖಾಲಿ)
		keyprint(c, hostkey);
	/* always abort key exchange */
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh2_capable(ಪೂರ್ಣಾಂಕ remote_major, ಪೂರ್ಣಾಂಕ remote_minor)
{
	ಆಯ್ಕೆ (remote_major) {
	ಸ್ಥಿತಿ 1:
		ಆದರೆ (remote_minor == 99)
			ಹಿಂತಿರುಗಿ 1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 2:
		ಹಿಂತಿರುಗಿ 1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
keygrab_ssh2(con *c)
{
	ಅಕ್ಷರ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ಪೂರ್ಣಾಂಕ r;

	ಆಯ್ಕೆ (c->c_keytype) {
	ಸ್ಥಿತಿ KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("unknown key type %d", c->c_keytype);
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ ((r = kex_ಸಿದ್ಧತೆ(c->c_ssh, myproposal)) != 0) {
		ಬಿಡುಗಡೆ(c->c_ssh);
		fprintf(stderr, "kex_setup: %s\n", ssh_err(r));
		ನಿರ್ಗಮಿಸು(1);
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#ಆದರೆ_ಅಂತ್ಯ
	c->c_ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh_ಗಣ_verify_host_ಕೀಲಿ_callback(c->c_ssh, ಕೀಲಿ_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_ಸತತ(c->c_ssh, DISPATCH_ಖಂಡ, &c->c_ಮುಗಿದ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
keyprint_one(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಅಕ್ಷರ *hostport = ಖಾಲಿ, *hashed = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ತಿಳಿದ_host;
	ಪೂರ್ಣಾಂಕ r = 0;

	ಸಿಕ್ಕಿತು_one = 1;

	ಆದರೆ (print_sshfp) {
		export_dns_rr(host, ಕೀಲಿ, stdout, 0, hashalg);
		ಹಿಂತಿರುಗಿ;
	}

	hostport = put_host_ಪೋರ್ಟ್(host, ssh_ಪೋರ್ಟ್);
	lowercase(hostport);
	ಆದರೆ (hash_hosts && (hashed = host_hash(hostport, ಖಾಲಿ, 0)) == ಖಾಲಿ)
		fatal("host_hash failed");
	ತಿಳಿದ_host = hash_hosts ? hashed : hostport;
	ಆದರೆ (!get_cert)
		r = fprintf(stdout, "%s ", ತಿಳಿದ_host);
	ಆದರೆ (r >= 0 && sshkey_write(ಕೀಲಿ, stdout) == 0)
		(ಶೂನ್ಯ)fputs("\n", stdout);
	ಬಿಡುಗಡೆ(hashed);
	ಬಿಡುಗಡೆ(hostport);
}

ಸ್ಥಿರ ಶೂನ್ಯ
keyprint(con *c, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಅಕ್ಷರ *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	ಅಕ್ಷರ *host, *ohosts;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (get_cert || (!hash_hosts && ssh_ಪೋರ್ಟ್ == SSH_DEFAULT_ಪೋರ್ಟ್)) {
		keyprint_one(hosts, ಕೀಲಿ);
		ಹಿಂತಿರುಗಿ;
	}
	ohosts = hosts = xstrdup(hosts);
	ಆಗ ((host = strsep(&hosts, ",")) != ಖಾಲಿ)
		keyprint_one(host, ಕೀಲಿ);
	ಬಿಡುಗಡೆ(ohosts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
tcpconnect(ಅಕ್ಷರ *host)
{
	ರಚನೆ addrinfo hints, *ai, *aitop;
	ಅಕ್ಷರ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಂಕ gaierr, s = -1;

	snprintf(strport, ಗಾತ್ರ strport, "%d", ssh_ಪೋರ್ಟ್);
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	ಆದರೆ ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಗಾಗಿ (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ಆದರೆ (s == -1) {
			error("socket: %s", strerror(errno));
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (ಗಣ_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		ಆದರೆ (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	ಹಿಂತಿರುಗಿ s;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
conalloc(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *iname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *oname, ಪೂರ್ಣಾಂಕ keytype)
{
	ಅಕ್ಷರ *namebase, *name, *namelist;
	ಪೂರ್ಣಾಂಕ s;

	namebase = namelist = xstrdup(iname);

	ಮಾಡು {
		name = xstrsep(&namelist, ",");
		ಆದರೆ (!name) {
			ಬಿಡುಗಡೆ(namebase);
			ಹಿಂತಿರುಗಿ (-1);
		}
	} ಆಗ ((s = tcpconnect(name)) < 0);

	ಆದರೆ (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	ಆದರೆ (fdcon[s].c_ಸ್ಥಿತಿ)
		fatal("conalloc: attempt to reuse fdno %d", s);

	debug3_f("oname %s kt %d", oname, keytype);
	fdcon[s].c_fd = s;
	fdcon[s].c_ಸ್ಥಿತಿ = CS_CON;
	fdcon[s].c_namebase = namebase;
	fdcon[s].c_name = name;
	fdcon[s].c_namelist = namelist;
	fdcon[s].c_output_name = xstrdup(oname);
	fdcon[s].c_keytype = keytype;
	fdcon[s].c_banner_len = 0;
	fdcon[s].c_banner_ಕಳುಹಿಸಿದ = 0;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	ಹಿಂತಿರುಗಿ (s);
}

ಸ್ಥಿರ ಶೂನ್ಯ
confree(ಪೂರ್ಣಾಂಕ s)
{
	ಆದರೆ (s >= maxfd || fdcon[s].c_ಸ್ಥಿತಿ == CS_ಬಳಸದ)
		fatal("confree: attempt to free bad fdno %d", s);
	ಬಿಡುಗಡೆ(fdcon[s].c_namebase);
	ಬಿಡುಗಡೆ(fdcon[s].c_output_name);
	fdcon[s].c_ಸ್ಥಿತಿ = CS_ಬಳಸದ;
	fdcon[s].c_keytype = 0;
	ಆದರೆ (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		ಬಿಡುಗಡೆ(fdcon[s].c_ssh);
		fdcon[s].c_ssh = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
conrecycle(ಪೂರ್ಣಾಂಕ s)
{
	con *c = &fdcon[s];
	ಪೂರ್ಣಾಂಕ ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	ಹಿಂತಿರುಗಿ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
congreet(ಪೂರ್ಣಾಂಕ s)
{
	ಪೂರ್ಣಾಂಕ remote_major = 0, remote_minor = 0;
	ssize_t n;
	ಅಕ್ಷರ buf[256], ch;
	ಅಕ್ಷರ remote_ಆವೃತ್ತಿ[ಗಾತ್ರ buf];
	con *c = &fdcon[s];

	ಆದರೆ (!c->c_banner_ಕಳುಹಿಸಿದ) {
		/* send client banner */
		n = snprintf(buf, ಗಾತ್ರ buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		ಆದರೆ (n < 0 || (ಗಾತ್ರ_t)n >= ಗಾತ್ರ(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			ಹಿಂತಿರುಗಿ;
		}
		ಆದರೆ (atomicio(vwrite, s, buf, n) != (ಗಾತ್ರ_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			ಹಿಂತಿರುಗಿ;
		}
		c->c_banner_ಕಳುಹಿಸಿದ = 1;
	}

	/*
	 * Read the server banner as per RFC4253 section 4.2.  The "SSH-"
	 * protocol identification string may be preceded by an arbitrarily
	 * large banner which we must read and ignore.  Read a single byte
	 * at a time so that the event loop retains control of connection
	 * timeouts.  Partial lines are retained in the connection state
	 * between calls.
	 */
	n = ಪಠ(s, &ch, ಗಾತ್ರ(ch));
	ಆದರೆ (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (n != 1) {
		ಆದರೆ (n == 0)
			errno = EPIPE;
		ಆಯ್ಕೆ (errno) {
		ಸ್ಥಿತಿ EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ECONNREFUSED:
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("read (%s): %s", c->c_name, strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		conrecycle(s);
		ಹಿಂತಿರುಗಿ;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	ಆದರೆ (ch != '\n') {
		ಆದರೆ (c->c_banner_len < ಗಾತ್ರ(c->c_banner) - 1)
			ಹಿಂತಿರುಗಿ; /* incomplete line */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			ಹಿಂತಿರುಗಿ;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		ಹಿಂತಿರುಗಿ;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	ಸ್ಮರಣೆ_ನಕಲು(buf, c->c_banner, c->c_banner_len);
	ಆದರೆ ((c->c_ssh = ssh_packet_ಗಣ_connection(ಖಾಲಿ, s, s)) == ಖಾಲಿ)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_ಗಣ_timeout(c->c_ssh, timeout, 1);
	ssh_ಗಣ_app_ದತ್ತಾಂಶ(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_ಆವೃತ್ತಿ) == 3)
		compat_banner(c->c_ssh, remote_ಆವೃತ್ತಿ);
	ಆದರೆ (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_ಪೋರ್ಟ್, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

ಸ್ಥಿರ ಶೂನ್ಯ
conread(ಪೂರ್ಣಾಂಕ s)
{
	con *c = &fdcon[s];

	ಆದರೆ (c->c_ಸ್ಥಿತಿ != CS_CON)
		fatal("conread: invalid status %d", c->c_ಸ್ಥಿತಿ);

	congreet(s);
}

ಸ್ಥಿರ ಶೂನ್ಯ
conloop(ಶೂನ್ಯ)
{
	ರಚನೆ timespec seltime, now;
	con *c;
	ಪೂರ್ಣಾಂಕ i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	ಆದರೆ (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	ಇಲ್ಲದಿದ್ದರೆ
		timespecclear(&seltime);

	ಆಗ (ppoll(read_wait, maxfd, &seltime, ಖಾಲಿ) == -1) {
		ಆದರೆ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ಮುಂದುವರಿ;
		error("poll error");
	}

	ಗಾಗಿ (i = 0; i < maxfd; i++) {
		ಆದರೆ (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	ಆಗ (c && timespeccmp(&c->c_ts, &now, <)) {
		ಪೂರ್ಣಾಂಕ s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_one_host(ಅಕ್ಷರ *host)
{
	ಅಕ್ಷರ *name = strnnsep(&host, " \t\n");
	ಪೂರ್ಣಾಂಕ j;

	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (j = KT_MIN; j <= KT_MAX; j *= 2) {
		ಆದರೆ (get_keytypes & j) {
			ಆಗ (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_host(ಅಕ್ಷರ *host)
{
	ಅಕ್ಷರ daddr[128];
	ರಚನೆ xaddr addr, ಕೊನೆ_addr;
	u_int masklen;

	ಆದರೆ (host == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		ಕೊನೆ_addr = addr;
		ಆದರೆ (addr_host_ಗಮ್ಯ_all1s(&ಕೊನೆ_addr, masklen) != 0)
			ಹೋಗು badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		ಗಾಗಿ (;;) {
			ಆದರೆ (addr_ntop(&addr, daddr, ಗಾತ್ರ(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				ಹಿಂತಿರುಗಿ;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			ಆದರೆ (addr_cmp(&addr, &ಕೊನೆ_addr) == 0)
				ನಿಲ್ಲಿಸು;
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
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	ಪೂರ್ಣಾಂಕ opt, fopt_ಎಣಿಕೆ = 0, j;
	ಅಕ್ಷರ *tname, *cp, *ಸಾಲು = ಖಾಲಿ;
	ಗಾತ್ರ_t linesize = 0;
	FILE *fp;

	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;

	__progname = ssh_get_progname(argv[0]);
	ಬೀಜ_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	ಆದರೆ (argc <= 1)
		usage();

	ಆಗ ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		ಆಯ್ಕೆ (opt) {
		ಸ್ಥಿತಿ 'H':
			hash_hosts = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			get_cert = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			print_sshfp = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			ssh_ಪೋರ್ಟ್ = a2port(optarg);
			ಆದರೆ (ssh_ಪೋರ್ಟ್ <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				ನಿರ್ಗಮಿಸು(1);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'T':
			timeout = convtime(optarg);
			ಆದರೆ (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'v':
			ಆದರೆ (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ಇಲ್ಲದಿದ್ದರೆ
				fatal("Too high debugging level.");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			quiet = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			ಆದರೆ (strcmp(optarg, "-") == 0)
				optarg = ಖಾಲಿ;
			argv[fopt_ಎಣಿಕೆ++] = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'O':
			/* Maybe other misc options in the future too */
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			ಆದರೆ ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			ಆಗ (tname) {
				ಪೂರ್ಣಾಂಕ type = sshkey_type_from_shortname(tname);

				ಆಯ್ಕೆ (type) {
				ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
					get_keytypes |= KT_ECDSA;
					ನಿಲ್ಲಿಸು;
				ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
					get_keytypes |= KT_RSA;
					ನಿಲ್ಲಿಸು;
				ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
					get_keytypes |= KT_ED25519;
					ನಿಲ್ಲಿಸು;
				ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					ನಿಲ್ಲಿಸು;
				ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					ನಿಲ್ಲಿಸು;
				ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					ನಿಲ್ಲಿಸು;
				ಸ್ಥಿತಿ ಕೀಲಿ_UNSPEC:
				ಪೂರ್ವನಿಯೋಜಿತ:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(ಖಾಲಿ, ",");
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '4':
			IPv4or6 = AF_INET;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '6':
			IPv4or6 = AF_INET6;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
		}
	}
	ಆದರೆ (optind == argc && !fopt_ಎಣಿಕೆ)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	ಆದರೆ (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	ಆದರೆ (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	ಆದರೆ (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	ಆದರೆ (maxfd > fdlim_get(0))
		fdlim_ಗಣ(maxfd);
	fdcon = xcalloc(maxfd, ಗಾತ್ರ(con));
	read_wait = xcalloc(maxfd, ಗಾತ್ರ(ರಚನೆ pollfd));
	ಗಾಗಿ (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	ಗಾಗಿ (j = 0; j < fopt_ಎಣಿಕೆ; j++) {
		ಆದರೆ (argv[j] == ಖಾಲಿ)
			fp = stdin;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((fp = fopen(argv[j], "r")) == ಖಾಲಿ)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ಆಗ (getline(&ಸಾಲು, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			ಆದರೆ ((cp = strchr(ಸಾಲು, '#')) == ಖಾಲಿ)
				cp = ಸಾಲು + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಾಲು) - 1;
			ಆಗ (cp >= ಸಾಲು) {
				ಆದರೆ (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				ಇಲ್ಲದಿದ್ದರೆ
					ನಿಲ್ಲಿಸು;
			}

			/* Skip empty lines */
			ಆದರೆ (*ಸಾಲು == '\0')
				ಮುಂದುವರಿ;

			do_host(ಸಾಲು);
		}

		ಆದರೆ (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ಆದರೆ (fp != stdin)
			fclose(fp);
	}
	ಬಿಡುಗಡೆ(ಸಾಲು);

	ಆಗ (optind < argc)
		do_host(argv[optind++]);

	ಆಗ (ncon > 0)
		conloop();

	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು_one ? 0 : 1;
}
