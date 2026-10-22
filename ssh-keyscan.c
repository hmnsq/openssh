/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
 
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/resource.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dns.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
ਪੂਰਨ IPv4or6 = AF_UNSPEC;

ਪੂਰਨ ssh_ਪੋਰਟ = SSH_DEFAULT_ਪੋਰਟ;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_RSA		(1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_ECDSA	(1<<1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_ED25519	(1<<2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_ECDSA_SK	(1<<4)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_ED25519_SK	(1<<5)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_MLDSA44_ED25519 (1<<6)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_MIN		KT_RSA
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KT_MAX		KT_MLDSA44_ED25519

ਪੂਰਨ get_cert = 0;
ਪੂਰਨ get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

ਪੂਰਨ hash_hosts = 0;		/* Hash hostname on output */

ਪੂਰਨ print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

ਪੂਰਨ ਮਿਲਿਆ_one = 0;		/* Successfully found a key */

ਪੂਰਨ hashalg = -1;		/* Hash for SSHFP records or -1 for all */

ਪੂਰਨ quiet = 0;			/* Don't print key comment lines */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
ਪੂਰਨ timeout = 5;

ਪੂਰਨ maxfd;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAXCON (maxfd - 10)

ਬਾਹਰੀ ਅੱਖਰ *__progname;
ਬਣਤਰ pollfd *read_wait;
ਪੂਰਨ ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Connection {
	u_char c_ਸਥਿਤੀ;	/* State of connection on this file desc. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CS_ਅਣਵਰਤਿਆ 0		/* File descriptor unused */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CS_CON 1		/* Waiting to connect/read greeting */
	ਪੂਰਨ c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	ਪੂਰਨ c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_ਪੂਰਾ;	/* SSH2 done */
	ਅੱਖਰ *c_namebase;	/* Address to free for c_name and c_namelist */
	ਅੱਖਰ *c_name;		/* Hostname of connection for errors */
	ਅੱਖਰ *c_namelist;	/* Pointer to other possible addresses */
	ਅੱਖਰ *c_output_name;	/* Hostname of connection for output */
	ਬਣਤਰ ssh *c_ssh;	/* SSH-connection */
	ਅੱਖਰ c_banner[256];	/* Partial server greeting */
	ਮਾਪ_t c_banner_len;	/* Length of partial server greeting */
	ਪੂਰਨ c_banner_ਭੇਜਿਆ;	/* Client greeting has been sent */
	ਬਣਤਰ timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

ਸਥਿਰ ਖਾਲੀ keyprint(con *c, ਬਣਤਰ sshkey *ਕੁੰਜੀ);

ਸਥਿਰ ਪੂਰਨ
fdlim_get(ਪੂਰਨ hard)
{
#ਜੇ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ਬਣਤਰ rlimit rlfd;
	rlim_t lim;

	ਜੇ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ਵਾਪਸ -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	ਜੇ (lim <= 0)
		ਵਾਪਸ -1;
	ਜੇ (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	ਜੇ (lim >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		lim = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
	ਵਾਪਸ lim;
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) ? ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ : SSH_SYSFDMAX);
#ਜੇ_ਅੰਤ
}

ਸਥਿਰ ਪੂਰਨ
fdlim_ਸੈੱਟ(ਪੂਰਨ lim)
{
#ਜੇ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ਬਣਤਰ rlimit rlfd;
#ਜੇ_ਅੰਤ

	ਜੇ (lim <= 0)
		ਵਾਪਸ (-1);
#ਜੇ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ਜੇ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ਵਾਪਸ (-1);
	rlfd.rlim_cur = lim;
	ਜੇ (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ਵਾਪਸ (-1);
#ਜਾਂਜੇ defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
ਸਥਿਰ ਅੱਖਰ *
xstrsep(ਅੱਖਰ **str, ਅਚਲ ਅੱਖਰ *delim)
{
	ਅੱਖਰ *s, *e;

	ਜੇ (!**str)
		ਵਾਪਸ (ਨਿਰਾ);

	s = *str;
	e = s + strcspn(s, delim);

	ਜੇ (*e != '\0')
		*e++ = '\0';
	*str = e;

	ਵਾਪਸ (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
ਸਥਿਰ ਅੱਖਰ *
strnnsep(ਅੱਖਰ **stringp, ਅੱਖਰ *delim)
{
	ਅੱਖਰ *tok;

	ਕਰੋ {
		tok = xstrsep(stringp, delim);
	} ਜਦੋਂ (tok && *tok == '\0');
	ਵਾਪਸ (tok);
}


ਸਥਿਰ ਪੂਰਨ
ਕੁੰਜੀ_print_wrapper(ਬਣਤਰ sshkey *hostkey, ਬਣਤਰ ssh *ssh)
{
	con *c;

	ਜੇ ((c = ssh_get_app_ਅੰਕੜੇ(ssh)) != ਨਿਰਾ)
		keyprint(c, hostkey);
	/* always abort key exchange */
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਪੂਰਨ
ssh2_capable(ਪੂਰਨ remote_major, ਪੂਰਨ remote_minor)
{
	ਚੋਣ (remote_major) {
	ਹਾਲਤ 1:
		ਜੇ (remote_minor == 99)
			ਵਾਪਸ 1;
		ਰੋਕੋ;
	ਹਾਲਤ 2:
		ਵਾਪਸ 1;
	ਮੂਲ:
		ਰੋਕੋ;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
keygrab_ssh2(con *c)
{
	ਅੱਖਰ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ਪੂਰਨ r;

	ਚੋਣ (c->c_keytype) {
	ਹਾਲਤ KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		ਰੋਕੋ;
	ਹਾਲਤ KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		ਰੋਕੋ;
	ਹਾਲਤ KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		ਰੋਕੋ;
	ਹਾਲਤ KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		ਰੋਕੋ;
	ਹਾਲਤ KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		ਰੋਕੋ;
	ਹਾਲਤ KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		ਰੋਕੋ;
	ਮੂਲ:
		fatal("unknown key type %d", c->c_keytype);
		ਰੋਕੋ;
	}
	ਜੇ ((r = kex_ਤਿਆਰੀ(c->c_ssh, myproposal)) != 0) {
		ਮੁਕਤ(c->c_ssh);
		fprintf(stderr, "kex_setup: %s\n", ssh_err(r));
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#ਜੇ_ਅੰਤ
	c->c_ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh_ਸੈੱਟ_verify_host_ਕੁੰਜੀ_callback(c->c_ssh, ਕੁੰਜੀ_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_ਲੜੀਵਾਰ(c->c_ssh, DISPATCH_ਖੰਡ, &c->c_ਪੂਰਾ);
}

ਸਥਿਰ ਖਾਲੀ
keyprint_one(ਅਚਲ ਅੱਖਰ *host, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅੱਖਰ *hostport = ਨਿਰਾ, *hashed = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *ਗਿਆਤ_host;
	ਪੂਰਨ r = 0;

	ਮਿਲਿਆ_one = 1;

	ਜੇ (print_sshfp) {
		export_dns_rr(host, ਕੁੰਜੀ, stdout, 0, hashalg);
		ਵਾਪਸ;
	}

	hostport = put_host_ਪੋਰਟ(host, ssh_ਪੋਰਟ);
	lowercase(hostport);
	ਜੇ (hash_hosts && (hashed = host_hash(hostport, ਨਿਰਾ, 0)) == ਨਿਰਾ)
		fatal("host_hash failed");
	ਗਿਆਤ_host = hash_hosts ? hashed : hostport;
	ਜੇ (!get_cert)
		r = fprintf(stdout, "%s ", ਗਿਆਤ_host);
	ਜੇ (r >= 0 && sshkey_write(ਕੁੰਜੀ, stdout) == 0)
		(ਖਾਲੀ)fputs("\n", stdout);
	ਮੁਕਤ(hashed);
	ਮੁਕਤ(hostport);
}

ਸਥਿਰ ਖਾਲੀ
keyprint(con *c, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅੱਖਰ *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	ਅੱਖਰ *host, *ohosts;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (get_cert || (!hash_hosts && ssh_ਪੋਰਟ == SSH_DEFAULT_ਪੋਰਟ)) {
		keyprint_one(hosts, ਕੁੰਜੀ);
		ਵਾਪਸ;
	}
	ohosts = hosts = xstrdup(hosts);
	ਜਦੋਂ ((host = strsep(&hosts, ",")) != ਨਿਰਾ)
		keyprint_one(host, ਕੁੰਜੀ);
	ਮੁਕਤ(ohosts);
}

ਸਥਿਰ ਪੂਰਨ
tcpconnect(ਅੱਖਰ *host)
{
	ਬਣਤਰ addrinfo hints, *ai, *aitop;
	ਅੱਖਰ strport[NI_MAXSERV];
	ਪੂਰਨ gaierr, s = -1;

	snprintf(strport, ਆਕਾਰ strport, "%d", ssh_ਪੋਰਟ);
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	ਜੇ ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		ਵਾਪਸ -1;
	}
	ਲਈ (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ਜੇ (s == -1) {
			error("socket: %s", strerror(errno));
			ਜਾਰੀ;
		}
		ਜੇ (ਸੈੱਟ_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		ਜੇ (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	ਵਾਪਸ s;
}

ਸਥਿਰ ਪੂਰਨ
conalloc(ਅਚਲ ਅੱਖਰ *iname, ਅਚਲ ਅੱਖਰ *oname, ਪੂਰਨ keytype)
{
	ਅੱਖਰ *namebase, *name, *namelist;
	ਪੂਰਨ s;

	namebase = namelist = xstrdup(iname);

	ਕਰੋ {
		name = xstrsep(&namelist, ",");
		ਜੇ (!name) {
			ਮੁਕਤ(namebase);
			ਵਾਪਸ (-1);
		}
	} ਜਦੋਂ ((s = tcpconnect(name)) < 0);

	ਜੇ (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	ਜੇ (fdcon[s].c_ਸਥਿਤੀ)
		fatal("conalloc: attempt to reuse fdno %d", s);

	debug3_f("oname %s kt %d", oname, keytype);
	fdcon[s].c_fd = s;
	fdcon[s].c_ਸਥਿਤੀ = CS_CON;
	fdcon[s].c_namebase = namebase;
	fdcon[s].c_name = name;
	fdcon[s].c_namelist = namelist;
	fdcon[s].c_output_name = xstrdup(oname);
	fdcon[s].c_keytype = keytype;
	fdcon[s].c_banner_len = 0;
	fdcon[s].c_banner_ਭੇਜਿਆ = 0;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	ਵਾਪਸ (s);
}

ਸਥਿਰ ਖਾਲੀ
confree(ਪੂਰਨ s)
{
	ਜੇ (s >= maxfd || fdcon[s].c_ਸਥਿਤੀ == CS_ਅਣਵਰਤਿਆ)
		fatal("confree: attempt to free bad fdno %d", s);
	ਮੁਕਤ(fdcon[s].c_namebase);
	ਮੁਕਤ(fdcon[s].c_output_name);
	fdcon[s].c_ਸਥਿਤੀ = CS_ਅਣਵਰਤਿਆ;
	fdcon[s].c_keytype = 0;
	ਜੇ (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		ਮੁਕਤ(fdcon[s].c_ssh);
		fdcon[s].c_ssh = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

ਸਥਿਰ ਪੂਰਨ
conrecycle(ਪੂਰਨ s)
{
	con *c = &fdcon[s];
	ਪੂਰਨ ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	ਵਾਪਸ (ret);
}

ਸਥਿਰ ਖਾਲੀ
congreet(ਪੂਰਨ s)
{
	ਪੂਰਨ remote_major = 0, remote_minor = 0;
	ssize_t n;
	ਅੱਖਰ buf[256], ch;
	ਅੱਖਰ remote_ਸੰਸਕਰਣ[ਆਕਾਰ buf];
	con *c = &fdcon[s];

	ਜੇ (!c->c_banner_ਭੇਜਿਆ) {
		/* send client banner */
		n = snprintf(buf, ਆਕਾਰ buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		ਜੇ (n < 0 || (ਮਾਪ_t)n >= ਆਕਾਰ(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			ਵਾਪਸ;
		}
		ਜੇ (atomicio(vwrite, s, buf, n) != (ਮਾਪ_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			ਵਾਪਸ;
		}
		c->c_banner_ਭੇਜਿਆ = 1;
	}

	/*
	 * Read the server banner as per RFC4253 section 4.2.  The "SSH-"
	 * protocol identification string may be preceded by an arbitrarily
	 * large banner which we must read and ignore.  Read a single byte
	 * at a time so that the event loop retains control of connection
	 * timeouts.  Partial lines are retained in the connection state
	 * between calls.
	 */
	n = ਪਠ(s, &ch, ਆਕਾਰ(ch));
	ਜੇ (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		ਵਾਪਸ;
	ਜੇ (n != 1) {
		ਜੇ (n == 0)
			errno = EPIPE;
		ਚੋਣ (errno) {
		ਹਾਲਤ EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			ਰੋਕੋ;
		ਹਾਲਤ ECONNREFUSED:
			ਰੋਕੋ;
		ਮੂਲ:
			error("read (%s): %s", c->c_name, strerror(errno));
			ਰੋਕੋ;
		}
		conrecycle(s);
		ਵਾਪਸ;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	ਜੇ (ch != '\n') {
		ਜੇ (c->c_banner_len < ਆਕਾਰ(c->c_banner) - 1)
			ਵਾਪਸ; /* incomplete line */
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			ਵਾਪਸ;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		ਵਾਪਸ;
	}
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		ਵਾਪਸ;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf, c->c_banner, c->c_banner_len);
	ਜੇ ((c->c_ssh = ssh_packet_ਸੈੱਟ_connection(ਨਿਰਾ, s, s)) == ਨਿਰਾ)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_ਸੈੱਟ_timeout(c->c_ssh, timeout, 1);
	ssh_ਸੈੱਟ_app_ਅੰਕੜੇ(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	ਜੇ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_ਸੰਸਕਰਣ) == 3)
		compat_banner(c->c_ssh, remote_ਸੰਸਕਰਣ);
	ਜੇ (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		ਵਾਪਸ;
	}
	ਜੇ (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_ਪੋਰਟ, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

ਸਥਿਰ ਖਾਲੀ
conread(ਪੂਰਨ s)
{
	con *c = &fdcon[s];

	ਜੇ (c->c_ਸਥਿਤੀ != CS_CON)
		fatal("conread: invalid status %d", c->c_ਸਥਿਤੀ);

	congreet(s);
}

ਸਥਿਰ ਖਾਲੀ
conloop(ਖਾਲੀ)
{
	ਬਣਤਰ timespec seltime, now;
	con *c;
	ਪੂਰਨ i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	ਜੇ (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	ਨਹੀਂਤਾਂ
		timespecclear(&seltime);

	ਜਦੋਂ (ppoll(read_wait, maxfd, &seltime, ਨਿਰਾ) == -1) {
		ਜੇ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ਜਾਰੀ;
		error("poll error");
	}

	ਲਈ (i = 0; i < maxfd; i++) {
		ਜੇ (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		ਨਹੀਂਤਾਂ ਜੇ (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	ਜਦੋਂ (c && timespeccmp(&c->c_ts, &now, <)) {
		ਪੂਰਨ s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

ਸਥਿਰ ਖਾਲੀ
do_one_host(ਅੱਖਰ *host)
{
	ਅੱਖਰ *name = strnnsep(&host, " \t\n");
	ਪੂਰਨ j;

	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (j = KT_MIN; j <= KT_MAX; j *= 2) {
		ਜੇ (get_keytypes & j) {
			ਜਦੋਂ (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
do_host(ਅੱਖਰ *host)
{
	ਅੱਖਰ daddr[128];
	ਬਣਤਰ xaddr addr, ਸਿਰਾ_addr;
	u_int masklen;

	ਜੇ (host == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} ਨਹੀਂਤਾਂ {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		ਸਿਰਾ_addr = addr;
		ਜੇ (addr_host_ਮੰਜ਼ਿਲ_all1s(&ਸਿਰਾ_addr, masklen) != 0)
			ਜਾਓ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		ਲਈ (;;) {
			ਜੇ (addr_ntop(&addr, daddr, ਆਕਾਰ(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				ਵਾਪਸ;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			ਜੇ (addr_cmp(&addr, &ਸਿਰਾ_addr) == 0)
				ਰੋਕੋ;
			addr_increment(&addr);
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	ਪੂਰਨ opt, fopt_ਗਿਣਤੀ = 0, j;
	ਅੱਖਰ *tname, *cp, *ਸਤਰ = ਨਿਰਾ;
	ਮਾਪ_t linesize = 0;
	FILE *fp;

	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;

	__progname = ssh_get_progname(argv[0]);
	ਬੀਜ_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	ਜੇ (argc <= 1)
		usage();

	ਜਦੋਂ ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		ਚੋਣ (opt) {
		ਹਾਲਤ 'H':
			hash_hosts = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			get_cert = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			print_sshfp = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			ssh_ਪੋਰਟ = a2port(optarg);
			ਜੇ (ssh_ਪੋਰਟ <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'T':
			timeout = convtime(optarg);
			ਜੇ (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'v':
			ਜੇ (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			ਨਹੀਂਤਾਂ ਜੇ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ਨਹੀਂਤਾਂ
				fatal("Too high debugging level.");
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			quiet = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			ਜੇ (strcmp(optarg, "-") == 0)
				optarg = ਨਿਰਾ;
			argv[fopt_ਗਿਣਤੀ++] = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'O':
			/* Maybe other misc options in the future too */
			ਜੇ (ਲੜੀ_ਤੁਲਨਾ(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			ਜੇ ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			ਜਦੋਂ (tname) {
				ਪੂਰਨ type = sshkey_type_from_shortname(tname);

				ਚੋਣ (type) {
				ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
					get_keytypes |= KT_ECDSA;
					ਰੋਕੋ;
				ਹਾਲਤ ਕੁੰਜੀ_RSA:
					get_keytypes |= KT_RSA;
					ਰੋਕੋ;
				ਹਾਲਤ ਕੁੰਜੀ_ED25519:
					get_keytypes |= KT_ED25519;
					ਰੋਕੋ;
				ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					ਰੋਕੋ;
				ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					ਰੋਕੋ;
				ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					ਰੋਕੋ;
				ਹਾਲਤ ਕੁੰਜੀ_UNSPEC:
				ਮੂਲ:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(ਨਿਰਾ, ",");
			}
			ਰੋਕੋ;
		ਹਾਲਤ '4':
			IPv4or6 = AF_INET;
			ਰੋਕੋ;
		ਹਾਲਤ '6':
			IPv4or6 = AF_INET6;
			ਰੋਕੋ;
		ਮੂਲ:
			usage();
		}
	}
	ਜੇ (optind == argc && !fopt_ਗਿਣਤੀ)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	ਜੇ (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	ਜੇ (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	ਜੇ (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	ਜੇ (maxfd > fdlim_get(0))
		fdlim_ਸੈੱਟ(maxfd);
	fdcon = xcalloc(maxfd, ਆਕਾਰ(con));
	read_wait = xcalloc(maxfd, ਆਕਾਰ(ਬਣਤਰ pollfd));
	ਲਈ (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	ਲਈ (j = 0; j < fopt_ਗਿਣਤੀ; j++) {
		ਜੇ (argv[j] == ਨਿਰਾ)
			fp = stdin;
		ਨਹੀਂਤਾਂ ਜੇ ((fp = fopen(argv[j], "r")) == ਨਿਰਾ)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ਜਦੋਂ (getline(&ਸਤਰ, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			ਜੇ ((cp = strchr(ਸਤਰ, '#')) == ਨਿਰਾ)
				cp = ਸਤਰ + ਲੜੀ_ਲੰਬਾਈ(ਸਤਰ) - 1;
			ਜਦੋਂ (cp >= ਸਤਰ) {
				ਜੇ (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				ਨਹੀਂਤਾਂ
					ਰੋਕੋ;
			}

			/* Skip empty lines */
			ਜੇ (*ਸਤਰ == '\0')
				ਜਾਰੀ;

			do_host(ਸਤਰ);
		}

		ਜੇ (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ਜੇ (fp != stdin)
			fclose(fp);
	}
	ਮੁਕਤ(ਸਤਰ);

	ਜਦੋਂ (optind < argc)
		do_host(argv[optind++]);

	ਜਦੋਂ (ncon > 0)
		conloop();

	ਵਾਪਸ ਮਿਲਿਆ_one ? 0 : 1;
}
