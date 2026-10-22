/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#അന്തര്ഭാവ "includes.h"
 
#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/resource.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#endif

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "dns.h"
#അന്തര്ഭാവ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
പൂർണ്ണസംഖ്യ IPv4or6 = AF_UNSPEC;

പൂർണ്ണസംഖ്യ ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

പൂർണ്ണസംഖ്യ get_cert = 0;
പൂർണ്ണസംഖ്യ get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

പൂർണ്ണസംഖ്യ hash_hosts = 0;		/* Hash hostname on output */

പൂർണ്ണസംഖ്യ print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

പൂർണ്ണസംഖ്യ found_one = 0;		/* Successfully found a key */

പൂർണ്ണസംഖ്യ hashalg = -1;		/* Hash for SSHFP records or -1 for all */

പൂർണ്ണസംഖ്യ quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
പൂർണ്ണസംഖ്യ timeout = 5;

പൂർണ്ണസംഖ്യ maxfd;
#define MAXCON (maxfd - 10)

ബാഹ്യ അക്ഷരം *__progname;
ഘടന pollfd *read_wait;
പൂർണ്ണസംഖ്യ ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
തരനിർവചനം ഘടന Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	പൂർണ്ണസംഖ്യ c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	പൂർണ്ണസംഖ്യ c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	അക്ഷരം *c_namebase;	/* Address to free for c_name and c_namelist */
	അക്ഷരം *c_name;		/* Hostname of connection for errors */
	അക്ഷരം *c_namelist;	/* Pointer to other possible addresses */
	അക്ഷരം *c_output_name;	/* Hostname of connection for output */
	ഘടന ssh *c_ssh;	/* SSH-connection */
	അക്ഷരം c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	പൂർണ്ണസംഖ്യ c_banner_sent;	/* Client greeting has been sent */
	ഘടന timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

സ്ഥിതം ശൂന്യം keyprint(con *c, ഘടന sshkey *താക്കോൽ);

സ്ഥിതം പൂർണ്ണസംഖ്യ
fdlim_get(പൂർണ്ണസംഖ്യ hard)
{
#എങ്കിൽ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ഘടന rlimit rlfd;
	rlim_t lim;

	എങ്കിൽ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		തിരികെ -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	എങ്കിൽ (lim <= 0)
		തിരികെ -1;
	എങ്കിൽ (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	എങ്കിൽ (lim >= INT_MAX)
		lim = INT_MAX;
	തിരികെ lim;
#അല്ലെങ്കിൽ
	തിരികെ (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
fdlim_set(പൂർണ്ണസംഖ്യ lim)
{
#എങ്കിൽ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	ഘടന rlimit rlfd;
#endif

	എങ്കിൽ (lim <= 0)
		തിരികെ (-1);
#എങ്കിൽ defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	എങ്കിൽ (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		തിരികെ (-1);
	rlfd.rlim_cur = lim;
	എങ്കിൽ (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		തിരികെ (-1);
#അല്ലെങ്കിലെങ്കിൽ defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	തിരികെ (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
സ്ഥിതം അക്ഷരം *
xstrsep(അക്ഷരം **str, സ്ഥിരം അക്ഷരം *delim)
{
	അക്ഷരം *s, *e;

	എങ്കിൽ (!**str)
		തിരികെ (ശൂന്യ);

	s = *str;
	e = s + strcspn(s, delim);

	എങ്കിൽ (*e != '\0')
		*e++ = '\0';
	*str = e;

	തിരികെ (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
സ്ഥിതം അക്ഷരം *
strnnsep(അക്ഷരം **stringp, അക്ഷരം *delim)
{
	അക്ഷരം *tok;

	ചെയ്യുക {
		tok = xstrsep(stringp, delim);
	} ആകുമ്പോൾ (tok && *tok == '\0');
	തിരികെ (tok);
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
താക്കോൽ_print_wrapper(ഘടന sshkey *hostkey, ഘടന ssh *ssh)
{
	con *c;

	എങ്കിൽ ((c = ssh_get_app_data(ssh)) != ശൂന്യ)
		keyprint(c, hostkey);
	/* always abort key exchange */
	തിരികെ -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh2_capable(പൂർണ്ണസംഖ്യ remote_major, പൂർണ്ണസംഖ്യ remote_minor)
{
	തിരഞ്ഞെടുപ്പ് (remote_major) {
	അവസ്ഥ 1:
		എങ്കിൽ (remote_minor == 99)
			തിരികെ 1;
		നിർത്തുക;
	അവസ്ഥ 2:
		തിരികെ 1;
	സ്ഥിരസ്ഥിതി:
		നിർത്തുക;
	}
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
keygrab_ssh2(con *c)
{
	അക്ഷരം *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	പൂർണ്ണസംഖ്യ r;

	തിരഞ്ഞെടുപ്പ് (c->c_keytype) {
	അവസ്ഥ KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		നിർത്തുക;
	അവസ്ഥ KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		നിർത്തുക;
	അവസ്ഥ KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		നിർത്തുക;
	അവസ്ഥ KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		നിർത്തുക;
	അവസ്ഥ KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		നിർത്തുക;
	അവസ്ഥ KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal("unknown key type %d", c->c_keytype);
		നിർത്തുക;
	}
	എങ്കിൽ ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		സ്വതന്ത്രം(c->c_ssh);
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
	ssh_set_verify_host_താക്കോൽ_callback(c->c_ssh, താക്കോൽ_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

സ്ഥിതം ശൂന്യം
keyprint_one(സ്ഥിരം അക്ഷരം *host, ഘടന sshkey *താക്കോൽ)
{
	അക്ഷരം *hostport = ശൂന്യ, *hashed = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *known_host;
	പൂർണ്ണസംഖ്യ r = 0;

	found_one = 1;

	എങ്കിൽ (print_sshfp) {
		export_dns_rr(host, താക്കോൽ, stdout, 0, hashalg);
		തിരികെ;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	എങ്കിൽ (hash_hosts && (hashed = host_hash(hostport, ശൂന്യ, 0)) == ശൂന്യ)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	എങ്കിൽ (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	എങ്കിൽ (r >= 0 && sshkey_write(താക്കോൽ, stdout) == 0)
		(ശൂന്യം)fputs("\n", stdout);
	സ്വതന്ത്രം(hashed);
	സ്വതന്ത്രം(hostport);
}

സ്ഥിതം ശൂന്യം
keyprint(con *c, ഘടന sshkey *താക്കോൽ)
{
	അക്ഷരം *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	അക്ഷരം *host, *ohosts;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, താക്കോൽ);
		തിരികെ;
	}
	ohosts = hosts = xstrdup(hosts);
	ആകുമ്പോൾ ((host = strsep(&hosts, ",")) != ശൂന്യ)
		keyprint_one(host, താക്കോൽ);
	സ്വതന്ത്രം(ohosts);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
tcpconnect(അക്ഷരം *host)
{
	ഘടന addrinfo hints, *ai, *aitop;
	അക്ഷരം strport[NI_MAXSERV];
	പൂർണ്ണസംഖ്യ gaierr, s = -1;

	snprintf(strport, വലുപ്പം strport, "%d", ssh_port);
	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	എങ്കിൽ ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		തിരികെ -1;
	}
	വേണ്ടി (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		എങ്കിൽ (s == -1) {
			error("socket: %s", strerror(errno));
			തുടരുക;
		}
		എങ്കിൽ (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		എങ്കിൽ (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		അല്ലെങ്കിൽ
			നിർത്തുക;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	തിരികെ s;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
conalloc(സ്ഥിരം അക്ഷരം *iname, സ്ഥിരം അക്ഷരം *oname, പൂർണ്ണസംഖ്യ keytype)
{
	അക്ഷരം *namebase, *name, *namelist;
	പൂർണ്ണസംഖ്യ s;

	namebase = namelist = xstrdup(iname);

	ചെയ്യുക {
		name = xstrsep(&namelist, ",");
		എങ്കിൽ (!name) {
			സ്വതന്ത്രം(namebase);
			തിരികെ (-1);
		}
	} ആകുമ്പോൾ ((s = tcpconnect(name)) < 0);

	എങ്കിൽ (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	എങ്കിൽ (fdcon[s].c_status)
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
	തിരികെ (s);
}

സ്ഥിതം ശൂന്യം
confree(പൂർണ്ണസംഖ്യ s)
{
	എങ്കിൽ (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	സ്വതന്ത്രം(fdcon[s].c_namebase);
	സ്വതന്ത്രം(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	എങ്കിൽ (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		സ്വതന്ത്രം(fdcon[s].c_ssh);
		fdcon[s].c_ssh = ശൂന്യ;
	} അല്ലെങ്കിൽ
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
conrecycle(പൂർണ്ണസംഖ്യ s)
{
	con *c = &fdcon[s];
	പൂർണ്ണസംഖ്യ ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	തിരികെ (ret);
}

സ്ഥിതം ശൂന്യം
congreet(പൂർണ്ണസംഖ്യ s)
{
	പൂർണ്ണസംഖ്യ remote_major = 0, remote_minor = 0;
	ssize_t n;
	അക്ഷരം buf[256], ch;
	അക്ഷരം remote_version[വലുപ്പം buf];
	con *c = &fdcon[s];

	എങ്കിൽ (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, വലുപ്പം buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		എങ്കിൽ (n < 0 || (size_t)n >= വലുപ്പം(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			തിരികെ;
		}
		എങ്കിൽ (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			തിരികെ;
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
	n = പഠ(s, &ch, വലുപ്പം(ch));
	എങ്കിൽ (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		തിരികെ;
	എങ്കിൽ (n != 1) {
		എങ്കിൽ (n == 0)
			errno = EPIPE;
		തിരഞ്ഞെടുപ്പ് (errno) {
		അവസ്ഥ EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			നിർത്തുക;
		അവസ്ഥ ECONNREFUSED:
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("read (%s): %s", c->c_name, strerror(errno));
			നിർത്തുക;
		}
		conrecycle(s);
		തിരികെ;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	എങ്കിൽ (ch != '\n') {
		എങ്കിൽ (c->c_banner_len < വലുപ്പം(c->c_banner) - 1)
			തിരികെ; /* incomplete line */
		എങ്കിൽ (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			തിരികെ;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		തിരികെ;
	}
	എങ്കിൽ (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		തിരികെ;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	എങ്കിൽ ((c->c_ssh = ssh_packet_set_connection(ശൂന്യ, s, s)) == ശൂന്യ)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	എങ്കിൽ (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	എങ്കിൽ (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		തിരികെ;
	}
	എങ്കിൽ (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

സ്ഥിതം ശൂന്യം
conread(പൂർണ്ണസംഖ്യ s)
{
	con *c = &fdcon[s];

	എങ്കിൽ (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

സ്ഥിതം ശൂന്യം
conloop(ശൂന്യം)
{
	ഘടന timespec seltime, now;
	con *c;
	പൂർണ്ണസംഖ്യ i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	എങ്കിൽ (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	അല്ലെങ്കിൽ
		timespecclear(&seltime);

	ആകുമ്പോൾ (ppoll(read_wait, maxfd, &seltime, ശൂന്യ) == -1) {
		എങ്കിൽ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			തുടരുക;
		error("poll error");
	}

	വേണ്ടി (i = 0; i < maxfd; i++) {
		എങ്കിൽ (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		അല്ലെങ്കിൽ എങ്കിൽ (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	ആകുമ്പോൾ (c && timespeccmp(&c->c_ts, &now, <)) {
		പൂർണ്ണസംഖ്യ s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

സ്ഥിതം ശൂന്യം
do_one_host(അക്ഷരം *host)
{
	അക്ഷരം *name = strnnsep(&host, " \t\n");
	പൂർണ്ണസംഖ്യ j;

	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (j = KT_MIN; j <= KT_MAX; j *= 2) {
		എങ്കിൽ (get_keytypes & j) {
			ആകുമ്പോൾ (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

സ്ഥിതം ശൂന്യം
do_host(അക്ഷരം *host)
{
	അക്ഷരം daddr[128];
	ഘടന xaddr addr, end_addr;
	u_int masklen;

	എങ്കിൽ (host == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} അല്ലെങ്കിൽ {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		എങ്കിൽ (addr_host_to_all1s(&end_addr, masklen) != 0)
			പോകുക badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		വേണ്ടി (;;) {
			എങ്കിൽ (addr_ntop(&addr, daddr, വലുപ്പം(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				തിരികെ;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			എങ്കിൽ (addr_cmp(&addr, &end_addr) == 0)
				നിർത്തുക;
			addr_increment(&addr);
		}
	}
}

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	പൂർണ്ണസംഖ്യ opt, fopt_എണ്ണം = 0, j;
	അക്ഷരം *tname, *cp, *വരി = ശൂന്യ;
	size_t linesize = 0;
	FILE *fp;

	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	ബാഹ്യ അക്ഷരം *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	എങ്കിൽ (argc <= 1)
		usage();

	ആകുമ്പോൾ ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (opt) {
		അവസ്ഥ 'H':
			hash_hosts = 1;
			നിർത്തുക;
		അവസ്ഥ 'c':
			get_cert = 1;
			നിർത്തുക;
		അവസ്ഥ 'D':
			print_sshfp = 1;
			നിർത്തുക;
		അവസ്ഥ 'p':
			ssh_port = a2port(optarg);
			എങ്കിൽ (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			നിർത്തുക;
		അവസ്ഥ 'T':
			timeout = convtime(optarg);
			എങ്കിൽ (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			നിർത്തുക;
		അവസ്ഥ 'v':
			എങ്കിൽ (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			അല്ലെങ്കിൽ എങ്കിൽ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			അല്ലെങ്കിൽ
				fatal("Too high debugging level.");
			നിർത്തുക;
		അവസ്ഥ 'q':
			quiet = 1;
			നിർത്തുക;
		അവസ്ഥ 'f':
			എങ്കിൽ (strcmp(optarg, "-") == 0)
				optarg = ശൂന്യ;
			argv[fopt_എണ്ണം++] = optarg;
			നിർത്തുക;
		അവസ്ഥ 'O':
			/* Maybe other misc options in the future too */
			എങ്കിൽ (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			എങ്കിൽ ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			നിർത്തുക;
		അവസ്ഥ 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			ആകുമ്പോൾ (tname) {
				പൂർണ്ണസംഖ്യ type = sshkey_type_from_shortname(tname);

				തിരഞ്ഞെടുപ്പ് (type) {
				അവസ്ഥ താക്കോൽ_ECDSA:
					get_keytypes |= KT_ECDSA;
					നിർത്തുക;
				അവസ്ഥ താക്കോൽ_RSA:
					get_keytypes |= KT_RSA;
					നിർത്തുക;
				അവസ്ഥ താക്കോൽ_ED25519:
					get_keytypes |= KT_ED25519;
					നിർത്തുക;
				അവസ്ഥ താക്കോൽ_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					നിർത്തുക;
				അവസ്ഥ താക്കോൽ_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					നിർത്തുക;
				അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					നിർത്തുക;
				അവസ്ഥ താക്കോൽ_UNSPEC:
				സ്ഥിരസ്ഥിതി:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(ശൂന്യ, ",");
			}
			നിർത്തുക;
		അവസ്ഥ '4':
			IPv4or6 = AF_INET;
			നിർത്തുക;
		അവസ്ഥ '6':
			IPv4or6 = AF_INET6;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage();
		}
	}
	എങ്കിൽ (optind == argc && !fopt_എണ്ണം)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	എങ്കിൽ (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	എങ്കിൽ (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	എങ്കിൽ (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	എങ്കിൽ (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, വലുപ്പം(con));
	read_wait = xcalloc(maxfd, വലുപ്പം(ഘടന pollfd));
	വേണ്ടി (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	വേണ്ടി (j = 0; j < fopt_എണ്ണം; j++) {
		എങ്കിൽ (argv[j] == ശൂന്യ)
			fp = stdin;
		അല്ലെങ്കിൽ എങ്കിൽ ((fp = fopen(argv[j], "r")) == ശൂന്യ)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		ആകുമ്പോൾ (getline(&വരി, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			എങ്കിൽ ((cp = strchr(വരി, '#')) == ശൂന്യ)
				cp = വരി + strlen(വരി) - 1;
			ആകുമ്പോൾ (cp >= വരി) {
				എങ്കിൽ (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				അല്ലെങ്കിൽ
					നിർത്തുക;
			}

			/* Skip empty lines */
			എങ്കിൽ (*വരി == '\0')
				തുടരുക;

			do_host(വരി);
		}

		എങ്കിൽ (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		എങ്കിൽ (fp != stdin)
			fclose(fp);
	}
	സ്വതന്ത്രം(വരി);

	ആകുമ്പോൾ (optind < argc)
		do_host(argv[optind++]);

	ആകുമ്പോൾ (ncon > 0)
		conloop();

	തിരികെ found_one ? 0 : 1;
}
