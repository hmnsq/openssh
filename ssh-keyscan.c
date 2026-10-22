/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#অন্তর্ভাৱ "includes.h"
 
#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/queue.h>
#অন্তর্ভাৱ <sys/time.h>
#অন্তর্ভাৱ <sys/resource.h>

#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <arpa/inet.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/bn.h>
#endif

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <netdb.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <poll.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "cipher.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "compat.h"
#অন্তর্ভাৱ "myproposal.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "dispatch.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "atomicio.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "ssh_api.h"
#অন্তর্ভাৱ "dns.h"
#অন্তর্ভাৱ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
পূর্ণাঙ্ক IPv4or6 = AF_UNSPEC;

পূর্ণাঙ্ক ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

পূর্ণাঙ্ক get_cert = 0;
পূর্ণাঙ্ক get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

পূর্ণাঙ্ক hash_hosts = 0;		/* Hash hostname on output */

পূর্ণাঙ্ক print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

পূর্ণাঙ্ক found_one = 0;		/* Successfully found a key */

পূর্ণাঙ্ক hashalg = -1;		/* Hash for SSHFP records or -1 for all */

পূর্ণাঙ্ক quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
পূর্ণাঙ্ক timeout = 5;

পূর্ণাঙ্ক maxfd;
#define MAXCON (maxfd - 10)

বাহ্য ৱর্ণ *__progname;
সংরচনা pollfd *read_wait;
পূর্ণাঙ্ক ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
প্রকারনির্দেশ সংরচনা Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	পূর্ণাঙ্ক c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	পূর্ণাঙ্ক c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	ৱর্ণ *c_namebase;	/* Address to free for c_name and c_namelist */
	ৱর্ণ *c_name;		/* Hostname of connection for errors */
	ৱর্ণ *c_namelist;	/* Pointer to other possible addresses */
	ৱর্ণ *c_output_name;	/* Hostname of connection for output */
	সংরচনা ssh *c_ssh;	/* SSH-connection */
	ৱর্ণ c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	পূর্ণাঙ্ক c_banner_sent;	/* Client greeting has been sent */
	সংরচনা timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

স্থির শূন্য keyprint(con *c, সংরচনা sshkey *চাবি);

স্থির পূর্ণাঙ্ক
fdlim_get(পূর্ণাঙ্ক hard)
{
#যদি defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	সংরচনা rlimit rlfd;
	rlim_t lim;

	যদি (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ঘূৰাই -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	যদি (lim <= 0)
		ঘূৰাই -1;
	যদি (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	যদি (lim >= INT_MAX)
		lim = INT_MAX;
	ঘূৰাই lim;
#অন্যথা
	ঘূৰাই (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

স্থির পূর্ণাঙ্ক
fdlim_set(পূর্ণাঙ্ক lim)
{
#যদি defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	সংরচনা rlimit rlfd;
#endif

	যদি (lim <= 0)
		ঘূৰাই (-1);
#যদি defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	যদি (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ঘূৰাই (-1);
	rlfd.rlim_cur = lim;
	যদি (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		ঘূৰাই (-1);
#নোচেদ্যদি defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	ঘূৰাই (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
স্থির ৱর্ণ *
xstrsep(ৱর্ণ **str, ধ্রুৱ ৱর্ণ *delim)
{
	ৱর্ণ *s, *e;

	যদি (!**str)
		ঘূৰাই (রিক্ত);

	s = *str;
	e = s + strcspn(s, delim);

	যদি (*e != '\0')
		*e++ = '\0';
	*str = e;

	ঘূৰাই (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
স্থির ৱর্ণ *
strnnsep(ৱর্ণ **stringp, ৱর্ণ *delim)
{
	ৱর্ণ *tok;

	কৰা {
		tok = xstrsep(stringp, delim);
	} যেতিয়ালৈ (tok && *tok == '\0');
	ঘূৰাই (tok);
}


স্থির পূর্ণাঙ্ক
চাবি_print_wrapper(সংরচনা sshkey *hostkey, সংরচনা ssh *ssh)
{
	con *c;

	যদি ((c = ssh_get_app_data(ssh)) != রিক্ত)
		keyprint(c, hostkey);
	/* always abort key exchange */
	ঘূৰাই -1;
}

স্থির পূর্ণাঙ্ক
ssh2_capable(পূর্ণাঙ্ক remote_major, পূর্ণাঙ্ক remote_minor)
{
	ৱিকল্প (remote_major) {
	পক্ষ 1:
		যদি (remote_minor == 99)
			ঘূৰাই 1;
		ভঙ্গ;
	পক্ষ 2:
		ঘূৰাই 1;
	স্ৱভাৱ:
		ভঙ্গ;
	}
	ঘূৰাই 0;
}

স্থির শূন্য
keygrab_ssh2(con *c)
{
	ৱর্ণ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	পূর্ণাঙ্ক r;

	ৱিকল্প (c->c_keytype) {
	পক্ষ KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		ভঙ্গ;
	পক্ষ KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		ভঙ্গ;
	পক্ষ KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		ভঙ্গ;
	পক্ষ KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		ভঙ্গ;
	পক্ষ KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		ভঙ্গ;
	পক্ষ KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		ভঙ্গ;
	স্ৱভাৱ:
		fatal("unknown key type %d", c->c_keytype);
		ভঙ্গ;
	}
	যদি ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		মুক্ত(c->c_ssh);
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
	ssh_set_verify_host_চাবি_callback(c->c_ssh, চাবি_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

স্থির শূন্য
keyprint_one(ধ্রুৱ ৱর্ণ *host, সংরচনা sshkey *চাবি)
{
	ৱর্ণ *hostport = রিক্ত, *hashed = রিক্ত;
	ধ্রুৱ ৱর্ণ *known_host;
	পূর্ণাঙ্ক r = 0;

	found_one = 1;

	যদি (print_sshfp) {
		export_dns_rr(host, চাবি, stdout, 0, hashalg);
		ঘূৰাই;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	যদি (hash_hosts && (hashed = host_hash(hostport, রিক্ত, 0)) == রিক্ত)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	যদি (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	যদি (r >= 0 && sshkey_write(চাবি, stdout) == 0)
		(শূন্য)fputs("\n", stdout);
	মুক্ত(hashed);
	মুক্ত(hostport);
}

স্থির শূন্য
keyprint(con *c, সংরচনা sshkey *চাবি)
{
	ৱর্ণ *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	ৱর্ণ *host, *ohosts;

	যদি (চাবি == রিক্ত)
		ঘূৰাই;
	যদি (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, চাবি);
		ঘূৰাই;
	}
	ohosts = hosts = xstrdup(hosts);
	যেতিয়ালৈ ((host = strsep(&hosts, ",")) != রিক্ত)
		keyprint_one(host, চাবি);
	মুক্ত(ohosts);
}

স্থির পূর্ণাঙ্ক
tcpconnect(ৱর্ণ *host)
{
	সংরচনা addrinfo hints, *ai, *aitop;
	ৱর্ণ strport[NI_MAXSERV];
	পূর্ণাঙ্ক gaierr, s = -1;

	snprintf(strport, পরিমাণ strport, "%d", ssh_port);
	memset(&hints, 0, পরিমাণ(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	যদি ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		ঘূৰাই -1;
	}
	বাবে (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		যদি (s == -1) {
			error("socket: %s", strerror(errno));
			অনুৱর্ত;
		}
		যদি (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		যদি (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		অন্যথা
			ভঙ্গ;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	ঘূৰাই s;
}

স্থির পূর্ণাঙ্ক
conalloc(ধ্রুৱ ৱর্ণ *iname, ধ্রুৱ ৱর্ণ *oname, পূর্ণাঙ্ক keytype)
{
	ৱর্ণ *namebase, *name, *namelist;
	পূর্ণাঙ্ক s;

	namebase = namelist = xstrdup(iname);

	কৰা {
		name = xstrsep(&namelist, ",");
		যদি (!name) {
			মুক্ত(namebase);
			ঘূৰাই (-1);
		}
	} যেতিয়ালৈ ((s = tcpconnect(name)) < 0);

	যদি (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	যদি (fdcon[s].c_status)
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
	ঘূৰাই (s);
}

স্থির শূন্য
confree(পূর্ণাঙ্ক s)
{
	যদি (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	মুক্ত(fdcon[s].c_namebase);
	মুক্ত(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	যদি (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		মুক্ত(fdcon[s].c_ssh);
		fdcon[s].c_ssh = রিক্ত;
	} অন্যথা
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

স্থির পূর্ণাঙ্ক
conrecycle(পূর্ণাঙ্ক s)
{
	con *c = &fdcon[s];
	পূর্ণাঙ্ক ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	ঘূৰাই (ret);
}

স্থির শূন্য
congreet(পূর্ণাঙ্ক s)
{
	পূর্ণাঙ্ক remote_major = 0, remote_minor = 0;
	ssize_t n;
	ৱর্ণ buf[256], ch;
	ৱর্ণ remote_version[পরিমাণ buf];
	con *c = &fdcon[s];

	যদি (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, পরিমাণ buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		যদি (n < 0 || (size_t)n >= পরিমাণ(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			ঘূৰাই;
		}
		যদি (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			ঘূৰাই;
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
	n = পঠ(s, &ch, পরিমাণ(ch));
	যদি (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		ঘূৰাই;
	যদি (n != 1) {
		যদি (n == 0)
			errno = EPIPE;
		ৱিকল্প (errno) {
		পক্ষ EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			ভঙ্গ;
		পক্ষ ECONNREFUSED:
			ভঙ্গ;
		স্ৱভাৱ:
			error("read (%s): %s", c->c_name, strerror(errno));
			ভঙ্গ;
		}
		conrecycle(s);
		ঘূৰাই;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	যদি (ch != '\n') {
		যদি (c->c_banner_len < পরিমাণ(c->c_banner) - 1)
			ঘূৰাই; /* incomplete line */
		যদি (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			ঘূৰাই;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		ঘূৰাই;
	}
	যদি (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		ঘূৰাই;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	যদি ((c->c_ssh = ssh_packet_set_connection(রিক্ত, s, s)) == রিক্ত)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	যদি (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	যদি (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		ঘূৰাই;
	}
	যদি (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

স্থির শূন্য
conread(পূর্ণাঙ্ক s)
{
	con *c = &fdcon[s];

	যদি (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

স্থির শূন্য
conloop(শূন্য)
{
	সংরচনা timespec seltime, now;
	con *c;
	পূর্ণাঙ্ক i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	যদি (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	অন্যথা
		timespecclear(&seltime);

	যেতিয়ালৈ (ppoll(read_wait, maxfd, &seltime, রিক্ত) == -1) {
		যদি (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			অনুৱর্ত;
		error("poll error");
	}

	বাবে (i = 0; i < maxfd; i++) {
		যদি (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		অন্যথা যদি (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	যেতিয়ালৈ (c && timespeccmp(&c->c_ts, &now, <)) {
		পূর্ণাঙ্ক s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

স্থির শূন্য
do_one_host(ৱর্ণ *host)
{
	ৱর্ণ *name = strnnsep(&host, " \t\n");
	পূর্ণাঙ্ক j;

	যদি (name == রিক্ত)
		ঘূৰাই;
	বাবে (j = KT_MIN; j <= KT_MAX; j *= 2) {
		যদি (get_keytypes & j) {
			যেতিয়ালৈ (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

স্থির শূন্য
do_host(ৱর্ণ *host)
{
	ৱর্ণ daddr[128];
	সংরচনা xaddr addr, end_addr;
	u_int masklen;

	যদি (host == রিক্ত)
		ঘূৰাই;
	যদি (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} অন্যথা {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		যদি (addr_host_to_all1s(&end_addr, masklen) != 0)
			গচ্ছ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		বাবে (;;) {
			যদি (addr_ntop(&addr, daddr, পরিমাণ(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				ঘূৰাই;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			যদি (addr_cmp(&addr, &end_addr) == 0)
				ভঙ্গ;
			addr_increment(&addr);
		}
	}
}

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, ৱর্ণ **argv)
{
	পূর্ণাঙ্ক debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	পূর্ণাঙ্ক opt, fopt_গুনতি = 0, j;
	ৱর্ণ *tname, *cp, *সাৰি = রিক্ত;
	size_t linesize = 0;
	FILE *fp;

	বাহ্য পূর্ণাঙ্ক optind;
	বাহ্য ৱর্ণ *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	যদি (argc <= 1)
		usage();

	যেতিয়ালৈ ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		ৱিকল্প (opt) {
		পক্ষ 'H':
			hash_hosts = 1;
			ভঙ্গ;
		পক্ষ 'c':
			get_cert = 1;
			ভঙ্গ;
		পক্ষ 'D':
			print_sshfp = 1;
			ভঙ্গ;
		পক্ষ 'p':
			ssh_port = a2port(optarg);
			যদি (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			ভঙ্গ;
		পক্ষ 'T':
			timeout = convtime(optarg);
			যদি (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			ভঙ্গ;
		পক্ষ 'v':
			যদি (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			অন্যথা
				fatal("Too high debugging level.");
			ভঙ্গ;
		পক্ষ 'q':
			quiet = 1;
			ভঙ্গ;
		পক্ষ 'f':
			যদি (strcmp(optarg, "-") == 0)
				optarg = রিক্ত;
			argv[fopt_গুনতি++] = optarg;
			ভঙ্গ;
		পক্ষ 'O':
			/* Maybe other misc options in the future too */
			যদি (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			যদি ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			ভঙ্গ;
		পক্ষ 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			যেতিয়ালৈ (tname) {
				পূর্ণাঙ্ক type = sshkey_type_from_shortname(tname);

				ৱিকল্প (type) {
				পক্ষ চাবি_ECDSA:
					get_keytypes |= KT_ECDSA;
					ভঙ্গ;
				পক্ষ চাবি_RSA:
					get_keytypes |= KT_RSA;
					ভঙ্গ;
				পক্ষ চাবি_ED25519:
					get_keytypes |= KT_ED25519;
					ভঙ্গ;
				পক্ষ চাবি_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					ভঙ্গ;
				পক্ষ চাবি_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					ভঙ্গ;
				পক্ষ চাবি_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					ভঙ্গ;
				পক্ষ চাবি_UNSPEC:
				স্ৱভাৱ:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(রিক্ত, ",");
			}
			ভঙ্গ;
		পক্ষ '4':
			IPv4or6 = AF_INET;
			ভঙ্গ;
		পক্ষ '6':
			IPv4or6 = AF_INET6;
			ভঙ্গ;
		স্ৱভাৱ:
			usage();
		}
	}
	যদি (optind == argc && !fopt_গুনতি)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	যদি (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	যদি (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	যদি (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	যদি (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, পরিমাণ(con));
	read_wait = xcalloc(maxfd, পরিমাণ(সংরচনা pollfd));
	বাবে (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	বাবে (j = 0; j < fopt_গুনতি; j++) {
		যদি (argv[j] == রিক্ত)
			fp = stdin;
		অন্যথা যদি ((fp = fopen(argv[j], "r")) == রিক্ত)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		যেতিয়ালৈ (getline(&সাৰি, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			যদি ((cp = strchr(সাৰি, '#')) == রিক্ত)
				cp = সাৰি + strlen(সাৰি) - 1;
			যেতিয়ালৈ (cp >= সাৰি) {
				যদি (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				অন্যথা
					ভঙ্গ;
			}

			/* Skip empty lines */
			যদি (*সাৰি == '\0')
				অনুৱর্ত;

			do_host(সাৰি);
		}

		যদি (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		যদি (fp != stdin)
			fclose(fp);
	}
	মুক্ত(সাৰি);

	যেতিয়ালৈ (optind < argc)
		do_host(argv[optind++]);

	যেতিয়ালৈ (ncon > 0)
		conloop();

	ঘূৰাই found_one ? 0 : 1;
}
