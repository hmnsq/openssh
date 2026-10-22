/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#અન્તર્ભાવ "includes.h"
 
#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/resource.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#endif

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "dns.h"
#અન્તર્ભાવ "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
પૂર્ણાંક IPv4or6 = AF_UNSPEC;

પૂર્ણાંક ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

પૂર્ણાંક get_cert = 0;
પૂર્ણાંક get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

પૂર્ણાંક hash_hosts = 0;		/* Hash hostname on output */

પૂર્ણાંક print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

પૂર્ણાંક found_one = 0;		/* Successfully found a key */

પૂર્ણાંક hashalg = -1;		/* Hash for SSHFP records or -1 for all */

પૂર્ણાંક quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
પૂર્ણાંક timeout = 5;

પૂર્ણાંક maxfd;
#define MAXCON (maxfd - 10)

બાહ્ય અક્ષર *__progname;
સંરચના pollfd *read_wait;
પૂર્ણાંક ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
પ્રકારવ્યાખ્યા સંરચના Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	પૂર્ણાંક c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	પૂર્ણાંક c_keytype;		/* Only one of KT_* */
	sig_atomic_t c_done;	/* SSH2 done */
	અક્ષર *c_namebase;	/* Address to free for c_name and c_namelist */
	અક્ષર *c_name;		/* Hostname of connection for errors */
	અક્ષર *c_namelist;	/* Pointer to other possible addresses */
	અક્ષર *c_output_name;	/* Hostname of connection for output */
	સંરચના ssh *c_ssh;	/* SSH-connection */
	અક્ષર c_banner[256];	/* Partial server greeting */
	size_t c_banner_len;	/* Length of partial server greeting */
	પૂર્ણાંક c_banner_sent;	/* Client greeting has been sent */
	સંરચના timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

સ્થિર શૂન્ય keyprint(con *c, સંરચના sshkey *ચાવી);

સ્થિર પૂર્ણાંક
fdlim_get(પૂર્ણાંક hard)
{
#જો defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	સંરચના rlimit rlfd;
	rlim_t lim;

	જો (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		પાછા -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	જો (lim <= 0)
		પાછા -1;
	જો (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	જો (lim >= INT_MAX)
		lim = INT_MAX;
	પાછા lim;
#નહીંતર
	પાછા (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= INT_MAX) ? INT_MAX : SSH_SYSFDMAX);
#endif
}

સ્થિર પૂર્ણાંક
fdlim_set(પૂર્ણાંક lim)
{
#જો defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	સંરચના rlimit rlfd;
#endif

	જો (lim <= 0)
		પાછા (-1);
#જો defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	જો (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		પાછા (-1);
	rlfd.rlim_cur = lim;
	જો (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		પાછા (-1);
#અથવાજો defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	પાછા (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
સ્થિર અક્ષર *
xstrsep(અક્ષર **str, અચલ અક્ષર *delim)
{
	અક્ષર *s, *e;

	જો (!**str)
		પાછા (ખાલી);

	s = *str;
	e = s + strcspn(s, delim);

	જો (*e != '\0')
		*e++ = '\0';
	*str = e;

	પાછા (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
સ્થિર અક્ષર *
strnnsep(અક્ષર **stringp, અક્ષર *delim)
{
	અક્ષર *tok;

	કરો {
		tok = xstrsep(stringp, delim);
	} જ્યારે (tok && *tok == '\0');
	પાછા (tok);
}


સ્થિર પૂર્ણાંક
ચાવી_print_wrapper(સંરચના sshkey *hostkey, સંરચના ssh *ssh)
{
	con *c;

	જો ((c = ssh_get_app_data(ssh)) != ખાલી)
		keyprint(c, hostkey);
	/* always abort key exchange */
	પાછા -1;
}

સ્થિર પૂર્ણાંક
ssh2_capable(પૂર્ણાંક remote_major, પૂર્ણાંક remote_minor)
{
	પસંદગી (remote_major) {
	સ્થિતિ 1:
		જો (remote_minor == 99)
			પાછા 1;
		તોડો;
	સ્થિતિ 2:
		પાછા 1;
	મૂળભૂત:
		તોડો;
	}
	પાછા 0;
}

સ્થિર શૂન્ય
keygrab_ssh2(con *c)
{
	અક્ષર *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	પૂર્ણાંક r;

	પસંદગી (c->c_keytype) {
	સ્થિતિ KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		તોડો;
	સ્થિતિ KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		તોડો;
	સ્થિતિ KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		તોડો;
	સ્થિતિ KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		તોડો;
	સ્થિતિ KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		તોડો;
	સ્થિતિ KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		તોડો;
	મૂળભૂત:
		fatal("unknown key type %d", c->c_keytype);
		તોડો;
	}
	જો ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		મુક્ત(c->c_ssh);
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
	ssh_set_verify_host_ચાવી_callback(c->c_ssh, ચાવી_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

સ્થિર શૂન્ય
keyprint_one(અચલ અક્ષર *host, સંરચના sshkey *ચાવી)
{
	અક્ષર *hostport = ખાલી, *hashed = ખાલી;
	અચલ અક્ષર *known_host;
	પૂર્ણાંક r = 0;

	found_one = 1;

	જો (print_sshfp) {
		export_dns_rr(host, ચાવી, stdout, 0, hashalg);
		પાછા;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	જો (hash_hosts && (hashed = host_hash(hostport, ખાલી, 0)) == ખાલી)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	જો (!get_cert)
		r = fprintf(stdout, "%s ", known_host);
	જો (r >= 0 && sshkey_write(ચાવી, stdout) == 0)
		(શૂન્ય)fputs("\n", stdout);
	મુક્ત(hashed);
	મુક્ત(hostport);
}

સ્થિર શૂન્ય
keyprint(con *c, સંરચના sshkey *ચાવી)
{
	અક્ષર *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	અક્ષર *host, *ohosts;

	જો (ચાવી == ખાલી)
		પાછા;
	જો (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, ચાવી);
		પાછા;
	}
	ohosts = hosts = xstrdup(hosts);
	જ્યારે ((host = strsep(&hosts, ",")) != ખાલી)
		keyprint_one(host, ચાવી);
	મુક્ત(ohosts);
}

સ્થિર પૂર્ણાંક
tcpconnect(અક્ષર *host)
{
	સંરચના addrinfo hints, *ai, *aitop;
	અક્ષર strport[NI_MAXSERV];
	પૂર્ણાંક gaierr, s = -1;

	snprintf(strport, કદ strport, "%d", ssh_port);
	memset(&hints, 0, કદ(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	જો ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		પાછા -1;
	}
	માટે (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		જો (s == -1) {
			error("socket: %s", strerror(errno));
			ચાલુ;
		}
		જો (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		જો (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		નહીંતર
			તોડો;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	પાછા s;
}

સ્થિર પૂર્ણાંક
conalloc(અચલ અક્ષર *iname, અચલ અક્ષર *oname, પૂર્ણાંક keytype)
{
	અક્ષર *namebase, *name, *namelist;
	પૂર્ણાંક s;

	namebase = namelist = xstrdup(iname);

	કરો {
		name = xstrsep(&namelist, ",");
		જો (!name) {
			મુક્ત(namebase);
			પાછા (-1);
		}
	} જ્યારે ((s = tcpconnect(name)) < 0);

	જો (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	જો (fdcon[s].c_status)
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
	પાછા (s);
}

સ્થિર શૂન્ય
confree(પૂર્ણાંક s)
{
	જો (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	મુક્ત(fdcon[s].c_namebase);
	મુક્ત(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	જો (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		મુક્ત(fdcon[s].c_ssh);
		fdcon[s].c_ssh = ખાલી;
	} નહીંતર
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

સ્થિર પૂર્ણાંક
conrecycle(પૂર્ણાંક s)
{
	con *c = &fdcon[s];
	પૂર્ણાંક ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	પાછા (ret);
}

સ્થિર શૂન્ય
congreet(પૂર્ણાંક s)
{
	પૂર્ણાંક remote_major = 0, remote_minor = 0;
	ssize_t n;
	અક્ષર buf[256], ch;
	અક્ષર remote_version[કદ buf];
	con *c = &fdcon[s];

	જો (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, કદ buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		જો (n < 0 || (size_t)n >= કદ(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			પાછા;
		}
		જો (atomicio(vwrite, s, buf, n) != (size_t)n) {
			error("write (%s): %s", c->c_name, strerror(errno));
			confree(s);
			પાછા;
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
	n = પઠ(s, &ch, કદ(ch));
	જો (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR))
		પાછા;
	જો (n != 1) {
		જો (n == 0)
			errno = EPIPE;
		પસંદગી (errno) {
		સ્થિતિ EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			તોડો;
		સ્થિતિ ECONNREFUSED:
			તોડો;
		મૂળભૂત:
			error("read (%s): %s", c->c_name, strerror(errno));
			તોડો;
		}
		conrecycle(s);
		પાછા;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	જો (ch != '\n') {
		જો (c->c_banner_len < કદ(c->c_banner) - 1)
			પાછા; /* incomplete line */
		જો (strncmp(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			પાછા;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		પાછા;
	}
	જો (strncmp(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		પાછા;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	memcpy(buf, c->c_banner, c->c_banner_len);
	જો ((c->c_ssh = ssh_packet_set_connection(ખાલી, s, s)) == ખાલી)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	જો (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	જો (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		પાછા;
	}
	જો (!quiet) {
		fprintf(stdout, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

સ્થિર શૂન્ય
conread(પૂર્ણાંક s)
{
	con *c = &fdcon[s];

	જો (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

સ્થિર શૂન્ય
conloop(શૂન્ય)
{
	સંરચના timespec seltime, now;
	con *c;
	પૂર્ણાંક i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	જો (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	નહીંતર
		timespecclear(&seltime);

	જ્યારે (ppoll(read_wait, maxfd, &seltime, ખાલી) == -1) {
		જો (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ચાલુ;
		error("poll error");
	}

	માટે (i = 0; i < maxfd; i++) {
		જો (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		નહીંતર જો (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	જ્યારે (c && timespeccmp(&c->c_ts, &now, <)) {
		પૂર્ણાંક s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

સ્થિર શૂન્ય
do_one_host(અક્ષર *host)
{
	અક્ષર *name = strnnsep(&host, " \t\n");
	પૂર્ણાંક j;

	જો (name == ખાલી)
		પાછા;
	માટે (j = KT_MIN; j <= KT_MAX; j *= 2) {
		જો (get_keytypes & j) {
			જ્યારે (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

સ્થિર શૂન્ય
do_host(અક્ષર *host)
{
	અક્ષર daddr[128];
	સંરચના xaddr addr, end_addr;
	u_int masklen;

	જો (host == ખાલી)
		પાછા;
	જો (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} નહીંતર {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		જો (addr_host_to_all1s(&end_addr, masklen) != 0)
			જાઓ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		માટે (;;) {
			જો (addr_ntop(&addr, daddr, કદ(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				પાછા;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			જો (addr_cmp(&addr, &end_addr) == 0)
				તોડો;
			addr_increment(&addr);
		}
	}
}

સ્થિર શૂન્ય
usage(શૂન્ય)
{
	fprintf(stderr,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	exit(1);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	પૂર્ણાંક opt, fopt_ગણતરી = 0, j;
	અક્ષર *tname, *cp, *લીટી = ખાલી;
	size_t linesize = 0;
	FILE *fp;

	બાહ્ય પૂર્ણાંક optind;
	બાહ્ય અક્ષર *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	જો (argc <= 1)
		usage();

	જ્યારે ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		પસંદગી (opt) {
		સ્થિતિ 'H':
			hash_hosts = 1;
			તોડો;
		સ્થિતિ 'c':
			get_cert = 1;
			તોડો;
		સ્થિતિ 'D':
			print_sshfp = 1;
			તોડો;
		સ્થિતિ 'p':
			ssh_port = a2port(optarg);
			જો (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			તોડો;
		સ્થિતિ 'T':
			timeout = convtime(optarg);
			જો (timeout == -1 || timeout == 0) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
			તોડો;
		સ્થિતિ 'v':
			જો (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			નહીંતર જો (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			નહીંતર
				fatal("Too high debugging level.");
			તોડો;
		સ્થિતિ 'q':
			quiet = 1;
			તોડો;
		સ્થિતિ 'f':
			જો (strcmp(optarg, "-") == 0)
				optarg = ખાલી;
			argv[fopt_ગણતરી++] = optarg;
			તોડો;
		સ્થિતિ 'O':
			/* Maybe other misc options in the future too */
			જો (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			જો ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			તોડો;
		સ્થિતિ 't':
			get_keytypes = 0;
			tname = strtok(optarg, ",");
			જ્યારે (tname) {
				પૂર્ણાંક type = sshkey_type_from_shortname(tname);

				પસંદગી (type) {
				સ્થિતિ ચાવી_ECDSA:
					get_keytypes |= KT_ECDSA;
					તોડો;
				સ્થિતિ ચાવી_RSA:
					get_keytypes |= KT_RSA;
					તોડો;
				સ્થિતિ ચાવી_ED25519:
					get_keytypes |= KT_ED25519;
					તોડો;
				સ્થિતિ ચાવી_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					તોડો;
				સ્થિતિ ચાવી_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					તોડો;
				સ્થિતિ ચાવી_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					તોડો;
				સ્થિતિ ચાવી_UNSPEC:
				મૂળભૂત:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = strtok(ખાલી, ",");
			}
			તોડો;
		સ્થિતિ '4':
			IPv4or6 = AF_INET;
			તોડો;
		સ્થિતિ '6':
			IPv4or6 = AF_INET6;
			તોડો;
		મૂળભૂત:
			usage();
		}
	}
	જો (optind == argc && !fopt_ગણતરી)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	જો (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	જો (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	જો (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	જો (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, કદ(con));
	read_wait = xcalloc(maxfd, કદ(સંરચના pollfd));
	માટે (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, SIG_IGN);
	માટે (j = 0; j < fopt_ગણતરી; j++) {
		જો (argv[j] == ખાલી)
			fp = stdin;
		નહીંતર જો ((fp = fopen(argv[j], "r")) == ખાલી)
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		જ્યારે (getline(&લીટી, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			જો ((cp = strchr(લીટી, '#')) == ખાલી)
				cp = લીટી + strlen(લીટી) - 1;
			જ્યારે (cp >= લીટી) {
				જો (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				નહીંતર
					તોડો;
			}

			/* Skip empty lines */
			જો (*લીટી == '\0')
				ચાલુ;

			do_host(લીટી);
		}

		જો (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		જો (fp != stdin)
			fclose(fp);
	}
	મુક્ત(લીટી);

	જ્યારે (optind < argc)
		do_host(argv[optind++]);

	જ્યારે (ncon > 0)
		conloop();

	પાછા found_one ? 0 : 1;
}
