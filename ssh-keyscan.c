/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#अन्तर्भाव "includes.h"
 
#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/resource.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#endif

#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "dns.h"
#अन्तर्भाव "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
पूर्णाङ्क IPv4or6 = AF_UNSPEC;

पूर्णाङ्क ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

पूर्णाङ्क get_cert = 0;
पूर्णाङ्क get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

पूर्णाङ्क hash_hosts = 0;		/* Hash hostname on output */

पूर्णाङ्क print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

पूर्णाङ्क found_one = 0;		/* Successfully found a key */

पूर्णाङ्क hashalg = -1;		/* Hash for SSHFP records or -1 for all */

पूर्णाङ्क quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
पूर्णाङ्क timeout = 5;

पूर्णाङ्क maxfd;
#define MAXCON (maxfd - 10)

बाह्य वर्ण *__progname;
संरचना pollfd *read_wait;
पूर्णाङ्क ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
प्रकारनिर्देश संरचना Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	पूर्णाङ्क c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	पूर्णाङ्क c_keytype;		/* Only one of KT_* */
	संक_पूर्ण_प्रकार c_done;	/* SSH2 done */
	वर्ण *c_namebase;	/* Address to free for c_name and c_namelist */
	वर्ण *c_name;		/* Hostname of connection for errors */
	वर्ण *c_namelist;	/* Pointer to other possible addresses */
	वर्ण *c_output_name;	/* Hostname of connection for output */
	संरचना ssh *c_ssh;	/* SSH-connection */
	वर्ण c_banner[256];	/* Partial server greeting */
	माप_प्रकार c_banner_len;	/* Length of partial server greeting */
	पूर्णाङ्क c_banner_sent;	/* Client greeting has been sent */
	संरचना timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

स्थिर शून्य keyprint(con *c, संरचना sshkey *कुंजी);

स्थिर पूर्णाङ्क
fdlim_get(पूर्णाङ्क hard)
{
#यदि defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	संरचना rlimit rlfd;
	rlim_t lim;

	यदि (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		प्रत्यागम -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	यदि (lim <= 0)
		प्रत्यागम -1;
	यदि (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	यदि (lim >= पूर्णांक_उच्च)
		lim = पूर्णांक_उच्च;
	प्रत्यागम lim;
#अन्यथा
	प्रत्यागम (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= पूर्णांक_उच्च) ? पूर्णांक_उच्च : SSH_SYSFDMAX);
#endif
}

स्थिर पूर्णाङ्क
fdlim_set(पूर्णाङ्क lim)
{
#यदि defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	संरचना rlimit rlfd;
#endif

	यदि (lim <= 0)
		प्रत्यागम (-1);
#यदि defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	यदि (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		प्रत्यागम (-1);
	rlfd.rlim_cur = lim;
	यदि (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		प्रत्यागम (-1);
#नोचेद्यदि defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	प्रत्यागम (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
स्थिर वर्ण *
xstrsep(वर्ण **str, ध्रुव वर्ण *delim)
{
	वर्ण *s, *e;

	यदि (!**str)
		प्रत्यागम (रिक्त);

	s = *str;
	e = s + म_खोज(s, delim);

	यदि (*e != '\0')
		*e++ = '\0';
	*str = e;

	प्रत्यागम (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
स्थिर वर्ण *
strnnsep(वर्ण **stringp, वर्ण *delim)
{
	वर्ण *tok;

	कुरु {
		tok = xstrsep(stringp, delim);
	} यावत् (tok && *tok == '\0');
	प्रत्यागम (tok);
}


स्थिर पूर्णाङ्क
कुंजी_print_wrapper(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	con *c;

	यदि ((c = ssh_get_app_data(ssh)) != रिक्त)
		keyprint(c, hostkey);
	/* always abort key exchange */
	प्रत्यागम -1;
}

स्थिर पूर्णाङ्क
ssh2_capable(पूर्णाङ्क remote_major, पूर्णाङ्क remote_minor)
{
	विकल्प (remote_major) {
	पक्ष 1:
		यदि (remote_minor == 99)
			प्रत्यागम 1;
		भङ्ग;
	पक्ष 2:
		प्रत्यागम 1;
	स्वभाव:
		भङ्ग;
	}
	प्रत्यागम 0;
}

स्थिर शून्य
keygrab_ssh2(con *c)
{
	वर्ण *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	पूर्णाङ्क r;

	विकल्प (c->c_keytype) {
	पक्ष KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		भङ्ग;
	पक्ष KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		भङ्ग;
	पक्ष KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		भङ्ग;
	पक्ष KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		भङ्ग;
	पक्ष KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		भङ्ग;
	पक्ष KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		भङ्ग;
	स्वभाव:
		fatal("unknown key type %d", c->c_keytype);
		भङ्ग;
	}
	यदि ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		मुक्त(c->c_ssh);
		ख_लिखो(मानक_त्रुटि, "kex_setup: %s\n", ssh_err(r));
		निकास(1);
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
	ssh_set_verify_host_कुंजी_callback(c->c_ssh, कुंजी_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

स्थिर शून्य
keyprint_one(ध्रुव वर्ण *host, संरचना sshkey *कुंजी)
{
	वर्ण *hostport = रिक्त, *hashed = रिक्त;
	ध्रुव वर्ण *known_host;
	पूर्णाङ्क r = 0;

	found_one = 1;

	यदि (print_sshfp) {
		export_dns_rr(host, कुंजी, मानक_निकास, 0, hashalg);
		प्रत्यागम;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	यदि (hash_hosts && (hashed = host_hash(hostport, रिक्त, 0)) == रिक्त)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	यदि (!get_cert)
		r = ख_लिखो(मानक_निकास, "%s ", known_host);
	यदि (r >= 0 && sshkey_write(कुंजी, मानक_निकास) == 0)
		(शून्य)ख_माला_दो("\n", मानक_निकास);
	मुक्त(hashed);
	मुक्त(hostport);
}

स्थिर शून्य
keyprint(con *c, संरचना sshkey *कुंजी)
{
	वर्ण *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	वर्ण *host, *ohosts;

	यदि (कुंजी == रिक्त)
		प्रत्यागम;
	यदि (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, कुंजी);
		प्रत्यागम;
	}
	ohosts = hosts = xstrdup(hosts);
	यावत् ((host = strsep(&hosts, ",")) != रिक्त)
		keyprint_one(host, कुंजी);
	मुक्त(ohosts);
}

स्थिर पूर्णाङ्क
tcpconnect(वर्ण *host)
{
	संरचना addrinfo hints, *ai, *aitop;
	वर्ण strport[NI_MAXSERV];
	पूर्णाङ्क gaierr, s = -1;

	snprintf(strport, परिमाण strport, "%d", ssh_port);
	स_रखो(&hints, 0, परिमाण(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	यदि ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		प्रत्यागम -1;
	}
	प्रति (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		यदि (s == -1) {
			error("socket: %s", म_त्रुटि(त्रुटि_सं));
			अनुवर्त;
		}
		यदि (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		यदि (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    त्रुटि_सं != EINPROGRESS)
			error("connect (`%s'): %s", host, म_त्रुटि(त्रुटि_सं));
		अन्यथा
			भङ्ग;
		बंद(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	प्रत्यागम s;
}

स्थिर पूर्णाङ्क
conalloc(ध्रुव वर्ण *iname, ध्रुव वर्ण *oname, पूर्णाङ्क keytype)
{
	वर्ण *namebase, *name, *namelist;
	पूर्णाङ्क s;

	namebase = namelist = xstrdup(iname);

	कुरु {
		name = xstrsep(&namelist, ",");
		यदि (!name) {
			मुक्त(namebase);
			प्रत्यागम (-1);
		}
	} यावत् ((s = tcpconnect(name)) < 0);

	यदि (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	यदि (fdcon[s].c_status)
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
	प्रत्यागम (s);
}

स्थिर शून्य
confree(पूर्णाङ्क s)
{
	यदि (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	मुक्त(fdcon[s].c_namebase);
	मुक्त(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	यदि (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		मुक्त(fdcon[s].c_ssh);
		fdcon[s].c_ssh = रिक्त;
	} अन्यथा
		बंद(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

स्थिर पूर्णाङ्क
conrecycle(पूर्णाङ्क s)
{
	con *c = &fdcon[s];
	पूर्णाङ्क ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	प्रत्यागम (ret);
}

स्थिर शून्य
congreet(पूर्णाङ्क s)
{
	पूर्णाङ्क remote_major = 0, remote_minor = 0;
	ssize_t n;
	वर्ण buf[256], ch;
	वर्ण remote_version[परिमाण buf];
	con *c = &fdcon[s];

	यदि (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, परिमाण buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		यदि (n < 0 || (माप_प्रकार)n >= परिमाण(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			प्रत्यागम;
		}
		यदि (atomicio(vwrite, s, buf, n) != (माप_प्रकार)n) {
			error("write (%s): %s", c->c_name, म_त्रुटि(त्रुटि_सं));
			confree(s);
			प्रत्यागम;
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
	n = पठ(s, &ch, परिमाण(ch));
	यदि (n == -1 && (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK ||
	    त्रुटि_सं == EINTR))
		प्रत्यागम;
	यदि (n != 1) {
		यदि (n == 0)
			त्रुटि_सं = EPIPE;
		विकल्प (त्रुटि_सं) {
		पक्ष EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			भङ्ग;
		पक्ष ECONNREFUSED:
			भङ्ग;
		स्वभाव:
			error("read (%s): %s", c->c_name, म_त्रुटि(त्रुटि_सं));
			भङ्ग;
		}
		conrecycle(s);
		प्रत्यागम;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	यदि (ch != '\n') {
		यदि (c->c_banner_len < परिमाण(c->c_banner) - 1)
			प्रत्यागम; /* incomplete line */
		यदि (म_भेदन(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			प्रत्यागम;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		प्रत्यागम;
	}
	यदि (म_भेदन(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		प्रत्यागम;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	स_नकल(buf, c->c_banner, c->c_banner_len);
	यदि ((c->c_ssh = ssh_packet_set_connection(रिक्त, s, s)) == रिक्त)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	यदि (माला_पूछो(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	यदि (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		प्रत्यागम;
	}
	यदि (!quiet) {
		ख_लिखो(मानक_निकास, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

स्थिर शून्य
conread(पूर्णाङ्क s)
{
	con *c = &fdcon[s];

	यदि (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

स्थिर शून्य
conloop(शून्य)
{
	संरचना timespec seltime, now;
	con *c;
	पूर्णाङ्क i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	यदि (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	अन्यथा
		timespecclear(&seltime);

	यावत् (ppoll(read_wait, maxfd, &seltime, रिक्त) == -1) {
		यदि (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR || त्रुटि_सं == EWOULDBLOCK)
			अनुवर्त;
		error("poll error");
	}

	प्रति (i = 0; i < maxfd; i++) {
		यदि (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		अन्यथा यदि (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	यावत् (c && timespeccmp(&c->c_ts, &now, <)) {
		पूर्णाङ्क s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

स्थिर शून्य
do_one_host(वर्ण *host)
{
	वर्ण *name = strnnsep(&host, " \t\n");
	पूर्णाङ्क j;

	यदि (name == रिक्त)
		प्रत्यागम;
	प्रति (j = KT_MIN; j <= KT_MAX; j *= 2) {
		यदि (get_keytypes & j) {
			यावत् (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

स्थिर शून्य
do_host(वर्ण *host)
{
	वर्ण daddr[128];
	संरचना xaddr addr, end_addr;
	u_int masklen;

	यदि (host == रिक्त)
		प्रत्यागम;
	यदि (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} अन्यथा {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		यदि (addr_host_to_all1s(&end_addr, masklen) != 0)
			गच्छ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		प्रति (;;) {
			यदि (addr_ntop(&addr, daddr, परिमाण(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				प्रत्यागम;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			यदि (addr_cmp(&addr, &end_addr) == 0)
				भङ्ग;
			addr_increment(&addr);
		}
	}
}

स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	निकास(1);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	पूर्णाङ्क opt, fopt_गिनती = 0, j;
	वर्ण *tname, *cp, *पंक्ति = रिक्त;
	माप_प्रकार linesize = 0;
	खाता *fp;

	बाह्य पूर्णाङ्क optind;
	बाह्य वर्ण *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	यदि (argc <= 1)
		usage();

	यावत् ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		विकल्प (opt) {
		पक्ष 'H':
			hash_hosts = 1;
			भङ्ग;
		पक्ष 'c':
			get_cert = 1;
			भङ्ग;
		पक्ष 'D':
			print_sshfp = 1;
			भङ्ग;
		पक्ष 'p':
			ssh_port = a2port(optarg);
			यदि (ssh_port <= 0) {
				ख_लिखो(मानक_त्रुटि, "Bad port '%s'\n", optarg);
				निकास(1);
			}
			भङ्ग;
		पक्ष 'T':
			timeout = convtime(optarg);
			यदि (timeout == -1 || timeout == 0) {
				ख_लिखो(मानक_त्रुटि, "Bad timeout '%s'\n", optarg);
				usage();
			}
			भङ्ग;
		पक्ष 'v':
			यदि (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			अन्यथा यदि (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			अन्यथा
				fatal("Too high debugging level.");
			भङ्ग;
		पक्ष 'q':
			quiet = 1;
			भङ्ग;
		पक्ष 'f':
			यदि (म_भेद(optarg, "-") == 0)
				optarg = रिक्त;
			argv[fopt_गिनती++] = optarg;
			भङ्ग;
		पक्ष 'O':
			/* Maybe other misc options in the future too */
			यदि (म_भेदन(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			यदि ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			भङ्ग;
		पक्ष 't':
			get_keytypes = 0;
			tname = म_मोहर(optarg, ",");
			यावत् (tname) {
				पूर्णाङ्क type = sshkey_type_from_shortname(tname);

				विकल्प (type) {
				पक्ष कुंजी_ECDSA:
					get_keytypes |= KT_ECDSA;
					भङ्ग;
				पक्ष कुंजी_RSA:
					get_keytypes |= KT_RSA;
					भङ्ग;
				पक्ष कुंजी_ED25519:
					get_keytypes |= KT_ED25519;
					भङ्ग;
				पक्ष कुंजी_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					भङ्ग;
				पक्ष कुंजी_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					भङ्ग;
				पक्ष कुंजी_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					भङ्ग;
				पक्ष कुंजी_UNSPEC:
				स्वभाव:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = म_मोहर(रिक्त, ",");
			}
			भङ्ग;
		पक्ष '4':
			IPv4or6 = AF_INET;
			भङ्ग;
		पक्ष '6':
			IPv4or6 = AF_INET6;
			भङ्ग;
		स्वभाव:
			usage();
		}
	}
	यदि (optind == argc && !fopt_गिनती)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	यदि (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	यदि (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	यदि (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	यदि (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, परिमाण(con));
	read_wait = xcalloc(maxfd, परिमाण(संरचना pollfd));
	प्रति (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, संक_छोड़ो);
	प्रति (j = 0; j < fopt_गिनती; j++) {
		यदि (argv[j] == रिक्त)
			fp = मानक_निवेश;
		अन्यथा यदि ((fp = ख_खोलो(argv[j], "r")) == रिक्त)
			fatal("%s: %s: %s", __progname,
			    fp == मानक_निवेश ? "<stdin>" : argv[j], म_त्रुटि(त्रुटि_सं));

		यावत् (getline(&पंक्ति, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			यदि ((cp = म_अक्षर(पंक्ति, '#')) == रिक्त)
				cp = पंक्ति + म_माप(पंक्ति) - 1;
			यावत् (cp >= पंक्ति) {
				यदि (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				अन्यथा
					भङ्ग;
			}

			/* Skip empty lines */
			यदि (*पंक्ति == '\0')
				अनुवर्त;

			do_host(पंक्ति);
		}

		यदि (ख_त्रुटि(fp))
			fatal("%s: %s: %s", __progname,
			    fp == मानक_निवेश ? "<stdin>" : argv[j], म_त्रुटि(त्रुटि_सं));

		यदि (fp != मानक_निवेश)
			ख_बंद(fp);
	}
	मुक्त(पंक्ति);

	यावत् (optind < argc)
		do_host(argv[optind++]);

	यावत् (ncon > 0)
		conloop();

	प्रत्यागम found_one ? 0 : 1;
}
