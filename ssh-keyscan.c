/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#समावेश "includes.h"
 
#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/queue.h>
#समावेश <sys/time.h>
#समावेश <sys/resource.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#पूर्ण_अगर

#समावेश <errno.h>
#समावेश <limits.h>
#समावेश <netdb.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <poll.h>
#समावेश <signal.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "cipher.h"
#समावेश "digest.h"
#समावेश "kex.h"
#समावेश "compat.h"
#समावेश "myproposal.h"
#समावेश "packet.h"
#समावेश "dispatch.h"
#समावेश "log.h"
#समावेश "atomicio.h"
#समावेश "misc.h"
#समावेश "hostfile.h"
#समावेश "ssherr.h"
#समावेश "ssh_api.h"
#समावेश "dns.h"
#समावेश "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
पूर्णांक IPv4or6 = AF_UNSPEC;

पूर्णांक ssh_port = SSH_DEFAULT_PORT;

#घोषणा KT_RSA		(1)
#घोषणा KT_ECDSA	(1<<1)
#घोषणा KT_ED25519	(1<<2)
#घोषणा KT_ECDSA_SK	(1<<4)
#घोषणा KT_ED25519_SK	(1<<5)
#घोषणा KT_MLDSA44_ED25519 (1<<6)

#घोषणा KT_MIN		KT_RSA
#घोषणा KT_MAX		KT_MLDSA44_ED25519

पूर्णांक get_cert = 0;
पूर्णांक get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

पूर्णांक hash_hosts = 0;		/* Hash hostname on output */

पूर्णांक print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

पूर्णांक found_one = 0;		/* Successfully found a key */

पूर्णांक hashalg = -1;		/* Hash for SSHFP records or -1 for all */

पूर्णांक quiet = 0;			/* Don't print key comment lines */

#घोषणा MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
पूर्णांक timeout = 5;

पूर्णांक maxfd;
#घोषणा MAXCON (maxfd - 10)

बाह्य अक्षर *__progname;
काष्ठा pollfd *read_wait;
पूर्णांक ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
प्रकार काष्ठा Connection {
	u_char c_status;	/* State of connection on this file desc. */
#घोषणा CS_UNUSED 0		/* File descriptor unused */
#घोषणा CS_CON 1		/* Waiting to connect/read greeting */
	पूर्णांक c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	पूर्णांक c_keytype;		/* Only one of KT_* */
	संक_पूर्ण_प्रकार c_done;	/* SSH2 done */
	अक्षर *c_namebase;	/* Address to free for c_name and c_namelist */
	अक्षर *c_name;		/* Hostname of connection for errors */
	अक्षर *c_namelist;	/* Pointer to other possible addresses */
	अक्षर *c_output_name;	/* Hostname of connection for output */
	काष्ठा ssh *c_ssh;	/* SSH-connection */
	अक्षर c_banner[256];	/* Partial server greeting */
	माप_प्रकार c_banner_len;	/* Length of partial server greeting */
	पूर्णांक c_banner_sent;	/* Client greeting has been sent */
	काष्ठा timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

अटल व्योम keyprint(con *c, काष्ठा sshkey *कुंजी);

अटल पूर्णांक
fdlim_get(पूर्णांक hard)
{
#अगर defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	काष्ठा rlimit rlfd;
	rlim_t lim;

	अगर (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		वापस -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	अगर (lim <= 0)
		वापस -1;
	अगर (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	अगर (lim >= पूर्णांक_उच्च)
		lim = पूर्णांक_उच्च;
	वापस lim;
#अन्यथा
	वापस (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= पूर्णांक_उच्च) ? पूर्णांक_उच्च : SSH_SYSFDMAX);
#पूर्ण_अगर
}

अटल पूर्णांक
fdlim_set(पूर्णांक lim)
{
#अगर defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	काष्ठा rlimit rlfd;
#पूर्ण_अगर

	अगर (lim <= 0)
		वापस (-1);
#अगर defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	अगर (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		वापस (-1);
	rlfd.rlim_cur = lim;
	अगर (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		वापस (-1);
#या_अगर defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#पूर्ण_अगर
	वापस (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
अटल अक्षर *
xstrsep(अक्षर **str, स्थिर अक्षर *delim)
{
	अक्षर *s, *e;

	अगर (!**str)
		वापस (शून्य);

	s = *str;
	e = s + म_खोज(s, delim);

	अगर (*e != '\0')
		*e++ = '\0';
	*str = e;

	वापस (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
अटल अक्षर *
strnnsep(अक्षर **stringp, अक्षर *delim)
{
	अक्षर *tok;

	करो {
		tok = xstrsep(stringp, delim);
	} जबतक (tok && *tok == '\0');
	वापस (tok);
}


अटल पूर्णांक
कुंजी_print_wrapper(काष्ठा sshkey *hostkey, काष्ठा ssh *ssh)
{
	con *c;

	अगर ((c = ssh_get_app_तथ्य(ssh)) != शून्य)
		keyprint(c, hostkey);
	/* always abort key exchange */
	वापस -1;
}

अटल पूर्णांक
ssh2_capable(पूर्णांक remote_major, पूर्णांक remote_minor)
{
	चयन (remote_major) {
	हाल 1:
		अगर (remote_minor == 99)
			वापस 1;
		अवरोध;
	हाल 2:
		वापस 1;
	शेष:
		अवरोध;
	}
	वापस 0;
}

अटल व्योम
keygrab_ssh2(con *c)
{
	अक्षर *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	पूर्णांक r;

	चयन (c->c_keytype) {
	हाल KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		अवरोध;
	हाल KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		अवरोध;
	हाल KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		अवरोध;
	हाल KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		अवरोध;
	हाल KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		अवरोध;
	हाल KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		अवरोध;
	शेष:
		fatal("unknown key type %d", c->c_keytype);
		अवरोध;
	}
	अगर ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		मुक्त(c->c_ssh);
		ख_लिखो(मानक_त्रुटि, "kex_setup: %s\n", ssh_err(r));
		निकास(1);
	}
#अगर_घोषित WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#पूर्ण_अगर
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

अटल व्योम
keyprint_one(स्थिर अक्षर *host, काष्ठा sshkey *कुंजी)
{
	अक्षर *hostport = शून्य, *hashed = शून्य;
	स्थिर अक्षर *known_host;
	पूर्णांक r = 0;

	found_one = 1;

	अगर (print_sshfp) {
		export_dns_rr(host, कुंजी, मानक_निकास, 0, hashalg);
		वापस;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	अगर (hash_hosts && (hashed = host_hash(hostport, शून्य, 0)) == शून्य)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	अगर (!get_cert)
		r = ख_लिखो(मानक_निकास, "%s ", known_host);
	अगर (r >= 0 && sshkey_write(कुंजी, मानक_निकास) == 0)
		(व्योम)ख_माला_दो("\n", मानक_निकास);
	मुक्त(hashed);
	मुक्त(hostport);
}

अटल व्योम
keyprint(con *c, काष्ठा sshkey *कुंजी)
{
	अक्षर *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	अक्षर *host, *ohosts;

	अगर (कुंजी == शून्य)
		वापस;
	अगर (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, कुंजी);
		वापस;
	}
	ohosts = hosts = xstrdup(hosts);
	जबतक ((host = strsep(&hosts, ",")) != शून्य)
		keyprint_one(host, कुंजी);
	मुक्त(ohosts);
}

अटल पूर्णांक
tcpconnect(अक्षर *host)
{
	काष्ठा addrinfo hints, *ai, *aitop;
	अक्षर strport[NI_MAXSERV];
	पूर्णांक gaierr, s = -1;

	snprintf(strport, माप strport, "%d", ssh_port);
	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	अगर ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		वापस -1;
	}
	क्रम (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		अगर (s == -1) {
			error("socket: %s", म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		अगर (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		अगर (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    त्रुटि_सं != EINPROGRESS)
			error("connect (`%s'): %s", host, म_त्रुटि(त्रुटि_सं));
		अन्यथा
			अवरोध;
		बंद(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	वापस s;
}

अटल पूर्णांक
conalloc(स्थिर अक्षर *iname, स्थिर अक्षर *oname, पूर्णांक keytype)
{
	अक्षर *namebase, *name, *namelist;
	पूर्णांक s;

	namebase = namelist = xstrdup(iname);

	करो {
		name = xstrsep(&namelist, ",");
		अगर (!name) {
			मुक्त(namebase);
			वापस (-1);
		}
	} जबतक ((s = tcpconnect(name)) < 0);

	अगर (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	अगर (fdcon[s].c_status)
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
	वापस (s);
}

अटल व्योम
confree(पूर्णांक s)
{
	अगर (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	मुक्त(fdcon[s].c_namebase);
	मुक्त(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	अगर (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		मुक्त(fdcon[s].c_ssh);
		fdcon[s].c_ssh = शून्य;
	} अन्यथा
		बंद(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

अटल पूर्णांक
conrecycle(पूर्णांक s)
{
	con *c = &fdcon[s];
	पूर्णांक ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	वापस (ret);
}

अटल व्योम
congreet(पूर्णांक s)
{
	पूर्णांक remote_major = 0, remote_minor = 0;
	ssize_t n;
	अक्षर buf[256], ch;
	अक्षर remote_version[माप buf];
	con *c = &fdcon[s];

	अगर (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, माप buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		अगर (n < 0 || (माप_प्रकार)n >= माप(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			वापस;
		}
		अगर (atomicio(vwrite, s, buf, n) != (माप_प्रकार)n) {
			error("write (%s): %s", c->c_name, म_त्रुटि(त्रुटि_सं));
			confree(s);
			वापस;
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
	n = पढ़ो(s, &ch, माप(ch));
	अगर (n == -1 && (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK ||
	    त्रुटि_सं == EINTR))
		वापस;
	अगर (n != 1) {
		अगर (n == 0)
			त्रुटि_सं = EPIPE;
		चयन (त्रुटि_सं) {
		हाल EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			अवरोध;
		हाल ECONNREFUSED:
			अवरोध;
		शेष:
			error("read (%s): %s", c->c_name, म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		conrecycle(s);
		वापस;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	अगर (ch != '\n') {
		अगर (c->c_banner_len < माप(c->c_banner) - 1)
			वापस; /* incomplete line */
		अगर (म_भेदन(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			वापस;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		वापस;
	}
	अगर (म_भेदन(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		वापस;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	स_नकल(buf, c->c_banner, c->c_banner_len);
	अगर ((c->c_ssh = ssh_packet_set_connection(शून्य, s, s)) == शून्य)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_तथ्य(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	अगर (माला_पूछो(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	अगर (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		वापस;
	}
	अगर (!quiet) {
		ख_लिखो(मानक_निकास, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

अटल व्योम
conread(पूर्णांक s)
{
	con *c = &fdcon[s];

	अगर (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

अटल व्योम
conloop(व्योम)
{
	काष्ठा timespec seltime, now;
	con *c;
	पूर्णांक i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	अगर (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	अन्यथा
		timespecclear(&seltime);

	जबतक (ppoll(read_wait, maxfd, &seltime, शून्य) == -1) {
		अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR || त्रुटि_सं == EWOULDBLOCK)
			जारी;
		error("poll error");
	}

	क्रम (i = 0; i < maxfd; i++) {
		अगर (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		अन्यथा अगर (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	जबतक (c && timespeccmp(&c->c_ts, &now, <)) {
		पूर्णांक s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

अटल व्योम
do_one_host(अक्षर *host)
{
	अक्षर *name = strnnsep(&host, " \t\n");
	पूर्णांक j;

	अगर (name == शून्य)
		वापस;
	क्रम (j = KT_MIN; j <= KT_MAX; j *= 2) {
		अगर (get_keytypes & j) {
			जबतक (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

अटल व्योम
do_host(अक्षर *host)
{
	अक्षर daddr[128];
	काष्ठा xaddr addr, end_addr;
	u_int masklen;

	अगर (host == शून्य)
		वापस;
	अगर (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} अन्यथा {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		अगर (addr_host_to_all1s(&end_addr, masklen) != 0)
			जाओ badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		क्रम (;;) {
			अगर (addr_ntop(&addr, daddr, माप(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				वापस;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			अगर (addr_cmp(&addr, &end_addr) == 0)
				अवरोध;
			addr_increment(&addr);
		}
	}
}

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	निकास(1);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	पूर्णांक opt, fopt_गिनती = 0, j;
	अक्षर *tname, *cp, *पंक्ति = शून्य;
	माप_प्रकार linesize = 0;
	खाता *fp;

	बाह्य पूर्णांक optind;
	बाह्य अक्षर *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	अगर (argc <= 1)
		usage();

	जबतक ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		चयन (opt) {
		हाल 'H':
			hash_hosts = 1;
			अवरोध;
		हाल 'c':
			get_cert = 1;
			अवरोध;
		हाल 'D':
			print_sshfp = 1;
			अवरोध;
		हाल 'p':
			ssh_port = a2port(optarg);
			अगर (ssh_port <= 0) {
				ख_लिखो(मानक_त्रुटि, "Bad port '%s'\n", optarg);
				निकास(1);
			}
			अवरोध;
		हाल 'T':
			timeout = convtime(optarg);
			अगर (timeout == -1 || timeout == 0) {
				ख_लिखो(मानक_त्रुटि, "Bad timeout '%s'\n", optarg);
				usage();
			}
			अवरोध;
		हाल 'v':
			अगर (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			अन्यथा अगर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			अन्यथा
				fatal("Too high debugging level.");
			अवरोध;
		हाल 'q':
			quiet = 1;
			अवरोध;
		हाल 'f':
			अगर (म_भेद(optarg, "-") == 0)
				optarg = शून्य;
			argv[fopt_गिनती++] = optarg;
			अवरोध;
		हाल 'O':
			/* Maybe other misc options in the future too */
			अगर (म_भेदन(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			अगर ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			अवरोध;
		हाल 't':
			get_keytypes = 0;
			tname = म_मोहर(optarg, ",");
			जबतक (tname) {
				पूर्णांक type = sshkey_type_from_shortname(tname);

				चयन (type) {
				हाल कुंजी_ECDSA:
					get_keytypes |= KT_ECDSA;
					अवरोध;
				हाल कुंजी_RSA:
					get_keytypes |= KT_RSA;
					अवरोध;
				हाल कुंजी_ED25519:
					get_keytypes |= KT_ED25519;
					अवरोध;
				हाल कुंजी_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					अवरोध;
				हाल कुंजी_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					अवरोध;
				हाल कुंजी_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					अवरोध;
				हाल कुंजी_UNSPEC:
				शेष:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = म_मोहर(शून्य, ",");
			}
			अवरोध;
		हाल '4':
			IPv4or6 = AF_INET;
			अवरोध;
		हाल '6':
			IPv4or6 = AF_INET6;
			अवरोध;
		शेष:
			usage();
		}
	}
	अगर (optind == argc && !fopt_गिनती)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	अगर (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	अगर (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	अगर (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	अगर (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, माप(con));
	read_wait = xcalloc(maxfd, माप(काष्ठा pollfd));
	क्रम (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, संक_छोड़ो);
	क्रम (j = 0; j < fopt_गिनती; j++) {
		अगर (argv[j] == शून्य)
			fp = मानक_निवेश;
		अन्यथा अगर ((fp = ख_खोलो(argv[j], "r")) == शून्य)
			fatal("%s: %s: %s", __progname,
			    fp == मानक_निवेश ? "<stdin>" : argv[j], म_त्रुटि(त्रुटि_सं));

		जबतक (getline(&पंक्ति, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			अगर ((cp = म_अक्षर(पंक्ति, '#')) == शून्य)
				cp = पंक्ति + म_माप(पंक्ति) - 1;
			जबतक (cp >= पंक्ति) {
				अगर (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				अन्यथा
					अवरोध;
			}

			/* Skip empty lines */
			अगर (*पंक्ति == '\0')
				जारी;

			do_host(पंक्ति);
		}

		अगर (ख_त्रुटि(fp))
			fatal("%s: %s: %s", __progname,
			    fp == मानक_निवेश ? "<stdin>" : argv[j], म_त्रुटि(त्रुटि_सं));

		अगर (fp != मानक_निवेश)
			ख_बंद(fp);
	}
	मुक्त(पंक्ति);

	जबतक (optind < argc)
		do_host(argv[optind++]);

	जबतक (ncon > 0)
		conloop();

	वापस found_one ? 0 : 1;
}
