#അന്തര്ഭാവ "fixed-keys.h"
#അന്തര്ഭാവ <assert.h>

#define പ്രധാന(ac, av) xxxmain(ac, av)
#അന്തര്ഭാവ "../../../ssh-agent.c"

ശൂന്യം test_one(സ്ഥിരം uint8_t* s, size_t slen);

സ്ഥിതം പൂർണ്ണസംഖ്യ
devnull_or_die(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ fd;

	എങ്കിൽ ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	തിരികെ fd;
}

സ്ഥിതം ഘടന sshkey *
pubkey_or_die(സ്ഥിരം അക്ഷരം *s)
{
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *pubkey;
	പൂർണ്ണസംഖ്യ r;

	tmp = cp = xstrdup(s);
	എങ്കിൽ ((pubkey = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
		abort();
	എങ്കിൽ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	സ്വതന്ത്രം(tmp);
	തിരികെ pubkey;
}

സ്ഥിതം ഘടന sshkey *
privkey_or_die(സ്ഥിരം അക്ഷരം *s)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *b;
	ഘടന sshkey *privkey;

	എങ്കിൽ ((b = sshbuf_from(s, strlen(s))) == ശൂന്യ) {
		error_f("sshbuf_from failed");
		abort();
	}
	എങ്കിൽ ((r = sshkey_parse_private_fileblob(b, "", &privkey, ശൂന്യ)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	തിരികെ privkey;
}

സ്ഥിതം ശൂന്യം
add_താക്കോൽ(സ്ഥിരം അക്ഷരം *privkey, സ്ഥിരം അക്ഷരം *certpath)
{
	Identity *id;
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshkey *cert;

	id = xcalloc(1, വലുപ്പം(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->താക്കോൽ = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	എങ്കിൽ (sshkey_is_sk(id->താക്കോൽ))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, വലുപ്പം(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->താക്കോൽ = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	എങ്കിൽ ((r = sshkey_to_certified(id->താക്കോൽ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	എങ്കിൽ ((r = sshkey_cert_copy(cert, id->താക്കോൽ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	എങ്കിൽ (sshkey_is_sk(id->താക്കോൽ))
		id->sk_provider = xstrdup("internal");
}

സ്ഥിതം ശൂന്യം
cleanup_idtab(ശൂന്യം)
{
	Identity *id;

	എങ്കിൽ (idtab == ശൂന്യ) തിരികെ;
	വേണ്ടി (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	സ്വതന്ത്രം(idtab);
	idtab = ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
reset_idtab(ശൂന്യം)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_താക്കോൽ(PRIV_RSA, CERT_RSA);
	add_താക്കോൽ(PRIV_ECDSA, CERT_ECDSA);
	add_താക്കോൽ(PRIV_ED25519, CERT_ED25519);
	add_താക്കോൽ(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_താക്കോൽ(PRIV_ED25519_SK, CERT_ED25519_SK);
}

സ്ഥിതം ശൂന്യം
cleanup_sockettab(ശൂന്യം)
{
	u_int i;
	വേണ്ടി (i = 0; i < sockets_alloc; i++) {
		എങ്കിൽ (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	സ്വതന്ത്രം(sockets);
	sockets = ശൂന്യ;
	sockets_alloc = 0;
}

സ്ഥിതം ശൂന്യം
reset_sockettab(പൂർണ്ണസംഖ്യ devnull)
{
	പൂർണ്ണസംഖ്യ fd;

	cleanup_sockettab();
	എങ്കിൽ ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	പ്രതിജ്ഞാ(sockets[0].type == AUTH_CONNECTION);
	പ്രതിജ്ഞാ(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
ശൂന്യം
test_one(സ്ഥിരം uint8_t* s, size_t slen)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ devnull = -1;
	size_t i, olen, nlen;

	എങ്കിൽ (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(ശൂന്യം)sshbuf_put(sockets[0].നിവേശം, s, slen);
	വേണ്ടി (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].നിവേശം);
		process_message(0);
		nlen = sshbuf_len(sockets[0].നിവേശം);
		എങ്കിൽ (nlen == 0 || nlen == olen)
			നിർത്തുക;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
