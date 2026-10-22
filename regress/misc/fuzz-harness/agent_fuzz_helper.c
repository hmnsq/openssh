#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"
#ਅਨ੍ਤਰ੍ਭਾਵ <assert.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੁੱਖ(ac, av) xxxmain(ac, av)
#ਅਨ੍ਤਰ੍ਭਾਵ "../../../ssh-agent.c"

ਖਾਲੀ test_one(ਅਚਲ uint8_t* s, ਮਾਪ_t slen);

ਸਥਿਰ ਪੂਰਨ
devnull_or_die(ਖਾਲੀ)
{
	ਪੂਰਨ fd;

	ਜੇ ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	ਵਾਪਸ fd;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
pubkey_or_die(ਅਚਲ ਅੱਖਰ *s)
{
	ਅੱਖਰ *tmp, *cp;
	ਬਣਤਰ sshkey *pubkey;
	ਪੂਰਨ r;

	tmp = cp = xstrdup(s);
	ਜੇ ((pubkey = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
		abort();
	ਜੇ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	ਮੁਕਤ(tmp);
	ਵਾਪਸ pubkey;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
privkey_or_die(ਅਚਲ ਅੱਖਰ *s)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *b;
	ਬਣਤਰ sshkey *privkey;

	ਜੇ ((b = sshbuf_from(s, ਲੜੀ_ਲੰਬਾਈ(s))) == ਨਿਰਾ) {
		error_f("sshbuf_from failed");
		abort();
	}
	ਜੇ ((r = sshkey_parse_ਨਿੱਜੀ_fileblob(b, "", &privkey, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	ਵਾਪਸ privkey;
}

ਸਥਿਰ ਖਾਲੀ
ਜੋੜੋ_ਕੁੰਜੀ(ਅਚਲ ਅੱਖਰ *privkey, ਅਚਲ ਅੱਖਰ *certpath)
{
	ਪਛਾਣ_ਤੱਤ *id;
	ਪੂਰਨ r;
	ਬਣਤਰ sshkey *cert;

	id = xcalloc(1, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, ਅਗਲਾ);
	idtab->nentries++;
	id->ਕੁੰਜੀ = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	ਜੇ (sshkey_is_sk(id->ਕੁੰਜੀ))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, ਅਗਲਾ);
	idtab->nentries++;
	id->ਕੁੰਜੀ = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_certified(id->ਕੁੰਜੀ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	ਜੇ ((r = sshkey_cert_copy(cert, id->ਕੁੰਜੀ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	ਜੇ (sshkey_is_sk(id->ਕੁੰਜੀ))
		id->sk_provider = xstrdup("internal");
}

ਸਥਿਰ ਖਾਲੀ
cleanup_idtab(ਖਾਲੀ)
{
	ਪਛਾਣ_ਤੱਤ *id;

	ਜੇ (idtab == ਨਿਰਾ) ਵਾਪਸ;
	ਲਈ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, ਅਗਲਾ);
		free_ਪਛਾਣ_ਤੱਤ(id);
	}
	ਮੁਕਤ(idtab);
	idtab = ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
reset_idtab(ਖਾਲੀ)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	ਜੋੜੋ_ਕੁੰਜੀ(PRIV_RSA, CERT_RSA);
	ਜੋੜੋ_ਕੁੰਜੀ(PRIV_ECDSA, CERT_ECDSA);
	ਜੋੜੋ_ਕੁੰਜੀ(PRIV_ED25519, CERT_ED25519);
	ਜੋੜੋ_ਕੁੰਜੀ(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	ਜੋੜੋ_ਕੁੰਜੀ(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ਸਥਿਰ ਖਾਲੀ
cleanup_sockettab(ਖਾਲੀ)
{
	u_int i;
	ਲਈ (i = 0; i < sockets_alloc; i++) {
		ਜੇ (sockets[i].type != AUTH_ਅਣਵਰਤਿਆ)
			close_socket(sockets + i);
	}
	ਮੁਕਤ(sockets);
	sockets = ਨਿਰਾ;
	sockets_alloc = 0;
}

ਸਥਿਰ ਖਾਲੀ
reset_sockettab(ਪੂਰਨ devnull)
{
	ਪੂਰਨ fd;

	cleanup_sockettab();
	ਜੇ ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	ਪ੍ਰਤਿਜ੍ਞਾ(sockets[0].type == AUTH_CONNECTION);
	ਪ੍ਰਤਿਜ੍ਞਾ(sockets[0].fd == fd);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_MESSAGES 256
ਖਾਲੀ
test_one(ਅਚਲ uint8_t* s, ਮਾਪ_t slen)
{
	ਸਥਿਰ ਪੂਰਨ devnull = -1;
	ਮਾਪ_t i, olen, nlen;

	ਜੇ (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(ਖਾਲੀ)sshbuf_put(sockets[0].ਨਿਵੇਸ਼, s, slen);
	ਲਈ (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].ਨਿਵੇਸ਼);
		process_ਸੁਨੇਹਾ(0);
		nlen = sshbuf_len(sockets[0].ਨਿਵੇਸ਼);
		ਜੇ (nlen == 0 || nlen == olen)
			ਰੋਕੋ;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
