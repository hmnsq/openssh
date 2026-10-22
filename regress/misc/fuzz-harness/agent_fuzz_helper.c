#ಅನ್ತರ್ಭಾವ "fixed-keys.h"
#ಅನ್ತರ್ಭಾವ <assert.h>

#ವ್ಯಾಖ್ಯಾನಿಸು ಮುಖ್ಯ(ac, av) xxxmain(ac, av)
#ಅನ್ತರ್ಭಾವ "../../../ssh-agent.c"

ಶೂನ್ಯ test_one(ಸ್ಥಿರಾಂಕ uint8_t* s, ಗಾತ್ರ_t slen);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
devnull_or_die(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ fd;

	ಆದರೆ ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	ಹಿಂತಿರುಗಿ fd;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
pubkey_or_die(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *pubkey;
	ಪೂರ್ಣಾಂಕ r;

	tmp = cp = xstrdup(s);
	ಆದರೆ ((pubkey = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
		abort();
	ಆದರೆ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ pubkey;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
privkey_or_die(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *b;
	ರಚನೆ sshkey *privkey;

	ಆದರೆ ((b = sshbuf_from(s, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s))) == ಖಾಲಿ) {
		error_f("sshbuf_from failed");
		abort();
	}
	ಆದರೆ ((r = sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &privkey, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ privkey;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಕೂಡಿಸು_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *privkey, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *certpath)
{
	ತಟಸ್ಥ *id;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshkey *cert;

	id = xcalloc(1, ಗಾತ್ರ(ತಟಸ್ಥ));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, ಮುಂದಿನ);
	idtab->nentries++;
	id->ಕೀಲಿ = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	ಆದರೆ (sshkey_is_sk(id->ಕೀಲಿ))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, ಗಾತ್ರ(ತಟಸ್ಥ));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, ಮುಂದಿನ);
	idtab->nentries++;
	id->ಕೀಲಿ = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_certified(id->ಕೀಲಿ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	ಆದರೆ ((r = sshkey_cert_copy(cert, id->ಕೀಲಿ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	ಆದರೆ (sshkey_is_sk(id->ಕೀಲಿ))
		id->sk_provider = xstrdup("internal");
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_idtab(ಶೂನ್ಯ)
{
	ತಟಸ್ಥ *id;

	ಆದರೆ (idtab == ಖಾಲಿ) ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, ಮುಂದಿನ);
		free_ತಟಸ್ಥ(id);
	}
	ಬಿಡುಗಡೆ(idtab);
	idtab = ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_idtab(ಶೂನ್ಯ)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	ಕೂಡಿಸು_ಕೀಲಿ(PRIV_RSA, CERT_RSA);
	ಕೂಡಿಸು_ಕೀಲಿ(PRIV_ECDSA, CERT_ECDSA);
	ಕೂಡಿಸು_ಕೀಲಿ(PRIV_ED25519, CERT_ED25519);
	ಕೂಡಿಸು_ಕೀಲಿ(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	ಕೂಡಿಸು_ಕೀಲಿ(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_sockettab(ಶೂನ್ಯ)
{
	u_int i;
	ಗಾಗಿ (i = 0; i < sockets_alloc; i++) {
		ಆದರೆ (sockets[i].type != AUTH_ಬಳಸದ)
			close_socket(sockets + i);
	}
	ಬಿಡುಗಡೆ(sockets);
	sockets = ಖಾಲಿ;
	sockets_alloc = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_sockettab(ಪೂರ್ಣಾಂಕ devnull)
{
	ಪೂರ್ಣಾಂಕ fd;

	cleanup_sockettab();
	ಆದರೆ ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	ಪ್ರತಿಜ್ಞಾ(sockets[0].type == AUTH_CONNECTION);
	ಪ್ರತಿಜ್ಞಾ(sockets[0].fd == fd);
}

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_MESSAGES 256
ಶೂನ್ಯ
test_one(ಸ್ಥಿರಾಂಕ uint8_t* s, ಗಾತ್ರ_t slen)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ devnull = -1;
	ಗಾತ್ರ_t i, olen, nlen;

	ಆದರೆ (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(ಶೂನ್ಯ)sshbuf_put(sockets[0].ಒಳಹರಿವು, s, slen);
	ಗಾಗಿ (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].ಒಳಹರಿವು);
		process_ಸಂದೇಶ(0);
		nlen = sshbuf_len(sockets[0].ಒಳಹರಿವು);
		ಆದರೆ (nlen == 0 || nlen == olen)
			ನಿಲ್ಲಿಸು;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
