#ಅನ್ತರ್ಭಾವ "fixed-keys.h"
#ಅನ್ತರ್ಭಾವ <assert.h>

#define main(ac, av) xxxmain(ac, av)
#ಅನ್ತರ್ಭಾವ "../../../ssh-agent.c"

ಶೂನ್ಯ test_one(ಧ್ರುವ uint8_t* s, size_t slen);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
devnull_or_die(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ fd;

	ಯದಿ ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	ಪ್ರತ್ಯಾಗಮ fd;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
pubkey_or_die(ಧ್ರುವ ವರ್ಣ *s)
{
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *pubkey;
	ಪೂರ್ಣಾಙ್ಕ r;

	tmp = cp = xstrdup(s);
	ಯದಿ ((pubkey = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
		abort();
	ಯದಿ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ pubkey;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
privkey_or_die(ಧ್ರುವ ವರ್ಣ *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *b;
	ಸಂರಚನಾ sshkey *privkey;

	ಯದಿ ((b = sshbuf_from(s, strlen(s))) == ರಿಕ್ತ) {
		error_f("sshbuf_from failed");
		abort();
	}
	ಯದಿ ((r = sshkey_parse_private_fileblob(b, "", &privkey, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ privkey;
}

ಸ್ಥಿರ ಶೂನ್ಯ
add_ಕೀಲಿ(ಧ್ರುವ ವರ್ಣ *privkey, ಧ್ರುವ ವರ್ಣ *certpath)
{
	Identity *id;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshkey *cert;

	id = xcalloc(1, ಪರಿಮಾಣ(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->ಕೀಲಿ = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	ಯದಿ (sshkey_is_sk(id->ಕೀಲಿ))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, ಪರಿಮಾಣ(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->ಕೀಲಿ = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	ಯದಿ ((r = sshkey_to_certified(id->ಕೀಲಿ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	ಯದಿ ((r = sshkey_cert_copy(cert, id->ಕೀಲಿ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	ಯದಿ (sshkey_is_sk(id->ಕೀಲಿ))
		id->sk_provider = xstrdup("internal");
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_idtab(ಶೂನ್ಯ)
{
	Identity *id;

	ಯದಿ (idtab == ರಿಕ್ತ) ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	ಮುಕ್ತ(idtab);
	idtab = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_idtab(ಶೂನ್ಯ)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_ಕೀಲಿ(PRIV_RSA, CERT_RSA);
	add_ಕೀಲಿ(PRIV_ECDSA, CERT_ECDSA);
	add_ಕೀಲಿ(PRIV_ED25519, CERT_ED25519);
	add_ಕೀಲಿ(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_ಕೀಲಿ(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_sockettab(ಶೂನ್ಯ)
{
	u_int i;
	ಪ್ರತಿ (i = 0; i < sockets_alloc; i++) {
		ಯದಿ (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	ಮುಕ್ತ(sockets);
	sockets = ರಿಕ್ತ;
	sockets_alloc = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_sockettab(ಪೂರ್ಣಾಙ್ಕ devnull)
{
	ಪೂರ್ಣಾಙ್ಕ fd;

	cleanup_sockettab();
	ಯದಿ ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	ಪ್ರತಿಜ್ಞಾ(sockets[0].type == AUTH_CONNECTION);
	ಪ್ರತಿಜ್ಞಾ(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
ಶೂನ್ಯ
test_one(ಧ್ರುವ uint8_t* s, size_t slen)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ devnull = -1;
	size_t i, olen, nlen;

	ಯದಿ (devnull == -1) {
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
	ಪ್ರತಿ (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].ಒಳಹರಿವು);
		process_message(0);
		nlen = sshbuf_len(sockets[0].ಒಳಹರಿವು);
		ಯದಿ (nlen == 0 || nlen == olen)
			ಭಙ್ಗ;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
