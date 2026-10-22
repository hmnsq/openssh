#अन्तर्भाव "fixed-keys.h"
#अन्तर्भाव <assert.h>

#define main(ac, av) xxxmain(ac, av)
#अन्तर्भाव "../../../ssh-agent.c"

शून्य test_one(ध्रुव uint8_t* s, size_t slen);

स्थिर पूर्णाङ्क
devnull_or_die(शून्य)
{
	पूर्णाङ्क fd;

	जइ ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	प्रत्यागम fd;
}

स्थिर संरचना sshkey *
pubkey_or_die(ध्रुव वर्ण *s)
{
	वर्ण *tmp, *cp;
	संरचना sshkey *pubkey;
	पूर्णाङ्क r;

	tmp = cp = xstrdup(s);
	जइ ((pubkey = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
		abort();
	जइ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	मुक्त(tmp);
	प्रत्यागम pubkey;
}

स्थिर संरचना sshkey *
privkey_or_die(ध्रुव वर्ण *s)
{
	पूर्णाङ्क r;
	संरचना sshbuf *b;
	संरचना sshkey *privkey;

	जइ ((b = sshbuf_from(s, strlen(s))) == रिक्त) {
		error_f("sshbuf_from failed");
		abort();
	}
	जइ ((r = sshkey_parse_private_fileblob(b, "", &privkey, रिक्त)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	प्रत्यागम privkey;
}

स्थिर शून्य
add_कुञ्चिका(ध्रुव वर्ण *privkey, ध्रुव वर्ण *certpath)
{
	Identity *id;
	पूर्णाङ्क r;
	संरचना sshkey *cert;

	id = xcalloc(1, परिमाण(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->कुञ्चिका = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	जइ (sshkey_is_sk(id->कुञ्चिका))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, परिमाण(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->कुञ्चिका = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	जइ ((r = sshkey_to_certified(id->कुञ्चिका)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	जइ ((r = sshkey_cert_copy(cert, id->कुञ्चिका)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	जइ (sshkey_is_sk(id->कुञ्चिका))
		id->sk_provider = xstrdup("internal");
}

स्थिर शून्य
cleanup_idtab(शून्य)
{
	Identity *id;

	जइ (idtab == रिक्त) प्रत्यागम;
	प्रति (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	मुक्त(idtab);
	idtab = रिक्त;
}

स्थिर शून्य
reset_idtab(शून्य)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_कुञ्चिका(PRIV_RSA, CERT_RSA);
	add_कुञ्चिका(PRIV_ECDSA, CERT_ECDSA);
	add_कुञ्चिका(PRIV_ED25519, CERT_ED25519);
	add_कुञ्चिका(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_कुञ्चिका(PRIV_ED25519_SK, CERT_ED25519_SK);
}

स्थिर शून्य
cleanup_sockettab(शून्य)
{
	u_int i;
	प्रति (i = 0; i < sockets_alloc; i++) {
		जइ (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	मुक्त(sockets);
	sockets = रिक्त;
	sockets_alloc = 0;
}

स्थिर शून्य
reset_sockettab(पूर्णाङ्क devnull)
{
	पूर्णाङ्क fd;

	cleanup_sockettab();
	जइ ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	प्रतिज्ञा(sockets[0].type == AUTH_CONNECTION);
	प्रतिज्ञा(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
शून्य
test_one(ध्रुव uint8_t* s, size_t slen)
{
	स्थिर पूर्णाङ्क devnull = -1;
	size_t i, olen, nlen;

	जइ (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(शून्य)sshbuf_put(sockets[0].निवेशः, s, slen);
	प्रति (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].निवेशः);
		process_message(0);
		nlen = sshbuf_len(sockets[0].निवेशः);
		जइ (nlen == 0 || nlen == olen)
			भङ्ग;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
