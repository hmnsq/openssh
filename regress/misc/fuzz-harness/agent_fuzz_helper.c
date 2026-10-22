#अन्तर्भाव "fixed-keys.h"
#अन्तर्भाव <assert.h>

#define main(ac, av) xxxmain(ac, av)
#अन्तर्भाव "../../../ssh-agent.c"

शून्य test_one(स्थिरांक uint8_t* s, माप_प्रकार slen);

स्थिर पूर्णांक
devnull_or_die(शून्य)
{
	पूर्णांक fd;

	जर ((fd = खोलो("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", म_त्रुटि(त्रुटि_सं));
		पात();
	}
	परत fd;
}

स्थिर संरचना sshkey *
pubkey_or_die(स्थिरांक अक्षर *s)
{
	अक्षर *tmp, *cp;
	संरचना sshkey *pubkey;
	पूर्णांक r;

	tmp = cp = xstrdup(s);
	जर ((pubkey = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
		पात();
	जर ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		पात();
	}
	मुक्त(tmp);
	परत pubkey;
}

स्थिर संरचना sshkey *
privkey_or_die(स्थिरांक अक्षर *s)
{
	पूर्णांक r;
	संरचना sshbuf *b;
	संरचना sshkey *privkey;

	जर ((b = sshbuf_from(s, म_माप(s))) == रिक्त) {
		error_f("sshbuf_from failed");
		पात();
	}
	जर ((r = sshkey_parse_private_fileblob(b, "", &privkey, रिक्त)) != 0) {
		error_fr(r, "parse");
		पात();
	}
	sshbuf_free(b);
	परत privkey;
}

स्थिर शून्य
add_किल्ली(स्थिरांक अक्षर *privkey, स्थिरांक अक्षर *certpath)
{
	Identity *id;
	पूर्णांक r;
	संरचना sshkey *cert;

	id = xcalloc(1, आकार(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->किल्ली = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	जर (sshkey_is_sk(id->किल्ली))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, आकार(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->किल्ली = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	जर ((r = sshkey_to_certified(id->किल्ली)) != 0) {
		error_fr(r, "sshkey_to_certified");
		पात();
	}
	जर ((r = sshkey_cert_copy(cert, id->किल्ली)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		पात();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	जर (sshkey_is_sk(id->किल्ली))
		id->sk_provider = xstrdup("internal");
}

स्थिर शून्य
cleanup_idtab(शून्य)
{
	Identity *id;

	जर (idtab == रिक्त) परत;
	साठी (id = TAILQ_FIRST(&idtab->idlist); id;
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
	add_किल्ली(PRIV_RSA, CERT_RSA);
	add_किल्ली(PRIV_ECDSA, CERT_ECDSA);
	add_किल्ली(PRIV_ED25519, CERT_ED25519);
	add_किल्ली(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_किल्ली(PRIV_ED25519_SK, CERT_ED25519_SK);
}

स्थिर शून्य
cleanup_sockettab(शून्य)
{
	u_int i;
	साठी (i = 0; i < sockets_alloc; i++) {
		जर (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	मुक्त(sockets);
	sockets = रिक्त;
	sockets_alloc = 0;
}

स्थिर शून्य
reset_sockettab(पूर्णांक devnull)
{
	पूर्णांक fd;

	cleanup_sockettab();
	जर ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", म_त्रुटि(त्रुटि_सं));
		पात();
	}
	new_socket(AUTH_CONNECTION, fd);
	प्रतिज्ञा(sockets[0].type == AUTH_CONNECTION);
	प्रतिज्ञा(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
शून्य
test_one(स्थिरांक uint8_t* s, माप_प्रकार slen)
{
	स्थिर पूर्णांक devnull = -1;
	माप_प्रकार i, olen, nlen;

	जर (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(शून्य)sshbuf_put(sockets[0].आदान, s, slen);
	साठी (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].आदान);
		process_message(0);
		nlen = sshbuf_len(sockets[0].आदान);
		जर (nlen == 0 || nlen == olen)
			थांबा;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
