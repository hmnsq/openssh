#अन्तर्भाव "fixed-keys.h"
#अन्तर्भाव <assert.h>

#define main(ac, av) xxxmain(ac, av)
#अन्तर्भाव "../../../ssh-agent.c"

शून्य test_one(अचर uint8_t* s, माप_प्रकार slen);

स्थिर पूर्णाङ्क
devnull_or_die(शून्य)
{
	पूर्णाङ्क fd;

	यदि ((fd = खोलो("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", म_त्रुटि(त्रुटि_सं));
		पात();
	}
	फर्काऊ fd;
}

स्थिर संरचना sshkey *
pubkey_or_die(अचर वर्ण *s)
{
	वर्ण *tmp, *cp;
	संरचना sshkey *pubkey;
	पूर्णाङ्क r;

	tmp = cp = xstrdup(s);
	यदि ((pubkey = sshkey_new(साँचो_UNSPEC)) == रिक्त)
		पात();
	यदि ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		पात();
	}
	मुक्त(tmp);
	फर्काऊ pubkey;
}

स्थिर संरचना sshkey *
privkey_or_die(अचर वर्ण *s)
{
	पूर्णाङ्क r;
	संरचना sshbuf *b;
	संरचना sshkey *privkey;

	यदि ((b = sshbuf_from(s, म_माप(s))) == रिक्त) {
		error_f("sshbuf_from failed");
		पात();
	}
	यदि ((r = sshkey_parse_private_fileblob(b, "", &privkey, रिक्त)) != 0) {
		error_fr(r, "parse");
		पात();
	}
	sshbuf_free(b);
	फर्काऊ privkey;
}

स्थिर शून्य
add_साँचो(अचर वर्ण *privkey, अचर वर्ण *certpath)
{
	Identity *id;
	पूर्णाङ्क r;
	संरचना sshkey *cert;

	id = xcalloc(1, परिमाण(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->साँचो = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	यदि (sshkey_is_sk(id->साँचो))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, परिमाण(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->साँचो = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	यदि ((r = sshkey_to_certified(id->साँचो)) != 0) {
		error_fr(r, "sshkey_to_certified");
		पात();
	}
	यदि ((r = sshkey_cert_copy(cert, id->साँचो)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		पात();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	यदि (sshkey_is_sk(id->साँचो))
		id->sk_provider = xstrdup("internal");
}

स्थिर शून्य
cleanup_idtab(शून्य)
{
	Identity *id;

	यदि (idtab == रिक्त) फर्काऊ;
	लागि (id = TAILQ_FIRST(&idtab->idlist); id;
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
	add_साँचो(PRIV_RSA, CERT_RSA);
	add_साँचो(PRIV_ECDSA, CERT_ECDSA);
	add_साँचो(PRIV_ED25519, CERT_ED25519);
	add_साँचो(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_साँचो(PRIV_ED25519_SK, CERT_ED25519_SK);
}

स्थिर शून्य
cleanup_sockettab(शून्य)
{
	u_int i;
	लागि (i = 0; i < sockets_alloc; i++) {
		यदि (sockets[i].type != AUTH_UNUSED)
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
	यदि ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", म_त्रुटि(त्रुटि_सं));
		पात();
	}
	new_socket(AUTH_CONNECTION, fd);
	प्रतिज्ञा(sockets[0].type == AUTH_CONNECTION);
	प्रतिज्ञा(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
शून्य
test_one(अचर uint8_t* s, माप_प्रकार slen)
{
	स्थिर पूर्णाङ्क devnull = -1;
	माप_प्रकार i, olen, nlen;

	यदि (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(शून्य)sshbuf_put(sockets[0].आगत, s, slen);
	लागि (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].आगत);
		process_message(0);
		nlen = sshbuf_len(sockets[0].आगत);
		यदि (nlen == 0 || nlen == olen)
			रोक;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
