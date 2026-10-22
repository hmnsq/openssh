#समावेश "fixed-keys.h"
#समावेश <assert.h>

#घोषणा मुख्य(ac, av) xxxmain(ac, av)
#समावेश "../../../ssh-agent.c"

व्योम test_one(स्थिर uint8_t* s, माप_प्रकार slen);

अटल पूर्णांक
devnull_or_die(व्योम)
{
	पूर्णांक fd;

	अगर ((fd = खोलो("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", म_त्रुटि(त्रुटि_सं));
		पात();
	}
	वापस fd;
}

अटल काष्ठा sshkey *
pubkey_or_die(स्थिर अक्षर *s)
{
	अक्षर *tmp, *cp;
	काष्ठा sshkey *pubkey;
	पूर्णांक r;

	tmp = cp = xstrdup(s);
	अगर ((pubkey = sshkey_new(कुंजी_UNSPEC)) == शून्य)
		पात();
	अगर ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		पात();
	}
	मुक्त(tmp);
	वापस pubkey;
}

अटल काष्ठा sshkey *
privkey_or_die(स्थिर अक्षर *s)
{
	पूर्णांक r;
	काष्ठा sshbuf *b;
	काष्ठा sshkey *privkey;

	अगर ((b = sshbuf_from(s, म_माप(s))) == शून्य) {
		error_f("sshbuf_from failed");
		पात();
	}
	अगर ((r = sshkey_parse_private_fileblob(b, "", &privkey, शून्य)) != 0) {
		error_fr(r, "parse");
		पात();
	}
	sshbuf_free(b);
	वापस privkey;
}

अटल व्योम
add_कुंजी(स्थिर अक्षर *privkey, स्थिर अक्षर *certpath)
{
	Identity *id;
	पूर्णांक r;
	काष्ठा sshkey *cert;

	id = xcalloc(1, माप(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, अग्र);
	idtab->nentries++;
	id->कुंजी = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	अगर (sshkey_is_sk(id->कुंजी))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, माप(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, अग्र);
	idtab->nentries++;
	id->कुंजी = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	अगर ((r = sshkey_to_certified(id->कुंजी)) != 0) {
		error_fr(r, "sshkey_to_certified");
		पात();
	}
	अगर ((r = sshkey_cert_copy(cert, id->कुंजी)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		पात();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	अगर (sshkey_is_sk(id->कुंजी))
		id->sk_provider = xstrdup("internal");
}

अटल व्योम
cleanup_idtab(व्योम)
{
	Identity *id;

	अगर (idtab == शून्य) वापस;
	क्रम (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, अग्र);
		free_identity(id);
	}
	मुक्त(idtab);
	idtab = शून्य;
}

अटल व्योम
reset_idtab(व्योम)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_कुंजी(PRIV_RSA, CERT_RSA);
	add_कुंजी(PRIV_ECDSA, CERT_ECDSA);
	add_कुंजी(PRIV_ED25519, CERT_ED25519);
	add_कुंजी(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_कुंजी(PRIV_ED25519_SK, CERT_ED25519_SK);
}

अटल व्योम
cleanup_sockettab(व्योम)
{
	u_int i;
	क्रम (i = 0; i < sockets_alloc; i++) {
		अगर (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	मुक्त(sockets);
	sockets = शून्य;
	sockets_alloc = 0;
}

अटल व्योम
reset_sockettab(पूर्णांक devnull)
{
	पूर्णांक fd;

	cleanup_sockettab();
	अगर ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", म_त्रुटि(त्रुटि_सं));
		पात();
	}
	new_socket(AUTH_CONNECTION, fd);
	निश्चित(sockets[0].type == AUTH_CONNECTION);
	निश्चित(sockets[0].fd == fd);
}

#घोषणा MAX_MESSAGES 256
व्योम
test_one(स्थिर uint8_t* s, माप_प्रकार slen)
{
	अटल पूर्णांक devnull = -1;
	माप_प्रकार i, olen, nlen;

	अगर (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(व्योम)sshbuf_put(sockets[0].निवेश, s, slen);
	क्रम (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].निवेश);
		process_message(0);
		nlen = sshbuf_len(sockets[0].निवेश);
		अगर (nlen == 0 || nlen == olen)
			अवरोध;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
