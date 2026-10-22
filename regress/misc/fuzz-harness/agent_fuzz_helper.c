#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"
#ଅନ୍ତର୍ଭାଵ <assert.h>

#define ମୁଖ୍ୟ(ac, av) xxxmain(ac, av)
#ଅନ୍ତର୍ଭାଵ "../../../ssh-agent.c"

ଶୂନ୍ୟ test_one(ଅଚଳ uint8_t* s, size_t slen);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
devnull_or_die(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	ଯଦି ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	ଫେରନ୍ତୁ fd;
}

ସ୍ଥିର ସଂରଚନା sshkey *
pubkey_or_die(ଅଚଳ ଅକ୍ଷର *s)
{
	ଅକ୍ଷର *tmp, *cp;
	ସଂରଚନା sshkey *pubkey;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	tmp = cp = xstrdup(s);
	ଯଦି ((pubkey = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
		abort();
	ଯଦି ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ pubkey;
}

ସ୍ଥିର ସଂରଚନା sshkey *
privkey_or_die(ଅଚଳ ଅକ୍ଷର *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *b;
	ସଂରଚନା sshkey *privkey;

	ଯଦି ((b = sshbuf_from(s, strlen(s))) == ଖାଲି) {
		error_f("sshbuf_from failed");
		abort();
	}
	ଯଦି ((r = sshkey_parse_private_fileblob(b, "", &privkey, ଖାଲି)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	ଫେରନ୍ତୁ privkey;
}

ସ୍ଥିର ଶୂନ୍ୟ
add_ଚାବି(ଅଚଳ ଅକ୍ଷର *privkey, ଅଚଳ ଅକ୍ଷର *certpath)
{
	Identity *id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshkey *cert;

	id = xcalloc(1, ଆକାର(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->ଚାବି = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	ଯଦି (sshkey_is_sk(id->ଚାବି))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, ଆକାର(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->ଚାବି = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	ଯଦି ((r = sshkey_to_certified(id->ଚାବି)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	ଯଦି ((r = sshkey_cert_copy(cert, id->ଚାବି)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	ଯଦି (sshkey_is_sk(id->ଚାବି))
		id->sk_provider = xstrdup("internal");
}

ସ୍ଥିର ଶୂନ୍ୟ
cleanup_idtab(ଶୂନ୍ୟ)
{
	Identity *id;

	ଯଦି (idtab == ଖାଲି) ଫେରନ୍ତୁ;
	ପାଇଁ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	ମୁକ୍ତ(idtab);
	idtab = ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
reset_idtab(ଶୂନ୍ୟ)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_ଚାବି(PRIV_RSA, CERT_RSA);
	add_ଚାବି(PRIV_ECDSA, CERT_ECDSA);
	add_ଚାବି(PRIV_ED25519, CERT_ED25519);
	add_ଚାବି(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_ଚାବି(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ସ୍ଥିର ଶୂନ୍ୟ
cleanup_sockettab(ଶୂନ୍ୟ)
{
	u_int i;
	ପାଇଁ (i = 0; i < sockets_alloc; i++) {
		ଯଦି (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	ମୁକ୍ତ(sockets);
	sockets = ଖାଲି;
	sockets_alloc = 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
reset_sockettab(ପୂର୍ଣ୍ଣସଂଖ୍ୟା devnull)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	cleanup_sockettab();
	ଯଦି ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	ପ୍ରତିଜ୍ଞା(sockets[0].type == AUTH_CONNECTION);
	ପ୍ରତିଜ୍ଞା(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
ଶୂନ୍ୟ
test_one(ଅଚଳ uint8_t* s, size_t slen)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା devnull = -1;
	size_t i, olen, nlen;

	ଯଦି (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(ଶୂନ୍ୟ)sshbuf_put(sockets[0].ନିବେଶ, s, slen);
	ପାଇଁ (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].ନିବେଶ);
		process_message(0);
		nlen = sshbuf_len(sockets[0].ନିବେଶ);
		ଯଦି (nlen == 0 || nlen == olen)
			ଭାଙ୍ଗ;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
