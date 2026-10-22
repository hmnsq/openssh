#અન્તર્ભાવ "fixed-keys.h"
#અન્તર્ભાવ <assert.h>

#define મુખ્ય(ac, av) xxxmain(ac, av)
#અન્તર્ભાવ "../../../ssh-agent.c"

શૂન્ય test_one(અચલ uint8_t* s, size_t slen);

સ્થિર પૂર્ણાંક
devnull_or_die(શૂન્ય)
{
	પૂર્ણાંક fd;

	જો ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	પાછા fd;
}

સ્થિર સંરચના sshkey *
pubkey_or_die(અચલ અક્ષર *s)
{
	અક્ષર *tmp, *cp;
	સંરચના sshkey *pubkey;
	પૂર્ણાંક r;

	tmp = cp = xstrdup(s);
	જો ((pubkey = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
		abort();
	જો ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	મુક્ત(tmp);
	પાછા pubkey;
}

સ્થિર સંરચના sshkey *
privkey_or_die(અચલ અક્ષર *s)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *b;
	સંરચના sshkey *privkey;

	જો ((b = sshbuf_from(s, strlen(s))) == ખાલી) {
		error_f("sshbuf_from failed");
		abort();
	}
	જો ((r = sshkey_parse_private_fileblob(b, "", &privkey, ખાલી)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	પાછા privkey;
}

સ્થિર શૂન્ય
add_ચાવી(અચલ અક્ષર *privkey, અચલ અક્ષર *certpath)
{
	Identity *id;
	પૂર્ણાંક r;
	સંરચના sshkey *cert;

	id = xcalloc(1, કદ(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->ચાવી = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	જો (sshkey_is_sk(id->ચાવી))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, કદ(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->ચાવી = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	જો ((r = sshkey_to_certified(id->ચાવી)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	જો ((r = sshkey_cert_copy(cert, id->ચાવી)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	જો (sshkey_is_sk(id->ચાવી))
		id->sk_provider = xstrdup("internal");
}

સ્થિર શૂન્ય
cleanup_idtab(શૂન્ય)
{
	Identity *id;

	જો (idtab == ખાલી) પાછા;
	માટે (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	મુક્ત(idtab);
	idtab = ખાલી;
}

સ્થિર શૂન્ય
reset_idtab(શૂન્ય)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_ચાવી(PRIV_RSA, CERT_RSA);
	add_ચાવી(PRIV_ECDSA, CERT_ECDSA);
	add_ચાવી(PRIV_ED25519, CERT_ED25519);
	add_ચાવી(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_ચાવી(PRIV_ED25519_SK, CERT_ED25519_SK);
}

સ્થિર શૂન્ય
cleanup_sockettab(શૂન્ય)
{
	u_int i;
	માટે (i = 0; i < sockets_alloc; i++) {
		જો (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	મુક્ત(sockets);
	sockets = ખાલી;
	sockets_alloc = 0;
}

સ્થિર શૂન્ય
reset_sockettab(પૂર્ણાંક devnull)
{
	પૂર્ણાંક fd;

	cleanup_sockettab();
	જો ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	પ્રતિજ્ઞા(sockets[0].type == AUTH_CONNECTION);
	પ્રતિજ્ઞા(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
શૂન્ય
test_one(અચલ uint8_t* s, size_t slen)
{
	સ્થિર પૂર્ણાંક devnull = -1;
	size_t i, olen, nlen;

	જો (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(શૂન્ય)sshbuf_put(sockets[0].આગત, s, slen);
	માટે (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].આગત);
		process_message(0);
		nlen = sshbuf_len(sockets[0].આગત);
		જો (nlen == 0 || nlen == olen)
			તોડો;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
