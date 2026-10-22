#অন্তর্ভাব "fixed-keys.h"
#অন্তর্ভাব <assert.h>

#define main(ac, av) xxxmain(ac, av)
#অন্তর্ভাব "../../../ssh-agent.c"

শূন্য test_one(ধ্রুব uint8_t* s, size_t slen);

স্থির পূর্ণাঙ্ক
devnull_or_die(শূন্য)
{
	পূর্ণাঙ্ক fd;

	যদি ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	প্রত্যাগম fd;
}

স্থির সংরচনা sshkey *
pubkey_or_die(ধ্রুব বর্ণ *s)
{
	বর্ণ *tmp, *cp;
	সংরচনা sshkey *pubkey;
	পূর্ণাঙ্ক r;

	tmp = cp = xstrdup(s);
	যদি ((pubkey = sshkey_new(চাবি_UNSPEC)) == রিক্ত)
		abort();
	যদি ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	মুক্ত(tmp);
	প্রত্যাগম pubkey;
}

স্থির সংরচনা sshkey *
privkey_or_die(ধ্রুব বর্ণ *s)
{
	পূর্ণাঙ্ক r;
	সংরচনা sshbuf *b;
	সংরচনা sshkey *privkey;

	যদি ((b = sshbuf_from(s, strlen(s))) == রিক্ত) {
		error_f("sshbuf_from failed");
		abort();
	}
	যদি ((r = sshkey_parse_private_fileblob(b, "", &privkey, রিক্ত)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	প্রত্যাগম privkey;
}

স্থির শূন্য
add_চাবি(ধ্রুব বর্ণ *privkey, ধ্রুব বর্ণ *certpath)
{
	Identity *id;
	পূর্ণাঙ্ক r;
	সংরচনা sshkey *cert;

	id = xcalloc(1, পরিমাণ(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->চাবি = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	যদি (sshkey_is_sk(id->চাবি))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, পরিমাণ(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->চাবি = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	যদি ((r = sshkey_to_certified(id->চাবি)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	যদি ((r = sshkey_cert_copy(cert, id->চাবি)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	যদি (sshkey_is_sk(id->চাবি))
		id->sk_provider = xstrdup("internal");
}

স্থির শূন্য
cleanup_idtab(শূন্য)
{
	Identity *id;

	যদি (idtab == রিক্ত) প্রত্যাগম;
	প্রতি (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	মুক্ত(idtab);
	idtab = রিক্ত;
}

স্থির শূন্য
reset_idtab(শূন্য)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_চাবি(PRIV_RSA, CERT_RSA);
	add_চাবি(PRIV_ECDSA, CERT_ECDSA);
	add_চাবি(PRIV_ED25519, CERT_ED25519);
	add_চাবি(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_চাবি(PRIV_ED25519_SK, CERT_ED25519_SK);
}

স্থির শূন্য
cleanup_sockettab(শূন্য)
{
	u_int i;
	প্রতি (i = 0; i < sockets_alloc; i++) {
		যদি (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	মুক্ত(sockets);
	sockets = রিক্ত;
	sockets_alloc = 0;
}

স্থির শূন্য
reset_sockettab(পূর্ণাঙ্ক devnull)
{
	পূর্ণাঙ্ক fd;

	cleanup_sockettab();
	যদি ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	প্রতিজ্ঞা(sockets[0].type == AUTH_CONNECTION);
	প্রতিজ্ঞা(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
শূন্য
test_one(ধ্রুব uint8_t* s, size_t slen)
{
	স্থির পূর্ণাঙ্ক devnull = -1;
	size_t i, olen, nlen;

	যদি (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(শূন্য)sshbuf_put(sockets[0].প্রবেশ, s, slen);
	প্রতি (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].প্রবেশ);
		process_message(0);
		nlen = sshbuf_len(sockets[0].প্রবেশ);
		যদি (nlen == 0 || nlen == olen)
			ভঙ্গ;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
