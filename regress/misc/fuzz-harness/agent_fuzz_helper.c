#অন্তর্ভাব "fixed-keys.h"
#অন্তর্ভাব <assert.h>

#define প্রধান(ac, av) xxxmain(ac, av)
#অন্তর্ভাব "../../../ssh-agent.c"

শূন্য test_one(ধ্রুবক uint8_t* s, আকার_t slen);

স্থির পূর্ণসংখ্যা
devnull_or_die(শূন্য)
{
	পূর্ণসংখ্যা fd;

	যদি ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	ফেরত fd;
}

স্থির কাঠামো sshkey *
pubkey_or_die(ধ্রুবক অক্ষর *s)
{
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *pubkey;
	পূর্ণসংখ্যা r;

	tmp = cp = xstrdup(s);
	যদি ((pubkey = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
		abort();
	যদি ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	মুক্ত(tmp);
	ফেরত pubkey;
}

স্থির কাঠামো sshkey *
privkey_or_die(ধ্রুবক অক্ষর *s)
{
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *b;
	কাঠামো sshkey *privkey;

	যদি ((b = sshbuf_from(s, strlen(s))) == ফাঁকা) {
		error_f("sshbuf_from failed");
		abort();
	}
	যদি ((r = sshkey_parse_private_fileblob(b, "", &privkey, ফাঁকা)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	ফেরত privkey;
}

স্থির শূন্য
add_চাবি(ধ্রুবক অক্ষর *privkey, ধ্রুবক অক্ষর *certpath)
{
	Identity *id;
	পূর্ণসংখ্যা r;
	কাঠামো sshkey *cert;

	id = xcalloc(1, আকার(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, পরবর্তী);
	idtab->nentries++;
	id->চাবি = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	যদি (sshkey_is_sk(id->চাবি))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, আকার(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, পরবর্তী);
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

	যদি (idtab == ফাঁকা) ফেরত;
	জন্য (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, পরবর্তী);
		free_identity(id);
	}
	মুক্ত(idtab);
	idtab = ফাঁকা;
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
	জন্য (i = 0; i < sockets_alloc; i++) {
		যদি (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	মুক্ত(sockets);
	sockets = ফাঁকা;
	sockets_alloc = 0;
}

স্থির শূন্য
reset_sockettab(পূর্ণসংখ্যা devnull)
{
	পূর্ণসংখ্যা fd;

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
test_one(ধ্রুবক uint8_t* s, আকার_t slen)
{
	স্থির পূর্ণসংখ্যা devnull = -1;
	আকার_t i, olen, nlen;

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
	জন্য (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].প্রবেশ);
		process_message(0);
		nlen = sshbuf_len(sockets[0].প্রবেশ);
		যদি (nlen == 0 || nlen == olen)
			বিরতি;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
