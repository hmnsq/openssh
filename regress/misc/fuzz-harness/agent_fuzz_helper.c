#అన్తర్భావ "fixed-keys.h"
#అన్తర్భావ <assert.h>

#నిర్వచించు ప్రధాన(ac, av) xxxmain(ac, av)
#అన్తర్భావ "../../../ssh-agent.c"

శూన్య test_one(స్థిరరాశి uint8_t* s, కొలత_t slen);

స్థిర పూర్ణాంకం
devnull_or_die(శూన్య)
{
	పూర్ణాంకం fd;

	ఒకవేళ ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	తిరిగి fd;
}

స్థిర నిర్మాణం sshkey *
pubkey_or_die(స్థిరరాశి అక్షరం *s)
{
	అక్షరం *tmp, *cp;
	నిర్మాణం sshkey *pubkey;
	పూర్ణాంకం r;

	tmp = cp = xstrdup(s);
	ఒకవేళ ((pubkey = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
		abort();
	ఒకవేళ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	విడుదల(tmp);
	తిరిగి pubkey;
}

స్థిర నిర్మాణం sshkey *
privkey_or_die(స్థిరరాశి అక్షరం *s)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *b;
	నిర్మాణం sshkey *privkey;

	ఒకవేళ ((b = sshbuf_from(s, అక్షరశ్రేణి_పొడవు(s))) == ఖాళీ) {
		error_f("sshbuf_from failed");
		abort();
	}
	ఒకవేళ ((r = sshkey_parse_వ్యక్తిగత_fileblob(b, "", &privkey, ఖాళీ)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	తిరిగి privkey;
}

స్థిర శూన్య
కూడు_కీలకం(స్థిరరాశి అక్షరం *privkey, స్థిరరాశి అక్షరం *certpath)
{
	తటస్థం *id;
	పూర్ణాంకం r;
	నిర్మాణం sshkey *cert;

	id = xcalloc(1, పరిమాణం(తటస్థం));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, తదుపరి);
	idtab->nentries++;
	id->కీలకం = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	ఒకవేళ (sshkey_is_sk(id->కీలకం))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, పరిమాణం(తటస్థం));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, తదుపరి);
	idtab->nentries++;
	id->కీలకం = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	ఒకవేళ ((r = sshkey_గమ్యం_certified(id->కీలకం)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	ఒకవేళ ((r = sshkey_cert_copy(cert, id->కీలకం)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	ఒకవేళ (sshkey_is_sk(id->కీలకం))
		id->sk_provider = xstrdup("internal");
}

స్థిర శూన్య
cleanup_idtab(శూన్య)
{
	తటస్థం *id;

	ఒకవేళ (idtab == ఖాళీ) తిరిగి;
	కొరకు (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, తదుపరి);
		free_తటస్థం(id);
	}
	విడుదల(idtab);
	idtab = ఖాళీ;
}

స్థిర శూన్య
reset_idtab(శూన్య)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	కూడు_కీలకం(PRIV_RSA, CERT_RSA);
	కూడు_కీలకం(PRIV_ECDSA, CERT_ECDSA);
	కూడు_కీలకం(PRIV_ED25519, CERT_ED25519);
	కూడు_కీలకం(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	కూడు_కీలకం(PRIV_ED25519_SK, CERT_ED25519_SK);
}

స్థిర శూన్య
cleanup_sockettab(శూన్య)
{
	u_int i;
	కొరకు (i = 0; i < sockets_alloc; i++) {
		ఒకవేళ (sockets[i].type != AUTH_వాడని)
			close_socket(sockets + i);
	}
	విడుదల(sockets);
	sockets = ఖాళీ;
	sockets_alloc = 0;
}

స్థిర శూన్య
reset_sockettab(పూర్ణాంకం devnull)
{
	పూర్ణాంకం fd;

	cleanup_sockettab();
	ఒకవేళ ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	ప్రతిజ్ఞా(sockets[0].type == AUTH_CONNECTION);
	ప్రతిజ్ఞా(sockets[0].fd == fd);
}

#నిర్వచించు MAX_MESSAGES 256
శూన్య
test_one(స్థిరరాశి uint8_t* s, కొలత_t slen)
{
	స్థిర పూర్ణాంకం devnull = -1;
	కొలత_t i, olen, nlen;

	ఒకవేళ (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(శూన్య)sshbuf_put(sockets[0].ఆదానం, s, slen);
	కొరకు (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].ఆదానం);
		process_సందేశం(0);
		nlen = sshbuf_len(sockets[0].ఆదానం);
		ఒకవేళ (nlen == 0 || nlen == olen)
			ఆపు;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
