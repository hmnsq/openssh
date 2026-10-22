// libfuzzer driver for key exchange fuzzing.


#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य "C" {

#अन्तर्भाव "includes.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "log.h"

#अन्तर्भाव "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

स्थिर पूर्णाङ्क prepare_कुञ्चिका(संरचना shared_state *st, पूर्णाङ्क keytype, पूर्णाङ्क bits);

संरचना shared_state {
	size_t nkeys;
	संरचना sshkey **privkeys, **pubkeys;
};

संरचना test_state {
	संरचना sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	संरचना sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	संरचना sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
संरचना kex_overrides {
	ध्रुव वर्ण *cipher;
	ध्रुव वर्ण *mac;
	ध्रुव वर्ण *comp;
};

स्थिर पूर्णाङ्क
do_send_and_receive(संरचना ssh *from, संरचना ssh *to,
    संरचना sshbuf *store, पूर्णाङ्क clobber, size_t *n)
{
	u_char type;
	size_t len;
	ध्रुव u_char *buf;
	पूर्णाङ्क r;

	अत्थाय (*n = 0;; (*n)++) {
		सचे ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			पटिनिवत्त r;
		}
		सचे (type != 0)
			पटिनिवत्त 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		सचे (len == 0)
			पटिनिवत्त 0;
		सचे ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			पटिनिवत्त r;
		}
		सचे (store != रिक्त && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			पटिनिवत्त r;
		}
		सचे (!clobber && (r = ssh_निवेशः_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			पटिनिवत्त r;
		}
	}
}

स्थिर पूर्णाङ्क
run_kex(संरचना test_state *ts, संरचना ssh *client, संरचना ssh *server)
{
	पूर्णाङ्क r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	सचे (ts->sin != रिक्त) {
		सचे ((r = ssh_निवेशः_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			पटिनिवत्त r;
		}
		sshbuf_reset(ts->sin);
	}
	सचे (ts->cin != रिक्त) {
		सचे ((r = ssh_निवेशः_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			पटिनिवत्त r;
		}
		sshbuf_reset(ts->cin);
	}
	याव (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		सचे ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != रिक्त, &sn)) != 0) {
			debug_fr(r, "S->C");
			भङ्ग;
		}
		debug_f("C:");
		सचे ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != रिक्त, &cn)) != 0) {
			debug_fr(r, "C->S");
			भङ्ग;
		}
		सचे (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			भङ्ग;
		}
	}
	debug_fr(r, "done");
	पटिनिवत्त r;
}

स्थिर शून्य
store_कुञ्चिका(संरचना shared_state *st, संरचना sshkey *pubkey,
    संरचना sshkey *privkey)
{
	सचे (st == रिक्त || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != रिक्त))
		abort();
	सचे ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (संरचना sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, परिमाण(*st->pubkeys));
		st->privkeys = (संरचना sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, परिमाण(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

स्थिर पूर्णाङ्क
prepare_कुञ्चिकाः(संरचना shared_state *st)
{
	सचे (prepare_कुञ्चिका(st, कुञ्चिका_RSA, 2048) != 0 ||
	    prepare_कुञ्चिका(st, कुञ्चिका_ECDSA, 256) != 0 ||
	    prepare_कुञ्चिका(st, कुञ्चिका_ED25519, 256) != 0) {
		error_f("key prepare failed");
		पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
}

स्थिर संरचना sshkey *
get_pubkey(संरचना shared_state *st, पूर्णाङ्क keytype)
{
	सचे (st == रिक्त || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == रिक्त || st->pubkeys[keytype] == रिक्त)
		abort();
	पटिनिवत्त st->pubkeys[keytype];
}

स्थिर संरचना sshkey *
get_privkey(संरचना shared_state *st, पूर्णाङ्क keytype)
{
	सचे (st == रिक्त || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == रिक्त || st->privkeys[keytype] == रिक्त)
		abort();
	पटिनिवत्त st->privkeys[keytype];
}

स्थिर पूर्णाङ्क
build_proposal_side(वर्ण **out, ध्रुव वर्ण *defaults[PROPOSAL_MAX],
    ध्रुव वर्ण *kex, ध्रुव वर्ण *keyname,
    ध्रुव वर्ण *cipher, ध्रुव वर्ण *mac, ध्रुव वर्ण *comp)
{
	पूर्णाङ्क i;
	अत्थाय (i = 0; i < PROPOSAL_MAX; i++) {
		ध्रुव वर्ण *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		सचे (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		सचे (i == PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS)
			ccp = keyname;
		अञ्ञथा सचे (i == PROPOSAL_KEX_ALGS && kex != रिक्त)
			ccp = kex;
		अञ्ञथा सचे ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != रिक्त)
			ccp = cipher;
		अञ्ञथा सचे ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != रिक्त)
			ccp = mac;
		अञ्ञथा सचे ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != रिक्त)
			ccp = comp;
		सचे ((out[i] = strdup(ccp)) == रिक्त)
			पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
do_kex_with_कुञ्चिका(संरचना shared_state *st, संरचना test_state *ts,
    ध्रुव वर्ण *kex, पूर्णाङ्क keytype, ध्रुव संरचना kex_overrides *ov)
{
	संरचना ssh *client = रिक्त, *server = रिक्त;
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	संरचना sshbuf *state = रिक्त;
	संरचना kex_params kex_params;
	ध्रुव वर्ण *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	वर्ण *myproposal[PROPOSAL_MAX] = {0};
	वर्ण *keyname = रिक्त;
	पूर्णाङ्क i, r;

	ts->cin = ts->sin = रिक्त;
	सचे (ts->c_template != रिक्त &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == रिक्त)
		abort();
	सचे (ts->s_template != रिक्त &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == रिक्त)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	सचे (ts->cin != रिक्त) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} अञ्ञथा सचे (ts->sin != रिक्त) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} अञ्ञथा
		debug_f("%s %s noclobber", kex, keyname);

	सचे (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : रिक्त,
	    ov ? ov->mac : रिक्त,
	    ov ? ov->comp : रिक्त) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ fail;
	}
	memcpy(kex_params.proposal, myproposal, परिमाण(myproposal));
	सचे ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		गच्छ fail;
	}
	सचे ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		गच्छ fail;
	}
	सचे ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		गच्छ fail;
	}
	सचे ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		गच्छ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	अत्थाय (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	मुक्त(keyname);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
prepare_कुञ्चिका(संरचना shared_state *st, पूर्णाङ्क kt, पूर्णाङ्क bits)
{
	ध्रुव वर्ण *pubstr = रिक्त;
	ध्रुव वर्ण *privstr = रिक्त;
	वर्ण *tmp, *cp;
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r;

	विकल्प (kt) {
	पक्ष कुञ्चिका_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		भङ्ग;
	पक्ष कुञ्चिका_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		भङ्ग;
	पक्ष कुञ्चिका_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		भङ्ग;
	स्वभाव:
		abort();
	}
	सचे ((b = sshbuf_from(privstr, strlen(privstr))) == रिक्त)
		abort();
	सचे ((r = sshkey_parse_private_fileblob(b, "", &privkey, रिक्त)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	सचे ((pubkey = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
		abort();
	सचे ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	मुक्त(tmp);

	store_कुञ्चिका(st, pubkey, privkey);
	पटिनिवत्त 0;
}

#सचे defined(STANDALONE)

#सचे 0 /* use this if generating new keys to embed above */
स्थिर पूर्णाङ्क
prepare_कुञ्चिका(संरचना shared_state *st, पूर्णाङ्क keytype, पूर्णाङ्क bits)
{
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	पूर्णाङ्क r;

	सचे ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	सचे ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_कुञ्चिका(st, pubkey, privkey);
	पटिनिवत्त 0;
}
#endif

पूर्णाङ्क main(शून्य)
{
	स्थिर संरचना shared_state *st;
	संरचना test_state *ts;
	ध्रुव पूर्णाङ्क keytypes[] = { कुञ्चिका_RSA, कुञ्चिका_ECDSA, कुञ्चिका_ED25519, -1 };
	स्थिर ध्रुव वर्ण * ध्रुव kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		रिक्त,
	};
	पूर्णाङ्क i, j;
	वर्ण *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	सचे (st == रिक्त) {
		st = (संरचना shared_state *)xcalloc(1, परिमाण(*st));
		prepare_कुञ्चिकाः(st);
	}
	/* Run each kex method for each key and save client/server packets */
	अत्थाय (i = 0; keytypes[i] != -1; i++) {
		अत्थाय (j = 0; kextypes[j] != रिक्त; j++) {
			ts = (संरचना test_state *)xcalloc(1, परिमाण(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_कुञ्चिका(st, ts, kextypes[j], keytypes[i], रिक्त);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			सचे ((f = fopen(path, "wb+")) == रिक्त)
				abort();
			सचे (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			मुक्त(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			सचे ((f = fopen(path, "wb+")) == रिक्त)
				abort();
			सचे (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			मुक्त(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			मुक्त(ts);
		}
	}
	अत्थाय (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		सचे (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, रिक्त, 0) != 0)
			abort();
		मुक्त(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		सचे (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		मुक्त(path);
	}
}
#अञ्ञथा /* !STANDALONE */
स्थिर शून्य
do_kex(संरचना shared_state *st, संरचना test_state *ts, ध्रुव वर्ण *kex)
{
	do_kex_with_कुञ्चिका(st, ts, kex, कुञ्चिका_RSA, रिक्त);
	do_kex_with_कुञ्चिका(st, ts, kex, कुञ्चिका_ECDSA, रिक्त);
	do_kex_with_कुञ्चिका(st, ts, kex, कुञ्चिका_ED25519, रिक्त);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
स्थिर शून्य
kex_extras(संरचना shared_state *st, संरचना test_state *ts)
{
	स्थिर ध्रुव वर्ण * ध्रुव ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		रिक्त,
	};
	स्थिर ध्रुव वर्ण * ध्रुव macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		रिक्त,
	};
	स्थिर ध्रुव वर्ण * ध्रुव comps[] = {
		"zlib@openssh.com",
		"zlib",
		रिक्त,
	};
	ध्रुव वर्ण *kex = "curve25519-sha256@libssh.org";
	पूर्णाङ्क i;

	अत्थाय (i = 0; ciphers[i] != रिक्त; i++) {
		संरचना kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_कुञ्चिका(st, ts, kex, कुञ्चिका_ED25519, &ov);
	}
	अत्थाय (i = 0; macs[i] != रिक्त; i++) {
		संरचना kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_कुञ्चिका(st, ts, kex, कुञ्चिका_ED25519, &ov);
	}
	अत्थाय (i = 0; comps[i] != रिक्त; i++) {
		संरचना kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_कुञ्चिका(st, ts, kex, कुञ्चिका_ED25519, &ov);
	}
}

स्थिर शून्य
kex_tests(संरचना shared_state *st, संरचना test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

पूर्णाङ्क LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t* data, size_t size)
{
	स्थिर संरचना shared_state *st;
	संरचना test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_पङ्क्तयः * 4];
	u_char zbuf[4096] = {0};
	स्थिर LogLevel loglevel = SYSLOG_LEVEL_INFO;

	सचे (st == रिक्त) {
		सचे (getenv("DEBUG") != रिक्त || getenv("KEX_FUZZ_DEBUG") != रिक्त)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (संरचना shared_state *)xcalloc(1, परिमाण(*st));
		prepare_कुञ्चिकाः(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', परिमाण(crbuf));

	ts = (संरचना test_state *)xcalloc(1, परिमाण(*ts));
	सचे ((ts->s_template = sshbuf_new()) == रिक्त ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, परिमाण(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, परिमाण(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	मुक्त(ts);

	ts = (संरचना test_state *)xcalloc(1, परिमाण(*ts));
	सचे ((ts->c_template = sshbuf_new()) == रिक्त ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, परिमाण(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, परिमाण(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	मुक्त(ts);

	पटिनिवत्त 0;
}
#endif /* STANDALONE */
} /* extern "C" */
