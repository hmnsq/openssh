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

स्थिर पूर्णाङ्क prepare_साँचो(संरचना shared_state *st, पूर्णाङ्क keytype, पूर्णाङ्क bits);

संरचना shared_state {
	माप_प्रकार nkeys;
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
	अचर वर्ण *cipher;
	अचर वर्ण *mac;
	अचर वर्ण *comp;
};

स्थिर पूर्णाङ्क
do_send_and_receive(संरचना ssh *from, संरचना ssh *to,
    संरचना sshbuf *store, पूर्णाङ्क clobber, माप_प्रकार *n)
{
	u_char type;
	माप_प्रकार len;
	अचर u_char *buf;
	पूर्णाङ्क r;

	लागि (*n = 0;; (*n)++) {
		यदि ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			फर्काऊ r;
		}
		यदि (type != 0)
			फर्काऊ 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		यदि (len == 0)
			फर्काऊ 0;
		यदि ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			फर्काऊ r;
		}
		यदि (store != रिक्त && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			फर्काऊ r;
		}
		यदि (!clobber && (r = ssh_आगत_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			फर्काऊ r;
		}
	}
}

स्थिर पूर्णाङ्क
run_kex(संरचना test_state *ts, संरचना ssh *client, संरचना ssh *server)
{
	पूर्णाङ्क r = 0;
	माप_प्रकार cn, sn;

	/* If fuzzing, replace server/client input */
	यदि (ts->sin != रिक्त) {
		यदि ((r = ssh_आगत_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			फर्काऊ r;
		}
		sshbuf_reset(ts->sin);
	}
	यदि (ts->cin != रिक्त) {
		यदि ((r = ssh_आगत_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			फर्काऊ r;
		}
		sshbuf_reset(ts->cin);
	}
	जबसम्म (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		यदि ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != रिक्त, &sn)) != 0) {
			debug_fr(r, "S->C");
			रोक;
		}
		debug_f("C:");
		यदि ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != रिक्त, &cn)) != 0) {
			debug_fr(r, "C->S");
			रोक;
		}
		यदि (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			रोक;
		}
	}
	debug_fr(r, "done");
	फर्काऊ r;
}

स्थिर शून्य
store_साँचो(संरचना shared_state *st, संरचना sshkey *pubkey,
    संरचना sshkey *privkey)
{
	यदि (st == रिक्त || pubkey->type < 0 || pubkey->type > पूर्णांक_उच्च ||
	    privkey->type != pubkey->type ||
	    ((माप_प्रकार)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != रिक्त))
		पात();
	यदि ((माप_प्रकार)pubkey->type >= st->nkeys) {
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
prepare_साँचोहरू(संरचना shared_state *st)
{
	यदि (prepare_साँचो(st, साँचो_RSA, 2048) != 0 ||
	    prepare_साँचो(st, साँचो_ECDSA, 256) != 0 ||
	    prepare_साँचो(st, साँचो_ED25519, 256) != 0) {
		error_f("key prepare failed");
		फर्काऊ -1;
	}
	फर्काऊ 0;
}

स्थिर संरचना sshkey *
get_pubkey(संरचना shared_state *st, पूर्णाङ्क keytype)
{
	यदि (st == रिक्त || keytype < 0 || (माप_प्रकार)keytype >= st->nkeys ||
	    st->pubkeys == रिक्त || st->pubkeys[keytype] == रिक्त)
		पात();
	फर्काऊ st->pubkeys[keytype];
}

स्थिर संरचना sshkey *
get_privkey(संरचना shared_state *st, पूर्णाङ्क keytype)
{
	यदि (st == रिक्त || keytype < 0 || (माप_प्रकार)keytype >= st->nkeys ||
	    st->privkeys == रिक्त || st->privkeys[keytype] == रिक्त)
		पात();
	फर्काऊ st->privkeys[keytype];
}

स्थिर पूर्णाङ्क
build_proposal_side(वर्ण **out, अचर वर्ण *defaults[PROPOSAL_MAX],
    अचर वर्ण *kex, अचर वर्ण *keyname,
    अचर वर्ण *cipher, अचर वर्ण *mac, अचर वर्ण *comp)
{
	पूर्णाङ्क i;
	लागि (i = 0; i < PROPOSAL_MAX; i++) {
		अचर वर्ण *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		यदि (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		यदि (i == PROPOSAL_SERVER_HOST_साँचो_ALGS)
			ccp = keyname;
		अन्यथा यदि (i == PROPOSAL_KEX_ALGS && kex != रिक्त)
			ccp = kex;
		अन्यथा यदि ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != रिक्त)
			ccp = cipher;
		अन्यथा यदि ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != रिक्त)
			ccp = mac;
		अन्यथा यदि ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != रिक्त)
			ccp = comp;
		यदि ((out[i] = strdup(ccp)) == रिक्त)
			फर्काऊ -1;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
do_kex_with_साँचो(संरचना shared_state *st, संरचना test_state *ts,
    अचर वर्ण *kex, पूर्णाङ्क keytype, अचर संरचना kex_overrides *ov)
{
	संरचना ssh *client = रिक्त, *server = रिक्त;
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	संरचना sshbuf *state = रिक्त;
	संरचना kex_params kex_params;
	अचर वर्ण *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	वर्ण *myproposal[PROPOSAL_MAX] = {0};
	वर्ण *keyname = रिक्त;
	पूर्णाङ्क i, r;

	ts->cin = ts->sin = रिक्त;
	यदि (ts->c_template != रिक्त &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == रिक्त)
		पात();
	यदि (ts->s_template != रिक्त &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == रिक्त)
		पात();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	यदि (ts->cin != रिक्त) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} अन्यथा यदि (ts->sin != रिक्त) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} अन्यथा
		debug_f("%s %s noclobber", kex, keyname);

	यदि (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : रिक्त,
	    ov ? ov->mac : रिक्त,
	    ov ? ov->comp : रिक्त) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ fail;
	}
	स_नकल(kex_params.proposal, myproposal, परिमाण(myproposal));
	यदि ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		गच्छ fail;
	}
	यदि ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		गच्छ fail;
	}
	यदि ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		गच्छ fail;
	}
	यदि ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		गच्छ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	लागि (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	मुक्त(keyname);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
prepare_साँचो(संरचना shared_state *st, पूर्णाङ्क kt, पूर्णाङ्क bits)
{
	अचर वर्ण *pubstr = रिक्त;
	अचर वर्ण *privstr = रिक्त;
	वर्ण *tmp, *cp;
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r;

	विकल्प (kt) {
	पक्ष साँचो_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		रोक;
	पक्ष साँचो_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		रोक;
	पक्ष साँचो_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		रोक;
	स्वभाव:
		पात();
	}
	यदि ((b = sshbuf_from(privstr, म_माप(privstr))) == रिक्त)
		पात();
	यदि ((r = sshkey_parse_private_fileblob(b, "", &privkey, रिक्त)) != 0) {
		error_fr(r, "priv %d", kt);
		पात();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	यदि ((pubkey = sshkey_new(साँचो_UNSPEC)) == रिक्त)
		पात();
	यदि ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		पात();
	}
	मुक्त(tmp);

	store_साँचो(st, pubkey, privkey);
	फर्काऊ 0;
}

#यदि defined(STANDALONE)

#यदि 0 /* use this if generating new keys to embed above */
स्थिर पूर्णाङ्क
prepare_साँचो(संरचना shared_state *st, पूर्णाङ्क keytype, पूर्णाङ्क bits)
{
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	पूर्णाङ्क r;

	यदि ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		पात();
	}
	यदि ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		पात();
	}
	store_साँचो(st, pubkey, privkey);
	फर्काऊ 0;
}
#endif

पूर्णाङ्क main(शून्य)
{
	स्थिर संरचना shared_state *st;
	संरचना test_state *ts;
	अचर पूर्णाङ्क keytypes[] = { साँचो_RSA, साँचो_ECDSA, साँचो_ED25519, -1 };
	स्थिर अचर वर्ण * अचर kextypes[] = {
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
	खाता *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	यदि (st == रिक्त) {
		st = (संरचना shared_state *)xcalloc(1, परिमाण(*st));
		prepare_साँचोहरू(st);
	}
	/* Run each kex method for each key and save client/server packets */
	लागि (i = 0; keytypes[i] != -1; i++) {
		लागि (j = 0; kextypes[j] != रिक्त; j++) {
			ts = (संरचना test_state *)xcalloc(1, परिमाण(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_साँचो(st, ts, kextypes[j], keytypes[i], रिक्त);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			यदि ((f = ख_खोलो(path, "wb+")) == रिक्त)
				पात();
			यदि (ख_डालो(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				पात();
			ख_बंद(f);
			मुक्त(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			यदि ((f = ख_खोलो(path, "wb+")) == रिक्त)
				पात();
			यदि (ख_डालो(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				पात();
			ख_बंद(f);
			मुक्त(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			मुक्त(ts);
		}
	}
	लागि (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		यदि (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, रिक्त, 0) != 0)
			पात();
		मुक्त(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		यदि (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			पात();
		मुक्त(path);
	}
}
#अन्यथा /* !STANDALONE */
स्थिर शून्य
do_kex(संरचना shared_state *st, संरचना test_state *ts, अचर वर्ण *kex)
{
	do_kex_with_साँचो(st, ts, kex, साँचो_RSA, रिक्त);
	do_kex_with_साँचो(st, ts, kex, साँचो_ECDSA, रिक्त);
	do_kex_with_साँचो(st, ts, kex, साँचो_ED25519, रिक्त);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
स्थिर शून्य
kex_extras(संरचना shared_state *st, संरचना test_state *ts)
{
	स्थिर अचर वर्ण * अचर ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		रिक्त,
	};
	स्थिर अचर वर्ण * अचर macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		रिक्त,
	};
	स्थिर अचर वर्ण * अचर comps[] = {
		"zlib@openssh.com",
		"zlib",
		रिक्त,
	};
	अचर वर्ण *kex = "curve25519-sha256@libssh.org";
	पूर्णाङ्क i;

	लागि (i = 0; ciphers[i] != रिक्त; i++) {
		संरचना kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_साँचो(st, ts, kex, साँचो_ED25519, &ov);
	}
	लागि (i = 0; macs[i] != रिक्त; i++) {
		संरचना kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_साँचो(st, ts, kex, साँचो_ED25519, &ov);
	}
	लागि (i = 0; comps[i] != रिक्त; i++) {
		संरचना kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_साँचो(st, ts, kex, साँचो_ED25519, &ov);
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

पूर्णाङ्क LLVMFuzzer_Test_One_आगत(अचर uint8_t* data, माप_प्रकार size)
{
	स्थिर संरचना shared_state *st;
	संरचना test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_पङ्क्तिहरू * 4];
	u_char zbuf[4096] = {0};
	स्थिर LogLevel loglevel = SYSLOG_LEVEL_INFO;

	यदि (st == रिक्त) {
		यदि (दो_पर्या("DEBUG") != रिक्त || दो_पर्या("KEX_FUZZ_DEBUG") != रिक्त)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (संरचना shared_state *)xcalloc(1, परिमाण(*st));
		prepare_साँचोहरू(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	स_रखो(crbuf, '\n', परिमाण(crbuf));

	ts = (संरचना test_state *)xcalloc(1, परिमाण(*ts));
	यदि ((ts->s_template = sshbuf_new()) == रिक्त ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, परिमाण(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, परिमाण(zbuf)) != 0)
		पात();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	मुक्त(ts);

	ts = (संरचना test_state *)xcalloc(1, परिमाण(*ts));
	यदि ((ts->c_template = sshbuf_new()) == रिक्त ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, परिमाण(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, परिमाण(zbuf)) != 0)
		पात();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	मुक्त(ts);

	फर्काऊ 0;
}
#endif /* STANDALONE */
} /* extern "C" */
