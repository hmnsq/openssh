// libfuzzer driver for key exchange fuzzing.


#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

बाह्य "C" {

#समावेश "includes.h"
#समावेश "ssherr.h"
#समावेश "ssh_api.h"
#समावेश "sshbuf.h"
#समावेश "packet.h"
#समावेश "myproposal.h"
#समावेश "xmalloc.h"
#समावेश "authfile.h"
#समावेश "log.h"

#समावेश "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

अटल पूर्णांक prepare_कुंजी(काष्ठा shared_state *st, पूर्णांक keytype, पूर्णांक bits);

काष्ठा shared_state {
	माप_प्रकार nkeys;
	काष्ठा sshkey **privkeys, **pubkeys;
};

काष्ठा test_state {
	काष्ठा sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	काष्ठा sshbuf *sin, *अ_अंदर; /* input; setup per-test in do_kex_with_key */
	काष्ठा sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
काष्ठा kex_overrides {
	स्थिर अक्षर *cipher;
	स्थिर अक्षर *mac;
	स्थिर अक्षर *comp;
};

अटल पूर्णांक
do_send_and_receive(काष्ठा ssh *from, काष्ठा ssh *to,
    काष्ठा sshbuf *store, पूर्णांक clobber, माप_प्रकार *n)
{
	u_char type;
	माप_प्रकार len;
	स्थिर u_char *buf;
	पूर्णांक r;

	क्रम (*n = 0;; (*n)++) {
		अगर ((r = ssh_packet_अग्र(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			वापस r;
		}
		अगर (type != 0)
			वापस 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		अगर (len == 0)
			वापस 0;
		अगर ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			वापस r;
		}
		अगर (store != शून्य && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			वापस r;
		}
		अगर (!clobber && (r = ssh_निवेश_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			वापस r;
		}
	}
}

अटल पूर्णांक
run_kex(काष्ठा test_state *ts, काष्ठा ssh *client, काष्ठा ssh *server)
{
	पूर्णांक r = 0;
	माप_प्रकार cn, sn;

	/* If fuzzing, replace server/client input */
	अगर (ts->sin != शून्य) {
		अगर ((r = ssh_निवेश_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			वापस r;
		}
		sshbuf_reset(ts->sin);
	}
	अगर (ts->अ_अंदर != शून्य) {
		अगर ((r = ssh_निवेश_append(client, sshbuf_ptr(ts->अ_अंदर),
		    sshbuf_len(ts->अ_अंदर))) != 0) {
			error_fr(r, "ssh_input_append");
			वापस r;
		}
		sshbuf_reset(ts->अ_अंदर);
	}
	जबतक (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		अगर ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->अ_अंदर != शून्य, &sn)) != 0) {
			debug_fr(r, "S->C");
			अवरोध;
		}
		debug_f("C:");
		अगर ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != शून्य, &cn)) != 0) {
			debug_fr(r, "C->S");
			अवरोध;
		}
		अगर (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			अवरोध;
		}
	}
	debug_fr(r, "done");
	वापस r;
}

अटल व्योम
store_कुंजी(काष्ठा shared_state *st, काष्ठा sshkey *pubkey,
    काष्ठा sshkey *privkey)
{
	अगर (st == शून्य || pubkey->type < 0 || pubkey->type > पूर्णांक_उच्च ||
	    privkey->type != pubkey->type ||
	    ((माप_प्रकार)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != शून्य))
		पात();
	अगर ((माप_प्रकार)pubkey->type >= st->nkeys) {
		st->pubkeys = (काष्ठा sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, माप(*st->pubkeys));
		st->privkeys = (काष्ठा sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, माप(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

अटल पूर्णांक
prepare_कुंजियाँ(काष्ठा shared_state *st)
{
	अगर (prepare_कुंजी(st, कुंजी_RSA, 2048) != 0 ||
	    prepare_कुंजी(st, कुंजी_ECDSA, 256) != 0 ||
	    prepare_कुंजी(st, कुंजी_ED25519, 256) != 0) {
		error_f("key prepare failed");
		वापस -1;
	}
	वापस 0;
}

अटल काष्ठा sshkey *
get_pubkey(काष्ठा shared_state *st, पूर्णांक keytype)
{
	अगर (st == शून्य || keytype < 0 || (माप_प्रकार)keytype >= st->nkeys ||
	    st->pubkeys == शून्य || st->pubkeys[keytype] == शून्य)
		पात();
	वापस st->pubkeys[keytype];
}

अटल काष्ठा sshkey *
get_privkey(काष्ठा shared_state *st, पूर्णांक keytype)
{
	अगर (st == शून्य || keytype < 0 || (माप_प्रकार)keytype >= st->nkeys ||
	    st->privkeys == शून्य || st->privkeys[keytype] == शून्य)
		पात();
	वापस st->privkeys[keytype];
}

अटल पूर्णांक
build_proposal_side(अक्षर **out, स्थिर अक्षर *defaults[PROPOSAL_MAX],
    स्थिर अक्षर *kex, स्थिर अक्षर *keyname,
    स्थिर अक्षर *cipher, स्थिर अक्षर *mac, स्थिर अक्षर *comp)
{
	पूर्णांक i;
	क्रम (i = 0; i < PROPOSAL_MAX; i++) {
		स्थिर अक्षर *ccp = defaults[i];
#अगर_घोषित CIPHER_NONE_AVAIL
		अगर (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#पूर्ण_अगर
		अगर (i == PROPOSAL_SERVER_HOST_कुंजी_ALGS)
			ccp = keyname;
		अन्यथा अगर (i == PROPOSAL_KEX_ALGS && kex != शून्य)
			ccp = kex;
		अन्यथा अगर ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != शून्य)
			ccp = cipher;
		अन्यथा अगर ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != शून्य)
			ccp = mac;
		अन्यथा अगर ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != शून्य)
			ccp = comp;
		अगर ((out[i] = strdup(ccp)) == शून्य)
			वापस -1;
	}
	वापस 0;
}

अटल पूर्णांक
do_kex_with_कुंजी(काष्ठा shared_state *st, काष्ठा test_state *ts,
    स्थिर अक्षर *kex, पूर्णांक keytype, स्थिर काष्ठा kex_overrides *ov)
{
	काष्ठा ssh *client = शून्य, *server = शून्य;
	काष्ठा sshkey *privkey = शून्य, *pubkey = शून्य;
	काष्ठा sshbuf *state = शून्य;
	काष्ठा kex_params kex_params;
	स्थिर अक्षर *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *myproposal[PROPOSAL_MAX] = {0};
	अक्षर *keyname = शून्य;
	पूर्णांक i, r;

	ts->अ_अंदर = ts->sin = शून्य;
	अगर (ts->c_template != शून्य &&
	    (ts->अ_अंदर = sshbuf_fromb(ts->c_template)) == शून्य)
		पात();
	अगर (ts->s_template != शून्य &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == शून्य)
		पात();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	अगर (ts->अ_अंदर != शून्य) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->अ_अंदर));
	} अन्यथा अगर (ts->sin != शून्य) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} अन्यथा
		debug_f("%s %s noclobber", kex, keyname);

	अगर (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : शून्य,
	    ov ? ov->mac : शून्य,
	    ov ? ov->comp : शून्य) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ हार;
	}
	स_नकल(kex_params.proposal, myproposal, माप(myproposal));
	अगर ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		जाओ हार;
	}
	अगर ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		जाओ हार;
	}
	अगर ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		जाओ हार;
	}
	अगर ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		जाओ हार;
	}
	/* XXX rekex, set_state, etc */
 हार:
	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->अ_अंदर);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	मुक्त(keyname);
	वापस r;
}

अटल पूर्णांक
prepare_कुंजी(काष्ठा shared_state *st, पूर्णांक kt, पूर्णांक bits)
{
	स्थिर अक्षर *pubstr = शून्य;
	स्थिर अक्षर *privstr = शून्य;
	अक्षर *tmp, *cp;
	काष्ठा sshkey *privkey = शून्य, *pubkey = शून्य;
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r;

	चयन (kt) {
	हाल कुंजी_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		अवरोध;
	हाल कुंजी_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		अवरोध;
	हाल कुंजी_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		अवरोध;
	शेष:
		पात();
	}
	अगर ((b = sshbuf_from(privstr, म_माप(privstr))) == शून्य)
		पात();
	अगर ((r = sshkey_parse_private_fileblob(b, "", &privkey, शून्य)) != 0) {
		error_fr(r, "priv %d", kt);
		पात();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	अगर ((pubkey = sshkey_new(कुंजी_UNSPEC)) == शून्य)
		पात();
	अगर ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		पात();
	}
	मुक्त(tmp);

	store_कुंजी(st, pubkey, privkey);
	वापस 0;
}

#अगर defined(STANDALONE)

#अगर 0 /* use this if generating new keys to embed above */
अटल पूर्णांक
prepare_कुंजी(काष्ठा shared_state *st, पूर्णांक keytype, पूर्णांक bits)
{
	काष्ठा sshkey *privkey = शून्य, *pubkey = शून्य;
	पूर्णांक r;

	अगर ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		पात();
	}
	अगर ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		पात();
	}
	store_कुंजी(st, pubkey, privkey);
	वापस 0;
}
#पूर्ण_अगर

पूर्णांक मुख्य(व्योम)
{
	अटल काष्ठा shared_state *st;
	काष्ठा test_state *ts;
	स्थिर पूर्णांक keytypes[] = { कुंजी_RSA, कुंजी_ECDSA, कुंजी_ED25519, -1 };
	अटल स्थिर अक्षर * स्थिर kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		शून्य,
	};
	पूर्णांक i, j;
	अक्षर *path;
	खाता *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	अगर (st == शून्य) {
		st = (काष्ठा shared_state *)xcalloc(1, माप(*st));
		prepare_कुंजियाँ(st);
	}
	/* Run each kex method for each key and save client/server packets */
	क्रम (i = 0; keytypes[i] != -1; i++) {
		क्रम (j = 0; kextypes[j] != शून्य; j++) {
			ts = (काष्ठा test_state *)xcalloc(1, माप(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_कुंजी(st, ts, kextypes[j], keytypes[i], शून्य);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			अगर ((f = ख_खोलो(path, "wb+")) == शून्य)
				पात();
			अगर (ख_डालो(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				पात();
			ख_बंद(f);
			मुक्त(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			अगर ((f = ख_खोलो(path, "wb+")) == शून्य)
				पात();
			अगर (ख_डालो(sshbuf_ptr(ts->cmsgs), 1,
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
	क्रम (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		अगर (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, शून्य, 0) != 0)
			पात();
		मुक्त(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		अगर (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			पात();
		मुक्त(path);
	}
}
#अन्यथा /* !STANDALONE */
अटल व्योम
do_kex(काष्ठा shared_state *st, काष्ठा test_state *ts, स्थिर अक्षर *kex)
{
	do_kex_with_कुंजी(st, ts, kex, कुंजी_RSA, शून्य);
	do_kex_with_कुंजी(st, ts, kex, कुंजी_ECDSA, शून्य);
	do_kex_with_कुंजी(st, ts, kex, कुंजी_ED25519, शून्य);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
अटल व्योम
kex_extras(काष्ठा shared_state *st, काष्ठा test_state *ts)
{
	अटल स्थिर अक्षर * स्थिर ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		शून्य,
	};
	अटल स्थिर अक्षर * स्थिर macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		शून्य,
	};
	अटल स्थिर अक्षर * स्थिर comps[] = {
		"zlib@openssh.com",
		"zlib",
		शून्य,
	};
	स्थिर अक्षर *kex = "curve25519-sha256@libssh.org";
	पूर्णांक i;

	क्रम (i = 0; ciphers[i] != शून्य; i++) {
		काष्ठा kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_कुंजी(st, ts, kex, कुंजी_ED25519, &ov);
	}
	क्रम (i = 0; macs[i] != शून्य; i++) {
		काष्ठा kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_कुंजी(st, ts, kex, कुंजी_ED25519, &ov);
	}
	क्रम (i = 0; comps[i] != शून्य; i++) {
		काष्ठा kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_कुंजी(st, ts, kex, कुंजी_ED25519, &ov);
	}
}

अटल व्योम
kex_tests(काष्ठा shared_state *st, काष्ठा test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* तथ्य, माप_प्रकार आकार)
{
	अटल काष्ठा shared_state *st;
	काष्ठा test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_पंक्तियाँ * 4];
	u_char zbuf[4096] = {0};
	अटल LogLevel loglevel = SYSLOG_LEVEL_INFO;

	अगर (st == शून्य) {
		अगर (दो_पर्या("DEBUG") != शून्य || दो_पर्या("KEX_FUZZ_DEBUG") != शून्य)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (काष्ठा shared_state *)xcalloc(1, माप(*st));
		prepare_कुंजियाँ(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	स_रखो(crbuf, '\n', माप(crbuf));

	ts = (काष्ठा test_state *)xcalloc(1, माप(*ts));
	अगर ((ts->s_template = sshbuf_new()) == शून्य ||
	    sshbuf_put(ts->s_template, तथ्य, आकार) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, माप(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, माप(zbuf)) != 0)
		पात();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	मुक्त(ts);

	ts = (काष्ठा test_state *)xcalloc(1, माप(*ts));
	अगर ((ts->c_template = sshbuf_new()) == शून्य ||
	    sshbuf_put(ts->c_template, तथ्य, आकार) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, माप(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, माप(zbuf)) != 0)
		पात();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	मुक्त(ts);

	वापस 0;
}
#पूर्ण_अगर /* STANDALONE */
} /* extern "C" */
