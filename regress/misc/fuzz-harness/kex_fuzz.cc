// libfuzzer driver for key exchange fuzzing.


#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

বাহ্যিক "C" {

#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "log.h"

#অন্তর্ভাব "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

স্থির পূর্ণসংখ্যা prepare_চাবি(কাঠামো shared_state *st, পূর্ণসংখ্যা keytype, পূর্ণসংখ্যা bits);

কাঠামো shared_state {
	আকার_t nkeys;
	কাঠামো sshkey **privkeys, **pubkeys;
};

কাঠামো test_state {
	কাঠামো sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	কাঠামো sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	কাঠামো sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
কাঠামো kex_overrides {
	ধ্রুবক অক্ষর *cipher;
	ধ্রুবক অক্ষর *mac;
	ধ্রুবক অক্ষর *comp;
};

স্থির পূর্ণসংখ্যা
do_send_and_receive(কাঠামো ssh *from, কাঠামো ssh *to,
    কাঠামো sshbuf *store, পূর্ণসংখ্যা clobber, আকার_t *n)
{
	u_char type;
	আকার_t len;
	ধ্রুবক u_char *buf;
	পূর্ণসংখ্যা r;

	জন্য (*n = 0;; (*n)++) {
		যদি ((r = ssh_packet_পরবর্তী(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ফেরত r;
		}
		যদি (type != 0)
			ফেরত 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		যদি (len == 0)
			ফেরত 0;
		যদি ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ফেরত r;
		}
		যদি (store != ফাঁকা && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ফেরত r;
		}
		যদি (!clobber && (r = ssh_প্রবেশ_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ফেরত r;
		}
	}
}

স্থির পূর্ণসংখ্যা
run_kex(কাঠামো test_state *ts, কাঠামো ssh *client, কাঠামো ssh *server)
{
	পূর্ণসংখ্যা r = 0;
	আকার_t cn, sn;

	/* If fuzzing, replace server/client input */
	যদি (ts->sin != ফাঁকা) {
		যদি ((r = ssh_প্রবেশ_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			ফেরত r;
		}
		sshbuf_reset(ts->sin);
	}
	যদি (ts->cin != ফাঁকা) {
		যদি ((r = ssh_প্রবেশ_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			ফেরত r;
		}
		sshbuf_reset(ts->cin);
	}
	যখন (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		যদি ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != ফাঁকা, &sn)) != 0) {
			debug_fr(r, "S->C");
			বিরতি;
		}
		debug_f("C:");
		যদি ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != ফাঁকা, &cn)) != 0) {
			debug_fr(r, "C->S");
			বিরতি;
		}
		যদি (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			বিরতি;
		}
	}
	debug_fr(r, "done");
	ফেরত r;
}

স্থির শূন্য
store_চাবি(কাঠামো shared_state *st, কাঠামো sshkey *pubkey,
    কাঠামো sshkey *privkey)
{
	যদি (st == ফাঁকা || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((আকার_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ফাঁকা))
		abort();
	যদি ((আকার_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (কাঠামো sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, আকার(*st->pubkeys));
		st->privkeys = (কাঠামো sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, আকার(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

স্থির পূর্ণসংখ্যা
prepare_চাবিগুলি(কাঠামো shared_state *st)
{
	যদি (prepare_চাবি(st, চাবি_RSA, 2048) != 0 ||
	    prepare_চাবি(st, চাবি_ECDSA, 256) != 0 ||
	    prepare_চাবি(st, চাবি_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ফেরত -1;
	}
	ফেরত 0;
}

স্থির কাঠামো sshkey *
get_pubkey(কাঠামো shared_state *st, পূর্ণসংখ্যা keytype)
{
	যদি (st == ফাঁকা || keytype < 0 || (আকার_t)keytype >= st->nkeys ||
	    st->pubkeys == ফাঁকা || st->pubkeys[keytype] == ফাঁকা)
		abort();
	ফেরত st->pubkeys[keytype];
}

স্থির কাঠামো sshkey *
get_privkey(কাঠামো shared_state *st, পূর্ণসংখ্যা keytype)
{
	যদি (st == ফাঁকা || keytype < 0 || (আকার_t)keytype >= st->nkeys ||
	    st->privkeys == ফাঁকা || st->privkeys[keytype] == ফাঁকা)
		abort();
	ফেরত st->privkeys[keytype];
}

স্থির পূর্ণসংখ্যা
build_proposal_side(অক্ষর **out, ধ্রুবক অক্ষর *defaults[PROPOSAL_MAX],
    ধ্রুবক অক্ষর *kex, ধ্রুবক অক্ষর *keyname,
    ধ্রুবক অক্ষর *cipher, ধ্রুবক অক্ষর *mac, ধ্রুবক অক্ষর *comp)
{
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুবক অক্ষর *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		যদি (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		যদি (i == PROPOSAL_SERVER_HOST_চাবি_ALGS)
			ccp = keyname;
		অন্যথা যদি (i == PROPOSAL_KEX_ALGS && kex != ফাঁকা)
			ccp = kex;
		অন্যথা যদি ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ফাঁকা)
			ccp = cipher;
		অন্যথা যদি ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ফাঁকা)
			ccp = mac;
		অন্যথা যদি ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ফাঁকা)
			ccp = comp;
		যদি ((out[i] = strdup(ccp)) == ফাঁকা)
			ফেরত -1;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
do_kex_with_চাবি(কাঠামো shared_state *st, কাঠামো test_state *ts,
    ধ্রুবক অক্ষর *kex, পূর্ণসংখ্যা keytype, ধ্রুবক কাঠামো kex_overrides *ov)
{
	কাঠামো ssh *client = ফাঁকা, *server = ফাঁকা;
	কাঠামো sshkey *privkey = ফাঁকা, *pubkey = ফাঁকা;
	কাঠামো sshbuf *state = ফাঁকা;
	কাঠামো kex_params kex_params;
	ধ্রুবক অক্ষর *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	অক্ষর *myproposal[PROPOSAL_MAX] = {0};
	অক্ষর *keyname = ফাঁকা;
	পূর্ণসংখ্যা i, r;

	ts->cin = ts->sin = ফাঁকা;
	যদি (ts->c_template != ফাঁকা &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == ফাঁকা)
		abort();
	যদি (ts->s_template != ফাঁকা &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == ফাঁকা)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	যদি (ts->cin != ফাঁকা) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} অন্যথা যদি (ts->sin != ফাঁকা) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} অন্যথা
		debug_f("%s %s noclobber", kex, keyname);

	যদি (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ফাঁকা,
	    ov ? ov->mac : ফাঁকা,
	    ov ? ov->comp : ফাঁকা) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		যাও fail;
	}
	memcpy(kex_params.proposal, myproposal, আকার(myproposal));
	যদি ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		যাও fail;
	}
	যদি ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		যাও fail;
	}
	যদি ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		যাও fail;
	}
	যদি ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		যাও fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	মুক্ত(keyname);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
prepare_চাবি(কাঠামো shared_state *st, পূর্ণসংখ্যা kt, পূর্ণসংখ্যা bits)
{
	ধ্রুবক অক্ষর *pubstr = ফাঁকা;
	ধ্রুবক অক্ষর *privstr = ফাঁকা;
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *privkey = ফাঁকা, *pubkey = ফাঁকা;
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r;

	নির্বাচন (kt) {
	ক্ষেত্র চাবি_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		বিরতি;
	ক্ষেত্র চাবি_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		বিরতি;
	ক্ষেত্র চাবি_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		বিরতি;
	পূর্বনির্ধারিত:
		abort();
	}
	যদি ((b = sshbuf_from(privstr, strlen(privstr))) == ফাঁকা)
		abort();
	যদি ((r = sshkey_parse_private_fileblob(b, "", &privkey, ফাঁকা)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	যদি ((pubkey = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
		abort();
	যদি ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	মুক্ত(tmp);

	store_চাবি(st, pubkey, privkey);
	ফেরত 0;
}

#যদি defined(STANDALONE)

#যদি 0 /* use this if generating new keys to embed above */
স্থির পূর্ণসংখ্যা
prepare_চাবি(কাঠামো shared_state *st, পূর্ণসংখ্যা keytype, পূর্ণসংখ্যা bits)
{
	কাঠামো sshkey *privkey = ফাঁকা, *pubkey = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	যদি ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_চাবি(st, pubkey, privkey);
	ফেরত 0;
}
#endif

পূর্ণসংখ্যা প্রধান(শূন্য)
{
	স্থির কাঠামো shared_state *st;
	কাঠামো test_state *ts;
	ধ্রুবক পূর্ণসংখ্যা keytypes[] = { চাবি_RSA, চাবি_ECDSA, চাবি_ED25519, -1 };
	স্থির ধ্রুবক অক্ষর * ধ্রুবক kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ফাঁকা,
	};
	পূর্ণসংখ্যা i, j;
	অক্ষর *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	যদি (st == ফাঁকা) {
		st = (কাঠামো shared_state *)xcalloc(1, আকার(*st));
		prepare_চাবিগুলি(st);
	}
	/* Run each kex method for each key and save client/server packets */
	জন্য (i = 0; keytypes[i] != -1; i++) {
		জন্য (j = 0; kextypes[j] != ফাঁকা; j++) {
			ts = (কাঠামো test_state *)xcalloc(1, আকার(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_চাবি(st, ts, kextypes[j], keytypes[i], ফাঁকা);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			যদি ((f = fopen(path, "wb+")) == ফাঁকা)
				abort();
			যদি (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			মুক্ত(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			যদি ((f = fopen(path, "wb+")) == ফাঁকা)
				abort();
			যদি (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			মুক্ত(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			মুক্ত(ts);
		}
	}
	জন্য (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		যদি (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, ফাঁকা, 0) != 0)
			abort();
		মুক্ত(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		যদি (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		মুক্ত(path);
	}
}
#অন্যথা /* !STANDALONE */
স্থির শূন্য
do_kex(কাঠামো shared_state *st, কাঠামো test_state *ts, ধ্রুবক অক্ষর *kex)
{
	do_kex_with_চাবি(st, ts, kex, চাবি_RSA, ফাঁকা);
	do_kex_with_চাবি(st, ts, kex, চাবি_ECDSA, ফাঁকা);
	do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, ফাঁকা);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
স্থির শূন্য
kex_extras(কাঠামো shared_state *st, কাঠামো test_state *ts)
{
	স্থির ধ্রুবক অক্ষর * ধ্রুবক ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ফাঁকা,
	};
	স্থির ধ্রুবক অক্ষর * ধ্রুবক macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ফাঁকা,
	};
	স্থির ধ্রুবক অক্ষর * ধ্রুবক comps[] = {
		"zlib@openssh.com",
		"zlib",
		ফাঁকা,
	};
	ধ্রুবক অক্ষর *kex = "curve25519-sha256@libssh.org";
	পূর্ণসংখ্যা i;

	জন্য (i = 0; ciphers[i] != ফাঁকা; i++) {
		কাঠামো kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, &ov);
	}
	জন্য (i = 0; macs[i] != ফাঁকা; i++) {
		কাঠামো kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, &ov);
	}
	জন্য (i = 0; comps[i] != ফাঁকা; i++) {
		কাঠামো kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, &ov);
	}
}

স্থির শূন্য
kex_tests(কাঠামো shared_state *st, কাঠামো test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* তথ্য, আকার_t আকার_2)
{
	স্থির কাঠামো shared_state *st;
	কাঠামো test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_সারিগুলি * 4];
	u_char zbuf[4096] = {0};
	স্থির LogLevel loglevel = SYSLOG_LEVEL_INFO;

	যদি (st == ফাঁকা) {
		যদি (getenv("DEBUG") != ফাঁকা || getenv("KEX_FUZZ_DEBUG") != ফাঁকা)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (কাঠামো shared_state *)xcalloc(1, আকার(*st));
		prepare_চাবিগুলি(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', আকার(crbuf));

	ts = (কাঠামো test_state *)xcalloc(1, আকার(*ts));
	যদি ((ts->s_template = sshbuf_new()) == ফাঁকা ||
	    sshbuf_put(ts->s_template, তথ্য, আকার_2) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, আকার(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, আকার(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	মুক্ত(ts);

	ts = (কাঠামো test_state *)xcalloc(1, আকার(*ts));
	যদি ((ts->c_template = sshbuf_new()) == ফাঁকা ||
	    sshbuf_put(ts->c_template, তথ্য, আকার_2) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, আকার(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, আকার(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	মুক্ত(ts);

	ফেরত 0;
}
#endif /* STANDALONE */
} /* extern "C" */
