/* $OpenBSD: dh.c,v 1.76 2026/02/08 19:54:31 dtucker Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#شامل "includes.h"

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"

#شامل <errno.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <limits.h>

#شامل <openssl/bn.h>
#شامل <openssl/dh.h>

#شامل "dh.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "ssherr.h"

ساکن ثابت حرف *moduli_filename;

خالی dh_سیٹ_moduli_file(ثابت حرف *filename)
{
	moduli_filename = filename;
}

ساکن ثابت حرف * get_moduli_filename(خالی)
{
	واپس moduli_filename ? moduli_filename : راستہ_DH_MODULI;
}

ساکن صحیح
parse_مفرد(صحیح linenum, حرف *سطر, ساخت dhgroup *dhg)
{
	حرف *cp, *arg;
	حرف *strsize, *gen, *مفرد;
	ثابت حرف *errstr = تہی;
	طویل طویل n;

	dhg->p = dhg->g = تہی;
	cp = سطر;
	اگر ((arg = strdelim(&cp)) == تہی)
		واپس 0;
	/* Ignore leading whitespace */
	اگر (*arg == '\0')
		arg = strdelim(&cp);
	اگر (!arg || !*arg || *arg == '#')
		واپس 0;

	/*وقت*/
	اگر (cp == تہی || *arg == '\0')
		جاؤ truncated;
	arg = strsep(&cp, " "); /* type */
	اگر (cp == تہی || *arg == '\0')
		جاؤ truncated;
	/* Ensure this is a safe prime */
	n = strtonum(arg, 0, 5, &errstr);
	اگر (errstr != تہی || n != MODULI_TYPE_محفوظ) {
		error("moduli:%d: type is not %d", linenum, MODULI_TYPE_محفوظ);
		جاؤ fail;
	}
	arg = strsep(&cp, " "); /* tests */
	اگر (cp == تہی || *arg == '\0')
		جاؤ truncated;
	/* Ensure prime has been tested and is not composite */
	n = strtonum(arg, 0, 0x1f, &errstr);
	اگر (errstr != تہی ||
	    (n & MODULI_TESTS_مرکب) || !(n & ~MODULI_TESTS_مرکب)) {
		error("moduli:%d: invalid moduli tests flag", linenum);
		جاؤ fail;
	}
	arg = strsep(&cp, " "); /* tries */
	اگر (cp == تہی || *arg == '\0')
		جاؤ truncated;
	n = strtonum(arg, 0, 1<<30, &errstr);
	اگر (errstr != تہی || n == 0) {
		error("moduli:%d: invalid primality trial count", linenum);
		جاؤ fail;
	}
	strsize = strsep(&cp, " "); /*سائز*/
	اگر (cp == تہی || *strsize == '\0' ||
	    (dhg->سائز = (صحیح)strtonum(strsize, 0, 64*1024, &errstr)) == 0 ||
	    errstr) {
		error("moduli:%d: invalid prime length", linenum);
		جاؤ fail;
	}
	/* The whole group is one bit larger */
	dhg->سائز++;
	gen = strsep(&cp, " "); /* gen */
	اگر (cp == تہی || *gen == '\0')
		جاؤ truncated;
	مفرد = strsep(&cp, " "); /*مفرد*/
	اگر (cp != تہی || *مفرد == '\0') {
 truncated:
		error("moduli:%d: truncated", linenum);
		جاؤ fail;
	}

	اگر ((dhg->g = BN_new()) == تہی ||
	    (dhg->p = BN_new()) == تہی) {
		error("parse_prime: BN_new failed");
		جاؤ fail;
	}
	اگر (BN_hex2bn(&dhg->g, gen) == 0) {
		error("moduli:%d: could not parse generator value", linenum);
		جاؤ fail;
	}
	اگر (BN_hex2bn(&dhg->p, مفرد) == 0) {
		error("moduli:%d: could not parse prime value", linenum);
		جاؤ fail;
	}
	اگر (BN_عدد_بٹ(dhg->p) != dhg->سائز) {
		error("moduli:%d: prime has wrong size: actual %d listed %d",
		    linenum, BN_عدد_بٹ(dhg->p), dhg->سائز - 1);
		جاؤ fail;
	}
	اگر (BN_cmp(dhg->g, BN_قدر_one()) <= 0) {
		error("moduli:%d: generator is invalid", linenum);
		جاؤ fail;
	}
	واپس 1;

 fail:
	BN_clear_free(dhg->g);
	BN_clear_free(dhg->p);
	dhg->g = dhg->p = تہی;
	واپس 0;
}

DH *
انتخاب_dh(صحیح min, صحیح wantbits, صحیح max)
{
	FILE *f;
	حرف *سطر = تہی;
	سائز_t linesize = 0;
	صحیح بہترین, bestcount, which, linenum;
	ساخت dhgroup dhg;

	اگر ((f = fopen(get_moduli_filename(), "r")) == تہی) {
		logit("WARNING: could not open %s (%s), using fixed modulus",
		    get_moduli_filename(), strerror(errno));
		واپس (dh_new_گروہ_fallback(max));
	}

	linenum = 0;
	بہترین = bestcount = 0;
	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		اگر (!parse_مفرد(linenum, سطر, &dhg))
			جاری;
		BN_clear_free(dhg.g);
		BN_clear_free(dhg.p);

		اگر (dhg.سائز > max || dhg.سائز < min)
			جاری;

		اگر ((dhg.سائز > wantbits && dhg.سائز < بہترین) ||
		    (dhg.سائز > بہترین && بہترین < wantbits)) {
			بہترین = dhg.سائز;
			bestcount = 0;
		}
		اگر (dhg.سائز == بہترین)
			bestcount++;
	}
	آزاد(سطر);
	سطر = تہی;
	linesize = 0;
	rewind(f);

	اگر (bestcount == 0) {
		fclose(f);
		logit("WARNING: no suitable primes (size %d/%d/%d) in %s",
		    min, wantbits, max, get_moduli_filename());
		واپس تہی;
	}
	which = arc4random_یکساں(bestcount);

	linenum = 0;
	bestcount = 0;
	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		اگر (!parse_مفرد(linenum, سطر, &dhg))
			جاری;
		اگر ((dhg.سائز > max || dhg.سائز < min) ||
		    dhg.سائز != بہترین ||
		    bestcount++ != which) {
			BN_clear_free(dhg.g);
			BN_clear_free(dhg.p);
			جاری;
		}
		توڑو;
	}
	آزاد(سطر);
	سطر = تہی;
	fclose(f);
	اگر (bestcount != which + 1) {
		logit("WARNING: selected prime disappeared in %s, giving up",
		    get_moduli_filename());
		واپس (dh_new_گروہ_fallback(max));
	}

	واپس (dh_new_گروہ(dhg.g, dhg.p));
}

/* diffie-hellman-groupN-sha1 */

صحیح
dh_pub_is_valid(ثابت DH *dh, ثابت BIGNUM *dh_pub)
{
	صحیح i;
	صحیح n = BN_عدد_بٹ(dh_pub);
	صحیح بٹ_سیٹ = 0;
	BIGNUM *tmp;
	ثابت BIGNUM *dh_p;

	DH_get0_pqg(dh, &dh_p, تہی, تہی);

	اگر (BN_is_negative(dh_pub)) {
		logit("invalid public DH value: negative");
		واپس 0;
	}
	اگر (BN_cmp(dh_pub, BN_قدر_one()) != 1) {	/* pub_exp <= 1 */
		logit("invalid public DH value: <= 1");
		واپس 0;
	}

	اگر ((tmp = BN_new()) == تہی) {
		error_f("BN_new failed");
		واپس 0;
	}
	اگر (!BN_sub(tmp, dh_p, BN_قدر_one()) ||
	    BN_cmp(dh_pub, tmp) != -1) {		/* pub_exp > p-2 */
		BN_clear_free(tmp);
		logit("invalid public DH value: >= p-1");
		واپس 0;
	}
	BN_clear_free(tmp);

	برائے (i = 0; i <= n; i++)
		اگر (BN_is_ثنائی_ہندسہ_سیٹ(dh_pub, i))
			بٹ_سیٹ++;
	debug2("bits set: %d/%d", بٹ_سیٹ, BN_عدد_بٹ(dh_p));

	/*
	 * if g==2 and bits_set==1 then computing log_g(dh_pub) is trivial
	 */
	اگر (بٹ_سیٹ < 4) {
		logit("invalid public DH value (%d/%d)",
		    بٹ_سیٹ, BN_عدد_بٹ(dh_p));
		واپس 0;
	}
	واپس 1;
}

صحیح
dh_gen_کلید(DH *dh, صحیح need)
{
	صحیح pbits;
	ثابت BIGNUM *dh_p, *pub_کلید;

	DH_get0_pqg(dh, &dh_p, تہی, تہی);

	اگر (need < 0 || dh_p == تہی ||
	    (pbits = BN_عدد_بٹ(dh_p)) <= 0 ||
	    need > زیادہ_سے_زیادہ_عدد / 2 || 2 * need > pbits)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (need < 256)
		need = 256;
	/*
	 * Pollard Rho, Big step/Little Step attacks are O(sqrt(n)),
	 * so double requested need here.
	 */
	اگر (!DH_سیٹ_لمبائی(dh, MINIMUM(need * 2, pbits - 1)))
		واپس SSH_ERR_LIBCRYPTO_ERROR;

	اگر (DH_generate_کلید(dh) == 0)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	DH_get0_کلید(dh, &pub_کلید, تہی);
	اگر (!dh_pub_is_valid(dh, pub_کلید))
		واپس SSH_ERR_INVALID_FORMAT;
	واپس 0;
}

DH *
dh_new_گروہ_asc(ثابت حرف *gen, ثابت حرف *modulus)
{
	DH *dh;
	BIGNUM *dh_p = تہی, *dh_g = تہی;

	اگر ((dh = DH_new()) == تہی)
		واپس تہی;
	اگر (BN_hex2bn(&dh_p, modulus) == 0 ||
	    BN_hex2bn(&dh_g, gen) == 0)
		جاؤ fail;
	اگر (!DH_set0_pqg(dh, dh_p, تہی, dh_g))
		جاؤ fail;
	واپس dh;
 fail:
	DH_free(dh);
	BN_clear_free(dh_p);
	BN_clear_free(dh_g);
	واپس تہی;
}

/*
 * This just returns the group, we still need to generate the exchange
 * value.
 */
DH *
dh_new_گروہ(BIGNUM *gen, BIGNUM *modulus)
{
	DH *dh;

	اگر ((dh = DH_new()) == تہی)
		واپس تہی;
	اگر (!DH_set0_pqg(dh, modulus, تہی, gen)) {
		DH_free(dh);
		واپس تہی;
	}

	واپس dh;
}

/* rfc2409 "Second Oakley Group" (1024 bits) */
DH *
dh_new_group1(خالی)
{
	ساکن حرف *gen = "2", *group1 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	    "FFFFFFFF" "FFFFFFFF";

	واپس (dh_new_گروہ_asc(gen, group1));
}

/* rfc3526 group 14 "2048-bit MODP Group" */
DH *
dh_new_group14(خالی)
{
	ساکن حرف *gen = "2", *group14 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF";

	واپس (dh_new_گروہ_asc(gen, group14));
}

/* rfc3526 group 16 "4096-bit MODP Group" */
DH *
dh_new_group16(خالی)
{
	ساکن حرف *gen = "2", *group16 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
	    "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
	    "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
	    "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
	    "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
	    "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
	    "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
	    "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
	    "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
	    "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
	    "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34063199"
	    "FFFFFFFF" "FFFFFFFF";

	واپس (dh_new_گروہ_asc(gen, group16));
}

/* rfc3526 group 18 "8192-bit MODP Group" */
DH *
dh_new_group18(خالی)
{
	ساکن حرف *gen = "2", *group18 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
	    "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
	    "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
	    "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
	    "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
	    "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
	    "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
	    "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
	    "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
	    "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
	    "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34028492"
	    "36C3FAB4" "D27C7026" "C1D4DCB2" "602646DE" "C9751E76" "3DBA37BD"
	    "F8FF9406" "AD9E530E" "E5DB382F" "413001AE" "B06A53ED" "9027D831"
	    "179727B0" "865A8918" "DA3EDBEB" "CF9B14ED" "44CE6CBA" "CED4BB1B"
	    "DB7F1447" "E6CC254B" "33205151" "2BD7AF42" "6FB8F401" "378CD2BF"
	    "5983CA01" "C64B92EC" "F032EA15" "D1721D03" "F482D7CE" "6E74FEF6"
	    "D55E702F" "46980C82" "B5A84031" "900B1C9E" "59E7C97F" "BEC7E8F3"
	    "23A97A7E" "36CC88BE" "0F1D45B7" "FF585AC5" "4BD407B2" "2B4154AA"
	    "CC8F6D7E" "BF48E1D8" "14CC5ED2" "0F8037E0" "A79715EE" "F29BE328"
	    "06A1D58B" "B7C5DA76" "F550AA3D" "8A1FBFF0" "EB19CCB1" "A313D55C"
	    "DA56C9EC" "2EF29632" "387FE8D7" "6E3C0468" "043E8F66" "3F4860EE"
	    "12BF2D5B" "0B7474D6" "E694F91E" "6DBE1159" "74A3926F" "12FEE5E4"
	    "38777CB6" "A932DF8C" "D8BEC4D0" "73B931BA" "3BC832B6" "8D9DD300"
	    "741FA7BF" "8AFC47ED" "2576F693" "6BA42466" "3AAB639C" "5AE4F568"
	    "3423B474" "2BF1C978" "238F16CB" "E39D652D" "E3FDB8BE" "FC848AD9"
	    "22222E04" "A4037C07" "13EB57A8" "1A23F0C7" "3473FC64" "6CEA306B"
	    "4BCBC886" "2F8385DD" "FA9D4B7F" "A2C087E8" "79683303" "ED5BDD3A"
	    "062B3CF5" "B3A278A6" "6D2A13F8" "3F44F82D" "DF310EE0" "74AB6A36"
	    "4597E899" "A0255DC1" "64F31CC5" "0846851D" "F9AB4819" "5DED7EA1"
	    "B1D510BD" "7EE74D73" "FAF36BC3" "1ECFA268" "359046F4" "EB879F92"
	    "4009438B" "481C6CD7" "889A002E" "D5EE382B" "C9190DA6" "FC026E47"
	    "9558E447" "5677E9AA" "9E3050E2" "765694DF" "C81F56E8" "80B96E71"
	    "60C980DD" "98EDD3DF" "FFFFFFFF" "FFFFFFFF";

	واپس (dh_new_گروہ_asc(gen, group18));
}

/* Select fallback group used by DH-GEX if moduli file cannot be read. */
DH *
dh_new_گروہ_fallback(صحیح max)
{
	debug3_f("requested max size %d", max);
	اگر (max < 3072) {
		debug3("using 2k bit group 14");
		واپس dh_new_group14();
	} ورنہ اگر (max < 6144) {
		debug3("using 4k bit group 16");
		واپس dh_new_group16();
	}
	debug3("using 8k bit group 18");
	واپس dh_new_group18();
}

/*
 * Estimates the group order for a Diffie-Hellman group that has an
 * attack complexity approximately the same as O(2**bits).
 * Values from NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 (rev 3) limited by the recommended maximum value
 * from RFC4419 section 3.
 */
u_int
dh_estimate(صحیح بٹ)
{
	اگر (بٹ <= 112)
		واپس 2048;
	اگر (بٹ <= 128)
		واپس 3072;
	اگر (بٹ <= 192)
		واپس 7680;
	واپس 8192;
}

#اگر_ختم /* WITH_OPENSSL */
