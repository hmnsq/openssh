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

#include "includes.h"

#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/bn.h>
#include <openssl/dh.h>

#include "dh.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "ssherr.h"

static const var_na *moduli_filename;

void dh_set_moduli_file(const var_na *filename)
{
	moduli_filename = filename;
}

static const var_na * get_moduli_filename(void)
{
	ආපසු moduli_filename ? moduli_filename : _PATH_DH_MODULI;
}

static පූර්ණ_සංඛ්‍යා
parse_prime(පූර්ණ_සංඛ්‍යා linenum, var_na *line, sa_nracanaa dhgroup *dhg)
{
	var_na *cp, *arg;
	var_na *strsize, *gen, *prime;
	const var_na *errstr = NULL;
	long long n;

	dhg->p = dhg->g = NULL;
	cp = line;
	නම් ((arg = strdelim(&cp)) == NULL)
		ආපසු 0;
	/* Ignore leading whitespace */
	නම් (*arg == '\0')
		arg = strdelim(&cp);
	නම් (!arg || !*arg || *arg == '#')
		ආපසු 0;

	/* time */
	නම් (cp == NULL || *arg == '\0')
		goto truncated;
	arg = strsep(&cp, " "); /* type */
	නම් (cp == NULL || *arg == '\0')
		goto truncated;
	/* Ensure this is a safe prime */
	n = strtonum(arg, 0, 5, &errstr);
	නම් (errstr != NULL || n != MODULI_TYPE_SAFE) {
		error("moduli:%d: type is not %d", linenum, MODULI_TYPE_SAFE);
		goto fail;
	}
	arg = strsep(&cp, " "); /* tests */
	නම් (cp == NULL || *arg == '\0')
		goto truncated;
	/* Ensure prime has been tested and is not composite */
	n = strtonum(arg, 0, 0x1f, &errstr);
	නම් (errstr != NULL ||
	    (n & MODULI_TESTS_COMPOSITE) || !(n & ~MODULI_TESTS_COMPOSITE)) {
		error("moduli:%d: invalid moduli tests flag", linenum);
		goto fail;
	}
	arg = strsep(&cp, " "); /* tries */
	නම් (cp == NULL || *arg == '\0')
		goto truncated;
	n = strtonum(arg, 0, 1<<30, &errstr);
	නම් (errstr != NULL || n == 0) {
		error("moduli:%d: invalid primality trial count", linenum);
		goto fail;
	}
	strsize = strsep(&cp, " "); /* size */
	නම් (cp == NULL || *strsize == '\0' ||
	    (dhg->size = (පූර්ණ_සංඛ්‍යා)strtonum(strsize, 0, 64*1024, &errstr)) == 0 ||
	    errstr) {
		error("moduli:%d: invalid prime length", linenum);
		goto fail;
	}
	/* The whole group is one bit larger */
	dhg->size++;
	gen = strsep(&cp, " "); /* gen */
	නම් (cp == NULL || *gen == '\0')
		goto truncated;
	prime = strsep(&cp, " "); /* prime */
	නම් (cp != NULL || *prime == '\0') {
 truncated:
		error("moduli:%d: truncated", linenum);
		goto fail;
	}

	නම් ((dhg->g = BN_new()) == NULL ||
	    (dhg->p = BN_new()) == NULL) {
		error("parse_prime: BN_new failed");
		goto fail;
	}
	නම් (BN_hex2bn(&dhg->g, gen) == 0) {
		error("moduli:%d: could not parse generator value", linenum);
		goto fail;
	}
	නම් (BN_hex2bn(&dhg->p, prime) == 0) {
		error("moduli:%d: could not parse prime value", linenum);
		goto fail;
	}
	නම් (BN_num_bits(dhg->p) != dhg->size) {
		error("moduli:%d: prime has wrong size: actual %d listed %d",
		    linenum, BN_num_bits(dhg->p), dhg->size - 1);
		goto fail;
	}
	නම් (BN_cmp(dhg->g, BN_value_one()) <= 0) {
		error("moduli:%d: generator is invalid", linenum);
		goto fail;
	}
	ආපසු 1;

 fail:
	BN_clear_free(dhg->g);
	BN_clear_free(dhg->p);
	dhg->g = dhg->p = NULL;
	ආපසු 0;
}

DH *
choose_dh(පූර්ණ_සංඛ්‍යා min, පූර්ණ_සංඛ්‍යා wantbits, පූර්ණ_සංඛ්‍යා max)
{
	FILE *f;
	var_na *line = NULL;
	size_t linesize = 0;
	පූර්ණ_සංඛ්‍යා best, bestcount, which, linenum;
	sa_nracanaa dhgroup dhg;

	නම් ((f = fopen(get_moduli_filename(), "r")) == NULL) {
		logit("WARNING: could not open %s (%s), using fixed modulus",
		    get_moduli_filename(), strerror(errno));
		ආපසු (dh_new_group_fallback(max));
	}

	linenum = 0;
	best = bestcount = 0;
	අතරතුර (getline(&line, &linesize, f) != -1) {
		linenum++;
		නම් (!parse_prime(linenum, line, &dhg))
			continue;
		BN_clear_free(dhg.g);
		BN_clear_free(dhg.p);

		නම් (dhg.size > max || dhg.size < min)
			continue;

		නම් ((dhg.size > wantbits && dhg.size < best) ||
		    (dhg.size > best && best < wantbits)) {
			best = dhg.size;
			bestcount = 0;
		}
		නම් (dhg.size == best)
			bestcount++;
	}
	free(line);
	line = NULL;
	linesize = 0;
	rewind(f);

	නම් (bestcount == 0) {
		fclose(f);
		logit("WARNING: no suitable primes (size %d/%d/%d) in %s",
		    min, wantbits, max, get_moduli_filename());
		ආපසු NULL;
	}
	which = arc4random_uniform(bestcount);

	linenum = 0;
	bestcount = 0;
	අතරතුර (getline(&line, &linesize, f) != -1) {
		linenum++;
		නම් (!parse_prime(linenum, line, &dhg))
			continue;
		නම් ((dhg.size > max || dhg.size < min) ||
		    dhg.size != best ||
		    bestcount++ != which) {
			BN_clear_free(dhg.g);
			BN_clear_free(dhg.p);
			continue;
		}
		bha_nga;
	}
	free(line);
	line = NULL;
	fclose(f);
	නම් (bestcount != which + 1) {
		logit("WARNING: selected prime disappeared in %s, giving up",
		    get_moduli_filename());
		ආපසු (dh_new_group_fallback(max));
	}

	ආපසු (dh_new_group(dhg.g, dhg.p));
}

/* diffie-hellman-groupN-sha1 */

පූර්ණ_සංඛ්‍යා
dh_pub_is_valid(const DH *dh, const BIGNUM *dh_pub)
{
	පූර්ණ_සංඛ්‍යා i;
	පූර්ණ_සංඛ්‍යා n = BN_num_bits(dh_pub);
	පූර්ණ_සංඛ්‍යා bits_set = 0;
	BIGNUM *tmp;
	const BIGNUM *dh_p;

	DH_get0_pqg(dh, &dh_p, NULL, NULL);

	නම් (BN_is_negative(dh_pub)) {
		logit("invalid public DH value: negative");
		ආපසු 0;
	}
	නම් (BN_cmp(dh_pub, BN_value_one()) != 1) {	/* pub_exp <= 1 */
		logit("invalid public DH value: <= 1");
		ආපසු 0;
	}

	නම් ((tmp = BN_new()) == NULL) {
		error_f("BN_new failed");
		ආපසු 0;
	}
	නම් (!BN_sub(tmp, dh_p, BN_value_one()) ||
	    BN_cmp(dh_pub, tmp) != -1) {		/* pub_exp > p-2 */
		BN_clear_free(tmp);
		logit("invalid public DH value: >= p-1");
		ආපසු 0;
	}
	BN_clear_free(tmp);

	සඳහා (i = 0; i <= n; i++)
		නම් (BN_is_bit_set(dh_pub, i))
			bits_set++;
	debug2("bits set: %d/%d", bits_set, BN_num_bits(dh_p));

	/*
	 * if g==2 and bits_set==1 then computing log_g(dh_pub) is trivial
	 */
	නම් (bits_set < 4) {
		logit("invalid public DH value (%d/%d)",
		    bits_set, BN_num_bits(dh_p));
		ආපසු 0;
	}
	ආපසු 1;
}

පූර්ණ_සංඛ්‍යා
dh_gen_key(DH *dh, පූර්ණ_සංඛ්‍යා need)
{
	පූර්ණ_සංඛ්‍යා pbits;
	const BIGNUM *dh_p, *pub_key;

	DH_get0_pqg(dh, &dh_p, NULL, NULL);

	නම් (need < 0 || dh_p == NULL ||
	    (pbits = BN_num_bits(dh_p)) <= 0 ||
	    need > INT_MAX / 2 || 2 * need > pbits)
		ආපසු SSH_ERR_INVALID_ARGUMENT;
	නම් (need < 256)
		need = 256;
	/*
	 * Pollard Rho, Big step/Little Step attacks are O(sqrt(n)),
	 * so double requested need here.
	 */
	නම් (!DH_set_length(dh, MINIMUM(need * 2, pbits - 1)))
		ආපසු SSH_ERR_LIBCRYPTO_ERROR;

	නම් (DH_generate_key(dh) == 0)
		ආපසු SSH_ERR_LIBCRYPTO_ERROR;
	DH_get0_key(dh, &pub_key, NULL);
	නම් (!dh_pub_is_valid(dh, pub_key))
		ආපසු SSH_ERR_INVALID_FORMAT;
	ආපසු 0;
}

DH *
dh_new_group_asc(const var_na *gen, const var_na *modulus)
{
	DH *dh;
	BIGNUM *dh_p = NULL, *dh_g = NULL;

	නම් ((dh = DH_new()) == NULL)
		ආපසු NULL;
	නම් (BN_hex2bn(&dh_p, modulus) == 0 ||
	    BN_hex2bn(&dh_g, gen) == 0)
		goto fail;
	නම් (!DH_set0_pqg(dh, dh_p, NULL, dh_g))
		goto fail;
	ආපසු dh;
 fail:
	DH_free(dh);
	BN_clear_free(dh_p);
	BN_clear_free(dh_g);
	ආපසු NULL;
}

/*
 * This just returns the group, we still need to generate the exchange
 * value.
 */
DH *
dh_new_group(BIGNUM *gen, BIGNUM *modulus)
{
	DH *dh;

	නම් ((dh = DH_new()) == NULL)
		ආපසු NULL;
	නම් (!DH_set0_pqg(dh, modulus, NULL, gen)) {
		DH_free(dh);
		ආපසු NULL;
	}

	ආපසු dh;
}

/* rfc2409 "Second Oakley Group" (1024 bits) */
DH *
dh_new_group1(void)
{
	static var_na *gen = "2", *group1 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	    "FFFFFFFF" "FFFFFFFF";

	ආපසු (dh_new_group_asc(gen, group1));
}

/* rfc3526 group 14 "2048-bit MODP Group" */
DH *
dh_new_group14(void)
{
	static var_na *gen = "2", *group14 =
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

	ආපසු (dh_new_group_asc(gen, group14));
}

/* rfc3526 group 16 "4096-bit MODP Group" */
DH *
dh_new_group16(void)
{
	static var_na *gen = "2", *group16 =
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

	ආපසු (dh_new_group_asc(gen, group16));
}

/* rfc3526 group 18 "8192-bit MODP Group" */
DH *
dh_new_group18(void)
{
	static var_na *gen = "2", *group18 =
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

	ආපසු (dh_new_group_asc(gen, group18));
}

/* Select fallback group used by DH-GEX if moduli file cannot be read. */
DH *
dh_new_group_fallback(පූර්ණ_සංඛ්‍යා max)
{
	debug3_f("requested max size %d", max);
	නම් (max < 3072) {
		debug3("using 2k bit group 14");
		ආපසු dh_new_group14();
	} නැතහොත් නම් (max < 6144) {
		debug3("using 4k bit group 16");
		ආපසු dh_new_group16();
	}
	debug3("using 8k bit group 18");
	ආපසු dh_new_group18();
}

/*
 * Estimates the group order for a Diffie-Hellman group that has an
 * attack complexity approximately the same as O(2**bits).
 * Values from NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 (rev 3) limited by the recommended maximum value
 * from RFC4419 section 3.
 */
u_int
dh_estimate(පූර්ණ_සංඛ්‍යා bits)
{
	නම් (bits <= 112)
		ආපසු 2048;
	නම් (bits <= 128)
		ආපසු 3072;
	නම් (bits <= 192)
		ආපසු 7680;
	ආපසු 8192;
}

#endif /* WITH_OPENSSL */
