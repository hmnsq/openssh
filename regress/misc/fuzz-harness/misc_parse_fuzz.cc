/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for small string-input parsers across OpenSSH
 *
 * Targets: misc.c, addr.c, addrmatch.c, match.c
 *
 * Threat model:
 * - User-supplied CLI arguments (user@host:port, ssh:// URIs, port and
 *   tunnel numbers)
 * - Admin-supplied patterns in sshd_config / ssh_config (Match Address
 *   CIDR lists, AllowUsers / DenyUsers, AllowGroups, hostname patterns)
 *
 * All targeted functions are pure (no inter-call state). Each iteration
 * invokes every parser exactly once on the same fuzz body in a fixed
 * source order. The body is split into two substrings at the first
 * embedded NUL so two-argument matchers can mutate either side.
 *
 * Parsers covered:
 * - parse_user_host_port, parse_uri, convtime, a2port, a2tun,
 *   argv_split + argv_assemble, valid_domain, valid_env_name,
 *   parse_absolute_time (misc.c)
 * - addr_pton, addr_pton_cidr (addr.c)
 * - addr_match_list, addr_match_cidr_list (addrmatch.c)
 * - match_pattern, match_pattern_list, match_hostname,
 *   match_host_and_ip, match_user (match.c)
 */

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

ಬಾಹ್ಯ "C" {
#ಅನ್ತರ್ಭಾವ "addr.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ log_initialized = 0;

ಸ್ಥಿರ ಅಕ್ಷರ *
dup_n(ಸ್ಥಿರಾಂಕ uint8_t *body, ಗಾತ್ರ_t blen)
{
	ಅಕ್ಷರ *s = (ಅಕ್ಷರ *)ಸ್ಮರಣೆ_ಕೊಡು(blen + 1);
	ಆದರೆ (s == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಸ್ಮರಣೆ_ನಕಲು(s, body, blen);
	s[blen] = '\0';
	ಹಿಂತಿರುಗಿ s;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ವಿಭಜಿಸು_two(ಸ್ಥಿರಾಂಕ uint8_t *body, ಗಾತ್ರ_t blen, ಅಕ್ಷರ **a, ಅಕ್ಷರ **b)
{
	ಸ್ಥಿರಾಂಕ uint8_t *nul = (ಸ್ಥಿರಾಂಕ uint8_t *)memchr(body, 0, blen);
	*a = ಖಾಲಿ;
	*b = ಖಾಲಿ;
	ಆದರೆ (nul == ಖಾಲಿ) {
		*a = dup_n(body, blen);
		*b = strdup("");
		ಹಿಂತಿರುಗಿ;
	}
	ಗಾತ್ರ_t alen = (ಗಾತ್ರ_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	ಆದರೆ (ಗಾತ್ರ_2 == 0)
		ಹಿಂತಿರುಗಿ 0;

	ಅಕ್ಷರ *s = dup_n(ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	ಅಕ್ಷರ *a = ಖಾಲಿ, *b = ಖಾಲಿ;
	ವಿಭಜಿಸು_two(ದತ್ತಾಂಶ, ಗಾತ್ರ_2, &a, &b);
	ಆದರೆ (s == ಖಾಲಿ || a == ಖಾಲಿ || b == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(s);
		ಬಿಡುಗಡೆ(a);
		ಬಿಡುಗಡೆ(b);
		ಹಿಂತಿರುಗಿ 0;
	}

	{
		ಅಕ್ಷರ *u = ಖಾಲಿ, *h = ಖಾಲಿ;
		ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್ = 0;
		ಆದರೆ (parse_user_host_ಪೋರ್ಟ್(s, &u, &h, &ಪೋರ್ಟ್) == 0) {
			ಬಿಡುಗಡೆ(u);
			ಬಿಡುಗಡೆ(h);
		}
	}
	{
		ಅಕ್ಷರ *u = ಖಾಲಿ, *h = ಖಾಲಿ, *p = ಖಾಲಿ;
		ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್ = 0;
		ಆದರೆ (parse_uri("ssh", s, &u, &h, &ಪೋರ್ಟ್, &p) == 0) {
			ಬಿಡುಗಡೆ(u);
			ಬಿಡುಗಡೆ(h);
			ಬಿಡುಗಡೆ(p);
		}
	}
	(ಶೂನ್ಯ)convtime(s);
	(ಶೂನ್ಯ)a2port(s);
	{
		ಪೂರ್ಣಾಂಕ tun = 0;
		(ಶೂನ್ಯ)a2tun(s, &tun);
	}
	{
		ಪೂರ್ಣಾಂಕ ac = 0;
		ಅಕ್ಷರ **av = ಖಾಲಿ;
		ಆದರೆ (argv_ವಿಭಜಿಸು(s, &ac, &av, 1) == 0) {
			ಅಕ್ಷರ *ಹಿಂಭಾಗ = argv_assemble(ac, av);
			ಬಿಡುಗಡೆ(ಹಿಂಭಾಗ);
			argv_free(av, ac);
		}
	}
	{
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *err = ಖಾಲಿ;
		(ಶೂನ್ಯ)valid_domain(s, 0, &err);
	}
	(ಶೂನ್ಯ)valid_env_name(s);
	{
		uint64_t t = 0;
		(ಶೂನ್ಯ)parse_absolute_ಸಮಯ(s, &t);
	}

	{
		ರಚನೆ xaddr n;
		(ಶೂನ್ಯ)addr_pton(s, &n);
	}
	{
		ರಚನೆ xaddr n;
		u_int ಪೂರ್ವಪ್ರತ್ಯಯ = 0;
		(ಶೂನ್ಯ)addr_pton_cidr(s, &n, &ಪೂರ್ವಪ್ರತ್ಯಯ);
	}

	(ಶೂನ್ಯ)addr_ಹೊಂದಿಕೆ_list(a, b);
	(ಶೂನ್ಯ)addr_ಹೊಂದಿಕೆ_cidr_list(a, b);
	(ಶೂನ್ಯ)ಹೊಂದಿಕೆ_ನಮೂನೆ(a, b);
	(ಶೂನ್ಯ)ಹೊಂದಿಕೆ_ನಮೂನೆ_list(a, b, 0);
	(ಶೂನ್ಯ)ಹೊಂದಿಕೆ_hostname(a, b);
	(ಶೂನ್ಯ)ಹೊಂದಿಕೆ_host_and_ip(a, "127.0.0.1", b);
	(ಶೂನ್ಯ)ಹೊಂದಿಕೆ_user("fuzz", a, "127.0.0.1", b);

	ಬಿಡುಗಡೆ(s);
	ಬಿಡುಗಡೆ(a);
	ಬಿಡುಗಡೆ(b);
	ಹಿಂತಿರುಗಿ 0;
}
