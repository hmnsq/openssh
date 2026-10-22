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

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <sys/types.h>

বাহ্যিক "C" {
#অন্তর্ভাব "addr.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "log.h"
}

স্থির পূর্ণসংখ্যা log_initialized = 0;

স্থির অক্ষর *
dup_n(ধ্রুবক uint8_t *body, আকার_t blen)
{
	অক্ষর *s = (অক্ষর *)malloc(blen + 1);
	যদি (s == ফাঁকা)
		ফেরত ফাঁকা;
	memcpy(s, body, blen);
	s[blen] = '\0';
	ফেরত s;
}

স্থির শূন্য
split_two(ধ্রুবক uint8_t *body, আকার_t blen, অক্ষর **a, অক্ষর **b)
{
	ধ্রুবক uint8_t *nul = (ধ্রুবক uint8_t *)memchr(body, 0, blen);
	*a = ফাঁকা;
	*b = ফাঁকা;
	যদি (nul == ফাঁকা) {
		*a = dup_n(body, blen);
		*b = strdup("");
		ফেরত;
	}
	আকার_t alen = (আকার_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

বাহ্যিক "C" পূর্ণসংখ্যা
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	যদি (আকার_2 == 0)
		ফেরত 0;

	অক্ষর *s = dup_n(তথ্য, আকার_2);
	অক্ষর *a = ফাঁকা, *b = ফাঁকা;
	split_two(তথ্য, আকার_2, &a, &b);
	যদি (s == ফাঁকা || a == ফাঁকা || b == ফাঁকা) {
		মুক্ত(s);
		মুক্ত(a);
		মুক্ত(b);
		ফেরত 0;
	}

	{
		অক্ষর *u = ফাঁকা, *h = ফাঁকা;
		পূর্ণসংখ্যা port = 0;
		যদি (parse_user_host_port(s, &u, &h, &port) == 0) {
			মুক্ত(u);
			মুক্ত(h);
		}
	}
	{
		অক্ষর *u = ফাঁকা, *h = ফাঁকা, *p = ফাঁকা;
		পূর্ণসংখ্যা port = 0;
		যদি (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			মুক্ত(u);
			মুক্ত(h);
			মুক্ত(p);
		}
	}
	(শূন্য)convtime(s);
	(শূন্য)a2port(s);
	{
		পূর্ণসংখ্যা tun = 0;
		(শূন্য)a2tun(s, &tun);
	}
	{
		পূর্ণসংখ্যা ac = 0;
		অক্ষর **av = ফাঁকা;
		যদি (argv_split(s, &ac, &av, 1) == 0) {
			অক্ষর *back = argv_assemble(ac, av);
			মুক্ত(back);
			argv_free(av, ac);
		}
	}
	{
		ধ্রুবক অক্ষর *err = ফাঁকা;
		(শূন্য)valid_domain(s, 0, &err);
	}
	(শূন্য)valid_env_name(s);
	{
		uint64_t t = 0;
		(শূন্য)parse_absolute_time(s, &t);
	}

	{
		কাঠামো xaddr n;
		(শূন্য)addr_pton(s, &n);
	}
	{
		কাঠামো xaddr n;
		u_int prefix = 0;
		(শূন্য)addr_pton_cidr(s, &n, &prefix);
	}

	(শূন্য)addr_match_list(a, b);
	(শূন্য)addr_match_cidr_list(a, b);
	(শূন্য)match_pattern(a, b);
	(শূন্য)match_pattern_list(a, b, 0);
	(শূন্য)match_hostname(a, b);
	(শূন্য)match_host_and_ip(a, "127.0.0.1", b);
	(শূন্য)match_user("fuzz", a, "127.0.0.1", b);

	মুক্ত(s);
	মুক্ত(a);
	মুক্ত(b);
	ফেরত 0;
}
