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

#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <sys/types.h>

বাহ্য "C" {
#অন্তর্ভাৱ "addr.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "log.h"
}

স্থির পূর্ণাঙ্ক log_initialized = 0;

স্থির ৱর্ণ *
dup_n(ধ্রুৱ uint8_t *body, size_t blen)
{
	ৱর্ণ *s = (ৱর্ণ *)malloc(blen + 1);
	যদি (s == রিক্ত)
		ঘূৰাই রিক্ত;
	memcpy(s, body, blen);
	s[blen] = '\0';
	ঘূৰাই s;
}

স্থির শূন্য
split_two(ধ্রুৱ uint8_t *body, size_t blen, ৱর্ণ **a, ৱর্ণ **b)
{
	ধ্রুৱ uint8_t *nul = (ধ্রুৱ uint8_t *)memchr(body, 0, blen);
	*a = রিক্ত;
	*b = রিক্ত;
	যদি (nul == রিক্ত) {
		*a = dup_n(body, blen);
		*b = strdup("");
		ঘূৰাই;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

বাহ্য "C" পূর্ণাঙ্ক
LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t *data, size_t size)
{
	যদি (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	যদি (size == 0)
		ঘূৰাই 0;

	ৱর্ণ *s = dup_n(data, size);
	ৱর্ণ *a = রিক্ত, *b = রিক্ত;
	split_two(data, size, &a, &b);
	যদি (s == রিক্ত || a == রিক্ত || b == রিক্ত) {
		মুক্ত(s);
		মুক্ত(a);
		মুক্ত(b);
		ঘূৰাই 0;
	}

	{
		ৱর্ণ *u = রিক্ত, *h = রিক্ত;
		পূর্ণাঙ্ক port = 0;
		যদি (parse_user_host_port(s, &u, &h, &port) == 0) {
			মুক্ত(u);
			মুক্ত(h);
		}
	}
	{
		ৱর্ণ *u = রিক্ত, *h = রিক্ত, *p = রিক্ত;
		পূর্ণাঙ্ক port = 0;
		যদি (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			মুক্ত(u);
			মুক্ত(h);
			মুক্ত(p);
		}
	}
	(শূন্য)convtime(s);
	(শূন্য)a2port(s);
	{
		পূর্ণাঙ্ক tun = 0;
		(শূন্য)a2tun(s, &tun);
	}
	{
		পূর্ণাঙ্ক ac = 0;
		ৱর্ণ **av = রিক্ত;
		যদি (argv_split(s, &ac, &av, 1) == 0) {
			ৱর্ণ *back = argv_assemble(ac, av);
			মুক্ত(back);
			argv_free(av, ac);
		}
	}
	{
		ধ্রুৱ ৱর্ণ *err = রিক্ত;
		(শূন্য)valid_domain(s, 0, &err);
	}
	(শূন্য)valid_env_name(s);
	{
		uint64_t t = 0;
		(শূন্য)parse_absolute_time(s, &t);
	}

	{
		সংরচনা xaddr n;
		(শূন্য)addr_pton(s, &n);
	}
	{
		সংরচনা xaddr n;
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
	ঘূৰাই 0;
}
