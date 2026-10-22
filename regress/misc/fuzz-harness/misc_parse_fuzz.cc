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

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

ବାହ୍ୟ "C" {
#ଅନ୍ତର୍ଭାଵ "addr.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_initialized = 0;

ସ୍ଥିର ଅକ୍ଷର *
dup_n(ଅଚଳ uint8_t *body, size_t blen)
{
	ଅକ୍ଷର *s = (ଅକ୍ଷର *)malloc(blen + 1);
	ଯଦି (s == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	memcpy(s, body, blen);
	s[blen] = '\0';
	ଫେରନ୍ତୁ s;
}

ସ୍ଥିର ଶୂନ୍ୟ
split_two(ଅଚଳ uint8_t *body, size_t blen, ଅକ୍ଷର **a, ଅକ୍ଷର **b)
{
	ଅଚଳ uint8_t *nul = (ଅଚଳ uint8_t *)memchr(body, 0, blen);
	*a = ଖାଲି;
	*b = ଖାଲି;
	ଯଦି (nul == ଖାଲି) {
		*a = dup_n(body, blen);
		*b = strdup("");
		ଫେରନ୍ତୁ;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା
LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	ଯଦି (size == 0)
		ଫେରନ୍ତୁ 0;

	ଅକ୍ଷର *s = dup_n(data, size);
	ଅକ୍ଷର *a = ଖାଲି, *b = ଖାଲି;
	split_two(data, size, &a, &b);
	ଯଦି (s == ଖାଲି || a == ଖାଲି || b == ଖାଲି) {
		ମୁକ୍ତ(s);
		ମୁକ୍ତ(a);
		ମୁକ୍ତ(b);
		ଫେରନ୍ତୁ 0;
	}

	{
		ଅକ୍ଷର *u = ଖାଲି, *h = ଖାଲି;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା port = 0;
		ଯଦି (parse_user_host_port(s, &u, &h, &port) == 0) {
			ମୁକ୍ତ(u);
			ମୁକ୍ତ(h);
		}
	}
	{
		ଅକ୍ଷର *u = ଖାଲି, *h = ଖାଲି, *p = ଖାଲି;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା port = 0;
		ଯଦି (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			ମୁକ୍ତ(u);
			ମୁକ୍ତ(h);
			ମୁକ୍ତ(p);
		}
	}
	(ଶୂନ୍ୟ)convtime(s);
	(ଶୂନ୍ୟ)a2port(s);
	{
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା tun = 0;
		(ଶୂନ୍ୟ)a2tun(s, &tun);
	}
	{
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac = 0;
		ଅକ୍ଷର **av = ଖାଲି;
		ଯଦି (argv_split(s, &ac, &av, 1) == 0) {
			ଅକ୍ଷର *back = argv_assemble(ac, av);
			ମୁକ୍ତ(back);
			argv_free(av, ac);
		}
	}
	{
		ଅଚଳ ଅକ୍ଷର *err = ଖାଲି;
		(ଶୂନ୍ୟ)valid_domain(s, 0, &err);
	}
	(ଶୂନ୍ୟ)valid_env_name(s);
	{
		uint64_t t = 0;
		(ଶୂନ୍ୟ)parse_absolute_time(s, &t);
	}

	{
		ସଂରଚନା xaddr n;
		(ଶୂନ୍ୟ)addr_pton(s, &n);
	}
	{
		ସଂରଚନା xaddr n;
		u_int prefix = 0;
		(ଶୂନ୍ୟ)addr_pton_cidr(s, &n, &prefix);
	}

	(ଶୂନ୍ୟ)addr_match_list(a, b);
	(ଶୂନ୍ୟ)addr_match_cidr_list(a, b);
	(ଶୂନ୍ୟ)match_pattern(a, b);
	(ଶୂନ୍ୟ)match_pattern_list(a, b, 0);
	(ଶୂନ୍ୟ)match_hostname(a, b);
	(ଶୂନ୍ୟ)match_host_and_ip(a, "127.0.0.1", b);
	(ଶୂନ୍ୟ)match_user("fuzz", a, "127.0.0.1", b);

	ମୁକ୍ତ(s);
	ମୁକ୍ତ(a);
	ମୁକ୍ତ(b);
	ଫେରନ୍ତୁ 0;
}
