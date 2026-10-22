/* $OpenBSD: dispatch.h,v 1.16 2026/03/03 09:57:25 dtucker Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#अगर_अघोषित DISPATCH_H
#घोषणा DISPATCH_H

#घोषणा DISPATCH_MAX	255

क्रमागत {
	DISPATCH_BLOCK,
	DISPATCH_NONBLOCK
};

काष्ठा ssh;

प्रकार पूर्णांक dispatch_fn(पूर्णांक, uint32_t, काष्ठा ssh *);

पूर्णांक	dispatch_protocol_error(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	dispatch_protocol_ignore(पूर्णांक, uint32_t, काष्ठा ssh *);
व्योम	ssh_dispatch_init(काष्ठा ssh *, dispatch_fn *);
व्योम	ssh_dispatch_set(काष्ठा ssh *, पूर्णांक, dispatch_fn *);
व्योम	ssh_dispatch_range(काष्ठा ssh *, u_int, u_int, dispatch_fn *);
पूर्णांक	ssh_dispatch_run(काष्ठा ssh *, पूर्णांक, अस्थिर संक_पूर्ण_प्रकार *);
व्योम	ssh_dispatch_run_fatal(काष्ठा ssh *, पूर्णांक, अस्थिर संक_पूर्ण_प्रकार *);

#पूर्ण_अगर
