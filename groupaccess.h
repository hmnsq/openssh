/* $OpenBSD: groupaccess.h,v 1.8 2008/07/04 03:44:59 djm Exp $ */

/*
 * Copyright (c) 2001 Kevin Steves.  All rights reserved.
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ GROUPACCESS_H
#ವ್ಯಾಖ್ಯಾನಿಸು GROUPACCESS_H

ಪೂರ್ಣಾಂಕ	 ga_init(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, gid_t);
ಪೂರ್ಣಾಂಕ	 ga_ಹೊಂದಿಕೆ(ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ga_ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 ga_free(ಶೂನ್ಯ);

#ಆದರೆ_ಅಂತ್ಯ
