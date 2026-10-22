/*	$OpenBSD: queue.h,v 1.45 2018/07/12 14:22:54 sashan Exp $	*/
/*	$NetBSD: queue.h,v 1.11 1996/05/16 05:17:14 mycroft Exp $	*/

/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */

/* OPENBSD ORIGINAL: sys/sys/queue.h */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ	FAKE_ಸರತಿ_H
#ವ್ಯಾಖ್ಯಾನಿಸು	FAKE_ಸರತಿ_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_EMPTY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_ಕೊನೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_ENTRY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_FIRST
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_FOREACH
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_FOREACH_REVERSE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_HEAD_INITIALIZER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_INIT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_INSERT_AFTER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_INSERT_BEFORE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_INSERT_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_INSERT_TAIL
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_LAST
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_NEXT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_PREV
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_REMOVE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CIRCLEQ_REPLACE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_EMPTY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_ಕೊನೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_ENTRY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_FIRST
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_FOREACH
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_FOREACH_ಸುರಕ್ಷಿತ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_HEAD_INITIALIZER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_INIT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_INSERT_AFTER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_INSERT_BEFORE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_INSERT_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_NEXT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_REMOVE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು LIST_REPLACE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_CONCAT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_EMPTY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_ಕೊನೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_ENTRY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_FIRST
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_FOREACH
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_FOREACH_ಸುರಕ್ಷಿತ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_HEAD_INITIALIZER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_INIT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_INSERT_AFTER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_INSERT_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_INSERT_TAIL
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_NEXT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_REMOVE_AFTER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SIMPLEQ_REMOVE_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_EMPTY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_ಕೊನೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_ENTRY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_FIRST
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_FOREACH
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_FOREACH_PREVPTR
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_FOREACH_ಸುರಕ್ಷಿತ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_HEAD_INITIALIZER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_INIT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_INSERT_AFTER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_INSERT_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_NEXT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_REMOVE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_REMOVE_AFTER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_REMOVE_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SLIST_REMOVE_ಮುಂದಿನ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_CONCAT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_EMPTY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_ಕೊನೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_ENTRY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_FIRST
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_FOREACH
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_FOREACH_ಹಿಮ್ಮುಖ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_FOREACH_ಹಿಮ್ಮುಖ_ಸುರಕ್ಷಿತ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_FOREACH_ಸುರಕ್ಷಿತ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_HEAD_INITIALIZER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_INIT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_INSERT_AFTER
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_INSERT_BEFORE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_INSERT_HEAD
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_INSERT_TAIL
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_LAST
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_NEXT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_PREV
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_REMOVE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TAILQ_REPLACE

/*
 * This file defines five types of data structures: singly-linked lists,
 * lists, simple queues, tail queues and XOR simple queues.
 *
 *
 * A singly-linked list is headed by a single forward pointer. The elements
 * are singly linked for minimum space and pointer manipulation overhead at
 * the expense of O(n) removal for arbitrary elements. New elements can be
 * added to the list after an existing element or at the head of the list.
 * Elements being removed from the head of the list should use the explicit
 * macro for this purpose for optimum efficiency. A singly-linked list may
 * only be traversed in the forward direction.  Singly-linked lists are ideal
 * for applications with large datasets and few or no removals or for
 * implementing a LIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list before or after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * An XOR simple queue is used in the same way as a regular simple queue.
 * The difference is that the head structure also includes a "cookie" that
 * is XOR'd with the queue pointer (first, last or next) to generate the
 * real pointer value.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

#ಆದರೆ defined(ಸರತಿ_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#ವ್ಯಾಖ್ಯಾನಿಸು _Q_INVALID ((ಶೂನ್ಯ *)-1)
#ವ್ಯಾಖ್ಯಾನಿಸು _Q_INVALIDATE(a) (a) = _Q_INVALID
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು _Q_INVALIDATE(a)
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Singly-linked List definitions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SLIST_HEAD(name, type)						\
ರಚನೆ name {								\
	ರಚನೆ type *slh_ಮೊದಲ;	/* first element */			\
}

#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_HEAD_INITIALIZER(ತಲೆ)					\
	{ ಖಾಲಿ }

#ವ್ಯಾಖ್ಯಾನಿಸು SLIST_ENTRY(type)						\
ರಚನೆ {								\
	ರಚನೆ type *sle_ಮುಂದಿನ;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_FIRST(ತಲೆ)	((ತಲೆ)->slh_ಮೊದಲ)
#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_ಕೊನೆ(ತಲೆ)		ಖಾಲಿ
#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_EMPTY(ತಲೆ)	(SLIST_FIRST(ತಲೆ) == SLIST_ಕೊನೆ(ತಲೆ))
#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_NEXT(elm, ಕ್ಷೇತ್ರ)	((elm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ)

#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_FOREACH(var, ತಲೆ, ಕ್ಷೇತ್ರ)					\
	ಗಾಗಿ((var) = SLIST_FIRST(ತಲೆ);					\
	    (var) != SLIST_ಕೊನೆ(ತಲೆ);					\
	    (var) = SLIST_NEXT(var, ಕ್ಷೇತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_FOREACH_ಸುರಕ್ಷಿತ(var, ತಲೆ, ಕ್ಷೇತ್ರ, tvar)			\
	ಗಾಗಿ ((var) = SLIST_FIRST(ತಲೆ);				\
	    (var) && ((tvar) = SLIST_NEXT(var, ಕ್ಷೇತ್ರ), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_INIT(ತಲೆ) {						\
	SLIST_FIRST(ತಲೆ) = SLIST_ಕೊನೆ(ತಲೆ);				\
}

#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_INSERT_AFTER(slistelm, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(elm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ = (slistelm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ;		\
	(slistelm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ = (elm);				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_INSERT_HEAD(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(elm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ = (ತಲೆ)->slh_ಮೊದಲ;			\
	(ತಲೆ)->slh_ಮೊದಲ = (elm);					\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_REMOVE_AFTER(elm, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	(elm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ = (elm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ;	\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು	SLIST_REMOVE_HEAD(ತಲೆ, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	(ತಲೆ)->slh_ಮೊದಲ = (ತಲೆ)->slh_ಮೊದಲ->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ;		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SLIST_REMOVE(ತಲೆ, elm, type, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ ((ತಲೆ)->slh_ಮೊದಲ == (elm)) {				\
		SLIST_REMOVE_HEAD((ತಲೆ), ಕ್ಷೇತ್ರ);			\
	} ಇಲ್ಲದಿದ್ದರೆ {							\
		ರಚನೆ type *curelm = (ತಲೆ)->slh_ಮೊದಲ;		\
									\
		ಆಗ (curelm->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ != (elm))			\
			curelm = curelm->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ;		\
		curelm->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ =				\
		    curelm->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ;		\
	}								\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.sle_ಮುಂದಿನ);				\
} ಆಗ (0)

/*
 * List definitions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು LIST_HEAD(name, type)						\
ರಚನೆ name {								\
	ರಚನೆ type *lh_ಮೊದಲ;	/* first element */			\
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIST_HEAD_INITIALIZER(ತಲೆ)					\
	{ ಖಾಲಿ }

#ವ್ಯಾಖ್ಯಾನಿಸು LIST_ENTRY(type)						\
ರಚನೆ {								\
	ರಚನೆ type *le_ಮುಂದಿನ;	/* next element */			\
	ರಚನೆ type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	LIST_FIRST(ತಲೆ)		((ತಲೆ)->lh_ಮೊದಲ)
#ವ್ಯಾಖ್ಯಾನಿಸು	LIST_ಕೊನೆ(ತಲೆ)			ಖಾಲಿ
#ವ್ಯಾಖ್ಯಾನಿಸು	LIST_EMPTY(ತಲೆ)		(LIST_FIRST(ತಲೆ) == LIST_ಕೊನೆ(ತಲೆ))
#ವ್ಯಾಖ್ಯಾನಿಸು	LIST_NEXT(elm, ಕ್ಷೇತ್ರ)		((elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ)

#ವ್ಯಾಖ್ಯಾನಿಸು LIST_FOREACH(var, ತಲೆ, ಕ್ಷೇತ್ರ)					\
	ಗಾಗಿ((var) = LIST_FIRST(ತಲೆ);					\
	    (var)!= LIST_ಕೊನೆ(ತಲೆ);					\
	    (var) = LIST_NEXT(var, ಕ್ಷೇತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು	LIST_FOREACH_ಸುರಕ್ಷಿತ(var, ತಲೆ, ಕ್ಷೇತ್ರ, tvar)			\
	ಗಾಗಿ ((var) = LIST_FIRST(ತಲೆ);				\
	    (var) && ((tvar) = LIST_NEXT(var, ಕ್ಷೇತ್ರ), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	LIST_INIT(ತಲೆ) ಮಾಡು {						\
	LIST_FIRST(ತಲೆ) = LIST_ಕೊನೆ(ತಲೆ);				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು LIST_INSERT_AFTER(listelm, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ = (listelm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ) != ಖಾಲಿ)	\
		(listelm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ->ಕ್ಷೇತ್ರ.le_prev =		\
		    &(elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ;				\
	(listelm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ = (elm);				\
	(elm)->ಕ್ಷೇತ್ರ.le_prev = &(listelm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ;		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು	LIST_INSERT_BEFORE(listelm, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(elm)->ಕ್ಷೇತ್ರ.le_prev = (listelm)->ಕ್ಷೇತ್ರ.le_prev;		\
	(elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ = (listelm);				\
	*(listelm)->ಕ್ಷೇತ್ರ.le_prev = (elm);				\
	(listelm)->ಕ್ಷೇತ್ರ.le_prev = &(elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ;		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು LIST_INSERT_HEAD(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ = (ತಲೆ)->lh_ಮೊದಲ) != ಖಾಲಿ)		\
		(ತಲೆ)->lh_ಮೊದಲ->ಕ್ಷೇತ್ರ.le_prev = &(elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ;\
	(ತಲೆ)->lh_ಮೊದಲ = (elm);					\
	(elm)->ಕ್ಷೇತ್ರ.le_prev = &(ತಲೆ)->lh_ಮೊದಲ;			\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು LIST_REMOVE(elm, ಕ್ಷೇತ್ರ) ಮಾಡು {					\
	ಆದರೆ ((elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ != ಖಾಲಿ)				\
		(elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ->ಕ್ಷೇತ್ರ.le_prev =			\
		    (elm)->ಕ್ಷೇತ್ರ.le_prev;				\
	*(elm)->ಕ್ಷೇತ್ರ.le_prev = (elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ;			\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.le_prev);				\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ);				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು LIST_REPLACE(elm, elm2, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	ಆದರೆ (((elm2)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ = (elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ) != ಖಾಲಿ)	\
		(elm2)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ->ಕ್ಷೇತ್ರ.le_prev =			\
		    &(elm2)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ;				\
	(elm2)->ಕ್ಷೇತ್ರ.le_prev = (elm)->ಕ್ಷೇತ್ರ.le_prev;			\
	*(elm2)->ಕ್ಷೇತ್ರ.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.le_prev);				\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.le_ಮುಂದಿನ);				\
} ಆಗ (0)

/*
 * Simple queue definitions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_HEAD(name, type)					\
ರಚನೆ name {								\
	ರಚನೆ type *sqh_ಮೊದಲ;	/* first element */			\
	ರಚನೆ type **sqh_ಕೊನೆಯ;	/* addr of last next element */		\
}

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_HEAD_INITIALIZER(ತಲೆ)					\
	{ ಖಾಲಿ, &(ತಲೆ).sqh_ಮೊದಲ }

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_ENTRY(type)						\
ರಚನೆ {								\
	ರಚನೆ type *sqe_ಮುಂದಿನ;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	SIMPLEQ_FIRST(ತಲೆ)	    ((ತಲೆ)->sqh_ಮೊದಲ)
#ವ್ಯಾಖ್ಯಾನಿಸು	SIMPLEQ_ಕೊನೆ(ತಲೆ)	    ಖಾಲಿ
#ವ್ಯಾಖ್ಯಾನಿಸು	SIMPLEQ_EMPTY(ತಲೆ)	    (SIMPLEQ_FIRST(ತಲೆ) == SIMPLEQ_ಕೊನೆ(ತಲೆ))
#ವ್ಯಾಖ್ಯಾನಿಸು	SIMPLEQ_NEXT(elm, ಕ್ಷೇತ್ರ)    ((elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ)

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_FOREACH(var, ತಲೆ, ಕ್ಷೇತ್ರ)				\
	ಗಾಗಿ((var) = SIMPLEQ_FIRST(ತಲೆ);				\
	    (var) != SIMPLEQ_ಕೊನೆ(ತಲೆ);					\
	    (var) = SIMPLEQ_NEXT(var, ಕ್ಷೇತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು	SIMPLEQ_FOREACH_ಸುರಕ್ಷಿತ(var, ತಲೆ, ಕ್ಷೇತ್ರ, tvar)			\
	ಗಾಗಿ ((var) = SIMPLEQ_FIRST(ತಲೆ);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, ಕ್ಷೇತ್ರ), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	SIMPLEQ_INIT(ತಲೆ) ಮಾಡು {						\
	(ತಲೆ)->sqh_ಮೊದಲ = ಖಾಲಿ;					\
	(ತಲೆ)->sqh_ಕೊನೆಯ = &(ತಲೆ)->sqh_ಮೊದಲ;				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_INSERT_HEAD(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ = (ತಲೆ)->sqh_ಮೊದಲ) == ಖಾಲಿ)	\
		(ತಲೆ)->sqh_ಕೊನೆಯ = &(elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ;		\
	(ತಲೆ)->sqh_ಮೊದಲ = (elm);					\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_INSERT_TAIL(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ = ಖಾಲಿ;					\
	*(ತಲೆ)->sqh_ಕೊನೆಯ = (elm);					\
	(ತಲೆ)->sqh_ಕೊನೆಯ = &(elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ;			\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_INSERT_AFTER(ತಲೆ, listelm, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {		\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ = (listelm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ) == ಖಾಲಿ)\
		(ತಲೆ)->sqh_ಕೊನೆಯ = &(elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ;		\
	(listelm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ = (elm);				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_REMOVE_HEAD(ತಲೆ, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((ತಲೆ)->sqh_ಮೊದಲ = (ತಲೆ)->sqh_ಮೊದಲ->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ) == ಖಾಲಿ) \
		(ತಲೆ)->sqh_ಕೊನೆಯ = &(ತಲೆ)->sqh_ಮೊದಲ;			\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_REMOVE_AFTER(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ = (elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ) \
	    == ಖಾಲಿ)							\
		(ತಲೆ)->sqh_ಕೊನೆಯ = &(elm)->ಕ್ಷೇತ್ರ.sqe_ಮುಂದಿನ;		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SIMPLEQ_CONCAT(head1, head2) ಮಾಡು {				\
	ಆದರೆ (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_ಕೊನೆಯ = (head2)->sqh_ಮೊದಲ;		\
		(head1)->sqh_ಕೊನೆಯ = (head2)->sqh_ಕೊನೆಯ;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} ಆಗ (0)

/*
 * XOR Simple queue definitions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_ತಲೆ(name, type)					\
ರಚನೆ name {								\
	ರಚನೆ type *sqx_ಮೊದಲ;	/* first element */			\
	ರಚನೆ type **sqx_ಕೊನೆಯ;	/* addr of last next element */		\
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ sqx_cookie;					\
}

#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_ನಮೂದು(type)						\
ರಚನೆ {								\
	ರಚನೆ type *sqx_ಮುಂದಿನ;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_XOR(ತಲೆ, ptr)	    ((__typeof(ptr))((ತಲೆ)->sqx_cookie ^ \
					(ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)(ptr)))
#ವ್ಯಾಖ್ಯಾನಿಸು	XSIMPLEQ_ಮೊದಲ(ತಲೆ)	    XSIMPLEQ_XOR(ತಲೆ, ((ತಲೆ)->sqx_ಮೊದಲ))
#ವ್ಯಾಖ್ಯಾನಿಸು	XSIMPLEQ_ಕೊನೆ(ತಲೆ)	    ಖಾಲಿ
#ವ್ಯಾಖ್ಯಾನಿಸು	XSIMPLEQ_ಖಾಲಿಗಳು(ತಲೆ)	    (XSIMPLEQ_ಮೊದಲ(ತಲೆ) == XSIMPLEQ_ಕೊನೆ(ತಲೆ))
#ವ್ಯಾಖ್ಯಾನಿಸು	XSIMPLEQ_ಮುಂದಿನ(ತಲೆ, elm, ಕ್ಷೇತ್ರ)    XSIMPLEQ_XOR(ತಲೆ, ((elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ))


#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_FOREACH(var, ತಲೆ, ಕ್ಷೇತ್ರ)				\
	ಗಾಗಿ ((var) = XSIMPLEQ_ಮೊದಲ(ತಲೆ);				\
	    (var) != XSIMPLEQ_ಕೊನೆ(ತಲೆ);				\
	    (var) = XSIMPLEQ_ಮುಂದಿನ(ತಲೆ, var, ಕ್ಷೇತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು	XSIMPLEQ_FOREACH_ಸುರಕ್ಷಿತ(var, ತಲೆ, ಕ್ಷೇತ್ರ, tvar)			\
	ಗಾಗಿ ((var) = XSIMPLEQ_ಮೊದಲ(ತಲೆ);				\
	    (var) && ((tvar) = XSIMPLEQ_ಮುಂದಿನ(ತಲೆ, var, ಕ್ಷೇತ್ರ), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	XSIMPLEQ_INIT(ತಲೆ) ಮಾಡು {					\
	arc4random_buf(&(ತಲೆ)->sqx_cookie, ಗಾತ್ರ((ತಲೆ)->sqx_cookie)); \
	(ತಲೆ)->sqx_ಮೊದಲ = XSIMPLEQ_XOR(ತಲೆ, ಖಾಲಿ);			\
	(ತಲೆ)->sqx_ಕೊನೆಯ = XSIMPLEQ_XOR(ತಲೆ, &(ತಲೆ)->sqx_ಮೊದಲ);	\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_ಸೇರಿಸು_ತಲೆ(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ = (ತಲೆ)->sqx_ಮೊದಲ) ==		\
	    XSIMPLEQ_XOR(ತಲೆ, ಖಾಲಿ))					\
		(ತಲೆ)->sqx_ಕೊನೆಯ = XSIMPLEQ_XOR(ತಲೆ, &(elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ); \
	(ತಲೆ)->sqx_ಮೊದಲ = XSIMPLEQ_XOR(ತಲೆ, (elm));			\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_ಸೇರಿಸು_ಬಾಲ(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ = XSIMPLEQ_XOR(ತಲೆ, ಖಾಲಿ);		\
	*(XSIMPLEQ_XOR(ತಲೆ, (ತಲೆ)->sqx_ಕೊನೆಯ)) = XSIMPLEQ_XOR(ತಲೆ, (elm)); \
	(ತಲೆ)->sqx_ಕೊನೆಯ = XSIMPLEQ_XOR(ತಲೆ, &(elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ);	\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_ಸೇರಿಸು_AFTER(ತಲೆ, listelm, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {		\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ = (listelm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ) ==	\
	    XSIMPLEQ_XOR(ತಲೆ, ಖಾಲಿ))					\
		(ತಲೆ)->sqx_ಕೊನೆಯ = XSIMPLEQ_XOR(ತಲೆ, &(elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ); \
	(listelm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ = XSIMPLEQ_XOR(ತಲೆ, (elm));		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_REMOVE_ತಲೆ(ತಲೆ, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	ಆದರೆ (((ತಲೆ)->sqx_ಮೊದಲ = XSIMPLEQ_XOR(ತಲೆ,			\
	    (ತಲೆ)->sqx_ಮೊದಲ)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ) == XSIMPLEQ_XOR(ತಲೆ, ಖಾಲಿ)) \
		(ತಲೆ)->sqx_ಕೊನೆಯ = XSIMPLEQ_XOR(ತಲೆ, &(ತಲೆ)->sqx_ಮೊದಲ); \
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು XSIMPLEQ_REMOVE_AFTER(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ = XSIMPLEQ_XOR(ತಲೆ,			\
	    (elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ)			\
	    == XSIMPLEQ_XOR(ತಲೆ, ಖಾಲಿ))				\
		(ತಲೆ)->sqx_ಕೊನೆಯ = 					\
		    XSIMPLEQ_XOR(ತಲೆ, &(elm)->ಕ್ಷೇತ್ರ.sqx_ಮುಂದಿನ);		\
} ಆಗ (0)


/*
 * Tail queue definitions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_HEAD(name, type)						\
ರಚನೆ name {								\
	ರಚನೆ type *tqh_first;	/* first element */			\
	ರಚನೆ type **tqh_last;	/* addr of last next element */		\
}

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_HEAD_INITIALIZER(ತಲೆ)					\
	{ ಖಾಲಿ, &(ತಲೆ).tqh_first }

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_ENTRY(type)						\
ರಚನೆ {								\
	ರಚನೆ type *tqe_next;	/* next element */			\
	ರಚನೆ type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_FIRST(ತಲೆ)		((ತಲೆ)->tqh_first)
#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_ಕೊನೆ(ತಲೆ)			ಖಾಲಿ
#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_NEXT(elm, ಕ್ಷೇತ್ರ)		((elm)->ಕ್ಷೇತ್ರ.tqe_next)
#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_LAST(ತಲೆ, headname)					\
	(*(((ರಚನೆ headname *)((ತಲೆ)->tqh_last))->tqh_last))
/* XXX */
#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_PREV(elm, headname, ಕ್ಷೇತ್ರ)				\
	(*(((ರಚನೆ headname *)((elm)->ಕ್ಷೇತ್ರ.tqe_prev))->tqh_last))
#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_EMPTY(ತಲೆ)						\
	(TAILQ_FIRST(ತಲೆ) == TAILQ_ಕೊನೆ(ತಲೆ))

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_FOREACH(var, ತಲೆ, ಕ್ಷೇತ್ರ)					\
	ಗಾಗಿ((var) = TAILQ_FIRST(ತಲೆ);					\
	    (var) != TAILQ_ಕೊನೆ(ತಲೆ);					\
	    (var) = TAILQ_NEXT(var, ಕ್ಷೇತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_FOREACH_ಸುರಕ್ಷಿತ(var, ತಲೆ, ಕ್ಷೇತ್ರ, tvar)			\
	ಗಾಗಿ ((var) = TAILQ_FIRST(ತಲೆ);					\
	    (var) != TAILQ_ಕೊನೆ(ತಲೆ) &&					\
	    ((tvar) = TAILQ_NEXT(var, ಕ್ಷೇತ್ರ), 1);			\
	    (var) = (tvar))


#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_FOREACH_ಹಿಮ್ಮುಖ(var, ತಲೆ, headname, ಕ್ಷೇತ್ರ)		\
	ಗಾಗಿ((var) = TAILQ_LAST(ತಲೆ, headname);				\
	    (var) != TAILQ_ಕೊನೆ(ತಲೆ);					\
	    (var) = TAILQ_PREV(var, headname, ಕ್ಷೇತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_FOREACH_ಹಿಮ್ಮುಖ_ಸುರಕ್ಷಿತ(var, ತಲೆ, headname, ಕ್ಷೇತ್ರ, tvar)	\
	ಗಾಗಿ ((var) = TAILQ_LAST(ತಲೆ, headname);			\
	    (var) != TAILQ_ಕೊನೆ(ತಲೆ) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, ಕ್ಷೇತ್ರ), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_INIT(ತಲೆ) ಮಾಡು {						\
	(ತಲೆ)->tqh_first = ಖಾಲಿ;					\
	(ತಲೆ)->tqh_last = &(ತಲೆ)->tqh_first;				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_INSERT_HEAD(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.tqe_next = (ತಲೆ)->tqh_first) != ಖಾಲಿ)	\
		(ತಲೆ)->tqh_first->ಕ್ಷೇತ್ರ.tqe_prev =			\
		    &(elm)->ಕ್ಷೇತ್ರ.tqe_next;				\
	ಇಲ್ಲದಿದ್ದರೆ								\
		(ತಲೆ)->tqh_last = &(elm)->ಕ್ಷೇತ್ರ.tqe_next;		\
	(ತಲೆ)->tqh_first = (elm);					\
	(elm)->ಕ್ಷೇತ್ರ.tqe_prev = &(ತಲೆ)->tqh_first;			\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_INSERT_TAIL(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(elm)->ಕ್ಷೇತ್ರ.tqe_next = ಖಾಲಿ;					\
	(elm)->ಕ್ಷೇತ್ರ.tqe_prev = (ತಲೆ)->tqh_last;			\
	*(ತಲೆ)->tqh_last = (elm);					\
	(ತಲೆ)->tqh_last = &(elm)->ಕ್ಷೇತ್ರ.tqe_next;			\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_INSERT_AFTER(ತಲೆ, listelm, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {		\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.tqe_next = (listelm)->ಕ್ಷೇತ್ರ.tqe_next) != ಖಾಲಿ)\
		(elm)->ಕ್ಷೇತ್ರ.tqe_next->ಕ್ಷೇತ್ರ.tqe_prev =			\
		    &(elm)->ಕ್ಷೇತ್ರ.tqe_next;				\
	ಇಲ್ಲದಿದ್ದರೆ								\
		(ತಲೆ)->tqh_last = &(elm)->ಕ್ಷೇತ್ರ.tqe_next;		\
	(listelm)->ಕ್ಷೇತ್ರ.tqe_next = (elm);				\
	(elm)->ಕ್ಷೇತ್ರ.tqe_prev = &(listelm)->ಕ್ಷೇತ್ರ.tqe_next;		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು	TAILQ_INSERT_BEFORE(listelm, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(elm)->ಕ್ಷೇತ್ರ.tqe_prev = (listelm)->ಕ್ಷೇತ್ರ.tqe_prev;		\
	(elm)->ಕ್ಷೇತ್ರ.tqe_next = (listelm);				\
	*(listelm)->ಕ್ಷೇತ್ರ.tqe_prev = (elm);				\
	(listelm)->ಕ್ಷೇತ್ರ.tqe_prev = &(elm)->ಕ್ಷೇತ್ರ.tqe_next;		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_REMOVE(ತಲೆ, elm, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	ಆದರೆ (((elm)->ಕ್ಷೇತ್ರ.tqe_next) != ಖಾಲಿ)				\
		(elm)->ಕ್ಷೇತ್ರ.tqe_next->ಕ್ಷೇತ್ರ.tqe_prev =			\
		    (elm)->ಕ್ಷೇತ್ರ.tqe_prev;				\
	ಇಲ್ಲದಿದ್ದರೆ								\
		(ತಲೆ)->tqh_last = (elm)->ಕ್ಷೇತ್ರ.tqe_prev;		\
	*(elm)->ಕ್ಷೇತ್ರ.tqe_prev = (elm)->ಕ್ಷೇತ್ರ.tqe_next;			\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.tqe_prev);				\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.tqe_next);				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_REPLACE(ತಲೆ, elm, elm2, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	ಆದರೆ (((elm2)->ಕ್ಷೇತ್ರ.tqe_next = (elm)->ಕ್ಷೇತ್ರ.tqe_next) != ಖಾಲಿ)	\
		(elm2)->ಕ್ಷೇತ್ರ.tqe_next->ಕ್ಷೇತ್ರ.tqe_prev =		\
		    &(elm2)->ಕ್ಷೇತ್ರ.tqe_next;				\
	ಇಲ್ಲದಿದ್ದರೆ								\
		(ತಲೆ)->tqh_last = &(elm2)->ಕ್ಷೇತ್ರ.tqe_next;		\
	(elm2)->ಕ್ಷೇತ್ರ.tqe_prev = (elm)->ಕ್ಷೇತ್ರ.tqe_prev;			\
	*(elm2)->ಕ್ಷೇತ್ರ.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.tqe_prev);				\
	_Q_INVALIDATE((elm)->ಕ್ಷೇತ್ರ.tqe_next);				\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು TAILQ_CONCAT(head1, head2, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	ಆದರೆ (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->ಕ್ಷೇತ್ರ.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} ಆಗ (0)

#ಆದರೆ_ಅಂತ್ಯ	/* !_SYS_QUEUE_H_ */
