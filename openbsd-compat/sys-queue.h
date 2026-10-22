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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ	FAKE_ਕਤਾਰ_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	FAKE_ਕਤਾਰ_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_EMPTY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_ਸਿਰਾ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_ENTRY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_FIRST
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_FOREACH
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_FOREACH_REVERSE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_HEAD_INITIALIZER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_INIT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_INSERT_AFTER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_INSERT_BEFORE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_INSERT_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_INSERT_TAIL
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_LAST
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_NEXT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_PREV
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_REMOVE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CIRCLEQ_REPLACE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_EMPTY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_ਸਿਰਾ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_ENTRY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_FIRST
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_FOREACH
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_FOREACH_ਸੁਰੱਖਿਅਤ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_HEAD_INITIALIZER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_INIT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_INSERT_AFTER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_INSERT_BEFORE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_INSERT_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_NEXT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_REMOVE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ LIST_REPLACE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_CONCAT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_EMPTY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_ਸਿਰਾ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_ENTRY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_FIRST
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_FOREACH
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_FOREACH_ਸੁਰੱਖਿਅਤ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_HEAD_INITIALIZER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_INIT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_INSERT_AFTER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_INSERT_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_INSERT_TAIL
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_NEXT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_REMOVE_AFTER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SIMPLEQ_REMOVE_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_EMPTY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_ਸਿਰਾ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_ENTRY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_FIRST
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_FOREACH
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_FOREACH_PREVPTR
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_FOREACH_ਸੁਰੱਖਿਅਤ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_HEAD_INITIALIZER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_INIT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_INSERT_AFTER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_INSERT_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_NEXT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_REMOVE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_REMOVE_AFTER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_REMOVE_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SLIST_REMOVE_ਅਗਲਾ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_CONCAT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_EMPTY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_ਸਿਰਾ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_ENTRY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_FIRST
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_FOREACH
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_FOREACH_ਉਲਟ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_FOREACH_ਉਲਟ_ਸੁਰੱਖਿਅਤ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_HEAD_INITIALIZER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_INIT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_INSERT_AFTER
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_INSERT_BEFORE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_INSERT_HEAD
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_INSERT_TAIL
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_LAST
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_NEXT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_PREV
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_REMOVE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TAILQ_REPLACE

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

#ਜੇ defined(ਕਤਾਰ_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _Q_INVALID ((ਖਾਲੀ *)-1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _Q_INVALIDATE(a) (a) = _Q_INVALID
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _Q_INVALIDATE(a)
#ਜੇ_ਅੰਤ

/*
 * Singly-linked List definitions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SLIST_HEAD(name, type)						\
ਬਣਤਰ name {								\
	ਬਣਤਰ type *slh_ਪਹਿਲਾ;	/* first element */			\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_HEAD_INITIALIZER(ਸਿਰ)					\
	{ ਨਿਰਾ }

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SLIST_ENTRY(type)						\
ਬਣਤਰ {								\
	ਬਣਤਰ type *sle_ਅਗਲਾ;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_FIRST(ਸਿਰ)	((ਸਿਰ)->slh_ਪਹਿਲਾ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_ਸਿਰਾ(ਸਿਰ)		ਨਿਰਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_EMPTY(ਸਿਰ)	(SLIST_FIRST(ਸਿਰ) == SLIST_ਸਿਰਾ(ਸਿਰ))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_NEXT(elm, ਖੇਤਰ)	((elm)->ਖੇਤਰ.sle_ਅਗਲਾ)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_FOREACH(var, ਸਿਰ, ਖੇਤਰ)					\
	ਲਈ((var) = SLIST_FIRST(ਸਿਰ);					\
	    (var) != SLIST_ਸਿਰਾ(ਸਿਰ);					\
	    (var) = SLIST_NEXT(var, ਖੇਤਰ))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_FOREACH_ਸੁਰੱਖਿਅਤ(var, ਸਿਰ, ਖੇਤਰ, tvar)			\
	ਲਈ ((var) = SLIST_FIRST(ਸਿਰ);				\
	    (var) && ((tvar) = SLIST_NEXT(var, ਖੇਤਰ), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_INIT(ਸਿਰ) {						\
	SLIST_FIRST(ਸਿਰ) = SLIST_ਸਿਰਾ(ਸਿਰ);				\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_INSERT_AFTER(slistelm, elm, ਖੇਤਰ) ਕਰੋ {			\
	(elm)->ਖੇਤਰ.sle_ਅਗਲਾ = (slistelm)->ਖੇਤਰ.sle_ਅਗਲਾ;		\
	(slistelm)->ਖੇਤਰ.sle_ਅਗਲਾ = (elm);				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_INSERT_HEAD(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	(elm)->ਖੇਤਰ.sle_ਅਗਲਾ = (ਸਿਰ)->slh_ਪਹਿਲਾ;			\
	(ਸਿਰ)->slh_ਪਹਿਲਾ = (elm);					\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_REMOVE_AFTER(elm, ਖੇਤਰ) ਕਰੋ {				\
	(elm)->ਖੇਤਰ.sle_ਅਗਲਾ = (elm)->ਖੇਤਰ.sle_ਅਗਲਾ->ਖੇਤਰ.sle_ਅਗਲਾ;	\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLIST_REMOVE_HEAD(ਸਿਰ, ਖੇਤਰ) ਕਰੋ {				\
	(ਸਿਰ)->slh_ਪਹਿਲਾ = (ਸਿਰ)->slh_ਪਹਿਲਾ->ਖੇਤਰ.sle_ਅਗਲਾ;		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SLIST_REMOVE(ਸਿਰ, elm, type, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ ((ਸਿਰ)->slh_ਪਹਿਲਾ == (elm)) {				\
		SLIST_REMOVE_HEAD((ਸਿਰ), ਖੇਤਰ);			\
	} ਨਹੀਂਤਾਂ {							\
		ਬਣਤਰ type *curelm = (ਸਿਰ)->slh_ਪਹਿਲਾ;		\
									\
		ਜਦੋਂ (curelm->ਖੇਤਰ.sle_ਅਗਲਾ != (elm))			\
			curelm = curelm->ਖੇਤਰ.sle_ਅਗਲਾ;		\
		curelm->ਖੇਤਰ.sle_ਅਗਲਾ =				\
		    curelm->ਖੇਤਰ.sle_ਅਗਲਾ->ਖੇਤਰ.sle_ਅਗਲਾ;		\
	}								\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.sle_ਅਗਲਾ);				\
} ਜਦੋਂ (0)

/*
 * List definitions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_HEAD(name, type)						\
ਬਣਤਰ name {								\
	ਬਣਤਰ type *lh_ਪਹਿਲਾ;	/* first element */			\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_HEAD_INITIALIZER(ਸਿਰ)					\
	{ ਨਿਰਾ }

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_ENTRY(type)						\
ਬਣਤਰ {								\
	ਬਣਤਰ type *le_ਅਗਲਾ;	/* next element */			\
	ਬਣਤਰ type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LIST_FIRST(ਸਿਰ)		((ਸਿਰ)->lh_ਪਹਿਲਾ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LIST_ਸਿਰਾ(ਸਿਰ)			ਨਿਰਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LIST_EMPTY(ਸਿਰ)		(LIST_FIRST(ਸਿਰ) == LIST_ਸਿਰਾ(ਸਿਰ))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LIST_NEXT(elm, ਖੇਤਰ)		((elm)->ਖੇਤਰ.le_ਅਗਲਾ)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_FOREACH(var, ਸਿਰ, ਖੇਤਰ)					\
	ਲਈ((var) = LIST_FIRST(ਸਿਰ);					\
	    (var)!= LIST_ਸਿਰਾ(ਸਿਰ);					\
	    (var) = LIST_NEXT(var, ਖੇਤਰ))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LIST_FOREACH_ਸੁਰੱਖਿਅਤ(var, ਸਿਰ, ਖੇਤਰ, tvar)			\
	ਲਈ ((var) = LIST_FIRST(ਸਿਰ);				\
	    (var) && ((tvar) = LIST_NEXT(var, ਖੇਤਰ), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LIST_INIT(ਸਿਰ) ਕਰੋ {						\
	LIST_FIRST(ਸਿਰ) = LIST_ਸਿਰਾ(ਸਿਰ);				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_INSERT_AFTER(listelm, elm, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((elm)->ਖੇਤਰ.le_ਅਗਲਾ = (listelm)->ਖੇਤਰ.le_ਅਗਲਾ) != ਨਿਰਾ)	\
		(listelm)->ਖੇਤਰ.le_ਅਗਲਾ->ਖੇਤਰ.le_prev =		\
		    &(elm)->ਖੇਤਰ.le_ਅਗਲਾ;				\
	(listelm)->ਖੇਤਰ.le_ਅਗਲਾ = (elm);				\
	(elm)->ਖੇਤਰ.le_prev = &(listelm)->ਖੇਤਰ.le_ਅਗਲਾ;		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LIST_INSERT_BEFORE(listelm, elm, ਖੇਤਰ) ਕਰੋ {			\
	(elm)->ਖੇਤਰ.le_prev = (listelm)->ਖੇਤਰ.le_prev;		\
	(elm)->ਖੇਤਰ.le_ਅਗਲਾ = (listelm);				\
	*(listelm)->ਖੇਤਰ.le_prev = (elm);				\
	(listelm)->ਖੇਤਰ.le_prev = &(elm)->ਖੇਤਰ.le_ਅਗਲਾ;		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_INSERT_HEAD(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {				\
	ਜੇ (((elm)->ਖੇਤਰ.le_ਅਗਲਾ = (ਸਿਰ)->lh_ਪਹਿਲਾ) != ਨਿਰਾ)		\
		(ਸਿਰ)->lh_ਪਹਿਲਾ->ਖੇਤਰ.le_prev = &(elm)->ਖੇਤਰ.le_ਅਗਲਾ;\
	(ਸਿਰ)->lh_ਪਹਿਲਾ = (elm);					\
	(elm)->ਖੇਤਰ.le_prev = &(ਸਿਰ)->lh_ਪਹਿਲਾ;			\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_REMOVE(elm, ਖੇਤਰ) ਕਰੋ {					\
	ਜੇ ((elm)->ਖੇਤਰ.le_ਅਗਲਾ != ਨਿਰਾ)				\
		(elm)->ਖੇਤਰ.le_ਅਗਲਾ->ਖੇਤਰ.le_prev =			\
		    (elm)->ਖੇਤਰ.le_prev;				\
	*(elm)->ਖੇਤਰ.le_prev = (elm)->ਖੇਤਰ.le_ਅਗਲਾ;			\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.le_prev);				\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.le_ਅਗਲਾ);				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LIST_REPLACE(elm, elm2, ਖੇਤਰ) ਕਰੋ {				\
	ਜੇ (((elm2)->ਖੇਤਰ.le_ਅਗਲਾ = (elm)->ਖੇਤਰ.le_ਅਗਲਾ) != ਨਿਰਾ)	\
		(elm2)->ਖੇਤਰ.le_ਅਗਲਾ->ਖੇਤਰ.le_prev =			\
		    &(elm2)->ਖੇਤਰ.le_ਅਗਲਾ;				\
	(elm2)->ਖੇਤਰ.le_prev = (elm)->ਖੇਤਰ.le_prev;			\
	*(elm2)->ਖੇਤਰ.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.le_prev);				\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.le_ਅਗਲਾ);				\
} ਜਦੋਂ (0)

/*
 * Simple queue definitions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_HEAD(name, type)					\
ਬਣਤਰ name {								\
	ਬਣਤਰ type *sqh_ਪਹਿਲਾ;	/* first element */			\
	ਬਣਤਰ type **sqh_ਆਖਰੀ;	/* addr of last next element */		\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_HEAD_INITIALIZER(ਸਿਰ)					\
	{ ਨਿਰਾ, &(ਸਿਰ).sqh_ਪਹਿਲਾ }

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_ENTRY(type)						\
ਬਣਤਰ {								\
	ਬਣਤਰ type *sqe_ਅਗਲਾ;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SIMPLEQ_FIRST(ਸਿਰ)	    ((ਸਿਰ)->sqh_ਪਹਿਲਾ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SIMPLEQ_ਸਿਰਾ(ਸਿਰ)	    ਨਿਰਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SIMPLEQ_EMPTY(ਸਿਰ)	    (SIMPLEQ_FIRST(ਸਿਰ) == SIMPLEQ_ਸਿਰਾ(ਸਿਰ))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SIMPLEQ_NEXT(elm, ਖੇਤਰ)    ((elm)->ਖੇਤਰ.sqe_ਅਗਲਾ)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_FOREACH(var, ਸਿਰ, ਖੇਤਰ)				\
	ਲਈ((var) = SIMPLEQ_FIRST(ਸਿਰ);				\
	    (var) != SIMPLEQ_ਸਿਰਾ(ਸਿਰ);					\
	    (var) = SIMPLEQ_NEXT(var, ਖੇਤਰ))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SIMPLEQ_FOREACH_ਸੁਰੱਖਿਅਤ(var, ਸਿਰ, ਖੇਤਰ, tvar)			\
	ਲਈ ((var) = SIMPLEQ_FIRST(ਸਿਰ);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, ਖੇਤਰ), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SIMPLEQ_INIT(ਸਿਰ) ਕਰੋ {						\
	(ਸਿਰ)->sqh_ਪਹਿਲਾ = ਨਿਰਾ;					\
	(ਸਿਰ)->sqh_ਆਖਰੀ = &(ਸਿਰ)->sqh_ਪਹਿਲਾ;				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_INSERT_HEAD(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((elm)->ਖੇਤਰ.sqe_ਅਗਲਾ = (ਸਿਰ)->sqh_ਪਹਿਲਾ) == ਨਿਰਾ)	\
		(ਸਿਰ)->sqh_ਆਖਰੀ = &(elm)->ਖੇਤਰ.sqe_ਅਗਲਾ;		\
	(ਸਿਰ)->sqh_ਪਹਿਲਾ = (elm);					\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_INSERT_TAIL(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	(elm)->ਖੇਤਰ.sqe_ਅਗਲਾ = ਨਿਰਾ;					\
	*(ਸਿਰ)->sqh_ਆਖਰੀ = (elm);					\
	(ਸਿਰ)->sqh_ਆਖਰੀ = &(elm)->ਖੇਤਰ.sqe_ਅਗਲਾ;			\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_INSERT_AFTER(ਸਿਰ, listelm, elm, ਖੇਤਰ) ਕਰੋ {		\
	ਜੇ (((elm)->ਖੇਤਰ.sqe_ਅਗਲਾ = (listelm)->ਖੇਤਰ.sqe_ਅਗਲਾ) == ਨਿਰਾ)\
		(ਸਿਰ)->sqh_ਆਖਰੀ = &(elm)->ਖੇਤਰ.sqe_ਅਗਲਾ;		\
	(listelm)->ਖੇਤਰ.sqe_ਅਗਲਾ = (elm);				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_REMOVE_HEAD(ਸਿਰ, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((ਸਿਰ)->sqh_ਪਹਿਲਾ = (ਸਿਰ)->sqh_ਪਹਿਲਾ->ਖੇਤਰ.sqe_ਅਗਲਾ) == ਨਿਰਾ) \
		(ਸਿਰ)->sqh_ਆਖਰੀ = &(ਸਿਰ)->sqh_ਪਹਿਲਾ;			\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_REMOVE_AFTER(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((elm)->ਖੇਤਰ.sqe_ਅਗਲਾ = (elm)->ਖੇਤਰ.sqe_ਅਗਲਾ->ਖੇਤਰ.sqe_ਅਗਲਾ) \
	    == ਨਿਰਾ)							\
		(ਸਿਰ)->sqh_ਆਖਰੀ = &(elm)->ਖੇਤਰ.sqe_ਅਗਲਾ;		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIMPLEQ_CONCAT(head1, head2) ਕਰੋ {				\
	ਜੇ (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_ਆਖਰੀ = (head2)->sqh_ਪਹਿਲਾ;		\
		(head1)->sqh_ਆਖਰੀ = (head2)->sqh_ਆਖਰੀ;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} ਜਦੋਂ (0)

/*
 * XOR Simple queue definitions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_ਸਿਰ(name, type)					\
ਬਣਤਰ name {								\
	ਬਣਤਰ type *sqx_ਪਹਿਲਾ;	/* first element */			\
	ਬਣਤਰ type **sqx_ਆਖਰੀ;	/* addr of last next element */		\
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ sqx_cookie;					\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_ਇੰਦਰਾਜ(type)						\
ਬਣਤਰ {								\
	ਬਣਤਰ type *sqx_ਅਗਲਾ;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_XOR(ਸਿਰ, ptr)	    ((__typeof(ptr))((ਸਿਰ)->sqx_cookie ^ \
					(ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)(ptr)))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	XSIMPLEQ_ਪਹਿਲਾ(ਸਿਰ)	    XSIMPLEQ_XOR(ਸਿਰ, ((ਸਿਰ)->sqx_ਪਹਿਲਾ))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	XSIMPLEQ_ਸਿਰਾ(ਸਿਰ)	    ਨਿਰਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	XSIMPLEQ_ਖਾਲੀ_ਥਾਵਾਂ(ਸਿਰ)	    (XSIMPLEQ_ਪਹਿਲਾ(ਸਿਰ) == XSIMPLEQ_ਸਿਰਾ(ਸਿਰ))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	XSIMPLEQ_ਅਗਲਾ(ਸਿਰ, elm, ਖੇਤਰ)    XSIMPLEQ_XOR(ਸਿਰ, ((elm)->ਖੇਤਰ.sqx_ਅਗਲਾ))


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_FOREACH(var, ਸਿਰ, ਖੇਤਰ)				\
	ਲਈ ((var) = XSIMPLEQ_ਪਹਿਲਾ(ਸਿਰ);				\
	    (var) != XSIMPLEQ_ਸਿਰਾ(ਸਿਰ);				\
	    (var) = XSIMPLEQ_ਅਗਲਾ(ਸਿਰ, var, ਖੇਤਰ))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	XSIMPLEQ_FOREACH_ਸੁਰੱਖਿਅਤ(var, ਸਿਰ, ਖੇਤਰ, tvar)			\
	ਲਈ ((var) = XSIMPLEQ_ਪਹਿਲਾ(ਸਿਰ);				\
	    (var) && ((tvar) = XSIMPLEQ_ਅਗਲਾ(ਸਿਰ, var, ਖੇਤਰ), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	XSIMPLEQ_INIT(ਸਿਰ) ਕਰੋ {					\
	arc4random_buf(&(ਸਿਰ)->sqx_cookie, ਆਕਾਰ((ਸਿਰ)->sqx_cookie)); \
	(ਸਿਰ)->sqx_ਪਹਿਲਾ = XSIMPLEQ_XOR(ਸਿਰ, ਨਿਰਾ);			\
	(ਸਿਰ)->sqx_ਆਖਰੀ = XSIMPLEQ_XOR(ਸਿਰ, &(ਸਿਰ)->sqx_ਪਹਿਲਾ);	\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_ਪਾਓ_ਸਿਰ(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((elm)->ਖੇਤਰ.sqx_ਅਗਲਾ = (ਸਿਰ)->sqx_ਪਹਿਲਾ) ==		\
	    XSIMPLEQ_XOR(ਸਿਰ, ਨਿਰਾ))					\
		(ਸਿਰ)->sqx_ਆਖਰੀ = XSIMPLEQ_XOR(ਸਿਰ, &(elm)->ਖੇਤਰ.sqx_ਅਗਲਾ); \
	(ਸਿਰ)->sqx_ਪਹਿਲਾ = XSIMPLEQ_XOR(ਸਿਰ, (elm));			\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_ਪਾਓ_ਪੂਛ(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	(elm)->ਖੇਤਰ.sqx_ਅਗਲਾ = XSIMPLEQ_XOR(ਸਿਰ, ਨਿਰਾ);		\
	*(XSIMPLEQ_XOR(ਸਿਰ, (ਸਿਰ)->sqx_ਆਖਰੀ)) = XSIMPLEQ_XOR(ਸਿਰ, (elm)); \
	(ਸਿਰ)->sqx_ਆਖਰੀ = XSIMPLEQ_XOR(ਸਿਰ, &(elm)->ਖੇਤਰ.sqx_ਅਗਲਾ);	\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_ਪਾਓ_AFTER(ਸਿਰ, listelm, elm, ਖੇਤਰ) ਕਰੋ {		\
	ਜੇ (((elm)->ਖੇਤਰ.sqx_ਅਗਲਾ = (listelm)->ਖੇਤਰ.sqx_ਅਗਲਾ) ==	\
	    XSIMPLEQ_XOR(ਸਿਰ, ਨਿਰਾ))					\
		(ਸਿਰ)->sqx_ਆਖਰੀ = XSIMPLEQ_XOR(ਸਿਰ, &(elm)->ਖੇਤਰ.sqx_ਅਗਲਾ); \
	(listelm)->ਖੇਤਰ.sqx_ਅਗਲਾ = XSIMPLEQ_XOR(ਸਿਰ, (elm));		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_REMOVE_ਸਿਰ(ਸਿਰ, ਖੇਤਰ) ਕਰੋ {				\
	ਜੇ (((ਸਿਰ)->sqx_ਪਹਿਲਾ = XSIMPLEQ_XOR(ਸਿਰ,			\
	    (ਸਿਰ)->sqx_ਪਹਿਲਾ)->ਖੇਤਰ.sqx_ਅਗਲਾ) == XSIMPLEQ_XOR(ਸਿਰ, ਨਿਰਾ)) \
		(ਸਿਰ)->sqx_ਆਖਰੀ = XSIMPLEQ_XOR(ਸਿਰ, &(ਸਿਰ)->sqx_ਪਹਿਲਾ); \
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ XSIMPLEQ_REMOVE_AFTER(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((elm)->ਖੇਤਰ.sqx_ਅਗਲਾ = XSIMPLEQ_XOR(ਸਿਰ,			\
	    (elm)->ਖੇਤਰ.sqx_ਅਗਲਾ)->ਖੇਤਰ.sqx_ਅਗਲਾ)			\
	    == XSIMPLEQ_XOR(ਸਿਰ, ਨਿਰਾ))				\
		(ਸਿਰ)->sqx_ਆਖਰੀ = 					\
		    XSIMPLEQ_XOR(ਸਿਰ, &(elm)->ਖੇਤਰ.sqx_ਅਗਲਾ);		\
} ਜਦੋਂ (0)


/*
 * Tail queue definitions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_HEAD(name, type)						\
ਬਣਤਰ name {								\
	ਬਣਤਰ type *tqh_first;	/* first element */			\
	ਬਣਤਰ type **tqh_last;	/* addr of last next element */		\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_HEAD_INITIALIZER(ਸਿਰ)					\
	{ ਨਿਰਾ, &(ਸਿਰ).tqh_first }

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_ENTRY(type)						\
ਬਣਤਰ {								\
	ਬਣਤਰ type *tqe_next;	/* next element */			\
	ਬਣਤਰ type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_FIRST(ਸਿਰ)		((ਸਿਰ)->tqh_first)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_ਸਿਰਾ(ਸਿਰ)			ਨਿਰਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_NEXT(elm, ਖੇਤਰ)		((elm)->ਖੇਤਰ.tqe_next)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_LAST(ਸਿਰ, headname)					\
	(*(((ਬਣਤਰ headname *)((ਸਿਰ)->tqh_last))->tqh_last))
/* XXX */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_PREV(elm, headname, ਖੇਤਰ)				\
	(*(((ਬਣਤਰ headname *)((elm)->ਖੇਤਰ.tqe_prev))->tqh_last))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_EMPTY(ਸਿਰ)						\
	(TAILQ_FIRST(ਸਿਰ) == TAILQ_ਸਿਰਾ(ਸਿਰ))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_FOREACH(var, ਸਿਰ, ਖੇਤਰ)					\
	ਲਈ((var) = TAILQ_FIRST(ਸਿਰ);					\
	    (var) != TAILQ_ਸਿਰਾ(ਸਿਰ);					\
	    (var) = TAILQ_NEXT(var, ਖੇਤਰ))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ(var, ਸਿਰ, ਖੇਤਰ, tvar)			\
	ਲਈ ((var) = TAILQ_FIRST(ਸਿਰ);					\
	    (var) != TAILQ_ਸਿਰਾ(ਸਿਰ) &&					\
	    ((tvar) = TAILQ_NEXT(var, ਖੇਤਰ), 1);			\
	    (var) = (tvar))


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_FOREACH_ਉਲਟ(var, ਸਿਰ, headname, ਖੇਤਰ)		\
	ਲਈ((var) = TAILQ_LAST(ਸਿਰ, headname);				\
	    (var) != TAILQ_ਸਿਰਾ(ਸਿਰ);					\
	    (var) = TAILQ_PREV(var, headname, ਖੇਤਰ))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_FOREACH_ਉਲਟ_ਸੁਰੱਖਿਅਤ(var, ਸਿਰ, headname, ਖੇਤਰ, tvar)	\
	ਲਈ ((var) = TAILQ_LAST(ਸਿਰ, headname);			\
	    (var) != TAILQ_ਸਿਰਾ(ਸਿਰ) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, ਖੇਤਰ), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_INIT(ਸਿਰ) ਕਰੋ {						\
	(ਸਿਰ)->tqh_first = ਨਿਰਾ;					\
	(ਸਿਰ)->tqh_last = &(ਸਿਰ)->tqh_first;				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_INSERT_HEAD(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((elm)->ਖੇਤਰ.tqe_next = (ਸਿਰ)->tqh_first) != ਨਿਰਾ)	\
		(ਸਿਰ)->tqh_first->ਖੇਤਰ.tqe_prev =			\
		    &(elm)->ਖੇਤਰ.tqe_next;				\
	ਨਹੀਂਤਾਂ								\
		(ਸਿਰ)->tqh_last = &(elm)->ਖੇਤਰ.tqe_next;		\
	(ਸਿਰ)->tqh_first = (elm);					\
	(elm)->ਖੇਤਰ.tqe_prev = &(ਸਿਰ)->tqh_first;			\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_INSERT_TAIL(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {			\
	(elm)->ਖੇਤਰ.tqe_next = ਨਿਰਾ;					\
	(elm)->ਖੇਤਰ.tqe_prev = (ਸਿਰ)->tqh_last;			\
	*(ਸਿਰ)->tqh_last = (elm);					\
	(ਸਿਰ)->tqh_last = &(elm)->ਖੇਤਰ.tqe_next;			\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_INSERT_AFTER(ਸਿਰ, listelm, elm, ਖੇਤਰ) ਕਰੋ {		\
	ਜੇ (((elm)->ਖੇਤਰ.tqe_next = (listelm)->ਖੇਤਰ.tqe_next) != ਨਿਰਾ)\
		(elm)->ਖੇਤਰ.tqe_next->ਖੇਤਰ.tqe_prev =			\
		    &(elm)->ਖੇਤਰ.tqe_next;				\
	ਨਹੀਂਤਾਂ								\
		(ਸਿਰ)->tqh_last = &(elm)->ਖੇਤਰ.tqe_next;		\
	(listelm)->ਖੇਤਰ.tqe_next = (elm);				\
	(elm)->ਖੇਤਰ.tqe_prev = &(listelm)->ਖੇਤਰ.tqe_next;		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TAILQ_INSERT_BEFORE(listelm, elm, ਖੇਤਰ) ਕਰੋ {			\
	(elm)->ਖੇਤਰ.tqe_prev = (listelm)->ਖੇਤਰ.tqe_prev;		\
	(elm)->ਖੇਤਰ.tqe_next = (listelm);				\
	*(listelm)->ਖੇਤਰ.tqe_prev = (elm);				\
	(listelm)->ਖੇਤਰ.tqe_prev = &(elm)->ਖੇਤਰ.tqe_next;		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_REMOVE(ਸਿਰ, elm, ਖੇਤਰ) ਕਰੋ {				\
	ਜੇ (((elm)->ਖੇਤਰ.tqe_next) != ਨਿਰਾ)				\
		(elm)->ਖੇਤਰ.tqe_next->ਖੇਤਰ.tqe_prev =			\
		    (elm)->ਖੇਤਰ.tqe_prev;				\
	ਨਹੀਂਤਾਂ								\
		(ਸਿਰ)->tqh_last = (elm)->ਖੇਤਰ.tqe_prev;		\
	*(elm)->ਖੇਤਰ.tqe_prev = (elm)->ਖੇਤਰ.tqe_next;			\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.tqe_prev);				\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.tqe_next);				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_REPLACE(ਸਿਰ, elm, elm2, ਖੇਤਰ) ਕਰੋ {			\
	ਜੇ (((elm2)->ਖੇਤਰ.tqe_next = (elm)->ਖੇਤਰ.tqe_next) != ਨਿਰਾ)	\
		(elm2)->ਖੇਤਰ.tqe_next->ਖੇਤਰ.tqe_prev =		\
		    &(elm2)->ਖੇਤਰ.tqe_next;				\
	ਨਹੀਂਤਾਂ								\
		(ਸਿਰ)->tqh_last = &(elm2)->ਖੇਤਰ.tqe_next;		\
	(elm2)->ਖੇਤਰ.tqe_prev = (elm)->ਖੇਤਰ.tqe_prev;			\
	*(elm2)->ਖੇਤਰ.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.tqe_prev);				\
	_Q_INVALIDATE((elm)->ਖੇਤਰ.tqe_next);				\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TAILQ_CONCAT(head1, head2, ਖੇਤਰ) ਕਰੋ {				\
	ਜੇ (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->ਖੇਤਰ.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} ਜਦੋਂ (0)

#ਜੇ_ਅੰਤ	/* !_SYS_QUEUE_H_ */
