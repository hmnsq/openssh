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

#که_نه_تعریف_شوی	FAKE_کتار_H
#تعریف_کړه	FAKE_کتار_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#تعریف_لغوه CIRCLEQ_EMPTY
#تعریف_لغوه CIRCLEQ_پای_ټکی
#تعریف_لغوه CIRCLEQ_ENTRY
#تعریف_لغوه CIRCLEQ_FIRST
#تعریف_لغوه CIRCLEQ_FOREACH
#تعریف_لغوه CIRCLEQ_FOREACH_REVERSE
#تعریف_لغوه CIRCLEQ_HEAD
#تعریف_لغوه CIRCLEQ_HEAD_INITIALIZER
#تعریف_لغوه CIRCLEQ_INIT
#تعریف_لغوه CIRCLEQ_INSERT_AFTER
#تعریف_لغوه CIRCLEQ_INSERT_BEFORE
#تعریف_لغوه CIRCLEQ_INSERT_HEAD
#تعریف_لغوه CIRCLEQ_INSERT_TAIL
#تعریف_لغوه CIRCLEQ_LAST
#تعریف_لغوه CIRCLEQ_NEXT
#تعریف_لغوه CIRCLEQ_PREV
#تعریف_لغوه CIRCLEQ_REMOVE
#تعریف_لغوه CIRCLEQ_REPLACE
#تعریف_لغوه LIST_EMPTY
#تعریف_لغوه LIST_پای_ټکی
#تعریف_لغوه LIST_ENTRY
#تعریف_لغوه LIST_FIRST
#تعریف_لغوه LIST_FOREACH
#تعریف_لغوه LIST_FOREACH_خوندي
#تعریف_لغوه LIST_HEAD
#تعریف_لغوه LIST_HEAD_INITIALIZER
#تعریف_لغوه LIST_INIT
#تعریف_لغوه LIST_INSERT_AFTER
#تعریف_لغوه LIST_INSERT_BEFORE
#تعریف_لغوه LIST_INSERT_HEAD
#تعریف_لغوه LIST_NEXT
#تعریف_لغوه LIST_REMOVE
#تعریف_لغوه LIST_REPLACE
#تعریف_لغوه SIMPLEQ_CONCAT
#تعریف_لغوه SIMPLEQ_EMPTY
#تعریف_لغوه SIMPLEQ_پای_ټکی
#تعریف_لغوه SIMPLEQ_ENTRY
#تعریف_لغوه SIMPLEQ_FIRST
#تعریف_لغوه SIMPLEQ_FOREACH
#تعریف_لغوه SIMPLEQ_FOREACH_خوندي
#تعریف_لغوه SIMPLEQ_HEAD
#تعریف_لغوه SIMPLEQ_HEAD_INITIALIZER
#تعریف_لغوه SIMPLEQ_INIT
#تعریف_لغوه SIMPLEQ_INSERT_AFTER
#تعریف_لغوه SIMPLEQ_INSERT_HEAD
#تعریف_لغوه SIMPLEQ_INSERT_TAIL
#تعریف_لغوه SIMPLEQ_NEXT
#تعریف_لغوه SIMPLEQ_REMOVE_AFTER
#تعریف_لغوه SIMPLEQ_REMOVE_HEAD
#تعریف_لغوه SLIST_EMPTY
#تعریف_لغوه SLIST_پای_ټکی
#تعریف_لغوه SLIST_ENTRY
#تعریف_لغوه SLIST_FIRST
#تعریف_لغوه SLIST_FOREACH
#تعریف_لغوه SLIST_FOREACH_PREVPTR
#تعریف_لغوه SLIST_FOREACH_خوندي
#تعریف_لغوه SLIST_HEAD
#تعریف_لغوه SLIST_HEAD_INITIALIZER
#تعریف_لغوه SLIST_INIT
#تعریف_لغوه SLIST_INSERT_AFTER
#تعریف_لغوه SLIST_INSERT_HEAD
#تعریف_لغوه SLIST_NEXT
#تعریف_لغوه SLIST_REMOVE
#تعریف_لغوه SLIST_REMOVE_AFTER
#تعریف_لغوه SLIST_REMOVE_HEAD
#تعریف_لغوه SLIST_REMOVE_بل
#تعریف_لغوه TAILQ_CONCAT
#تعریف_لغوه TAILQ_EMPTY
#تعریف_لغوه TAILQ_پای_ټکی
#تعریف_لغوه TAILQ_ENTRY
#تعریف_لغوه TAILQ_FIRST
#تعریف_لغوه TAILQ_FOREACH
#تعریف_لغوه TAILQ_FOREACH_سرچپه
#تعریف_لغوه TAILQ_FOREACH_سرچپه_خوندي
#تعریف_لغوه TAILQ_FOREACH_خوندي
#تعریف_لغوه TAILQ_HEAD
#تعریف_لغوه TAILQ_HEAD_INITIALIZER
#تعریف_لغوه TAILQ_INIT
#تعریف_لغوه TAILQ_INSERT_AFTER
#تعریف_لغوه TAILQ_INSERT_BEFORE
#تعریف_لغوه TAILQ_INSERT_HEAD
#تعریف_لغوه TAILQ_INSERT_TAIL
#تعریف_لغوه TAILQ_LAST
#تعریف_لغوه TAILQ_NEXT
#تعریف_لغوه TAILQ_PREV
#تعریف_لغوه TAILQ_REMOVE
#تعریف_لغوه TAILQ_REPLACE

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

#إذا defined(کتار_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#تعریف_کړه _Q_INVALID ((فراغ *)-1)
#تعریف_کړه _Q_INVALIDATE(a) (a) = _Q_INVALID
#وإلا
#تعریف_کړه _Q_INVALIDATE(a)
#د_که_پای

/*
 * Singly-linked List definitions.
 */
#تعریف_کړه SLIST_HEAD(name, type)						\
بنية name {								\
	بنية type *slh_لومړی;	/* first element */			\
}

#تعریف_کړه	SLIST_HEAD_INITIALIZER(سر_2)					\
	{ عدم }

#تعریف_کړه SLIST_ENTRY(type)						\
بنية {								\
	بنية type *sle_بل;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#تعریف_کړه	SLIST_FIRST(سر_2)	((سر_2)->slh_لومړی)
#تعریف_کړه	SLIST_پای_ټکی(سر_2)		عدم
#تعریف_کړه	SLIST_EMPTY(سر_2)	(SLIST_FIRST(سر_2) == SLIST_پای_ټکی(سر_2))
#تعریف_کړه	SLIST_NEXT(elm, ډګر)	((elm)->ډګر.sle_بل)

#تعریف_کړه	SLIST_FOREACH(var, سر_2, ډګر)					\
	لكل((var) = SLIST_FIRST(سر_2);					\
	    (var) != SLIST_پای_ټکی(سر_2);					\
	    (var) = SLIST_NEXT(var, ډګر))

#تعریف_کړه	SLIST_FOREACH_خوندي(var, سر_2, ډګر, tvar)			\
	لكل ((var) = SLIST_FIRST(سر_2);				\
	    (var) && ((tvar) = SLIST_NEXT(var, ډګر), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#تعریف_کړه	SLIST_INIT(سر_2) {						\
	SLIST_FIRST(سر_2) = SLIST_پای_ټکی(سر_2);				\
}

#تعریف_کړه	SLIST_INSERT_AFTER(slistelm, elm, ډګر) افعل {			\
	(elm)->ډګر.sle_بل = (slistelm)->ډګر.sle_بل;		\
	(slistelm)->ډګر.sle_بل = (elm);				\
} طالما (0)

#تعریف_کړه	SLIST_INSERT_HEAD(سر_2, elm, ډګر) افعل {			\
	(elm)->ډګر.sle_بل = (سر_2)->slh_لومړی;			\
	(سر_2)->slh_لومړی = (elm);					\
} طالما (0)

#تعریف_کړه	SLIST_REMOVE_AFTER(elm, ډګر) افعل {				\
	(elm)->ډګر.sle_بل = (elm)->ډګر.sle_بل->ډګر.sle_بل;	\
} طالما (0)

#تعریف_کړه	SLIST_REMOVE_HEAD(سر_2, ډګر) افعل {				\
	(سر_2)->slh_لومړی = (سر_2)->slh_لومړی->ډګر.sle_بل;		\
} طالما (0)

#تعریف_کړه SLIST_REMOVE(سر_2, elm, type, ډګر) افعل {			\
	إذا ((سر_2)->slh_لومړی == (elm)) {				\
		SLIST_REMOVE_HEAD((سر_2), ډګر);			\
	} وإلا {							\
		بنية type *curelm = (سر_2)->slh_لومړی;		\
									\
		طالما (curelm->ډګر.sle_بل != (elm))			\
			curelm = curelm->ډګر.sle_بل;		\
		curelm->ډګر.sle_بل =				\
		    curelm->ډګر.sle_بل->ډګر.sle_بل;		\
	}								\
	_Q_INVALIDATE((elm)->ډګر.sle_بل);				\
} طالما (0)

/*
 * List definitions.
 */
#تعریف_کړه LIST_HEAD(name, type)						\
بنية name {								\
	بنية type *lh_لومړی;	/* first element */			\
}

#تعریف_کړه LIST_HEAD_INITIALIZER(سر_2)					\
	{ عدم }

#تعریف_کړه LIST_ENTRY(type)						\
بنية {								\
	بنية type *le_بل;	/* next element */			\
	بنية type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#تعریف_کړه	LIST_FIRST(سر_2)		((سر_2)->lh_لومړی)
#تعریف_کړه	LIST_پای_ټکی(سر_2)			عدم
#تعریف_کړه	LIST_EMPTY(سر_2)		(LIST_FIRST(سر_2) == LIST_پای_ټکی(سر_2))
#تعریف_کړه	LIST_NEXT(elm, ډګر)		((elm)->ډګر.le_بل)

#تعریف_کړه LIST_FOREACH(var, سر_2, ډګر)					\
	لكل((var) = LIST_FIRST(سر_2);					\
	    (var)!= LIST_پای_ټکی(سر_2);					\
	    (var) = LIST_NEXT(var, ډګر))

#تعریف_کړه	LIST_FOREACH_خوندي(var, سر_2, ډګر, tvar)			\
	لكل ((var) = LIST_FIRST(سر_2);				\
	    (var) && ((tvar) = LIST_NEXT(var, ډګر), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#تعریف_کړه	LIST_INIT(سر_2) افعل {						\
	LIST_FIRST(سر_2) = LIST_پای_ټکی(سر_2);				\
} طالما (0)

#تعریف_کړه LIST_INSERT_AFTER(listelm, elm, ډګر) افعل {			\
	إذا (((elm)->ډګر.le_بل = (listelm)->ډګر.le_بل) != عدم)	\
		(listelm)->ډګر.le_بل->ډګر.le_prev =		\
		    &(elm)->ډګر.le_بل;				\
	(listelm)->ډګر.le_بل = (elm);				\
	(elm)->ډګر.le_prev = &(listelm)->ډګر.le_بل;		\
} طالما (0)

#تعریف_کړه	LIST_INSERT_BEFORE(listelm, elm, ډګر) افعل {			\
	(elm)->ډګر.le_prev = (listelm)->ډګر.le_prev;		\
	(elm)->ډګر.le_بل = (listelm);				\
	*(listelm)->ډګر.le_prev = (elm);				\
	(listelm)->ډګر.le_prev = &(elm)->ډګر.le_بل;		\
} طالما (0)

#تعریف_کړه LIST_INSERT_HEAD(سر_2, elm, ډګر) افعل {				\
	إذا (((elm)->ډګر.le_بل = (سر_2)->lh_لومړی) != عدم)		\
		(سر_2)->lh_لومړی->ډګر.le_prev = &(elm)->ډګر.le_بل;\
	(سر_2)->lh_لومړی = (elm);					\
	(elm)->ډګر.le_prev = &(سر_2)->lh_لومړی;			\
} طالما (0)

#تعریف_کړه LIST_REMOVE(elm, ډګر) افعل {					\
	إذا ((elm)->ډګر.le_بل != عدم)				\
		(elm)->ډګر.le_بل->ډګر.le_prev =			\
		    (elm)->ډګر.le_prev;				\
	*(elm)->ډګر.le_prev = (elm)->ډګر.le_بل;			\
	_Q_INVALIDATE((elm)->ډګر.le_prev);				\
	_Q_INVALIDATE((elm)->ډګر.le_بل);				\
} طالما (0)

#تعریف_کړه LIST_REPLACE(elm, elm2, ډګر) افعل {				\
	إذا (((elm2)->ډګر.le_بل = (elm)->ډګر.le_بل) != عدم)	\
		(elm2)->ډګر.le_بل->ډګر.le_prev =			\
		    &(elm2)->ډګر.le_بل;				\
	(elm2)->ډګر.le_prev = (elm)->ډګر.le_prev;			\
	*(elm2)->ډګر.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ډګر.le_prev);				\
	_Q_INVALIDATE((elm)->ډګر.le_بل);				\
} طالما (0)

/*
 * Simple queue definitions.
 */
#تعریف_کړه SIMPLEQ_HEAD(name, type)					\
بنية name {								\
	بنية type *sqh_لومړی;	/* first element */			\
	بنية type **sqh_وروستی;	/* addr of last next element */		\
}

#تعریف_کړه SIMPLEQ_HEAD_INITIALIZER(سر_2)					\
	{ عدم, &(سر_2).sqh_لومړی }

#تعریف_کړه SIMPLEQ_ENTRY(type)						\
بنية {								\
	بنية type *sqe_بل;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#تعریف_کړه	SIMPLEQ_FIRST(سر_2)	    ((سر_2)->sqh_لومړی)
#تعریف_کړه	SIMPLEQ_پای_ټکی(سر_2)	    عدم
#تعریف_کړه	SIMPLEQ_EMPTY(سر_2)	    (SIMPLEQ_FIRST(سر_2) == SIMPLEQ_پای_ټکی(سر_2))
#تعریف_کړه	SIMPLEQ_NEXT(elm, ډګر)    ((elm)->ډګر.sqe_بل)

#تعریف_کړه SIMPLEQ_FOREACH(var, سر_2, ډګر)				\
	لكل((var) = SIMPLEQ_FIRST(سر_2);				\
	    (var) != SIMPLEQ_پای_ټکی(سر_2);					\
	    (var) = SIMPLEQ_NEXT(var, ډګر))

#تعریف_کړه	SIMPLEQ_FOREACH_خوندي(var, سر_2, ډګر, tvar)			\
	لكل ((var) = SIMPLEQ_FIRST(سر_2);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, ډګر), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#تعریف_کړه	SIMPLEQ_INIT(سر_2) افعل {						\
	(سر_2)->sqh_لومړی = عدم;					\
	(سر_2)->sqh_وروستی = &(سر_2)->sqh_لومړی;				\
} طالما (0)

#تعریف_کړه SIMPLEQ_INSERT_HEAD(سر_2, elm, ډګر) افعل {			\
	إذا (((elm)->ډګر.sqe_بل = (سر_2)->sqh_لومړی) == عدم)	\
		(سر_2)->sqh_وروستی = &(elm)->ډګر.sqe_بل;		\
	(سر_2)->sqh_لومړی = (elm);					\
} طالما (0)

#تعریف_کړه SIMPLEQ_INSERT_TAIL(سر_2, elm, ډګر) افعل {			\
	(elm)->ډګر.sqe_بل = عدم;					\
	*(سر_2)->sqh_وروستی = (elm);					\
	(سر_2)->sqh_وروستی = &(elm)->ډګر.sqe_بل;			\
} طالما (0)

#تعریف_کړه SIMPLEQ_INSERT_AFTER(سر_2, listelm, elm, ډګر) افعل {		\
	إذا (((elm)->ډګر.sqe_بل = (listelm)->ډګر.sqe_بل) == عدم)\
		(سر_2)->sqh_وروستی = &(elm)->ډګر.sqe_بل;		\
	(listelm)->ډګر.sqe_بل = (elm);				\
} طالما (0)

#تعریف_کړه SIMPLEQ_REMOVE_HEAD(سر_2, ډګر) افعل {			\
	إذا (((سر_2)->sqh_لومړی = (سر_2)->sqh_لومړی->ډګر.sqe_بل) == عدم) \
		(سر_2)->sqh_وروستی = &(سر_2)->sqh_لومړی;			\
} طالما (0)

#تعریف_کړه SIMPLEQ_REMOVE_AFTER(سر_2, elm, ډګر) افعل {			\
	إذا (((elm)->ډګر.sqe_بل = (elm)->ډګر.sqe_بل->ډګر.sqe_بل) \
	    == عدم)							\
		(سر_2)->sqh_وروستی = &(elm)->ډګر.sqe_بل;		\
} طالما (0)

#تعریف_کړه SIMPLEQ_CONCAT(head1, head2) افعل {				\
	إذا (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_وروستی = (head2)->sqh_لومړی;		\
		(head1)->sqh_وروستی = (head2)->sqh_وروستی;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} طالما (0)

/*
 * XOR Simple queue definitions.
 */
#تعریف_کړه XSIMPLEQ_سر(name, type)					\
بنية name {								\
	بنية type *sqx_لومړی;	/* first element */			\
	بنية type **sqx_وروستی;	/* addr of last next element */		\
	بینښه اوږد sqx_cookie;					\
}

#تعریف_کړه XSIMPLEQ_ثبت(type)						\
بنية {								\
	بنية type *sqx_بل;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#تعریف_کړه XSIMPLEQ_XOR(سر_2, ptr)	    ((__typeof(ptr))((سر_2)->sqx_cookie ^ \
					(بینښه اوږد)(ptr)))
#تعریف_کړه	XSIMPLEQ_لومړی(سر_2)	    XSIMPLEQ_XOR(سر_2, ((سر_2)->sqx_لومړی))
#تعریف_کړه	XSIMPLEQ_پای_ټکی(سر_2)	    عدم
#تعریف_کړه	XSIMPLEQ_تشه(سر_2)	    (XSIMPLEQ_لومړی(سر_2) == XSIMPLEQ_پای_ټکی(سر_2))
#تعریف_کړه	XSIMPLEQ_بل(سر_2, elm, ډګر)    XSIMPLEQ_XOR(سر_2, ((elm)->ډګر.sqx_بل))


#تعریف_کړه XSIMPLEQ_FOREACH(var, سر_2, ډګر)				\
	لكل ((var) = XSIMPLEQ_لومړی(سر_2);				\
	    (var) != XSIMPLEQ_پای_ټکی(سر_2);				\
	    (var) = XSIMPLEQ_بل(سر_2, var, ډګر))

#تعریف_کړه	XSIMPLEQ_FOREACH_خوندي(var, سر_2, ډګر, tvar)			\
	لكل ((var) = XSIMPLEQ_لومړی(سر_2);				\
	    (var) && ((tvar) = XSIMPLEQ_بل(سر_2, var, ډګر), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#تعریف_کړه	XSIMPLEQ_INIT(سر_2) افعل {					\
	arc4random_buf(&(سر_2)->sqx_cookie, حجم((سر_2)->sqx_cookie)); \
	(سر_2)->sqx_لومړی = XSIMPLEQ_XOR(سر_2, عدم);			\
	(سر_2)->sqx_وروستی = XSIMPLEQ_XOR(سر_2, &(سر_2)->sqx_لومړی);	\
} طالما (0)

#تعریف_کړه XSIMPLEQ_ورننباسه_سر(سر_2, elm, ډګر) افعل {			\
	إذا (((elm)->ډګر.sqx_بل = (سر_2)->sqx_لومړی) ==		\
	    XSIMPLEQ_XOR(سر_2, عدم))					\
		(سر_2)->sqx_وروستی = XSIMPLEQ_XOR(سر_2, &(elm)->ډګر.sqx_بل); \
	(سر_2)->sqx_لومړی = XSIMPLEQ_XOR(سر_2, (elm));			\
} طالما (0)

#تعریف_کړه XSIMPLEQ_ورننباسه_لکۍ(سر_2, elm, ډګر) افعل {			\
	(elm)->ډګر.sqx_بل = XSIMPLEQ_XOR(سر_2, عدم);		\
	*(XSIMPLEQ_XOR(سر_2, (سر_2)->sqx_وروستی)) = XSIMPLEQ_XOR(سر_2, (elm)); \
	(سر_2)->sqx_وروستی = XSIMPLEQ_XOR(سر_2, &(elm)->ډګر.sqx_بل);	\
} طالما (0)

#تعریف_کړه XSIMPLEQ_ورننباسه_AFTER(سر_2, listelm, elm, ډګر) افعل {		\
	إذا (((elm)->ډګر.sqx_بل = (listelm)->ډګر.sqx_بل) ==	\
	    XSIMPLEQ_XOR(سر_2, عدم))					\
		(سر_2)->sqx_وروستی = XSIMPLEQ_XOR(سر_2, &(elm)->ډګر.sqx_بل); \
	(listelm)->ډګر.sqx_بل = XSIMPLEQ_XOR(سر_2, (elm));		\
} طالما (0)

#تعریف_کړه XSIMPLEQ_REMOVE_سر(سر_2, ډګر) افعل {				\
	إذا (((سر_2)->sqx_لومړی = XSIMPLEQ_XOR(سر_2,			\
	    (سر_2)->sqx_لومړی)->ډګر.sqx_بل) == XSIMPLEQ_XOR(سر_2, عدم)) \
		(سر_2)->sqx_وروستی = XSIMPLEQ_XOR(سر_2, &(سر_2)->sqx_لومړی); \
} طالما (0)

#تعریف_کړه XSIMPLEQ_REMOVE_AFTER(سر_2, elm, ډګر) افعل {			\
	إذا (((elm)->ډګر.sqx_بل = XSIMPLEQ_XOR(سر_2,			\
	    (elm)->ډګر.sqx_بل)->ډګر.sqx_بل)			\
	    == XSIMPLEQ_XOR(سر_2, عدم))				\
		(سر_2)->sqx_وروستی = 					\
		    XSIMPLEQ_XOR(سر_2, &(elm)->ډګر.sqx_بل);		\
} طالما (0)


/*
 * Tail queue definitions.
 */
#تعریف_کړه TAILQ_HEAD(name, type)						\
بنية name {								\
	بنية type *tqh_first;	/* first element */			\
	بنية type **tqh_last;	/* addr of last next element */		\
}

#تعریف_کړه TAILQ_HEAD_INITIALIZER(سر_2)					\
	{ عدم, &(سر_2).tqh_first }

#تعریف_کړه TAILQ_ENTRY(type)						\
بنية {								\
	بنية type *tqe_next;	/* next element */			\
	بنية type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#تعریف_کړه	TAILQ_FIRST(سر_2)		((سر_2)->tqh_first)
#تعریف_کړه	TAILQ_پای_ټکی(سر_2)			عدم
#تعریف_کړه	TAILQ_NEXT(elm, ډګر)		((elm)->ډګر.tqe_next)
#تعریف_کړه TAILQ_LAST(سر_2, headname)					\
	(*(((بنية headname *)((سر_2)->tqh_last))->tqh_last))
/* XXX */
#تعریف_کړه TAILQ_PREV(elm, headname, ډګر)				\
	(*(((بنية headname *)((elm)->ډګر.tqe_prev))->tqh_last))
#تعریف_کړه	TAILQ_EMPTY(سر_2)						\
	(TAILQ_FIRST(سر_2) == TAILQ_پای_ټکی(سر_2))

#تعریف_کړه TAILQ_FOREACH(var, سر_2, ډګر)					\
	لكل((var) = TAILQ_FIRST(سر_2);					\
	    (var) != TAILQ_پای_ټکی(سر_2);					\
	    (var) = TAILQ_NEXT(var, ډګر))

#تعریف_کړه	TAILQ_FOREACH_خوندي(var, سر_2, ډګر, tvar)			\
	لكل ((var) = TAILQ_FIRST(سر_2);					\
	    (var) != TAILQ_پای_ټکی(سر_2) &&					\
	    ((tvar) = TAILQ_NEXT(var, ډګر), 1);			\
	    (var) = (tvar))


#تعریف_کړه TAILQ_FOREACH_سرچپه(var, سر_2, headname, ډګر)		\
	لكل((var) = TAILQ_LAST(سر_2, headname);				\
	    (var) != TAILQ_پای_ټکی(سر_2);					\
	    (var) = TAILQ_PREV(var, headname, ډګر))

#تعریف_کړه	TAILQ_FOREACH_سرچپه_خوندي(var, سر_2, headname, ډګر, tvar)	\
	لكل ((var) = TAILQ_LAST(سر_2, headname);			\
	    (var) != TAILQ_پای_ټکی(سر_2) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, ډګر), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#تعریف_کړه	TAILQ_INIT(سر_2) افعل {						\
	(سر_2)->tqh_first = عدم;					\
	(سر_2)->tqh_last = &(سر_2)->tqh_first;				\
} طالما (0)

#تعریف_کړه TAILQ_INSERT_HEAD(سر_2, elm, ډګر) افعل {			\
	إذا (((elm)->ډګر.tqe_next = (سر_2)->tqh_first) != عدم)	\
		(سر_2)->tqh_first->ډګر.tqe_prev =			\
		    &(elm)->ډګر.tqe_next;				\
	وإلا								\
		(سر_2)->tqh_last = &(elm)->ډګر.tqe_next;		\
	(سر_2)->tqh_first = (elm);					\
	(elm)->ډګر.tqe_prev = &(سر_2)->tqh_first;			\
} طالما (0)

#تعریف_کړه TAILQ_INSERT_TAIL(سر_2, elm, ډګر) افعل {			\
	(elm)->ډګر.tqe_next = عدم;					\
	(elm)->ډګر.tqe_prev = (سر_2)->tqh_last;			\
	*(سر_2)->tqh_last = (elm);					\
	(سر_2)->tqh_last = &(elm)->ډګر.tqe_next;			\
} طالما (0)

#تعریف_کړه TAILQ_INSERT_AFTER(سر_2, listelm, elm, ډګر) افعل {		\
	إذا (((elm)->ډګر.tqe_next = (listelm)->ډګر.tqe_next) != عدم)\
		(elm)->ډګر.tqe_next->ډګر.tqe_prev =			\
		    &(elm)->ډګر.tqe_next;				\
	وإلا								\
		(سر_2)->tqh_last = &(elm)->ډګر.tqe_next;		\
	(listelm)->ډګر.tqe_next = (elm);				\
	(elm)->ډګر.tqe_prev = &(listelm)->ډګر.tqe_next;		\
} طالما (0)

#تعریف_کړه	TAILQ_INSERT_BEFORE(listelm, elm, ډګر) افعل {			\
	(elm)->ډګر.tqe_prev = (listelm)->ډګر.tqe_prev;		\
	(elm)->ډګر.tqe_next = (listelm);				\
	*(listelm)->ډګر.tqe_prev = (elm);				\
	(listelm)->ډګر.tqe_prev = &(elm)->ډګر.tqe_next;		\
} طالما (0)

#تعریف_کړه TAILQ_REMOVE(سر_2, elm, ډګر) افعل {				\
	إذا (((elm)->ډګر.tqe_next) != عدم)				\
		(elm)->ډګر.tqe_next->ډګر.tqe_prev =			\
		    (elm)->ډګر.tqe_prev;				\
	وإلا								\
		(سر_2)->tqh_last = (elm)->ډګر.tqe_prev;		\
	*(elm)->ډګر.tqe_prev = (elm)->ډګر.tqe_next;			\
	_Q_INVALIDATE((elm)->ډګر.tqe_prev);				\
	_Q_INVALIDATE((elm)->ډګر.tqe_next);				\
} طالما (0)

#تعریف_کړه TAILQ_REPLACE(سر_2, elm, elm2, ډګر) افعل {			\
	إذا (((elm2)->ډګر.tqe_next = (elm)->ډګر.tqe_next) != عدم)	\
		(elm2)->ډګر.tqe_next->ډګر.tqe_prev =		\
		    &(elm2)->ډګر.tqe_next;				\
	وإلا								\
		(سر_2)->tqh_last = &(elm2)->ډګر.tqe_next;		\
	(elm2)->ډګر.tqe_prev = (elm)->ډګر.tqe_prev;			\
	*(elm2)->ډګر.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ډګر.tqe_prev);				\
	_Q_INVALIDATE((elm)->ډګر.tqe_next);				\
} طالما (0)

#تعریف_کړه TAILQ_CONCAT(head1, head2, ډګر) افعل {				\
	إذا (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->ډګر.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} طالما (0)

#د_که_پای	/* !_SYS_QUEUE_H_ */
