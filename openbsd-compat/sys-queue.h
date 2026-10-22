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

#جيڪڏهن_وصف_نه_ٿيل	FAKE_قطار_H
#وصف_ڪريو	FAKE_قطار_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#وصف_رد CIRCLEQ_EMPTY
#وصف_رد CIRCLEQ_پڇاڙي
#وصف_رد CIRCLEQ_ENTRY
#وصف_رد CIRCLEQ_FIRST
#وصف_رد CIRCLEQ_FOREACH
#وصف_رد CIRCLEQ_FOREACH_REVERSE
#وصف_رد CIRCLEQ_HEAD
#وصف_رد CIRCLEQ_HEAD_INITIALIZER
#وصف_رد CIRCLEQ_INIT
#وصف_رد CIRCLEQ_INSERT_AFTER
#وصف_رد CIRCLEQ_INSERT_BEFORE
#وصف_رد CIRCLEQ_INSERT_HEAD
#وصف_رد CIRCLEQ_INSERT_TAIL
#وصف_رد CIRCLEQ_LAST
#وصف_رد CIRCLEQ_NEXT
#وصف_رد CIRCLEQ_PREV
#وصف_رد CIRCLEQ_REMOVE
#وصف_رد CIRCLEQ_REPLACE
#وصف_رد LIST_EMPTY
#وصف_رد LIST_پڇاڙي
#وصف_رد LIST_ENTRY
#وصف_رد LIST_FIRST
#وصف_رد LIST_FOREACH
#وصف_رد LIST_FOREACH_محفوظ
#وصف_رد LIST_HEAD
#وصف_رد LIST_HEAD_INITIALIZER
#وصف_رد LIST_INIT
#وصف_رد LIST_INSERT_AFTER
#وصف_رد LIST_INSERT_BEFORE
#وصف_رد LIST_INSERT_HEAD
#وصف_رد LIST_NEXT
#وصف_رد LIST_REMOVE
#وصف_رد LIST_REPLACE
#وصف_رد SIMPLEQ_CONCAT
#وصف_رد SIMPLEQ_EMPTY
#وصف_رد SIMPLEQ_پڇاڙي
#وصف_رد SIMPLEQ_ENTRY
#وصف_رد SIMPLEQ_FIRST
#وصف_رد SIMPLEQ_FOREACH
#وصف_رد SIMPLEQ_FOREACH_محفوظ
#وصف_رد SIMPLEQ_HEAD
#وصف_رد SIMPLEQ_HEAD_INITIALIZER
#وصف_رد SIMPLEQ_INIT
#وصف_رد SIMPLEQ_INSERT_AFTER
#وصف_رد SIMPLEQ_INSERT_HEAD
#وصف_رد SIMPLEQ_INSERT_TAIL
#وصف_رد SIMPLEQ_NEXT
#وصف_رد SIMPLEQ_REMOVE_AFTER
#وصف_رد SIMPLEQ_REMOVE_HEAD
#وصف_رد SLIST_EMPTY
#وصف_رد SLIST_پڇاڙي
#وصف_رد SLIST_ENTRY
#وصف_رد SLIST_FIRST
#وصف_رد SLIST_FOREACH
#وصف_رد SLIST_FOREACH_PREVPTR
#وصف_رد SLIST_FOREACH_محفوظ
#وصف_رد SLIST_HEAD
#وصف_رد SLIST_HEAD_INITIALIZER
#وصف_رد SLIST_INIT
#وصف_رد SLIST_INSERT_AFTER
#وصف_رد SLIST_INSERT_HEAD
#وصف_رد SLIST_NEXT
#وصف_رد SLIST_REMOVE
#وصف_رد SLIST_REMOVE_AFTER
#وصف_رد SLIST_REMOVE_HEAD
#وصف_رد SLIST_REMOVE_ايندڙ
#وصف_رد TAILQ_CONCAT
#وصف_رد TAILQ_EMPTY
#وصف_رد TAILQ_پڇاڙي
#وصف_رد TAILQ_ENTRY
#وصف_رد TAILQ_FIRST
#وصف_رد TAILQ_FOREACH
#وصف_رد TAILQ_FOREACH_ابتو
#وصف_رد TAILQ_FOREACH_ابتو_محفوظ
#وصف_رد TAILQ_FOREACH_محفوظ
#وصف_رد TAILQ_HEAD
#وصف_رد TAILQ_HEAD_INITIALIZER
#وصف_رد TAILQ_INIT
#وصف_رد TAILQ_INSERT_AFTER
#وصف_رد TAILQ_INSERT_BEFORE
#وصف_رد TAILQ_INSERT_HEAD
#وصف_رد TAILQ_INSERT_TAIL
#وصف_رد TAILQ_LAST
#وصف_رد TAILQ_NEXT
#وصف_رد TAILQ_PREV
#وصف_رد TAILQ_REMOVE
#وصف_رد TAILQ_REPLACE

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

#إذا defined(قطار_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#وصف_ڪريو _Q_INVALID ((فراغ *)-1)
#وصف_ڪريو _Q_INVALIDATE(a) (a) = _Q_INVALID
#وإلا
#وصف_ڪريو _Q_INVALIDATE(a)
#جيڪڏهن_پورو

/*
 * Singly-linked List definitions.
 */
#وصف_ڪريو SLIST_HEAD(name, type)						\
بنية name {								\
	بنية type *slh_پهريون;	/* first element */			\
}

#وصف_ڪريو	SLIST_HEAD_INITIALIZER(سر)					\
	{ عدم }

#وصف_ڪريو SLIST_ENTRY(type)						\
بنية {								\
	بنية type *sle_ايندڙ;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#وصف_ڪريو	SLIST_FIRST(سر)	((سر)->slh_پهريون)
#وصف_ڪريو	SLIST_پڇاڙي(سر)		عدم
#وصف_ڪريو	SLIST_EMPTY(سر)	(SLIST_FIRST(سر) == SLIST_پڇاڙي(سر))
#وصف_ڪريو	SLIST_NEXT(elm, ميدان)	((elm)->ميدان.sle_ايندڙ)

#وصف_ڪريو	SLIST_FOREACH(var, سر, ميدان)					\
	لكل((var) = SLIST_FIRST(سر);					\
	    (var) != SLIST_پڇاڙي(سر);					\
	    (var) = SLIST_NEXT(var, ميدان))

#وصف_ڪريو	SLIST_FOREACH_محفوظ(var, سر, ميدان, tvar)			\
	لكل ((var) = SLIST_FIRST(سر);				\
	    (var) && ((tvar) = SLIST_NEXT(var, ميدان), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#وصف_ڪريو	SLIST_INIT(سر) {						\
	SLIST_FIRST(سر) = SLIST_پڇاڙي(سر);				\
}

#وصف_ڪريو	SLIST_INSERT_AFTER(slistelm, elm, ميدان) افعل {			\
	(elm)->ميدان.sle_ايندڙ = (slistelm)->ميدان.sle_ايندڙ;		\
	(slistelm)->ميدان.sle_ايندڙ = (elm);				\
} طالما (0)

#وصف_ڪريو	SLIST_INSERT_HEAD(سر, elm, ميدان) افعل {			\
	(elm)->ميدان.sle_ايندڙ = (سر)->slh_پهريون;			\
	(سر)->slh_پهريون = (elm);					\
} طالما (0)

#وصف_ڪريو	SLIST_REMOVE_AFTER(elm, ميدان) افعل {				\
	(elm)->ميدان.sle_ايندڙ = (elm)->ميدان.sle_ايندڙ->ميدان.sle_ايندڙ;	\
} طالما (0)

#وصف_ڪريو	SLIST_REMOVE_HEAD(سر, ميدان) افعل {				\
	(سر)->slh_پهريون = (سر)->slh_پهريون->ميدان.sle_ايندڙ;		\
} طالما (0)

#وصف_ڪريو SLIST_REMOVE(سر, elm, type, ميدان) افعل {			\
	إذا ((سر)->slh_پهريون == (elm)) {				\
		SLIST_REMOVE_HEAD((سر), ميدان);			\
	} وإلا {							\
		بنية type *curelm = (سر)->slh_پهريون;		\
									\
		طالما (curelm->ميدان.sle_ايندڙ != (elm))			\
			curelm = curelm->ميدان.sle_ايندڙ;		\
		curelm->ميدان.sle_ايندڙ =				\
		    curelm->ميدان.sle_ايندڙ->ميدان.sle_ايندڙ;		\
	}								\
	_Q_INVALIDATE((elm)->ميدان.sle_ايندڙ);				\
} طالما (0)

/*
 * List definitions.
 */
#وصف_ڪريو LIST_HEAD(name, type)						\
بنية name {								\
	بنية type *lh_پهريون;	/* first element */			\
}

#وصف_ڪريو LIST_HEAD_INITIALIZER(سر)					\
	{ عدم }

#وصف_ڪريو LIST_ENTRY(type)						\
بنية {								\
	بنية type *le_ايندڙ;	/* next element */			\
	بنية type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#وصف_ڪريو	LIST_FIRST(سر)		((سر)->lh_پهريون)
#وصف_ڪريو	LIST_پڇاڙي(سر)			عدم
#وصف_ڪريو	LIST_EMPTY(سر)		(LIST_FIRST(سر) == LIST_پڇاڙي(سر))
#وصف_ڪريو	LIST_NEXT(elm, ميدان)		((elm)->ميدان.le_ايندڙ)

#وصف_ڪريو LIST_FOREACH(var, سر, ميدان)					\
	لكل((var) = LIST_FIRST(سر);					\
	    (var)!= LIST_پڇاڙي(سر);					\
	    (var) = LIST_NEXT(var, ميدان))

#وصف_ڪريو	LIST_FOREACH_محفوظ(var, سر, ميدان, tvar)			\
	لكل ((var) = LIST_FIRST(سر);				\
	    (var) && ((tvar) = LIST_NEXT(var, ميدان), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#وصف_ڪريو	LIST_INIT(سر) افعل {						\
	LIST_FIRST(سر) = LIST_پڇاڙي(سر);				\
} طالما (0)

#وصف_ڪريو LIST_INSERT_AFTER(listelm, elm, ميدان) افعل {			\
	إذا (((elm)->ميدان.le_ايندڙ = (listelm)->ميدان.le_ايندڙ) != عدم)	\
		(listelm)->ميدان.le_ايندڙ->ميدان.le_prev =		\
		    &(elm)->ميدان.le_ايندڙ;				\
	(listelm)->ميدان.le_ايندڙ = (elm);				\
	(elm)->ميدان.le_prev = &(listelm)->ميدان.le_ايندڙ;		\
} طالما (0)

#وصف_ڪريو	LIST_INSERT_BEFORE(listelm, elm, ميدان) افعل {			\
	(elm)->ميدان.le_prev = (listelm)->ميدان.le_prev;		\
	(elm)->ميدان.le_ايندڙ = (listelm);				\
	*(listelm)->ميدان.le_prev = (elm);				\
	(listelm)->ميدان.le_prev = &(elm)->ميدان.le_ايندڙ;		\
} طالما (0)

#وصف_ڪريو LIST_INSERT_HEAD(سر, elm, ميدان) افعل {				\
	إذا (((elm)->ميدان.le_ايندڙ = (سر)->lh_پهريون) != عدم)		\
		(سر)->lh_پهريون->ميدان.le_prev = &(elm)->ميدان.le_ايندڙ;\
	(سر)->lh_پهريون = (elm);					\
	(elm)->ميدان.le_prev = &(سر)->lh_پهريون;			\
} طالما (0)

#وصف_ڪريو LIST_REMOVE(elm, ميدان) افعل {					\
	إذا ((elm)->ميدان.le_ايندڙ != عدم)				\
		(elm)->ميدان.le_ايندڙ->ميدان.le_prev =			\
		    (elm)->ميدان.le_prev;				\
	*(elm)->ميدان.le_prev = (elm)->ميدان.le_ايندڙ;			\
	_Q_INVALIDATE((elm)->ميدان.le_prev);				\
	_Q_INVALIDATE((elm)->ميدان.le_ايندڙ);				\
} طالما (0)

#وصف_ڪريو LIST_REPLACE(elm, elm2, ميدان) افعل {				\
	إذا (((elm2)->ميدان.le_ايندڙ = (elm)->ميدان.le_ايندڙ) != عدم)	\
		(elm2)->ميدان.le_ايندڙ->ميدان.le_prev =			\
		    &(elm2)->ميدان.le_ايندڙ;				\
	(elm2)->ميدان.le_prev = (elm)->ميدان.le_prev;			\
	*(elm2)->ميدان.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ميدان.le_prev);				\
	_Q_INVALIDATE((elm)->ميدان.le_ايندڙ);				\
} طالما (0)

/*
 * Simple queue definitions.
 */
#وصف_ڪريو SIMPLEQ_HEAD(name, type)					\
بنية name {								\
	بنية type *sqh_پهريون;	/* first element */			\
	بنية type **sqh_آخري;	/* addr of last next element */		\
}

#وصف_ڪريو SIMPLEQ_HEAD_INITIALIZER(سر)					\
	{ عدم, &(سر).sqh_پهريون }

#وصف_ڪريو SIMPLEQ_ENTRY(type)						\
بنية {								\
	بنية type *sqe_ايندڙ;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#وصف_ڪريو	SIMPLEQ_FIRST(سر)	    ((سر)->sqh_پهريون)
#وصف_ڪريو	SIMPLEQ_پڇاڙي(سر)	    عدم
#وصف_ڪريو	SIMPLEQ_EMPTY(سر)	    (SIMPLEQ_FIRST(سر) == SIMPLEQ_پڇاڙي(سر))
#وصف_ڪريو	SIMPLEQ_NEXT(elm, ميدان)    ((elm)->ميدان.sqe_ايندڙ)

#وصف_ڪريو SIMPLEQ_FOREACH(var, سر, ميدان)				\
	لكل((var) = SIMPLEQ_FIRST(سر);				\
	    (var) != SIMPLEQ_پڇاڙي(سر);					\
	    (var) = SIMPLEQ_NEXT(var, ميدان))

#وصف_ڪريو	SIMPLEQ_FOREACH_محفوظ(var, سر, ميدان, tvar)			\
	لكل ((var) = SIMPLEQ_FIRST(سر);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, ميدان), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#وصف_ڪريو	SIMPLEQ_INIT(سر) افعل {						\
	(سر)->sqh_پهريون = عدم;					\
	(سر)->sqh_آخري = &(سر)->sqh_پهريون;				\
} طالما (0)

#وصف_ڪريو SIMPLEQ_INSERT_HEAD(سر, elm, ميدان) افعل {			\
	إذا (((elm)->ميدان.sqe_ايندڙ = (سر)->sqh_پهريون) == عدم)	\
		(سر)->sqh_آخري = &(elm)->ميدان.sqe_ايندڙ;		\
	(سر)->sqh_پهريون = (elm);					\
} طالما (0)

#وصف_ڪريو SIMPLEQ_INSERT_TAIL(سر, elm, ميدان) افعل {			\
	(elm)->ميدان.sqe_ايندڙ = عدم;					\
	*(سر)->sqh_آخري = (elm);					\
	(سر)->sqh_آخري = &(elm)->ميدان.sqe_ايندڙ;			\
} طالما (0)

#وصف_ڪريو SIMPLEQ_INSERT_AFTER(سر, listelm, elm, ميدان) افعل {		\
	إذا (((elm)->ميدان.sqe_ايندڙ = (listelm)->ميدان.sqe_ايندڙ) == عدم)\
		(سر)->sqh_آخري = &(elm)->ميدان.sqe_ايندڙ;		\
	(listelm)->ميدان.sqe_ايندڙ = (elm);				\
} طالما (0)

#وصف_ڪريو SIMPLEQ_REMOVE_HEAD(سر, ميدان) افعل {			\
	إذا (((سر)->sqh_پهريون = (سر)->sqh_پهريون->ميدان.sqe_ايندڙ) == عدم) \
		(سر)->sqh_آخري = &(سر)->sqh_پهريون;			\
} طالما (0)

#وصف_ڪريو SIMPLEQ_REMOVE_AFTER(سر, elm, ميدان) افعل {			\
	إذا (((elm)->ميدان.sqe_ايندڙ = (elm)->ميدان.sqe_ايندڙ->ميدان.sqe_ايندڙ) \
	    == عدم)							\
		(سر)->sqh_آخري = &(elm)->ميدان.sqe_ايندڙ;		\
} طالما (0)

#وصف_ڪريو SIMPLEQ_CONCAT(head1, head2) افعل {				\
	إذا (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_آخري = (head2)->sqh_پهريون;		\
		(head1)->sqh_آخري = (head2)->sqh_آخري;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} طالما (0)

/*
 * XOR Simple queue definitions.
 */
#وصف_ڪريو XSIMPLEQ_سر(name, type)					\
بنية name {								\
	بنية type *sqx_پهريون;	/* first element */			\
	بنية type **sqx_آخري;	/* addr of last next element */		\
	بنانشان ڊگهو sqx_cookie;					\
}

#وصف_ڪريو XSIMPLEQ_داخلا(type)						\
بنية {								\
	بنية type *sqx_ايندڙ;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#وصف_ڪريو XSIMPLEQ_XOR(سر, ptr)	    ((__typeof(ptr))((سر)->sqx_cookie ^ \
					(بنانشان ڊگهو)(ptr)))
#وصف_ڪريو	XSIMPLEQ_پهريون(سر)	    XSIMPLEQ_XOR(سر, ((سر)->sqx_پهريون))
#وصف_ڪريو	XSIMPLEQ_پڇاڙي(سر)	    عدم
#وصف_ڪريو	XSIMPLEQ_خالي_جايون(سر)	    (XSIMPLEQ_پهريون(سر) == XSIMPLEQ_پڇاڙي(سر))
#وصف_ڪريو	XSIMPLEQ_ايندڙ(سر, elm, ميدان)    XSIMPLEQ_XOR(سر, ((elm)->ميدان.sqx_ايندڙ))


#وصف_ڪريو XSIMPLEQ_FOREACH(var, سر, ميدان)				\
	لكل ((var) = XSIMPLEQ_پهريون(سر);				\
	    (var) != XSIMPLEQ_پڇاڙي(سر);				\
	    (var) = XSIMPLEQ_ايندڙ(سر, var, ميدان))

#وصف_ڪريو	XSIMPLEQ_FOREACH_محفوظ(var, سر, ميدان, tvar)			\
	لكل ((var) = XSIMPLEQ_پهريون(سر);				\
	    (var) && ((tvar) = XSIMPLEQ_ايندڙ(سر, var, ميدان), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#وصف_ڪريو	XSIMPLEQ_INIT(سر) افعل {					\
	arc4random_buf(&(سر)->sqx_cookie, حجم((سر)->sqx_cookie)); \
	(سر)->sqx_پهريون = XSIMPLEQ_XOR(سر, عدم);			\
	(سر)->sqx_آخري = XSIMPLEQ_XOR(سر, &(سر)->sqx_پهريون);	\
} طالما (0)

#وصف_ڪريو XSIMPLEQ_وجهو_سر(سر, elm, ميدان) افعل {			\
	إذا (((elm)->ميدان.sqx_ايندڙ = (سر)->sqx_پهريون) ==		\
	    XSIMPLEQ_XOR(سر, عدم))					\
		(سر)->sqx_آخري = XSIMPLEQ_XOR(سر, &(elm)->ميدان.sqx_ايندڙ); \
	(سر)->sqx_پهريون = XSIMPLEQ_XOR(سر, (elm));			\
} طالما (0)

#وصف_ڪريو XSIMPLEQ_وجهو_پڇ(سر, elm, ميدان) افعل {			\
	(elm)->ميدان.sqx_ايندڙ = XSIMPLEQ_XOR(سر, عدم);		\
	*(XSIMPLEQ_XOR(سر, (سر)->sqx_آخري)) = XSIMPLEQ_XOR(سر, (elm)); \
	(سر)->sqx_آخري = XSIMPLEQ_XOR(سر, &(elm)->ميدان.sqx_ايندڙ);	\
} طالما (0)

#وصف_ڪريو XSIMPLEQ_وجهو_AFTER(سر, listelm, elm, ميدان) افعل {		\
	إذا (((elm)->ميدان.sqx_ايندڙ = (listelm)->ميدان.sqx_ايندڙ) ==	\
	    XSIMPLEQ_XOR(سر, عدم))					\
		(سر)->sqx_آخري = XSIMPLEQ_XOR(سر, &(elm)->ميدان.sqx_ايندڙ); \
	(listelm)->ميدان.sqx_ايندڙ = XSIMPLEQ_XOR(سر, (elm));		\
} طالما (0)

#وصف_ڪريو XSIMPLEQ_REMOVE_سر(سر, ميدان) افعل {				\
	إذا (((سر)->sqx_پهريون = XSIMPLEQ_XOR(سر,			\
	    (سر)->sqx_پهريون)->ميدان.sqx_ايندڙ) == XSIMPLEQ_XOR(سر, عدم)) \
		(سر)->sqx_آخري = XSIMPLEQ_XOR(سر, &(سر)->sqx_پهريون); \
} طالما (0)

#وصف_ڪريو XSIMPLEQ_REMOVE_AFTER(سر, elm, ميدان) افعل {			\
	إذا (((elm)->ميدان.sqx_ايندڙ = XSIMPLEQ_XOR(سر,			\
	    (elm)->ميدان.sqx_ايندڙ)->ميدان.sqx_ايندڙ)			\
	    == XSIMPLEQ_XOR(سر, عدم))				\
		(سر)->sqx_آخري = 					\
		    XSIMPLEQ_XOR(سر, &(elm)->ميدان.sqx_ايندڙ);		\
} طالما (0)


/*
 * Tail queue definitions.
 */
#وصف_ڪريو TAILQ_HEAD(name, type)						\
بنية name {								\
	بنية type *tqh_first;	/* first element */			\
	بنية type **tqh_last;	/* addr of last next element */		\
}

#وصف_ڪريو TAILQ_HEAD_INITIALIZER(سر)					\
	{ عدم, &(سر).tqh_first }

#وصف_ڪريو TAILQ_ENTRY(type)						\
بنية {								\
	بنية type *tqe_next;	/* next element */			\
	بنية type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#وصف_ڪريو	TAILQ_FIRST(سر)		((سر)->tqh_first)
#وصف_ڪريو	TAILQ_پڇاڙي(سر)			عدم
#وصف_ڪريو	TAILQ_NEXT(elm, ميدان)		((elm)->ميدان.tqe_next)
#وصف_ڪريو TAILQ_LAST(سر, headname)					\
	(*(((بنية headname *)((سر)->tqh_last))->tqh_last))
/* XXX */
#وصف_ڪريو TAILQ_PREV(elm, headname, ميدان)				\
	(*(((بنية headname *)((elm)->ميدان.tqe_prev))->tqh_last))
#وصف_ڪريو	TAILQ_EMPTY(سر)						\
	(TAILQ_FIRST(سر) == TAILQ_پڇاڙي(سر))

#وصف_ڪريو TAILQ_FOREACH(var, سر, ميدان)					\
	لكل((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_پڇاڙي(سر);					\
	    (var) = TAILQ_NEXT(var, ميدان))

#وصف_ڪريو	TAILQ_FOREACH_محفوظ(var, سر, ميدان, tvar)			\
	لكل ((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_پڇاڙي(سر) &&					\
	    ((tvar) = TAILQ_NEXT(var, ميدان), 1);			\
	    (var) = (tvar))


#وصف_ڪريو TAILQ_FOREACH_ابتو(var, سر, headname, ميدان)		\
	لكل((var) = TAILQ_LAST(سر, headname);				\
	    (var) != TAILQ_پڇاڙي(سر);					\
	    (var) = TAILQ_PREV(var, headname, ميدان))

#وصف_ڪريو	TAILQ_FOREACH_ابتو_محفوظ(var, سر, headname, ميدان, tvar)	\
	لكل ((var) = TAILQ_LAST(سر, headname);			\
	    (var) != TAILQ_پڇاڙي(سر) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, ميدان), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#وصف_ڪريو	TAILQ_INIT(سر) افعل {						\
	(سر)->tqh_first = عدم;					\
	(سر)->tqh_last = &(سر)->tqh_first;				\
} طالما (0)

#وصف_ڪريو TAILQ_INSERT_HEAD(سر, elm, ميدان) افعل {			\
	إذا (((elm)->ميدان.tqe_next = (سر)->tqh_first) != عدم)	\
		(سر)->tqh_first->ميدان.tqe_prev =			\
		    &(elm)->ميدان.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm)->ميدان.tqe_next;		\
	(سر)->tqh_first = (elm);					\
	(elm)->ميدان.tqe_prev = &(سر)->tqh_first;			\
} طالما (0)

#وصف_ڪريو TAILQ_INSERT_TAIL(سر, elm, ميدان) افعل {			\
	(elm)->ميدان.tqe_next = عدم;					\
	(elm)->ميدان.tqe_prev = (سر)->tqh_last;			\
	*(سر)->tqh_last = (elm);					\
	(سر)->tqh_last = &(elm)->ميدان.tqe_next;			\
} طالما (0)

#وصف_ڪريو TAILQ_INSERT_AFTER(سر, listelm, elm, ميدان) افعل {		\
	إذا (((elm)->ميدان.tqe_next = (listelm)->ميدان.tqe_next) != عدم)\
		(elm)->ميدان.tqe_next->ميدان.tqe_prev =			\
		    &(elm)->ميدان.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm)->ميدان.tqe_next;		\
	(listelm)->ميدان.tqe_next = (elm);				\
	(elm)->ميدان.tqe_prev = &(listelm)->ميدان.tqe_next;		\
} طالما (0)

#وصف_ڪريو	TAILQ_INSERT_BEFORE(listelm, elm, ميدان) افعل {			\
	(elm)->ميدان.tqe_prev = (listelm)->ميدان.tqe_prev;		\
	(elm)->ميدان.tqe_next = (listelm);				\
	*(listelm)->ميدان.tqe_prev = (elm);				\
	(listelm)->ميدان.tqe_prev = &(elm)->ميدان.tqe_next;		\
} طالما (0)

#وصف_ڪريو TAILQ_REMOVE(سر, elm, ميدان) افعل {				\
	إذا (((elm)->ميدان.tqe_next) != عدم)				\
		(elm)->ميدان.tqe_next->ميدان.tqe_prev =			\
		    (elm)->ميدان.tqe_prev;				\
	وإلا								\
		(سر)->tqh_last = (elm)->ميدان.tqe_prev;		\
	*(elm)->ميدان.tqe_prev = (elm)->ميدان.tqe_next;			\
	_Q_INVALIDATE((elm)->ميدان.tqe_prev);				\
	_Q_INVALIDATE((elm)->ميدان.tqe_next);				\
} طالما (0)

#وصف_ڪريو TAILQ_REPLACE(سر, elm, elm2, ميدان) افعل {			\
	إذا (((elm2)->ميدان.tqe_next = (elm)->ميدان.tqe_next) != عدم)	\
		(elm2)->ميدان.tqe_next->ميدان.tqe_prev =		\
		    &(elm2)->ميدان.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm2)->ميدان.tqe_next;		\
	(elm2)->ميدان.tqe_prev = (elm)->ميدان.tqe_prev;			\
	*(elm2)->ميدان.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->ميدان.tqe_prev);				\
	_Q_INVALIDATE((elm)->ميدان.tqe_next);				\
} طالما (0)

#وصف_ڪريو TAILQ_CONCAT(head1, head2, ميدان) افعل {				\
	إذا (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->ميدان.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} طالما (0)

#جيڪڏهن_پورو	/* !_SYS_QUEUE_H_ */
