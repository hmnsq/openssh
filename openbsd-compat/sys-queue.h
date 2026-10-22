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

#جے_بنا_تعریف	FAKE_قطار_H
#تعریف_کرو	FAKE_قطار_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#تعریف_رد CIRCLEQ_EMPTY
#تعریف_رد CIRCLEQ_سرا
#تعریف_رد CIRCLEQ_ENTRY
#تعریف_رد CIRCLEQ_FIRST
#تعریف_رد CIRCLEQ_FOREACH
#تعریف_رد CIRCLEQ_FOREACH_REVERSE
#تعریف_رد CIRCLEQ_HEAD
#تعریف_رد CIRCLEQ_HEAD_INITIALIZER
#تعریف_رد CIRCLEQ_INIT
#تعریف_رد CIRCLEQ_INSERT_AFTER
#تعریف_رد CIRCLEQ_INSERT_BEFORE
#تعریف_رد CIRCLEQ_INSERT_HEAD
#تعریف_رد CIRCLEQ_INSERT_TAIL
#تعریف_رد CIRCLEQ_LAST
#تعریف_رد CIRCLEQ_NEXT
#تعریف_رد CIRCLEQ_PREV
#تعریف_رد CIRCLEQ_REMOVE
#تعریف_رد CIRCLEQ_REPLACE
#تعریف_رد LIST_EMPTY
#تعریف_رد LIST_سرا
#تعریف_رد LIST_ENTRY
#تعریف_رد LIST_FIRST
#تعریف_رد LIST_FOREACH
#تعریف_رد LIST_FOREACH_محفوظ
#تعریف_رد LIST_HEAD
#تعریف_رد LIST_HEAD_INITIALIZER
#تعریف_رد LIST_INIT
#تعریف_رد LIST_INSERT_AFTER
#تعریف_رد LIST_INSERT_BEFORE
#تعریف_رد LIST_INSERT_HEAD
#تعریف_رد LIST_NEXT
#تعریف_رد LIST_REMOVE
#تعریف_رد LIST_REPLACE
#تعریف_رد SIMPLEQ_CONCAT
#تعریف_رد SIMPLEQ_EMPTY
#تعریف_رد SIMPLEQ_سرا
#تعریف_رد SIMPLEQ_ENTRY
#تعریف_رد SIMPLEQ_FIRST
#تعریف_رد SIMPLEQ_FOREACH
#تعریف_رد SIMPLEQ_FOREACH_محفوظ
#تعریف_رد SIMPLEQ_HEAD
#تعریف_رد SIMPLEQ_HEAD_INITIALIZER
#تعریف_رد SIMPLEQ_INIT
#تعریف_رد SIMPLEQ_INSERT_AFTER
#تعریف_رد SIMPLEQ_INSERT_HEAD
#تعریف_رد SIMPLEQ_INSERT_TAIL
#تعریف_رد SIMPLEQ_NEXT
#تعریف_رد SIMPLEQ_REMOVE_AFTER
#تعریف_رد SIMPLEQ_REMOVE_HEAD
#تعریف_رد SLIST_EMPTY
#تعریف_رد SLIST_سرا
#تعریف_رد SLIST_ENTRY
#تعریف_رد SLIST_FIRST
#تعریف_رد SLIST_FOREACH
#تعریف_رد SLIST_FOREACH_PREVPTR
#تعریف_رد SLIST_FOREACH_محفوظ
#تعریف_رد SLIST_HEAD
#تعریف_رد SLIST_HEAD_INITIALIZER
#تعریف_رد SLIST_INIT
#تعریف_رد SLIST_INSERT_AFTER
#تعریف_رد SLIST_INSERT_HEAD
#تعریف_رد SLIST_NEXT
#تعریف_رد SLIST_REMOVE
#تعریف_رد SLIST_REMOVE_AFTER
#تعریف_رد SLIST_REMOVE_HEAD
#تعریف_رد SLIST_REMOVE_اگلا
#تعریف_رد TAILQ_CONCAT
#تعریف_رد TAILQ_EMPTY
#تعریف_رد TAILQ_سرا
#تعریف_رد TAILQ_ENTRY
#تعریف_رد TAILQ_FIRST
#تعریف_رد TAILQ_FOREACH
#تعریف_رد TAILQ_FOREACH_الٹ
#تعریف_رد TAILQ_FOREACH_الٹ_محفوظ
#تعریف_رد TAILQ_FOREACH_محفوظ
#تعریف_رد TAILQ_HEAD
#تعریف_رد TAILQ_HEAD_INITIALIZER
#تعریف_رد TAILQ_INIT
#تعریف_رد TAILQ_INSERT_AFTER
#تعریف_رد TAILQ_INSERT_BEFORE
#تعریف_رد TAILQ_INSERT_HEAD
#تعریف_رد TAILQ_INSERT_TAIL
#تعریف_رد TAILQ_LAST
#تعریف_رد TAILQ_NEXT
#تعریف_رد TAILQ_PREV
#تعریف_رد TAILQ_REMOVE
#تعریف_رد TAILQ_REPLACE

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
#تعریف_کرو _Q_INVALID ((فراغ *)-1)
#تعریف_کرو _Q_INVALIDATE(a) (a) = _Q_INVALID
#وإلا
#تعریف_کرو _Q_INVALIDATE(a)
#جے_انت

/*
 * Singly-linked List definitions.
 */
#تعریف_کرو SLIST_HEAD(name, type)						\
بنية name {								\
	بنية type *slh_پہلا;	/* first element */			\
}

#تعریف_کرو	SLIST_HEAD_INITIALIZER(سر)					\
	{ عدم }

#تعریف_کرو SLIST_ENTRY(type)						\
بنية {								\
	بنية type *sle_اگلا;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#تعریف_کرو	SLIST_FIRST(سر)	((سر)->slh_پہلا)
#تعریف_کرو	SLIST_سرا(سر)		عدم
#تعریف_کرو	SLIST_EMPTY(سر)	(SLIST_FIRST(سر) == SLIST_سرا(سر))
#تعریف_کرو	SLIST_NEXT(elm, میدان)	((elm)->میدان.sle_اگلا)

#تعریف_کرو	SLIST_FOREACH(var, سر, میدان)					\
	لكل((var) = SLIST_FIRST(سر);					\
	    (var) != SLIST_سرا(سر);					\
	    (var) = SLIST_NEXT(var, میدان))

#تعریف_کرو	SLIST_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	لكل ((var) = SLIST_FIRST(سر);				\
	    (var) && ((tvar) = SLIST_NEXT(var, میدان), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#تعریف_کرو	SLIST_INIT(سر) {						\
	SLIST_FIRST(سر) = SLIST_سرا(سر);				\
}

#تعریف_کرو	SLIST_INSERT_AFTER(slistelm, elm, میدان) افعل {			\
	(elm)->میدان.sle_اگلا = (slistelm)->میدان.sle_اگلا;		\
	(slistelm)->میدان.sle_اگلا = (elm);				\
} طالما (0)

#تعریف_کرو	SLIST_INSERT_HEAD(سر, elm, میدان) افعل {			\
	(elm)->میدان.sle_اگلا = (سر)->slh_پہلا;			\
	(سر)->slh_پہلا = (elm);					\
} طالما (0)

#تعریف_کرو	SLIST_REMOVE_AFTER(elm, میدان) افعل {				\
	(elm)->میدان.sle_اگلا = (elm)->میدان.sle_اگلا->میدان.sle_اگلا;	\
} طالما (0)

#تعریف_کرو	SLIST_REMOVE_HEAD(سر, میدان) افعل {				\
	(سر)->slh_پہلا = (سر)->slh_پہلا->میدان.sle_اگلا;		\
} طالما (0)

#تعریف_کرو SLIST_REMOVE(سر, elm, type, میدان) افعل {			\
	إذا ((سر)->slh_پہلا == (elm)) {				\
		SLIST_REMOVE_HEAD((سر), میدان);			\
	} وإلا {							\
		بنية type *curelm = (سر)->slh_پہلا;		\
									\
		طالما (curelm->میدان.sle_اگلا != (elm))			\
			curelm = curelm->میدان.sle_اگلا;		\
		curelm->میدان.sle_اگلا =				\
		    curelm->میدان.sle_اگلا->میدان.sle_اگلا;		\
	}								\
	_Q_INVALIDATE((elm)->میدان.sle_اگلا);				\
} طالما (0)

/*
 * List definitions.
 */
#تعریف_کرو LIST_HEAD(name, type)						\
بنية name {								\
	بنية type *lh_پہلا;	/* first element */			\
}

#تعریف_کرو LIST_HEAD_INITIALIZER(سر)					\
	{ عدم }

#تعریف_کرو LIST_ENTRY(type)						\
بنية {								\
	بنية type *le_اگلا;	/* next element */			\
	بنية type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#تعریف_کرو	LIST_FIRST(سر)		((سر)->lh_پہلا)
#تعریف_کرو	LIST_سرا(سر)			عدم
#تعریف_کرو	LIST_EMPTY(سر)		(LIST_FIRST(سر) == LIST_سرا(سر))
#تعریف_کرو	LIST_NEXT(elm, میدان)		((elm)->میدان.le_اگلا)

#تعریف_کرو LIST_FOREACH(var, سر, میدان)					\
	لكل((var) = LIST_FIRST(سر);					\
	    (var)!= LIST_سرا(سر);					\
	    (var) = LIST_NEXT(var, میدان))

#تعریف_کرو	LIST_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	لكل ((var) = LIST_FIRST(سر);				\
	    (var) && ((tvar) = LIST_NEXT(var, میدان), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#تعریف_کرو	LIST_INIT(سر) افعل {						\
	LIST_FIRST(سر) = LIST_سرا(سر);				\
} طالما (0)

#تعریف_کرو LIST_INSERT_AFTER(listelm, elm, میدان) افعل {			\
	إذا (((elm)->میدان.le_اگلا = (listelm)->میدان.le_اگلا) != عدم)	\
		(listelm)->میدان.le_اگلا->میدان.le_prev =		\
		    &(elm)->میدان.le_اگلا;				\
	(listelm)->میدان.le_اگلا = (elm);				\
	(elm)->میدان.le_prev = &(listelm)->میدان.le_اگلا;		\
} طالما (0)

#تعریف_کرو	LIST_INSERT_BEFORE(listelm, elm, میدان) افعل {			\
	(elm)->میدان.le_prev = (listelm)->میدان.le_prev;		\
	(elm)->میدان.le_اگلا = (listelm);				\
	*(listelm)->میدان.le_prev = (elm);				\
	(listelm)->میدان.le_prev = &(elm)->میدان.le_اگلا;		\
} طالما (0)

#تعریف_کرو LIST_INSERT_HEAD(سر, elm, میدان) افعل {				\
	إذا (((elm)->میدان.le_اگلا = (سر)->lh_پہلا) != عدم)		\
		(سر)->lh_پہلا->میدان.le_prev = &(elm)->میدان.le_اگلا;\
	(سر)->lh_پہلا = (elm);					\
	(elm)->میدان.le_prev = &(سر)->lh_پہلا;			\
} طالما (0)

#تعریف_کرو LIST_REMOVE(elm, میدان) افعل {					\
	إذا ((elm)->میدان.le_اگلا != عدم)				\
		(elm)->میدان.le_اگلا->میدان.le_prev =			\
		    (elm)->میدان.le_prev;				\
	*(elm)->میدان.le_prev = (elm)->میدان.le_اگلا;			\
	_Q_INVALIDATE((elm)->میدان.le_prev);				\
	_Q_INVALIDATE((elm)->میدان.le_اگلا);				\
} طالما (0)

#تعریف_کرو LIST_REPLACE(elm, elm2, میدان) افعل {				\
	إذا (((elm2)->میدان.le_اگلا = (elm)->میدان.le_اگلا) != عدم)	\
		(elm2)->میدان.le_اگلا->میدان.le_prev =			\
		    &(elm2)->میدان.le_اگلا;				\
	(elm2)->میدان.le_prev = (elm)->میدان.le_prev;			\
	*(elm2)->میدان.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->میدان.le_prev);				\
	_Q_INVALIDATE((elm)->میدان.le_اگلا);				\
} طالما (0)

/*
 * Simple queue definitions.
 */
#تعریف_کرو SIMPLEQ_HEAD(name, type)					\
بنية name {								\
	بنية type *sqh_پہلا;	/* first element */			\
	بنية type **sqh_آخری;	/* addr of last next element */		\
}

#تعریف_کرو SIMPLEQ_HEAD_INITIALIZER(سر)					\
	{ عدم, &(سر).sqh_پہلا }

#تعریف_کرو SIMPLEQ_ENTRY(type)						\
بنية {								\
	بنية type *sqe_اگلا;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#تعریف_کرو	SIMPLEQ_FIRST(سر)	    ((سر)->sqh_پہلا)
#تعریف_کرو	SIMPLEQ_سرا(سر)	    عدم
#تعریف_کرو	SIMPLEQ_EMPTY(سر)	    (SIMPLEQ_FIRST(سر) == SIMPLEQ_سرا(سر))
#تعریف_کرو	SIMPLEQ_NEXT(elm, میدان)    ((elm)->میدان.sqe_اگلا)

#تعریف_کرو SIMPLEQ_FOREACH(var, سر, میدان)				\
	لكل((var) = SIMPLEQ_FIRST(سر);				\
	    (var) != SIMPLEQ_سرا(سر);					\
	    (var) = SIMPLEQ_NEXT(var, میدان))

#تعریف_کرو	SIMPLEQ_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	لكل ((var) = SIMPLEQ_FIRST(سر);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, میدان), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#تعریف_کرو	SIMPLEQ_INIT(سر) افعل {						\
	(سر)->sqh_پہلا = عدم;					\
	(سر)->sqh_آخری = &(سر)->sqh_پہلا;				\
} طالما (0)

#تعریف_کرو SIMPLEQ_INSERT_HEAD(سر, elm, میدان) افعل {			\
	إذا (((elm)->میدان.sqe_اگلا = (سر)->sqh_پہلا) == عدم)	\
		(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;		\
	(سر)->sqh_پہلا = (elm);					\
} طالما (0)

#تعریف_کرو SIMPLEQ_INSERT_TAIL(سر, elm, میدان) افعل {			\
	(elm)->میدان.sqe_اگلا = عدم;					\
	*(سر)->sqh_آخری = (elm);					\
	(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;			\
} طالما (0)

#تعریف_کرو SIMPLEQ_INSERT_AFTER(سر, listelm, elm, میدان) افعل {		\
	إذا (((elm)->میدان.sqe_اگلا = (listelm)->میدان.sqe_اگلا) == عدم)\
		(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;		\
	(listelm)->میدان.sqe_اگلا = (elm);				\
} طالما (0)

#تعریف_کرو SIMPLEQ_REMOVE_HEAD(سر, میدان) افعل {			\
	إذا (((سر)->sqh_پہلا = (سر)->sqh_پہلا->میدان.sqe_اگلا) == عدم) \
		(سر)->sqh_آخری = &(سر)->sqh_پہلا;			\
} طالما (0)

#تعریف_کرو SIMPLEQ_REMOVE_AFTER(سر, elm, میدان) افعل {			\
	إذا (((elm)->میدان.sqe_اگلا = (elm)->میدان.sqe_اگلا->میدان.sqe_اگلا) \
	    == عدم)							\
		(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;		\
} طالما (0)

#تعریف_کرو SIMPLEQ_CONCAT(head1, head2) افعل {				\
	إذا (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_آخری = (head2)->sqh_پہلا;		\
		(head1)->sqh_آخری = (head2)->sqh_آخری;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} طالما (0)

/*
 * XOR Simple queue definitions.
 */
#تعریف_کرو XSIMPLEQ_سر(name, type)					\
بنية name {								\
	بنية type *sqx_پہلا;	/* first element */			\
	بنية type **sqx_آخری;	/* addr of last next element */		\
	بنانشانی لما sqx_cookie;					\
}

#تعریف_کرو XSIMPLEQ_اندراج(type)						\
بنية {								\
	بنية type *sqx_اگلا;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#تعریف_کرو XSIMPLEQ_XOR(سر, ptr)	    ((__typeof(ptr))((سر)->sqx_cookie ^ \
					(بنانشانی لما)(ptr)))
#تعریف_کرو	XSIMPLEQ_پہلا(سر)	    XSIMPLEQ_XOR(سر, ((سر)->sqx_پہلا))
#تعریف_کرو	XSIMPLEQ_سرا(سر)	    عدم
#تعریف_کرو	XSIMPLEQ_خالی_تھاواں(سر)	    (XSIMPLEQ_پہلا(سر) == XSIMPLEQ_سرا(سر))
#تعریف_کرو	XSIMPLEQ_اگلا(سر, elm, میدان)    XSIMPLEQ_XOR(سر, ((elm)->میدان.sqx_اگلا))


#تعریف_کرو XSIMPLEQ_FOREACH(var, سر, میدان)				\
	لكل ((var) = XSIMPLEQ_پہلا(سر);				\
	    (var) != XSIMPLEQ_سرا(سر);				\
	    (var) = XSIMPLEQ_اگلا(سر, var, میدان))

#تعریف_کرو	XSIMPLEQ_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	لكل ((var) = XSIMPLEQ_پہلا(سر);				\
	    (var) && ((tvar) = XSIMPLEQ_اگلا(سر, var, میدان), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#تعریف_کرو	XSIMPLEQ_INIT(سر) افعل {					\
	arc4random_buf(&(سر)->sqx_cookie, حجم((سر)->sqx_cookie)); \
	(سر)->sqx_پہلا = XSIMPLEQ_XOR(سر, عدم);			\
	(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(سر)->sqx_پہلا);	\
} طالما (0)

#تعریف_کرو XSIMPLEQ_داخل_کرو_سر(سر, elm, میدان) افعل {			\
	إذا (((elm)->میدان.sqx_اگلا = (سر)->sqx_پہلا) ==		\
	    XSIMPLEQ_XOR(سر, عدم))					\
		(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا); \
	(سر)->sqx_پہلا = XSIMPLEQ_XOR(سر, (elm));			\
} طالما (0)

#تعریف_کرو XSIMPLEQ_داخل_کرو_پوچھ(سر, elm, میدان) افعل {			\
	(elm)->میدان.sqx_اگلا = XSIMPLEQ_XOR(سر, عدم);		\
	*(XSIMPLEQ_XOR(سر, (سر)->sqx_آخری)) = XSIMPLEQ_XOR(سر, (elm)); \
	(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا);	\
} طالما (0)

#تعریف_کرو XSIMPLEQ_داخل_کرو_AFTER(سر, listelm, elm, میدان) افعل {		\
	إذا (((elm)->میدان.sqx_اگلا = (listelm)->میدان.sqx_اگلا) ==	\
	    XSIMPLEQ_XOR(سر, عدم))					\
		(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا); \
	(listelm)->میدان.sqx_اگلا = XSIMPLEQ_XOR(سر, (elm));		\
} طالما (0)

#تعریف_کرو XSIMPLEQ_REMOVE_سر(سر, میدان) افعل {				\
	إذا (((سر)->sqx_پہلا = XSIMPLEQ_XOR(سر,			\
	    (سر)->sqx_پہلا)->میدان.sqx_اگلا) == XSIMPLEQ_XOR(سر, عدم)) \
		(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(سر)->sqx_پہلا); \
} طالما (0)

#تعریف_کرو XSIMPLEQ_REMOVE_AFTER(سر, elm, میدان) افعل {			\
	إذا (((elm)->میدان.sqx_اگلا = XSIMPLEQ_XOR(سر,			\
	    (elm)->میدان.sqx_اگلا)->میدان.sqx_اگلا)			\
	    == XSIMPLEQ_XOR(سر, عدم))				\
		(سر)->sqx_آخری = 					\
		    XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا);		\
} طالما (0)


/*
 * Tail queue definitions.
 */
#تعریف_کرو TAILQ_HEAD(name, type)						\
بنية name {								\
	بنية type *tqh_first;	/* first element */			\
	بنية type **tqh_last;	/* addr of last next element */		\
}

#تعریف_کرو TAILQ_HEAD_INITIALIZER(سر)					\
	{ عدم, &(سر).tqh_first }

#تعریف_کرو TAILQ_ENTRY(type)						\
بنية {								\
	بنية type *tqe_next;	/* next element */			\
	بنية type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#تعریف_کرو	TAILQ_FIRST(سر)		((سر)->tqh_first)
#تعریف_کرو	TAILQ_سرا(سر)			عدم
#تعریف_کرو	TAILQ_NEXT(elm, میدان)		((elm)->میدان.tqe_next)
#تعریف_کرو TAILQ_LAST(سر, headname)					\
	(*(((بنية headname *)((سر)->tqh_last))->tqh_last))
/* XXX */
#تعریف_کرو TAILQ_PREV(elm, headname, میدان)				\
	(*(((بنية headname *)((elm)->میدان.tqe_prev))->tqh_last))
#تعریف_کرو	TAILQ_EMPTY(سر)						\
	(TAILQ_FIRST(سر) == TAILQ_سرا(سر))

#تعریف_کرو TAILQ_FOREACH(var, سر, میدان)					\
	لكل((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_سرا(سر);					\
	    (var) = TAILQ_NEXT(var, میدان))

#تعریف_کرو	TAILQ_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	لكل ((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_سرا(سر) &&					\
	    ((tvar) = TAILQ_NEXT(var, میدان), 1);			\
	    (var) = (tvar))


#تعریف_کرو TAILQ_FOREACH_الٹ(var, سر, headname, میدان)		\
	لكل((var) = TAILQ_LAST(سر, headname);				\
	    (var) != TAILQ_سرا(سر);					\
	    (var) = TAILQ_PREV(var, headname, میدان))

#تعریف_کرو	TAILQ_FOREACH_الٹ_محفوظ(var, سر, headname, میدان, tvar)	\
	لكل ((var) = TAILQ_LAST(سر, headname);			\
	    (var) != TAILQ_سرا(سر) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, میدان), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#تعریف_کرو	TAILQ_INIT(سر) افعل {						\
	(سر)->tqh_first = عدم;					\
	(سر)->tqh_last = &(سر)->tqh_first;				\
} طالما (0)

#تعریف_کرو TAILQ_INSERT_HEAD(سر, elm, میدان) افعل {			\
	إذا (((elm)->میدان.tqe_next = (سر)->tqh_first) != عدم)	\
		(سر)->tqh_first->میدان.tqe_prev =			\
		    &(elm)->میدان.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm)->میدان.tqe_next;		\
	(سر)->tqh_first = (elm);					\
	(elm)->میدان.tqe_prev = &(سر)->tqh_first;			\
} طالما (0)

#تعریف_کرو TAILQ_INSERT_TAIL(سر, elm, میدان) افعل {			\
	(elm)->میدان.tqe_next = عدم;					\
	(elm)->میدان.tqe_prev = (سر)->tqh_last;			\
	*(سر)->tqh_last = (elm);					\
	(سر)->tqh_last = &(elm)->میدان.tqe_next;			\
} طالما (0)

#تعریف_کرو TAILQ_INSERT_AFTER(سر, listelm, elm, میدان) افعل {		\
	إذا (((elm)->میدان.tqe_next = (listelm)->میدان.tqe_next) != عدم)\
		(elm)->میدان.tqe_next->میدان.tqe_prev =			\
		    &(elm)->میدان.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm)->میدان.tqe_next;		\
	(listelm)->میدان.tqe_next = (elm);				\
	(elm)->میدان.tqe_prev = &(listelm)->میدان.tqe_next;		\
} طالما (0)

#تعریف_کرو	TAILQ_INSERT_BEFORE(listelm, elm, میدان) افعل {			\
	(elm)->میدان.tqe_prev = (listelm)->میدان.tqe_prev;		\
	(elm)->میدان.tqe_next = (listelm);				\
	*(listelm)->میدان.tqe_prev = (elm);				\
	(listelm)->میدان.tqe_prev = &(elm)->میدان.tqe_next;		\
} طالما (0)

#تعریف_کرو TAILQ_REMOVE(سر, elm, میدان) افعل {				\
	إذا (((elm)->میدان.tqe_next) != عدم)				\
		(elm)->میدان.tqe_next->میدان.tqe_prev =			\
		    (elm)->میدان.tqe_prev;				\
	وإلا								\
		(سر)->tqh_last = (elm)->میدان.tqe_prev;		\
	*(elm)->میدان.tqe_prev = (elm)->میدان.tqe_next;			\
	_Q_INVALIDATE((elm)->میدان.tqe_prev);				\
	_Q_INVALIDATE((elm)->میدان.tqe_next);				\
} طالما (0)

#تعریف_کرو TAILQ_REPLACE(سر, elm, elm2, میدان) افعل {			\
	إذا (((elm2)->میدان.tqe_next = (elm)->میدان.tqe_next) != عدم)	\
		(elm2)->میدان.tqe_next->میدان.tqe_prev =		\
		    &(elm2)->میدان.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm2)->میدان.tqe_next;		\
	(elm2)->میدان.tqe_prev = (elm)->میدان.tqe_prev;			\
	*(elm2)->میدان.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->میدان.tqe_prev);				\
	_Q_INVALIDATE((elm)->میدان.tqe_next);				\
} طالما (0)

#تعریف_کرو TAILQ_CONCAT(head1, head2, میدان) افعل {				\
	إذا (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->میدان.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} طالما (0)

#جے_انت	/* !_SYS_QUEUE_H_ */
