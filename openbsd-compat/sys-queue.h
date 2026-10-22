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

#اگر_غیر_تعریف_شدہ	FAKE_قطار_H
#تعریف_کرو	FAKE_قطار_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#تعریف_منسوخ CIRCLEQ_EMPTY
#تعریف_منسوخ CIRCLEQ_انتہا
#تعریف_منسوخ CIRCLEQ_ENTRY
#تعریف_منسوخ CIRCLEQ_FIRST
#تعریف_منسوخ CIRCLEQ_FOREACH
#تعریف_منسوخ CIRCLEQ_FOREACH_REVERSE
#تعریف_منسوخ CIRCLEQ_HEAD
#تعریف_منسوخ CIRCLEQ_HEAD_INITIALIZER
#تعریف_منسوخ CIRCLEQ_INIT
#تعریف_منسوخ CIRCLEQ_INSERT_AFTER
#تعریف_منسوخ CIRCLEQ_INSERT_BEFORE
#تعریف_منسوخ CIRCLEQ_INSERT_HEAD
#تعریف_منسوخ CIRCLEQ_INSERT_TAIL
#تعریف_منسوخ CIRCLEQ_LAST
#تعریف_منسوخ CIRCLEQ_NEXT
#تعریف_منسوخ CIRCLEQ_PREV
#تعریف_منسوخ CIRCLEQ_REMOVE
#تعریف_منسوخ CIRCLEQ_REPLACE
#تعریف_منسوخ LIST_EMPTY
#تعریف_منسوخ LIST_انتہا
#تعریف_منسوخ LIST_ENTRY
#تعریف_منسوخ LIST_FIRST
#تعریف_منسوخ LIST_FOREACH
#تعریف_منسوخ LIST_FOREACH_محفوظ
#تعریف_منسوخ LIST_HEAD
#تعریف_منسوخ LIST_HEAD_INITIALIZER
#تعریف_منسوخ LIST_INIT
#تعریف_منسوخ LIST_INSERT_AFTER
#تعریف_منسوخ LIST_INSERT_BEFORE
#تعریف_منسوخ LIST_INSERT_HEAD
#تعریف_منسوخ LIST_NEXT
#تعریف_منسوخ LIST_REMOVE
#تعریف_منسوخ LIST_REPLACE
#تعریف_منسوخ SIMPLEQ_CONCAT
#تعریف_منسوخ SIMPLEQ_EMPTY
#تعریف_منسوخ SIMPLEQ_انتہا
#تعریف_منسوخ SIMPLEQ_ENTRY
#تعریف_منسوخ SIMPLEQ_FIRST
#تعریف_منسوخ SIMPLEQ_FOREACH
#تعریف_منسوخ SIMPLEQ_FOREACH_محفوظ
#تعریف_منسوخ SIMPLEQ_HEAD
#تعریف_منسوخ SIMPLEQ_HEAD_INITIALIZER
#تعریف_منسوخ SIMPLEQ_INIT
#تعریف_منسوخ SIMPLEQ_INSERT_AFTER
#تعریف_منسوخ SIMPLEQ_INSERT_HEAD
#تعریف_منسوخ SIMPLEQ_INSERT_TAIL
#تعریف_منسوخ SIMPLEQ_NEXT
#تعریف_منسوخ SIMPLEQ_REMOVE_AFTER
#تعریف_منسوخ SIMPLEQ_REMOVE_HEAD
#تعریف_منسوخ SLIST_EMPTY
#تعریف_منسوخ SLIST_انتہا
#تعریف_منسوخ SLIST_ENTRY
#تعریف_منسوخ SLIST_FIRST
#تعریف_منسوخ SLIST_FOREACH
#تعریف_منسوخ SLIST_FOREACH_PREVPTR
#تعریف_منسوخ SLIST_FOREACH_محفوظ
#تعریف_منسوخ SLIST_HEAD
#تعریف_منسوخ SLIST_HEAD_INITIALIZER
#تعریف_منسوخ SLIST_INIT
#تعریف_منسوخ SLIST_INSERT_AFTER
#تعریف_منسوخ SLIST_INSERT_HEAD
#تعریف_منسوخ SLIST_NEXT
#تعریف_منسوخ SLIST_REMOVE
#تعریف_منسوخ SLIST_REMOVE_AFTER
#تعریف_منسوخ SLIST_REMOVE_HEAD
#تعریف_منسوخ SLIST_REMOVE_اگلا
#تعریف_منسوخ TAILQ_CONCAT
#تعریف_منسوخ TAILQ_EMPTY
#تعریف_منسوخ TAILQ_انتہا
#تعریف_منسوخ TAILQ_ENTRY
#تعریف_منسوخ TAILQ_FIRST
#تعریف_منسوخ TAILQ_FOREACH
#تعریف_منسوخ TAILQ_FOREACH_الٹ
#تعریف_منسوخ TAILQ_FOREACH_الٹ_محفوظ
#تعریف_منسوخ TAILQ_FOREACH_محفوظ
#تعریف_منسوخ TAILQ_HEAD
#تعریف_منسوخ TAILQ_HEAD_INITIALIZER
#تعریف_منسوخ TAILQ_INIT
#تعریف_منسوخ TAILQ_INSERT_AFTER
#تعریف_منسوخ TAILQ_INSERT_BEFORE
#تعریف_منسوخ TAILQ_INSERT_HEAD
#تعریف_منسوخ TAILQ_INSERT_TAIL
#تعریف_منسوخ TAILQ_LAST
#تعریف_منسوخ TAILQ_NEXT
#تعریف_منسوخ TAILQ_PREV
#تعریف_منسوخ TAILQ_REMOVE
#تعریف_منسوخ TAILQ_REPLACE

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

#اگر defined(قطار_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#تعریف_کرو _Q_INVALID ((خالی *)-1)
#تعریف_کرو _Q_INVALIDATE(a) (a) = _Q_INVALID
#ورنہ
#تعریف_کرو _Q_INVALIDATE(a)
#اگر_ختم

/*
 * Singly-linked List definitions.
 */
#تعریف_کرو SLIST_HEAD(name, type)						\
ساخت name {								\
	ساخت type *slh_پہلا;	/* first element */			\
}

#تعریف_کرو	SLIST_HEAD_INITIALIZER(سر)					\
	{ تہی }

#تعریف_کرو SLIST_ENTRY(type)						\
ساخت {								\
	ساخت type *sle_اگلا;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#تعریف_کرو	SLIST_FIRST(سر)	((سر)->slh_پہلا)
#تعریف_کرو	SLIST_انتہا(سر)		تہی
#تعریف_کرو	SLIST_EMPTY(سر)	(SLIST_FIRST(سر) == SLIST_انتہا(سر))
#تعریف_کرو	SLIST_NEXT(elm, میدان)	((elm)->میدان.sle_اگلا)

#تعریف_کرو	SLIST_FOREACH(var, سر, میدان)					\
	برائے((var) = SLIST_FIRST(سر);					\
	    (var) != SLIST_انتہا(سر);					\
	    (var) = SLIST_NEXT(var, میدان))

#تعریف_کرو	SLIST_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	برائے ((var) = SLIST_FIRST(سر);				\
	    (var) && ((tvar) = SLIST_NEXT(var, میدان), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#تعریف_کرو	SLIST_INIT(سر) {						\
	SLIST_FIRST(سر) = SLIST_انتہا(سر);				\
}

#تعریف_کرو	SLIST_INSERT_AFTER(slistelm, elm, میدان) کرو {			\
	(elm)->میدان.sle_اگلا = (slistelm)->میدان.sle_اگلا;		\
	(slistelm)->میدان.sle_اگلا = (elm);				\
} جب (0)

#تعریف_کرو	SLIST_INSERT_HEAD(سر, elm, میدان) کرو {			\
	(elm)->میدان.sle_اگلا = (سر)->slh_پہلا;			\
	(سر)->slh_پہلا = (elm);					\
} جب (0)

#تعریف_کرو	SLIST_REMOVE_AFTER(elm, میدان) کرو {				\
	(elm)->میدان.sle_اگلا = (elm)->میدان.sle_اگلا->میدان.sle_اگلا;	\
} جب (0)

#تعریف_کرو	SLIST_REMOVE_HEAD(سر, میدان) کرو {				\
	(سر)->slh_پہلا = (سر)->slh_پہلا->میدان.sle_اگلا;		\
} جب (0)

#تعریف_کرو SLIST_REMOVE(سر, elm, type, میدان) کرو {			\
	اگر ((سر)->slh_پہلا == (elm)) {				\
		SLIST_REMOVE_HEAD((سر), میدان);			\
	} ورنہ {							\
		ساخت type *curelm = (سر)->slh_پہلا;		\
									\
		جب (curelm->میدان.sle_اگلا != (elm))			\
			curelm = curelm->میدان.sle_اگلا;		\
		curelm->میدان.sle_اگلا =				\
		    curelm->میدان.sle_اگلا->میدان.sle_اگلا;		\
	}								\
	_Q_INVALIDATE((elm)->میدان.sle_اگلا);				\
} جب (0)

/*
 * List definitions.
 */
#تعریف_کرو LIST_HEAD(name, type)						\
ساخت name {								\
	ساخت type *lh_پہلا;	/* first element */			\
}

#تعریف_کرو LIST_HEAD_INITIALIZER(سر)					\
	{ تہی }

#تعریف_کرو LIST_ENTRY(type)						\
ساخت {								\
	ساخت type *le_اگلا;	/* next element */			\
	ساخت type **le_پچھلا;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#تعریف_کرو	LIST_FIRST(سر)		((سر)->lh_پہلا)
#تعریف_کرو	LIST_انتہا(سر)			تہی
#تعریف_کرو	LIST_EMPTY(سر)		(LIST_FIRST(سر) == LIST_انتہا(سر))
#تعریف_کرو	LIST_NEXT(elm, میدان)		((elm)->میدان.le_اگلا)

#تعریف_کرو LIST_FOREACH(var, سر, میدان)					\
	برائے((var) = LIST_FIRST(سر);					\
	    (var)!= LIST_انتہا(سر);					\
	    (var) = LIST_NEXT(var, میدان))

#تعریف_کرو	LIST_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	برائے ((var) = LIST_FIRST(سر);				\
	    (var) && ((tvar) = LIST_NEXT(var, میدان), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#تعریف_کرو	LIST_INIT(سر) کرو {						\
	LIST_FIRST(سر) = LIST_انتہا(سر);				\
} جب (0)

#تعریف_کرو LIST_INSERT_AFTER(listelm, elm, میدان) کرو {			\
	اگر (((elm)->میدان.le_اگلا = (listelm)->میدان.le_اگلا) != تہی)	\
		(listelm)->میدان.le_اگلا->میدان.le_پچھلا =		\
		    &(elm)->میدان.le_اگلا;				\
	(listelm)->میدان.le_اگلا = (elm);				\
	(elm)->میدان.le_پچھلا = &(listelm)->میدان.le_اگلا;		\
} جب (0)

#تعریف_کرو	LIST_INSERT_BEFORE(listelm, elm, میدان) کرو {			\
	(elm)->میدان.le_پچھلا = (listelm)->میدان.le_پچھلا;		\
	(elm)->میدان.le_اگلا = (listelm);				\
	*(listelm)->میدان.le_پچھلا = (elm);				\
	(listelm)->میدان.le_پچھلا = &(elm)->میدان.le_اگلا;		\
} جب (0)

#تعریف_کرو LIST_INSERT_HEAD(سر, elm, میدان) کرو {				\
	اگر (((elm)->میدان.le_اگلا = (سر)->lh_پہلا) != تہی)		\
		(سر)->lh_پہلا->میدان.le_پچھلا = &(elm)->میدان.le_اگلا;\
	(سر)->lh_پہلا = (elm);					\
	(elm)->میدان.le_پچھلا = &(سر)->lh_پہلا;			\
} جب (0)

#تعریف_کرو LIST_REMOVE(elm, میدان) کرو {					\
	اگر ((elm)->میدان.le_اگلا != تہی)				\
		(elm)->میدان.le_اگلا->میدان.le_پچھلا =			\
		    (elm)->میدان.le_پچھلا;				\
	*(elm)->میدان.le_پچھلا = (elm)->میدان.le_اگلا;			\
	_Q_INVALIDATE((elm)->میدان.le_پچھلا);				\
	_Q_INVALIDATE((elm)->میدان.le_اگلا);				\
} جب (0)

#تعریف_کرو LIST_REPLACE(elm, elm2, میدان) کرو {				\
	اگر (((elm2)->میدان.le_اگلا = (elm)->میدان.le_اگلا) != تہی)	\
		(elm2)->میدان.le_اگلا->میدان.le_پچھلا =			\
		    &(elm2)->میدان.le_اگلا;				\
	(elm2)->میدان.le_پچھلا = (elm)->میدان.le_پچھلا;			\
	*(elm2)->میدان.le_پچھلا = (elm2);				\
	_Q_INVALIDATE((elm)->میدان.le_پچھلا);				\
	_Q_INVALIDATE((elm)->میدان.le_اگلا);				\
} جب (0)

/*
 * Simple queue definitions.
 */
#تعریف_کرو SIMPLEQ_HEAD(name, type)					\
ساخت name {								\
	ساخت type *sqh_پہلا;	/* first element */			\
	ساخت type **sqh_آخری;	/* addr of last next element */		\
}

#تعریف_کرو SIMPLEQ_HEAD_INITIALIZER(سر)					\
	{ تہی, &(سر).sqh_پہلا }

#تعریف_کرو SIMPLEQ_ENTRY(type)						\
ساخت {								\
	ساخت type *sqe_اگلا;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#تعریف_کرو	SIMPLEQ_FIRST(سر)	    ((سر)->sqh_پہلا)
#تعریف_کرو	SIMPLEQ_انتہا(سر)	    تہی
#تعریف_کرو	SIMPLEQ_EMPTY(سر)	    (SIMPLEQ_FIRST(سر) == SIMPLEQ_انتہا(سر))
#تعریف_کرو	SIMPLEQ_NEXT(elm, میدان)    ((elm)->میدان.sqe_اگلا)

#تعریف_کرو SIMPLEQ_FOREACH(var, سر, میدان)				\
	برائے((var) = SIMPLEQ_FIRST(سر);				\
	    (var) != SIMPLEQ_انتہا(سر);					\
	    (var) = SIMPLEQ_NEXT(var, میدان))

#تعریف_کرو	SIMPLEQ_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	برائے ((var) = SIMPLEQ_FIRST(سر);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, میدان), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#تعریف_کرو	SIMPLEQ_INIT(سر) کرو {						\
	(سر)->sqh_پہلا = تہی;					\
	(سر)->sqh_آخری = &(سر)->sqh_پہلا;				\
} جب (0)

#تعریف_کرو SIMPLEQ_INSERT_HEAD(سر, elm, میدان) کرو {			\
	اگر (((elm)->میدان.sqe_اگلا = (سر)->sqh_پہلا) == تہی)	\
		(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;		\
	(سر)->sqh_پہلا = (elm);					\
} جب (0)

#تعریف_کرو SIMPLEQ_INSERT_TAIL(سر, elm, میدان) کرو {			\
	(elm)->میدان.sqe_اگلا = تہی;					\
	*(سر)->sqh_آخری = (elm);					\
	(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;			\
} جب (0)

#تعریف_کرو SIMPLEQ_INSERT_AFTER(سر, listelm, elm, میدان) کرو {		\
	اگر (((elm)->میدان.sqe_اگلا = (listelm)->میدان.sqe_اگلا) == تہی)\
		(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;		\
	(listelm)->میدان.sqe_اگلا = (elm);				\
} جب (0)

#تعریف_کرو SIMPLEQ_REMOVE_HEAD(سر, میدان) کرو {			\
	اگر (((سر)->sqh_پہلا = (سر)->sqh_پہلا->میدان.sqe_اگلا) == تہی) \
		(سر)->sqh_آخری = &(سر)->sqh_پہلا;			\
} جب (0)

#تعریف_کرو SIMPLEQ_REMOVE_AFTER(سر, elm, میدان) کرو {			\
	اگر (((elm)->میدان.sqe_اگلا = (elm)->میدان.sqe_اگلا->میدان.sqe_اگلا) \
	    == تہی)							\
		(سر)->sqh_آخری = &(elm)->میدان.sqe_اگلا;		\
} جب (0)

#تعریف_کرو SIMPLEQ_CONCAT(head1, head2) کرو {				\
	اگر (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_آخری = (head2)->sqh_پہلا;		\
		(head1)->sqh_آخری = (head2)->sqh_آخری;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} جب (0)

/*
 * XOR Simple queue definitions.
 */
#تعریف_کرو XSIMPLEQ_سر(name, type)					\
ساخت name {								\
	ساخت type *sqx_پہلا;	/* first element */			\
	ساخت type **sqx_آخری;	/* addr of last next element */		\
	غیرعلامتی طویل sqx_cookie;					\
}

#تعریف_کرو XSIMPLEQ_اندراج(type)						\
ساخت {								\
	ساخت type *sqx_اگلا;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#تعریف_کرو XSIMPLEQ_XOR(سر, ptr)	    ((__typeof(ptr))((سر)->sqx_cookie ^ \
					(غیرعلامتی طویل)(ptr)))
#تعریف_کرو	XSIMPLEQ_پہلا(سر)	    XSIMPLEQ_XOR(سر, ((سر)->sqx_پہلا))
#تعریف_کرو	XSIMPLEQ_انتہا(سر)	    تہی
#تعریف_کرو	XSIMPLEQ_خالی_خانے(سر)	    (XSIMPLEQ_پہلا(سر) == XSIMPLEQ_انتہا(سر))
#تعریف_کرو	XSIMPLEQ_اگلا(سر, elm, میدان)    XSIMPLEQ_XOR(سر, ((elm)->میدان.sqx_اگلا))


#تعریف_کرو XSIMPLEQ_FOREACH(var, سر, میدان)				\
	برائے ((var) = XSIMPLEQ_پہلا(سر);				\
	    (var) != XSIMPLEQ_انتہا(سر);				\
	    (var) = XSIMPLEQ_اگلا(سر, var, میدان))

#تعریف_کرو	XSIMPLEQ_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	برائے ((var) = XSIMPLEQ_پہلا(سر);				\
	    (var) && ((tvar) = XSIMPLEQ_اگلا(سر, var, میدان), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#تعریف_کرو	XSIMPLEQ_INIT(سر) کرو {					\
	arc4random_buf(&(سر)->sqx_cookie, حجم((سر)->sqx_cookie)); \
	(سر)->sqx_پہلا = XSIMPLEQ_XOR(سر, تہی);			\
	(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(سر)->sqx_پہلا);	\
} جب (0)

#تعریف_کرو XSIMPLEQ_داخل_کرو_سر(سر, elm, میدان) کرو {			\
	اگر (((elm)->میدان.sqx_اگلا = (سر)->sqx_پہلا) ==		\
	    XSIMPLEQ_XOR(سر, تہی))					\
		(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا); \
	(سر)->sqx_پہلا = XSIMPLEQ_XOR(سر, (elm));			\
} جب (0)

#تعریف_کرو XSIMPLEQ_داخل_کرو_دم(سر, elm, میدان) کرو {			\
	(elm)->میدان.sqx_اگلا = XSIMPLEQ_XOR(سر, تہی);		\
	*(XSIMPLEQ_XOR(سر, (سر)->sqx_آخری)) = XSIMPLEQ_XOR(سر, (elm)); \
	(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا);	\
} جب (0)

#تعریف_کرو XSIMPLEQ_داخل_کرو_AFTER(سر, listelm, elm, میدان) کرو {		\
	اگر (((elm)->میدان.sqx_اگلا = (listelm)->میدان.sqx_اگلا) ==	\
	    XSIMPLEQ_XOR(سر, تہی))					\
		(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا); \
	(listelm)->میدان.sqx_اگلا = XSIMPLEQ_XOR(سر, (elm));		\
} جب (0)

#تعریف_کرو XSIMPLEQ_REMOVE_سر(سر, میدان) کرو {				\
	اگر (((سر)->sqx_پہلا = XSIMPLEQ_XOR(سر,			\
	    (سر)->sqx_پہلا)->میدان.sqx_اگلا) == XSIMPLEQ_XOR(سر, تہی)) \
		(سر)->sqx_آخری = XSIMPLEQ_XOR(سر, &(سر)->sqx_پہلا); \
} جب (0)

#تعریف_کرو XSIMPLEQ_REMOVE_AFTER(سر, elm, میدان) کرو {			\
	اگر (((elm)->میدان.sqx_اگلا = XSIMPLEQ_XOR(سر,			\
	    (elm)->میدان.sqx_اگلا)->میدان.sqx_اگلا)			\
	    == XSIMPLEQ_XOR(سر, تہی))				\
		(سر)->sqx_آخری = 					\
		    XSIMPLEQ_XOR(سر, &(elm)->میدان.sqx_اگلا);		\
} جب (0)


/*
 * Tail queue definitions.
 */
#تعریف_کرو TAILQ_HEAD(name, type)						\
ساخت name {								\
	ساخت type *tqh_first;	/* first element */			\
	ساخت type **tqh_last;	/* addr of last next element */		\
}

#تعریف_کرو TAILQ_HEAD_INITIALIZER(سر)					\
	{ تہی, &(سر).tqh_first }

#تعریف_کرو TAILQ_ENTRY(type)						\
ساخت {								\
	ساخت type *tqe_next;	/* next element */			\
	ساخت type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#تعریف_کرو	TAILQ_FIRST(سر)		((سر)->tqh_first)
#تعریف_کرو	TAILQ_انتہا(سر)			تہی
#تعریف_کرو	TAILQ_NEXT(elm, میدان)		((elm)->میدان.tqe_next)
#تعریف_کرو TAILQ_LAST(سر, headname)					\
	(*(((ساخت headname *)((سر)->tqh_last))->tqh_last))
/* XXX */
#تعریف_کرو TAILQ_PREV(elm, headname, میدان)				\
	(*(((ساخت headname *)((elm)->میدان.tqe_prev))->tqh_last))
#تعریف_کرو	TAILQ_EMPTY(سر)						\
	(TAILQ_FIRST(سر) == TAILQ_انتہا(سر))

#تعریف_کرو TAILQ_FOREACH(var, سر, میدان)					\
	برائے((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_انتہا(سر);					\
	    (var) = TAILQ_NEXT(var, میدان))

#تعریف_کرو	TAILQ_FOREACH_محفوظ(var, سر, میدان, tvar)			\
	برائے ((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_انتہا(سر) &&					\
	    ((tvar) = TAILQ_NEXT(var, میدان), 1);			\
	    (var) = (tvar))


#تعریف_کرو TAILQ_FOREACH_الٹ(var, سر, headname, میدان)		\
	برائے((var) = TAILQ_LAST(سر, headname);				\
	    (var) != TAILQ_انتہا(سر);					\
	    (var) = TAILQ_PREV(var, headname, میدان))

#تعریف_کرو	TAILQ_FOREACH_الٹ_محفوظ(var, سر, headname, میدان, tvar)	\
	برائے ((var) = TAILQ_LAST(سر, headname);			\
	    (var) != TAILQ_انتہا(سر) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, میدان), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#تعریف_کرو	TAILQ_INIT(سر) کرو {						\
	(سر)->tqh_first = تہی;					\
	(سر)->tqh_last = &(سر)->tqh_first;				\
} جب (0)

#تعریف_کرو TAILQ_INSERT_HEAD(سر, elm, میدان) کرو {			\
	اگر (((elm)->میدان.tqe_next = (سر)->tqh_first) != تہی)	\
		(سر)->tqh_first->میدان.tqe_prev =			\
		    &(elm)->میدان.tqe_next;				\
	ورنہ								\
		(سر)->tqh_last = &(elm)->میدان.tqe_next;		\
	(سر)->tqh_first = (elm);					\
	(elm)->میدان.tqe_prev = &(سر)->tqh_first;			\
} جب (0)

#تعریف_کرو TAILQ_INSERT_TAIL(سر, elm, میدان) کرو {			\
	(elm)->میدان.tqe_next = تہی;					\
	(elm)->میدان.tqe_prev = (سر)->tqh_last;			\
	*(سر)->tqh_last = (elm);					\
	(سر)->tqh_last = &(elm)->میدان.tqe_next;			\
} جب (0)

#تعریف_کرو TAILQ_INSERT_AFTER(سر, listelm, elm, میدان) کرو {		\
	اگر (((elm)->میدان.tqe_next = (listelm)->میدان.tqe_next) != تہی)\
		(elm)->میدان.tqe_next->میدان.tqe_prev =			\
		    &(elm)->میدان.tqe_next;				\
	ورنہ								\
		(سر)->tqh_last = &(elm)->میدان.tqe_next;		\
	(listelm)->میدان.tqe_next = (elm);				\
	(elm)->میدان.tqe_prev = &(listelm)->میدان.tqe_next;		\
} جب (0)

#تعریف_کرو	TAILQ_INSERT_BEFORE(listelm, elm, میدان) کرو {			\
	(elm)->میدان.tqe_prev = (listelm)->میدان.tqe_prev;		\
	(elm)->میدان.tqe_next = (listelm);				\
	*(listelm)->میدان.tqe_prev = (elm);				\
	(listelm)->میدان.tqe_prev = &(elm)->میدان.tqe_next;		\
} جب (0)

#تعریف_کرو TAILQ_REMOVE(سر, elm, میدان) کرو {				\
	اگر (((elm)->میدان.tqe_next) != تہی)				\
		(elm)->میدان.tqe_next->میدان.tqe_prev =			\
		    (elm)->میدان.tqe_prev;				\
	ورنہ								\
		(سر)->tqh_last = (elm)->میدان.tqe_prev;		\
	*(elm)->میدان.tqe_prev = (elm)->میدان.tqe_next;			\
	_Q_INVALIDATE((elm)->میدان.tqe_prev);				\
	_Q_INVALIDATE((elm)->میدان.tqe_next);				\
} جب (0)

#تعریف_کرو TAILQ_REPLACE(سر, elm, elm2, میدان) کرو {			\
	اگر (((elm2)->میدان.tqe_next = (elm)->میدان.tqe_next) != تہی)	\
		(elm2)->میدان.tqe_next->میدان.tqe_prev =		\
		    &(elm2)->میدان.tqe_next;				\
	ورنہ								\
		(سر)->tqh_last = &(elm2)->میدان.tqe_next;		\
	(elm2)->میدان.tqe_prev = (elm)->میدان.tqe_prev;			\
	*(elm2)->میدان.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->میدان.tqe_prev);				\
	_Q_INVALIDATE((elm)->میدان.tqe_next);				\
} جب (0)

#تعریف_کرو TAILQ_CONCAT(head1, head2, میدان) کرو {				\
	اگر (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->میدان.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} جب (0)

#اگر_ختم	/* !_SYS_QUEUE_H_ */
