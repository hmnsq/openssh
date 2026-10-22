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

#ifndef	_FAKE_QUEUE_H_
#define	_FAKE_QUEUE_H_

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#undef CIRCLEQ_EMPTY
#undef CIRCLEQ_END
#undef CIRCLEQ_ENTRY
#undef CIRCLEQ_FIRST
#undef CIRCLEQ_FOREACH
#undef CIRCLEQ_FOREACH_REVERSE
#undef CIRCLEQ_HEAD
#undef CIRCLEQ_HEAD_INITIALIZER
#undef CIRCLEQ_INIT
#undef CIRCLEQ_INSERT_AFTER
#undef CIRCLEQ_INSERT_BEFORE
#undef CIRCLEQ_INSERT_HEAD
#undef CIRCLEQ_INSERT_TAIL
#undef CIRCLEQ_LAST
#undef CIRCLEQ_NEXT
#undef CIRCLEQ_PREV
#undef CIRCLEQ_REMOVE
#undef CIRCLEQ_REPLACE
#undef LIST_EMPTY
#undef LIST_END
#undef LIST_ENTRY
#undef LIST_FIRST
#undef LIST_FOREACH
#undef LIST_FOREACH_SAFE
#undef LIST_HEAD
#undef LIST_HEAD_INITIALIZER
#undef LIST_INIT
#undef LIST_INSERT_AFTER
#undef LIST_INSERT_BEFORE
#undef LIST_INSERT_HEAD
#undef LIST_NEXT
#undef LIST_REMOVE
#undef LIST_REPLACE
#undef SIMPLEQ_CONCAT
#undef SIMPLEQ_EMPTY
#undef SIMPLEQ_END
#undef SIMPLEQ_ENTRY
#undef SIMPLEQ_FIRST
#undef SIMPLEQ_FOREACH
#undef SIMPLEQ_FOREACH_SAFE
#undef SIMPLEQ_HEAD
#undef SIMPLEQ_HEAD_INITIALIZER
#undef SIMPLEQ_INIT
#undef SIMPLEQ_INSERT_AFTER
#undef SIMPLEQ_INSERT_HEAD
#undef SIMPLEQ_INSERT_TAIL
#undef SIMPLEQ_NEXT
#undef SIMPLEQ_REMOVE_AFTER
#undef SIMPLEQ_REMOVE_HEAD
#undef SLIST_EMPTY
#undef SLIST_END
#undef SLIST_ENTRY
#undef SLIST_FIRST
#undef SLIST_FOREACH
#undef SLIST_FOREACH_PREVPTR
#undef SLIST_FOREACH_SAFE
#undef SLIST_HEAD
#undef SLIST_HEAD_INITIALIZER
#undef SLIST_INIT
#undef SLIST_INSERT_AFTER
#undef SLIST_INSERT_HEAD
#undef SLIST_NEXT
#undef SLIST_REMOVE
#undef SLIST_REMOVE_AFTER
#undef SLIST_REMOVE_HEAD
#undef SLIST_REMOVE_NEXT
#undef TAILQ_CONCAT
#undef TAILQ_EMPTY
#undef TAILQ_END
#undef TAILQ_ENTRY
#undef TAILQ_FIRST
#undef TAILQ_FOREACH
#undef TAILQ_FOREACH_REVERSE
#undef TAILQ_FOREACH_REVERSE_SAFE
#undef TAILQ_FOREACH_SAFE
#undef TAILQ_HEAD
#undef TAILQ_HEAD_INITIALIZER
#undef TAILQ_INIT
#undef TAILQ_INSERT_AFTER
#undef TAILQ_INSERT_BEFORE
#undef TAILQ_INSERT_HEAD
#undef TAILQ_INSERT_TAIL
#undef TAILQ_LAST
#undef TAILQ_NEXT
#undef TAILQ_PREV
#undef TAILQ_REMOVE
#undef TAILQ_REPLACE

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

#إذا defined(QUEUE_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#define _Q_INVALID ((فراغ *)-1)
#define _Q_INVALIDATE(a) (a) = _Q_INVALID
#وإلا
#define _Q_INVALIDATE(a)
#endif

/*
 * Singly-linked List definitions.
 */
#define SLIST_HEAD(name, type)						\
بنية name {								\
	بنية type *slh_first;	/* first element */			\
}

#define	SLIST_HEAD_INITIALIZER(head)					\
	{ عدم }

#define SLIST_ENTRY(type)						\
بنية {								\
	بنية type *sle_next;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#define	SLIST_FIRST(head)	((head)->slh_first)
#define	SLIST_END(head)		عدم
#define	SLIST_EMPTY(head)	(SLIST_FIRST(head) == SLIST_END(head))
#define	SLIST_NEXT(elm, field)	((elm)->field.sle_next)

#define	SLIST_FOREACH(var, head, field)					\
	لكل((var) = SLIST_FIRST(head);					\
	    (var) != SLIST_END(head);					\
	    (var) = SLIST_NEXT(var, field))

#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	لكل ((var) = SLIST_FIRST(head);				\
	    (var) && ((tvar) = SLIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#define	SLIST_INIT(head) {						\
	SLIST_FIRST(head) = SLIST_END(head);				\
}

#define	SLIST_INSERT_AFTER(slistelm, elm, field) افعل {			\
	(elm)->field.sle_next = (slistelm)->field.sle_next;		\
	(slistelm)->field.sle_next = (elm);				\
} طالما (0)

#define	SLIST_INSERT_HEAD(head, elm, field) افعل {			\
	(elm)->field.sle_next = (head)->slh_first;			\
	(head)->slh_first = (elm);					\
} طالما (0)

#define	SLIST_REMOVE_AFTER(elm, field) افعل {				\
	(elm)->field.sle_next = (elm)->field.sle_next->field.sle_next;	\
} طالما (0)

#define	SLIST_REMOVE_HEAD(head, field) افعل {				\
	(head)->slh_first = (head)->slh_first->field.sle_next;		\
} طالما (0)

#define SLIST_REMOVE(head, elm, type, field) افعل {			\
	إذا ((head)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((head), field);			\
	} وإلا {							\
		بنية type *curelm = (head)->slh_first;		\
									\
		طالما (curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
	}								\
	_Q_INVALIDATE((elm)->field.sle_next);				\
} طالما (0)

/*
 * List definitions.
 */
#define LIST_HEAD(name, type)						\
بنية name {								\
	بنية type *lh_first;	/* first element */			\
}

#define LIST_HEAD_INITIALIZER(head)					\
	{ عدم }

#define LIST_ENTRY(type)						\
بنية {								\
	بنية type *le_next;	/* next element */			\
	بنية type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#define	LIST_FIRST(head)		((head)->lh_first)
#define	LIST_END(head)			عدم
#define	LIST_EMPTY(head)		(LIST_FIRST(head) == LIST_END(head))
#define	LIST_NEXT(elm, field)		((elm)->field.le_next)

#define LIST_FOREACH(var, head, field)					\
	لكل((var) = LIST_FIRST(head);					\
	    (var)!= LIST_END(head);					\
	    (var) = LIST_NEXT(var, field))

#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	لكل ((var) = LIST_FIRST(head);				\
	    (var) && ((tvar) = LIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#define	LIST_INIT(head) افعل {						\
	LIST_FIRST(head) = LIST_END(head);				\
} طالما (0)

#define LIST_INSERT_AFTER(listelm, elm, field) افعل {			\
	إذا (((elm)->field.le_next = (listelm)->field.le_next) != عدم)	\
		(listelm)->field.le_next->field.le_prev =		\
		    &(elm)->field.le_next;				\
	(listelm)->field.le_next = (elm);				\
	(elm)->field.le_prev = &(listelm)->field.le_next;		\
} طالما (0)

#define	LIST_INSERT_BEFORE(listelm, elm, field) افعل {			\
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	(elm)->field.le_next = (listelm);				\
	*(listelm)->field.le_prev = (elm);				\
	(listelm)->field.le_prev = &(elm)->field.le_next;		\
} طالما (0)

#define LIST_INSERT_HEAD(head, elm, field) افعل {				\
	إذا (((elm)->field.le_next = (head)->lh_first) != عدم)		\
		(head)->lh_first->field.le_prev = &(elm)->field.le_next;\
	(head)->lh_first = (elm);					\
	(elm)->field.le_prev = &(head)->lh_first;			\
} طالما (0)

#define LIST_REMOVE(elm, field) افعل {					\
	إذا ((elm)->field.le_next != عدم)				\
		(elm)->field.le_next->field.le_prev =			\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = (elm)->field.le_next;			\
	_Q_INVALIDATE((elm)->field.le_prev);				\
	_Q_INVALIDATE((elm)->field.le_next);				\
} طالما (0)

#define LIST_REPLACE(elm, elm2, field) افعل {				\
	إذا (((elm2)->field.le_next = (elm)->field.le_next) != عدم)	\
		(elm2)->field.le_next->field.le_prev =			\
		    &(elm2)->field.le_next;				\
	(elm2)->field.le_prev = (elm)->field.le_prev;			\
	*(elm2)->field.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.le_prev);				\
	_Q_INVALIDATE((elm)->field.le_next);				\
} طالما (0)

/*
 * Simple queue definitions.
 */
#define SIMPLEQ_HEAD(name, type)					\
بنية name {								\
	بنية type *sqh_first;	/* first element */			\
	بنية type **sqh_last;	/* addr of last next element */		\
}

#define SIMPLEQ_HEAD_INITIALIZER(head)					\
	{ عدم, &(head).sqh_first }

#define SIMPLEQ_ENTRY(type)						\
بنية {								\
	بنية type *sqe_next;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#define	SIMPLEQ_FIRST(head)	    ((head)->sqh_first)
#define	SIMPLEQ_END(head)	    عدم
#define	SIMPLEQ_EMPTY(head)	    (SIMPLEQ_FIRST(head) == SIMPLEQ_END(head))
#define	SIMPLEQ_NEXT(elm, field)    ((elm)->field.sqe_next)

#define SIMPLEQ_FOREACH(var, head, field)				\
	لكل((var) = SIMPLEQ_FIRST(head);				\
	    (var) != SIMPLEQ_END(head);					\
	    (var) = SIMPLEQ_NEXT(var, field))

#define	SIMPLEQ_FOREACH_SAFE(var, head, field, tvar)			\
	لكل ((var) = SIMPLEQ_FIRST(head);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#define	SIMPLEQ_INIT(head) افعل {						\
	(head)->sqh_first = عدم;					\
	(head)->sqh_last = &(head)->sqh_first;				\
} طالما (0)

#define SIMPLEQ_INSERT_HEAD(head, elm, field) افعل {			\
	إذا (((elm)->field.sqe_next = (head)->sqh_first) == عدم)	\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(head)->sqh_first = (elm);					\
} طالما (0)

#define SIMPLEQ_INSERT_TAIL(head, elm, field) افعل {			\
	(elm)->field.sqe_next = عدم;					\
	*(head)->sqh_last = (elm);					\
	(head)->sqh_last = &(elm)->field.sqe_next;			\
} طالما (0)

#define SIMPLEQ_INSERT_AFTER(head, listelm, elm, field) افعل {		\
	إذا (((elm)->field.sqe_next = (listelm)->field.sqe_next) == عدم)\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(listelm)->field.sqe_next = (elm);				\
} طالما (0)

#define SIMPLEQ_REMOVE_HEAD(head, field) افعل {			\
	إذا (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == عدم) \
		(head)->sqh_last = &(head)->sqh_first;			\
} طالما (0)

#define SIMPLEQ_REMOVE_AFTER(head, elm, field) افعل {			\
	إذا (((elm)->field.sqe_next = (elm)->field.sqe_next->field.sqe_next) \
	    == عدم)							\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
} طالما (0)

#define SIMPLEQ_CONCAT(head1, head2) افعل {				\
	إذا (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} طالما (0)

/*
 * XOR Simple queue definitions.
 */
#define XSIMPLEQ_HEAD(name, type)					\
بنية name {								\
	بنية type *sqx_first;	/* first element */			\
	بنية type **sqx_last;	/* addr of last next element */		\
	unsigned long sqx_cookie;					\
}

#define XSIMPLEQ_ENTRY(type)						\
بنية {								\
	بنية type *sqx_next;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#define XSIMPLEQ_XOR(head, ptr)	    ((__typeof(ptr))((head)->sqx_cookie ^ \
					(unsigned long)(ptr)))
#define	XSIMPLEQ_FIRST(head)	    XSIMPLEQ_XOR(head, ((head)->sqx_first))
#define	XSIMPLEQ_END(head)	    عدم
#define	XSIMPLEQ_EMPTY(head)	    (XSIMPLEQ_FIRST(head) == XSIMPLEQ_END(head))
#define	XSIMPLEQ_NEXT(head, elm, field)    XSIMPLEQ_XOR(head, ((elm)->field.sqx_next))


#define XSIMPLEQ_FOREACH(var, head, field)				\
	لكل ((var) = XSIMPLEQ_FIRST(head);				\
	    (var) != XSIMPLEQ_END(head);				\
	    (var) = XSIMPLEQ_NEXT(head, var, field))

#define	XSIMPLEQ_FOREACH_SAFE(var, head, field, tvar)			\
	لكل ((var) = XSIMPLEQ_FIRST(head);				\
	    (var) && ((tvar) = XSIMPLEQ_NEXT(head, var, field), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#define	XSIMPLEQ_INIT(head) افعل {					\
	arc4random_buf(&(head)->sqx_cookie, حجم((head)->sqx_cookie)); \
	(head)->sqx_first = XSIMPLEQ_XOR(head, عدم);			\
	(head)->sqx_last = XSIMPLEQ_XOR(head, &(head)->sqx_first);	\
} طالما (0)

#define XSIMPLEQ_سيسيڤ_HEAD(head, elm, field) افعل {			\
	إذا (((elm)->field.sqx_next = (head)->sqx_first) ==		\
	    XSIMPLEQ_XOR(head, عدم))					\
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next); \
	(head)->sqx_first = XSIMPLEQ_XOR(head, (elm));			\
} طالما (0)

#define XSIMPLEQ_سيسيڤ_TAIL(head, elm, field) افعل {			\
	(elm)->field.sqx_next = XSIMPLEQ_XOR(head, عدم);		\
	*(XSIMPLEQ_XOR(head, (head)->sqx_last)) = XSIMPLEQ_XOR(head, (elm)); \
	(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next);	\
} طالما (0)

#define XSIMPLEQ_سيسيڤ_AFTER(head, listelm, elm, field) افعل {		\
	إذا (((elm)->field.sqx_next = (listelm)->field.sqx_next) ==	\
	    XSIMPLEQ_XOR(head, عدم))					\
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(elm)->field.sqx_next); \
	(listelm)->field.sqx_next = XSIMPLEQ_XOR(head, (elm));		\
} طالما (0)

#define XSIMPLEQ_REMOVE_HEAD(head, field) افعل {				\
	إذا (((head)->sqx_first = XSIMPLEQ_XOR(head,			\
	    (head)->sqx_first)->field.sqx_next) == XSIMPLEQ_XOR(head, عدم)) \
		(head)->sqx_last = XSIMPLEQ_XOR(head, &(head)->sqx_first); \
} طالما (0)

#define XSIMPLEQ_REMOVE_AFTER(head, elm, field) افعل {			\
	إذا (((elm)->field.sqx_next = XSIMPLEQ_XOR(head,			\
	    (elm)->field.sqx_next)->field.sqx_next)			\
	    == XSIMPLEQ_XOR(head, عدم))				\
		(head)->sqx_last = 					\
		    XSIMPLEQ_XOR(head, &(elm)->field.sqx_next);		\
} طالما (0)


/*
 * Tail queue definitions.
 */
#define TAILQ_HEAD(name, type)						\
بنية name {								\
	بنية type *tqh_first;	/* first element */			\
	بنية type **tqh_last;	/* addr of last next element */		\
}

#define TAILQ_HEAD_INITIALIZER(head)					\
	{ عدم, &(head).tqh_first }

#define TAILQ_ENTRY(type)						\
بنية {								\
	بنية type *tqe_next;	/* next element */			\
	بنية type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#define	TAILQ_FIRST(head)		((head)->tqh_first)
#define	TAILQ_END(head)			عدم
#define	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#define TAILQ_LAST(head, headname)					\
	(*(((بنية headname *)((head)->tqh_last))->tqh_last))
/* XXX */
#define TAILQ_PREV(elm, headname, field)				\
	(*(((بنية headname *)((elm)->field.tqe_prev))->tqh_last))
#define	TAILQ_EMPTY(head)						\
	(TAILQ_FIRST(head) == TAILQ_END(head))

#define TAILQ_FOREACH(var, head, field)					\
	لكل((var) = TAILQ_FIRST(head);					\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_NEXT(var, field))

#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	لكل ((var) = TAILQ_FIRST(head);					\
	    (var) != TAILQ_END(head) &&					\
	    ((tvar) = TAILQ_NEXT(var, field), 1);			\
	    (var) = (tvar))


#define TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	لكل((var) = TAILQ_LAST(head, headname);				\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_PREV(var, headname, field))

#define	TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	لكل ((var) = TAILQ_LAST(head, headname);			\
	    (var) != TAILQ_END(head) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, field), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#define	TAILQ_INIT(head) افعل {						\
	(head)->tqh_first = عدم;					\
	(head)->tqh_last = &(head)->tqh_first;				\
} طالما (0)

#define TAILQ_INSERT_HEAD(head, elm, field) افعل {			\
	إذا (((elm)->field.tqe_next = (head)->tqh_first) != عدم)	\
		(head)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	وإلا								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(head)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(head)->tqh_first;			\
} طالما (0)

#define TAILQ_INSERT_TAIL(head, elm, field) افعل {			\
	(elm)->field.tqe_next = عدم;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} طالما (0)

#define TAILQ_INSERT_AFTER(head, listelm, elm, field) افعل {		\
	إذا (((elm)->field.tqe_next = (listelm)->field.tqe_next) != عدم)\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	وإلا								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} طالما (0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) افعل {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} طالما (0)

#define TAILQ_REMOVE(head, elm, field) افعل {				\
	إذا (((elm)->field.tqe_next) != عدم)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    (elm)->field.tqe_prev;				\
	وإلا								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} طالما (0)

#define TAILQ_REPLACE(head, elm, elm2, field) افعل {			\
	إذا (((elm2)->field.tqe_next = (elm)->field.tqe_next) != عدم)	\
		(elm2)->field.tqe_next->field.tqe_prev =		\
		    &(elm2)->field.tqe_next;				\
	وإلا								\
		(head)->tqh_last = &(elm2)->field.tqe_next;		\
	(elm2)->field.tqe_prev = (elm)->field.tqe_prev;			\
	*(elm2)->field.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} طالما (0)

#define TAILQ_CONCAT(head1, head2, field) افعل {				\
	إذا (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} طالما (0)

#endif	/* !_SYS_QUEUE_H_ */
