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

#నిర్వచితం_కాకపోతే	FAKE_వరుస_H
#నిర్వచించు	FAKE_వరుస_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#నిర్వచనం_రద్దు CIRCLEQ_EMPTY
#నిర్వచనం_రద్దు CIRCLEQ_చివర
#నిర్వచనం_రద్దు CIRCLEQ_ENTRY
#నిర్వచనం_రద్దు CIRCLEQ_FIRST
#నిర్వచనం_రద్దు CIRCLEQ_FOREACH
#నిర్వచనం_రద్దు CIRCLEQ_FOREACH_REVERSE
#నిర్వచనం_రద్దు CIRCLEQ_HEAD
#నిర్వచనం_రద్దు CIRCLEQ_HEAD_INITIALIZER
#నిర్వచనం_రద్దు CIRCLEQ_INIT
#నిర్వచనం_రద్దు CIRCLEQ_INSERT_AFTER
#నిర్వచనం_రద్దు CIRCLEQ_INSERT_BEFORE
#నిర్వచనం_రద్దు CIRCLEQ_INSERT_HEAD
#నిర్వచనం_రద్దు CIRCLEQ_INSERT_TAIL
#నిర్వచనం_రద్దు CIRCLEQ_LAST
#నిర్వచనం_రద్దు CIRCLEQ_NEXT
#నిర్వచనం_రద్దు CIRCLEQ_PREV
#నిర్వచనం_రద్దు CIRCLEQ_REMOVE
#నిర్వచనం_రద్దు CIRCLEQ_REPLACE
#నిర్వచనం_రద్దు LIST_EMPTY
#నిర్వచనం_రద్దు LIST_చివర
#నిర్వచనం_రద్దు LIST_ENTRY
#నిర్వచనం_రద్దు LIST_FIRST
#నిర్వచనం_రద్దు LIST_FOREACH
#నిర్వచనం_రద్దు LIST_FOREACH_సురక్షిత
#నిర్వచనం_రద్దు LIST_HEAD
#నిర్వచనం_రద్దు LIST_HEAD_INITIALIZER
#నిర్వచనం_రద్దు LIST_INIT
#నిర్వచనం_రద్దు LIST_INSERT_AFTER
#నిర్వచనం_రద్దు LIST_INSERT_BEFORE
#నిర్వచనం_రద్దు LIST_INSERT_HEAD
#నిర్వచనం_రద్దు LIST_NEXT
#నిర్వచనం_రద్దు LIST_REMOVE
#నిర్వచనం_రద్దు LIST_REPLACE
#నిర్వచనం_రద్దు SIMPLEQ_CONCAT
#నిర్వచనం_రద్దు SIMPLEQ_EMPTY
#నిర్వచనం_రద్దు SIMPLEQ_చివర
#నిర్వచనం_రద్దు SIMPLEQ_ENTRY
#నిర్వచనం_రద్దు SIMPLEQ_FIRST
#నిర్వచనం_రద్దు SIMPLEQ_FOREACH
#నిర్వచనం_రద్దు SIMPLEQ_FOREACH_సురక్షిత
#నిర్వచనం_రద్దు SIMPLEQ_HEAD
#నిర్వచనం_రద్దు SIMPLEQ_HEAD_INITIALIZER
#నిర్వచనం_రద్దు SIMPLEQ_INIT
#నిర్వచనం_రద్దు SIMPLEQ_INSERT_AFTER
#నిర్వచనం_రద్దు SIMPLEQ_INSERT_HEAD
#నిర్వచనం_రద్దు SIMPLEQ_INSERT_TAIL
#నిర్వచనం_రద్దు SIMPLEQ_NEXT
#నిర్వచనం_రద్దు SIMPLEQ_REMOVE_AFTER
#నిర్వచనం_రద్దు SIMPLEQ_REMOVE_HEAD
#నిర్వచనం_రద్దు SLIST_EMPTY
#నిర్వచనం_రద్దు SLIST_చివర
#నిర్వచనం_రద్దు SLIST_ENTRY
#నిర్వచనం_రద్దు SLIST_FIRST
#నిర్వచనం_రద్దు SLIST_FOREACH
#నిర్వచనం_రద్దు SLIST_FOREACH_PREVPTR
#నిర్వచనం_రద్దు SLIST_FOREACH_సురక్షిత
#నిర్వచనం_రద్దు SLIST_HEAD
#నిర్వచనం_రద్దు SLIST_HEAD_INITIALIZER
#నిర్వచనం_రద్దు SLIST_INIT
#నిర్వచనం_రద్దు SLIST_INSERT_AFTER
#నిర్వచనం_రద్దు SLIST_INSERT_HEAD
#నిర్వచనం_రద్దు SLIST_NEXT
#నిర్వచనం_రద్దు SLIST_REMOVE
#నిర్వచనం_రద్దు SLIST_REMOVE_AFTER
#నిర్వచనం_రద్దు SLIST_REMOVE_HEAD
#నిర్వచనం_రద్దు SLIST_REMOVE_తదుపరి
#నిర్వచనం_రద్దు TAILQ_CONCAT
#నిర్వచనం_రద్దు TAILQ_EMPTY
#నిర్వచనం_రద్దు TAILQ_చివర
#నిర్వచనం_రద్దు TAILQ_ENTRY
#నిర్వచనం_రద్దు TAILQ_FIRST
#నిర్వచనం_రద్దు TAILQ_FOREACH
#నిర్వచనం_రద్దు TAILQ_FOREACH_తిరగేయి
#నిర్వచనం_రద్దు TAILQ_FOREACH_తిరగేయి_సురక్షిత
#నిర్వచనం_రద్దు TAILQ_FOREACH_సురక్షిత
#నిర్వచనం_రద్దు TAILQ_HEAD
#నిర్వచనం_రద్దు TAILQ_HEAD_INITIALIZER
#నిర్వచనం_రద్దు TAILQ_INIT
#నిర్వచనం_రద్దు TAILQ_INSERT_AFTER
#నిర్వచనం_రద్దు TAILQ_INSERT_BEFORE
#నిర్వచనం_రద్దు TAILQ_INSERT_HEAD
#నిర్వచనం_రద్దు TAILQ_INSERT_TAIL
#నిర్వచనం_రద్దు TAILQ_LAST
#నిర్వచనం_రద్దు TAILQ_NEXT
#నిర్వచనం_రద్దు TAILQ_PREV
#నిర్వచనం_రద్దు TAILQ_REMOVE
#నిర్వచనం_రద్దు TAILQ_REPLACE

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

#ఒకవేళ defined(వరుస_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#నిర్వచించు _Q_INVALID ((శూన్య *)-1)
#నిర్వచించు _Q_INVALIDATE(a) (a) = _Q_INVALID
#లేకపోతే
#నిర్వచించు _Q_INVALIDATE(a)
#అయితే_ముగింపు

/*
 * Singly-linked List definitions.
 */
#నిర్వచించు SLIST_HEAD(name, type)						\
నిర్మాణం name {								\
	నిర్మాణం type *slh_మొదటి;	/* first element */			\
}

#నిర్వచించు	SLIST_HEAD_INITIALIZER(తల)					\
	{ ఖాళీ }

#నిర్వచించు SLIST_ENTRY(type)						\
నిర్మాణం {								\
	నిర్మాణం type *sle_తదుపరి;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#నిర్వచించు	SLIST_FIRST(తల)	((తల)->slh_మొదటి)
#నిర్వచించు	SLIST_చివర(తల)		ఖాళీ
#నిర్వచించు	SLIST_EMPTY(తల)	(SLIST_FIRST(తల) == SLIST_చివర(తల))
#నిర్వచించు	SLIST_NEXT(elm, క్షేత్రం)	((elm)->క్షేత్రం.sle_తదుపరి)

#నిర్వచించు	SLIST_FOREACH(var, తల, క్షేత్రం)					\
	కొరకు((var) = SLIST_FIRST(తల);					\
	    (var) != SLIST_చివర(తల);					\
	    (var) = SLIST_NEXT(var, క్షేత్రం))

#నిర్వచించు	SLIST_FOREACH_సురక్షిత(var, తల, క్షేత్రం, tvar)			\
	కొరకు ((var) = SLIST_FIRST(తల);				\
	    (var) && ((tvar) = SLIST_NEXT(var, క్షేత్రం), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#నిర్వచించు	SLIST_INIT(తల) {						\
	SLIST_FIRST(తల) = SLIST_చివర(తల);				\
}

#నిర్వచించు	SLIST_INSERT_AFTER(slistelm, elm, క్షేత్రం) చేయి {			\
	(elm)->క్షేత్రం.sle_తదుపరి = (slistelm)->క్షేత్రం.sle_తదుపరి;		\
	(slistelm)->క్షేత్రం.sle_తదుపరి = (elm);				\
} అయితే (0)

#నిర్వచించు	SLIST_INSERT_HEAD(తల, elm, క్షేత్రం) చేయి {			\
	(elm)->క్షేత్రం.sle_తదుపరి = (తల)->slh_మొదటి;			\
	(తల)->slh_మొదటి = (elm);					\
} అయితే (0)

#నిర్వచించు	SLIST_REMOVE_AFTER(elm, క్షేత్రం) చేయి {				\
	(elm)->క్షేత్రం.sle_తదుపరి = (elm)->క్షేత్రం.sle_తదుపరి->క్షేత్రం.sle_తదుపరి;	\
} అయితే (0)

#నిర్వచించు	SLIST_REMOVE_HEAD(తల, క్షేత్రం) చేయి {				\
	(తల)->slh_మొదటి = (తల)->slh_మొదటి->క్షేత్రం.sle_తదుపరి;		\
} అయితే (0)

#నిర్వచించు SLIST_REMOVE(తల, elm, type, క్షేత్రం) చేయి {			\
	ఒకవేళ ((తల)->slh_మొదటి == (elm)) {				\
		SLIST_REMOVE_HEAD((తల), క్షేత్రం);			\
	} లేకపోతే {							\
		నిర్మాణం type *curelm = (తల)->slh_మొదటి;		\
									\
		అయితే (curelm->క్షేత్రం.sle_తదుపరి != (elm))			\
			curelm = curelm->క్షేత్రం.sle_తదుపరి;		\
		curelm->క్షేత్రం.sle_తదుపరి =				\
		    curelm->క్షేత్రం.sle_తదుపరి->క్షేత్రం.sle_తదుపరి;		\
	}								\
	_Q_INVALIDATE((elm)->క్షేత్రం.sle_తదుపరి);				\
} అయితే (0)

/*
 * List definitions.
 */
#నిర్వచించు LIST_HEAD(name, type)						\
నిర్మాణం name {								\
	నిర్మాణం type *lh_మొదటి;	/* first element */			\
}

#నిర్వచించు LIST_HEAD_INITIALIZER(తల)					\
	{ ఖాళీ }

#నిర్వచించు LIST_ENTRY(type)						\
నిర్మాణం {								\
	నిర్మాణం type *le_తదుపరి;	/* next element */			\
	నిర్మాణం type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#నిర్వచించు	LIST_FIRST(తల)		((తల)->lh_మొదటి)
#నిర్వచించు	LIST_చివర(తల)			ఖాళీ
#నిర్వచించు	LIST_EMPTY(తల)		(LIST_FIRST(తల) == LIST_చివర(తల))
#నిర్వచించు	LIST_NEXT(elm, క్షేత్రం)		((elm)->క్షేత్రం.le_తదుపరి)

#నిర్వచించు LIST_FOREACH(var, తల, క్షేత్రం)					\
	కొరకు((var) = LIST_FIRST(తల);					\
	    (var)!= LIST_చివర(తల);					\
	    (var) = LIST_NEXT(var, క్షేత్రం))

#నిర్వచించు	LIST_FOREACH_సురక్షిత(var, తల, క్షేత్రం, tvar)			\
	కొరకు ((var) = LIST_FIRST(తల);				\
	    (var) && ((tvar) = LIST_NEXT(var, క్షేత్రం), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#నిర్వచించు	LIST_INIT(తల) చేయి {						\
	LIST_FIRST(తల) = LIST_చివర(తల);				\
} అయితే (0)

#నిర్వచించు LIST_INSERT_AFTER(listelm, elm, క్షేత్రం) చేయి {			\
	ఒకవేళ (((elm)->క్షేత్రం.le_తదుపరి = (listelm)->క్షేత్రం.le_తదుపరి) != ఖాళీ)	\
		(listelm)->క్షేత్రం.le_తదుపరి->క్షేత్రం.le_prev =		\
		    &(elm)->క్షేత్రం.le_తదుపరి;				\
	(listelm)->క్షేత్రం.le_తదుపరి = (elm);				\
	(elm)->క్షేత్రం.le_prev = &(listelm)->క్షేత్రం.le_తదుపరి;		\
} అయితే (0)

#నిర్వచించు	LIST_INSERT_BEFORE(listelm, elm, క్షేత్రం) చేయి {			\
	(elm)->క్షేత్రం.le_prev = (listelm)->క్షేత్రం.le_prev;		\
	(elm)->క్షేత్రం.le_తదుపరి = (listelm);				\
	*(listelm)->క్షేత్రం.le_prev = (elm);				\
	(listelm)->క్షేత్రం.le_prev = &(elm)->క్షేత్రం.le_తదుపరి;		\
} అయితే (0)

#నిర్వచించు LIST_INSERT_HEAD(తల, elm, క్షేత్రం) చేయి {				\
	ఒకవేళ (((elm)->క్షేత్రం.le_తదుపరి = (తల)->lh_మొదటి) != ఖాళీ)		\
		(తల)->lh_మొదటి->క్షేత్రం.le_prev = &(elm)->క్షేత్రం.le_తదుపరి;\
	(తల)->lh_మొదటి = (elm);					\
	(elm)->క్షేత్రం.le_prev = &(తల)->lh_మొదటి;			\
} అయితే (0)

#నిర్వచించు LIST_REMOVE(elm, క్షేత్రం) చేయి {					\
	ఒకవేళ ((elm)->క్షేత్రం.le_తదుపరి != ఖాళీ)				\
		(elm)->క్షేత్రం.le_తదుపరి->క్షేత్రం.le_prev =			\
		    (elm)->క్షేత్రం.le_prev;				\
	*(elm)->క్షేత్రం.le_prev = (elm)->క్షేత్రం.le_తదుపరి;			\
	_Q_INVALIDATE((elm)->క్షేత్రం.le_prev);				\
	_Q_INVALIDATE((elm)->క్షేత్రం.le_తదుపరి);				\
} అయితే (0)

#నిర్వచించు LIST_REPLACE(elm, elm2, క్షేత్రం) చేయి {				\
	ఒకవేళ (((elm2)->క్షేత్రం.le_తదుపరి = (elm)->క్షేత్రం.le_తదుపరి) != ఖాళీ)	\
		(elm2)->క్షేత్రం.le_తదుపరి->క్షేత్రం.le_prev =			\
		    &(elm2)->క్షేత్రం.le_తదుపరి;				\
	(elm2)->క్షేత్రం.le_prev = (elm)->క్షేత్రం.le_prev;			\
	*(elm2)->క్షేత్రం.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->క్షేత్రం.le_prev);				\
	_Q_INVALIDATE((elm)->క్షేత్రం.le_తదుపరి);				\
} అయితే (0)

/*
 * Simple queue definitions.
 */
#నిర్వచించు SIMPLEQ_HEAD(name, type)					\
నిర్మాణం name {								\
	నిర్మాణం type *sqh_మొదటి;	/* first element */			\
	నిర్మాణం type **sqh_చివరి;	/* addr of last next element */		\
}

#నిర్వచించు SIMPLEQ_HEAD_INITIALIZER(తల)					\
	{ ఖాళీ, &(తల).sqh_మొదటి }

#నిర్వచించు SIMPLEQ_ENTRY(type)						\
నిర్మాణం {								\
	నిర్మాణం type *sqe_తదుపరి;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#నిర్వచించు	SIMPLEQ_FIRST(తల)	    ((తల)->sqh_మొదటి)
#నిర్వచించు	SIMPLEQ_చివర(తల)	    ఖాళీ
#నిర్వచించు	SIMPLEQ_EMPTY(తల)	    (SIMPLEQ_FIRST(తల) == SIMPLEQ_చివర(తల))
#నిర్వచించు	SIMPLEQ_NEXT(elm, క్షేత్రం)    ((elm)->క్షేత్రం.sqe_తదుపరి)

#నిర్వచించు SIMPLEQ_FOREACH(var, తల, క్షేత్రం)				\
	కొరకు((var) = SIMPLEQ_FIRST(తల);				\
	    (var) != SIMPLEQ_చివర(తల);					\
	    (var) = SIMPLEQ_NEXT(var, క్షేత్రం))

#నిర్వచించు	SIMPLEQ_FOREACH_సురక్షిత(var, తల, క్షేత్రం, tvar)			\
	కొరకు ((var) = SIMPLEQ_FIRST(తల);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, క్షేత్రం), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#నిర్వచించు	SIMPLEQ_INIT(తల) చేయి {						\
	(తల)->sqh_మొదటి = ఖాళీ;					\
	(తల)->sqh_చివరి = &(తల)->sqh_మొదటి;				\
} అయితే (0)

#నిర్వచించు SIMPLEQ_INSERT_HEAD(తల, elm, క్షేత్రం) చేయి {			\
	ఒకవేళ (((elm)->క్షేత్రం.sqe_తదుపరి = (తల)->sqh_మొదటి) == ఖాళీ)	\
		(తల)->sqh_చివరి = &(elm)->క్షేత్రం.sqe_తదుపరి;		\
	(తల)->sqh_మొదటి = (elm);					\
} అయితే (0)

#నిర్వచించు SIMPLEQ_INSERT_TAIL(తల, elm, క్షేత్రం) చేయి {			\
	(elm)->క్షేత్రం.sqe_తదుపరి = ఖాళీ;					\
	*(తల)->sqh_చివరి = (elm);					\
	(తల)->sqh_చివరి = &(elm)->క్షేత్రం.sqe_తదుపరి;			\
} అయితే (0)

#నిర్వచించు SIMPLEQ_INSERT_AFTER(తల, listelm, elm, క్షేత్రం) చేయి {		\
	ఒకవేళ (((elm)->క్షేత్రం.sqe_తదుపరి = (listelm)->క్షేత్రం.sqe_తదుపరి) == ఖాళీ)\
		(తల)->sqh_చివరి = &(elm)->క్షేత్రం.sqe_తదుపరి;		\
	(listelm)->క్షేత్రం.sqe_తదుపరి = (elm);				\
} అయితే (0)

#నిర్వచించు SIMPLEQ_REMOVE_HEAD(తల, క్షేత్రం) చేయి {			\
	ఒకవేళ (((తల)->sqh_మొదటి = (తల)->sqh_మొదటి->క్షేత్రం.sqe_తదుపరి) == ఖాళీ) \
		(తల)->sqh_చివరి = &(తల)->sqh_మొదటి;			\
} అయితే (0)

#నిర్వచించు SIMPLEQ_REMOVE_AFTER(తల, elm, క్షేత్రం) చేయి {			\
	ఒకవేళ (((elm)->క్షేత్రం.sqe_తదుపరి = (elm)->క్షేత్రం.sqe_తదుపరి->క్షేత్రం.sqe_తదుపరి) \
	    == ఖాళీ)							\
		(తల)->sqh_చివరి = &(elm)->క్షేత్రం.sqe_తదుపరి;		\
} అయితే (0)

#నిర్వచించు SIMPLEQ_CONCAT(head1, head2) చేయి {				\
	ఒకవేళ (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_చివరి = (head2)->sqh_మొదటి;		\
		(head1)->sqh_చివరి = (head2)->sqh_చివరి;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} అయితే (0)

/*
 * XOR Simple queue definitions.
 */
#నిర్వచించు XSIMPLEQ_తల(name, type)					\
నిర్మాణం name {								\
	నిర్మాణం type *sqx_మొదటి;	/* first element */			\
	నిర్మాణం type **sqx_చివరి;	/* addr of last next element */		\
	గుర్తులేని దీర్ఘ sqx_cookie;					\
}

#నిర్వచించు XSIMPLEQ_నమోదు(type)						\
నిర్మాణం {								\
	నిర్మాణం type *sqx_తదుపరి;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#నిర్వచించు XSIMPLEQ_XOR(తల, ptr)	    ((__typeof(ptr))((తల)->sqx_cookie ^ \
					(గుర్తులేని దీర్ఘ)(ptr)))
#నిర్వచించు	XSIMPLEQ_మొదటి(తల)	    XSIMPLEQ_XOR(తల, ((తల)->sqx_మొదటి))
#నిర్వచించు	XSIMPLEQ_చివర(తల)	    ఖాళీ
#నిర్వచించు	XSIMPLEQ_ఖాళీలు(తల)	    (XSIMPLEQ_మొదటి(తల) == XSIMPLEQ_చివర(తల))
#నిర్వచించు	XSIMPLEQ_తదుపరి(తల, elm, క్షేత్రం)    XSIMPLEQ_XOR(తల, ((elm)->క్షేత్రం.sqx_తదుపరి))


#నిర్వచించు XSIMPLEQ_FOREACH(var, తల, క్షేత్రం)				\
	కొరకు ((var) = XSIMPLEQ_మొదటి(తల);				\
	    (var) != XSIMPLEQ_చివర(తల);				\
	    (var) = XSIMPLEQ_తదుపరి(తల, var, క్షేత్రం))

#నిర్వచించు	XSIMPLEQ_FOREACH_సురక్షిత(var, తల, క్షేత్రం, tvar)			\
	కొరకు ((var) = XSIMPLEQ_మొదటి(తల);				\
	    (var) && ((tvar) = XSIMPLEQ_తదుపరి(తల, var, క్షేత్రం), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#నిర్వచించు	XSIMPLEQ_INIT(తల) చేయి {					\
	arc4random_buf(&(తల)->sqx_cookie, పరిమాణం((తల)->sqx_cookie)); \
	(తల)->sqx_మొదటి = XSIMPLEQ_XOR(తల, ఖాళీ);			\
	(తల)->sqx_చివరి = XSIMPLEQ_XOR(తల, &(తల)->sqx_మొదటి);	\
} అయితే (0)

#నిర్వచించు XSIMPLEQ_చొప్పించు_తల(తల, elm, క్షేత్రం) చేయి {			\
	ఒకవేళ (((elm)->క్షేత్రం.sqx_తదుపరి = (తల)->sqx_మొదటి) ==		\
	    XSIMPLEQ_XOR(తల, ఖాళీ))					\
		(తల)->sqx_చివరి = XSIMPLEQ_XOR(తల, &(elm)->క్షేత్రం.sqx_తదుపరి); \
	(తల)->sqx_మొదటి = XSIMPLEQ_XOR(తల, (elm));			\
} అయితే (0)

#నిర్వచించు XSIMPLEQ_చొప్పించు_తోక(తల, elm, క్షేత్రం) చేయి {			\
	(elm)->క్షేత్రం.sqx_తదుపరి = XSIMPLEQ_XOR(తల, ఖాళీ);		\
	*(XSIMPLEQ_XOR(తల, (తల)->sqx_చివరి)) = XSIMPLEQ_XOR(తల, (elm)); \
	(తల)->sqx_చివరి = XSIMPLEQ_XOR(తల, &(elm)->క్షేత్రం.sqx_తదుపరి);	\
} అయితే (0)

#నిర్వచించు XSIMPLEQ_చొప్పించు_AFTER(తల, listelm, elm, క్షేత్రం) చేయి {		\
	ఒకవేళ (((elm)->క్షేత్రం.sqx_తదుపరి = (listelm)->క్షేత్రం.sqx_తదుపరి) ==	\
	    XSIMPLEQ_XOR(తల, ఖాళీ))					\
		(తల)->sqx_చివరి = XSIMPLEQ_XOR(తల, &(elm)->క్షేత్రం.sqx_తదుపరి); \
	(listelm)->క్షేత్రం.sqx_తదుపరి = XSIMPLEQ_XOR(తల, (elm));		\
} అయితే (0)

#నిర్వచించు XSIMPLEQ_REMOVE_తల(తల, క్షేత్రం) చేయి {				\
	ఒకవేళ (((తల)->sqx_మొదటి = XSIMPLEQ_XOR(తల,			\
	    (తల)->sqx_మొదటి)->క్షేత్రం.sqx_తదుపరి) == XSIMPLEQ_XOR(తల, ఖాళీ)) \
		(తల)->sqx_చివరి = XSIMPLEQ_XOR(తల, &(తల)->sqx_మొదటి); \
} అయితే (0)

#నిర్వచించు XSIMPLEQ_REMOVE_AFTER(తల, elm, క్షేత్రం) చేయి {			\
	ఒకవేళ (((elm)->క్షేత్రం.sqx_తదుపరి = XSIMPLEQ_XOR(తల,			\
	    (elm)->క్షేత్రం.sqx_తదుపరి)->క్షేత్రం.sqx_తదుపరి)			\
	    == XSIMPLEQ_XOR(తల, ఖాళీ))				\
		(తల)->sqx_చివరి = 					\
		    XSIMPLEQ_XOR(తల, &(elm)->క్షేత్రం.sqx_తదుపరి);		\
} అయితే (0)


/*
 * Tail queue definitions.
 */
#నిర్వచించు TAILQ_HEAD(name, type)						\
నిర్మాణం name {								\
	నిర్మాణం type *tqh_first;	/* first element */			\
	నిర్మాణం type **tqh_last;	/* addr of last next element */		\
}

#నిర్వచించు TAILQ_HEAD_INITIALIZER(తల)					\
	{ ఖాళీ, &(తల).tqh_first }

#నిర్వచించు TAILQ_ENTRY(type)						\
నిర్మాణం {								\
	నిర్మాణం type *tqe_next;	/* next element */			\
	నిర్మాణం type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#నిర్వచించు	TAILQ_FIRST(తల)		((తల)->tqh_first)
#నిర్వచించు	TAILQ_చివర(తల)			ఖాళీ
#నిర్వచించు	TAILQ_NEXT(elm, క్షేత్రం)		((elm)->క్షేత్రం.tqe_next)
#నిర్వచించు TAILQ_LAST(తల, headname)					\
	(*(((నిర్మాణం headname *)((తల)->tqh_last))->tqh_last))
/* XXX */
#నిర్వచించు TAILQ_PREV(elm, headname, క్షేత్రం)				\
	(*(((నిర్మాణం headname *)((elm)->క్షేత్రం.tqe_prev))->tqh_last))
#నిర్వచించు	TAILQ_EMPTY(తల)						\
	(TAILQ_FIRST(తల) == TAILQ_చివర(తల))

#నిర్వచించు TAILQ_FOREACH(var, తల, క్షేత్రం)					\
	కొరకు((var) = TAILQ_FIRST(తల);					\
	    (var) != TAILQ_చివర(తల);					\
	    (var) = TAILQ_NEXT(var, క్షేత్రం))

#నిర్వచించు	TAILQ_FOREACH_సురక్షిత(var, తల, క్షేత్రం, tvar)			\
	కొరకు ((var) = TAILQ_FIRST(తల);					\
	    (var) != TAILQ_చివర(తల) &&					\
	    ((tvar) = TAILQ_NEXT(var, క్షేత్రం), 1);			\
	    (var) = (tvar))


#నిర్వచించు TAILQ_FOREACH_తిరగేయి(var, తల, headname, క్షేత్రం)		\
	కొరకు((var) = TAILQ_LAST(తల, headname);				\
	    (var) != TAILQ_చివర(తల);					\
	    (var) = TAILQ_PREV(var, headname, క్షేత్రం))

#నిర్వచించు	TAILQ_FOREACH_తిరగేయి_సురక్షిత(var, తల, headname, క్షేత్రం, tvar)	\
	కొరకు ((var) = TAILQ_LAST(తల, headname);			\
	    (var) != TAILQ_చివర(తల) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, క్షేత్రం), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#నిర్వచించు	TAILQ_INIT(తల) చేయి {						\
	(తల)->tqh_first = ఖాళీ;					\
	(తల)->tqh_last = &(తల)->tqh_first;				\
} అయితే (0)

#నిర్వచించు TAILQ_INSERT_HEAD(తల, elm, క్షేత్రం) చేయి {			\
	ఒకవేళ (((elm)->క్షేత్రం.tqe_next = (తల)->tqh_first) != ఖాళీ)	\
		(తల)->tqh_first->క్షేత్రం.tqe_prev =			\
		    &(elm)->క్షేత్రం.tqe_next;				\
	లేకపోతే								\
		(తల)->tqh_last = &(elm)->క్షేత్రం.tqe_next;		\
	(తల)->tqh_first = (elm);					\
	(elm)->క్షేత్రం.tqe_prev = &(తల)->tqh_first;			\
} అయితే (0)

#నిర్వచించు TAILQ_INSERT_TAIL(తల, elm, క్షేత్రం) చేయి {			\
	(elm)->క్షేత్రం.tqe_next = ఖాళీ;					\
	(elm)->క్షేత్రం.tqe_prev = (తల)->tqh_last;			\
	*(తల)->tqh_last = (elm);					\
	(తల)->tqh_last = &(elm)->క్షేత్రం.tqe_next;			\
} అయితే (0)

#నిర్వచించు TAILQ_INSERT_AFTER(తల, listelm, elm, క్షేత్రం) చేయి {		\
	ఒకవేళ (((elm)->క్షేత్రం.tqe_next = (listelm)->క్షేత్రం.tqe_next) != ఖాళీ)\
		(elm)->క్షేత్రం.tqe_next->క్షేత్రం.tqe_prev =			\
		    &(elm)->క్షేత్రం.tqe_next;				\
	లేకపోతే								\
		(తల)->tqh_last = &(elm)->క్షేత్రం.tqe_next;		\
	(listelm)->క్షేత్రం.tqe_next = (elm);				\
	(elm)->క్షేత్రం.tqe_prev = &(listelm)->క్షేత్రం.tqe_next;		\
} అయితే (0)

#నిర్వచించు	TAILQ_INSERT_BEFORE(listelm, elm, క్షేత్రం) చేయి {			\
	(elm)->క్షేత్రం.tqe_prev = (listelm)->క్షేత్రం.tqe_prev;		\
	(elm)->క్షేత్రం.tqe_next = (listelm);				\
	*(listelm)->క్షేత్రం.tqe_prev = (elm);				\
	(listelm)->క్షేత్రం.tqe_prev = &(elm)->క్షేత్రం.tqe_next;		\
} అయితే (0)

#నిర్వచించు TAILQ_REMOVE(తల, elm, క్షేత్రం) చేయి {				\
	ఒకవేళ (((elm)->క్షేత్రం.tqe_next) != ఖాళీ)				\
		(elm)->క్షేత్రం.tqe_next->క్షేత్రం.tqe_prev =			\
		    (elm)->క్షేత్రం.tqe_prev;				\
	లేకపోతే								\
		(తల)->tqh_last = (elm)->క్షేత్రం.tqe_prev;		\
	*(elm)->క్షేత్రం.tqe_prev = (elm)->క్షేత్రం.tqe_next;			\
	_Q_INVALIDATE((elm)->క్షేత్రం.tqe_prev);				\
	_Q_INVALIDATE((elm)->క్షేత్రం.tqe_next);				\
} అయితే (0)

#నిర్వచించు TAILQ_REPLACE(తల, elm, elm2, క్షేత్రం) చేయి {			\
	ఒకవేళ (((elm2)->క్షేత్రం.tqe_next = (elm)->క్షేత్రం.tqe_next) != ఖాళీ)	\
		(elm2)->క్షేత్రం.tqe_next->క్షేత్రం.tqe_prev =		\
		    &(elm2)->క్షేత్రం.tqe_next;				\
	లేకపోతే								\
		(తల)->tqh_last = &(elm2)->క్షేత్రం.tqe_next;		\
	(elm2)->క్షేత్రం.tqe_prev = (elm)->క్షేత్రం.tqe_prev;			\
	*(elm2)->క్షేత్రం.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->క్షేత్రం.tqe_prev);				\
	_Q_INVALIDATE((elm)->క్షేత్రం.tqe_next);				\
} అయితే (0)

#నిర్వచించు TAILQ_CONCAT(head1, head2, క్షేత్రం) చేయి {				\
	ఒకవేళ (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->క్షేత్రం.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} అయితే (0)

#అయితే_ముగింపు	/* !_SYS_QUEUE_H_ */
