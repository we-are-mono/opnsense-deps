/*
 *  Copyright (c) 2011, 2014 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/**
 * @file                main.c
 * @description         dpaa offload application
 */

#include <stdio.h>
#include <stdlib.h>

//#define ENABLE_TESTAPP		1

extern int dpa_init(void);
extern int test_app_init(void);

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
	if (dpa_init())
		return -1;
#ifdef ENABLE_TESTAPP
	if (test_app_init())
		return -1;
#endif
	return 0;
}
