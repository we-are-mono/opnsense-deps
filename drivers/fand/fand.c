/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * Fan control daemon for the Mono Gateway.
 * Linearly scales PWM from 20% at 40°C to 100% at 80°C
 * using the SoC TMU temperature and EMC2302 fan controller.
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Temperature thresholds (millidegrees C) */
#define	TEMP_LOW_MC	40000	/* 40°C — minimum fan speed */
#define	TEMP_HIGH_MC	80000	/* 80°C — maximum fan speed */

/* PWM range (0-255) */
#define	PWM_MIN		51	/* 20% of 255 */
#define	PWM_MAX		255	/* 100% */

/* Polling interval */
#define	POLL_INTERVAL	2	/* seconds */

/* Sysctl names */
#define	SYSCTL_TEMP	"hw.temperature.core-cluster"
#define	SYSCTL_FAN0_PWM	"dev.emc2302.0.fan0.pwm"
#define	SYSCTL_FAN1_PWM	"dev.emc2302.0.fan1.pwm"

static volatile sig_atomic_t running = 1;

static void
signal_handler(int sig __unused)
{

	running = 0;
}

static int
read_temp_mc(void)
{
	int val;
	size_t len;

	len = sizeof(val);
	if (sysctlbyname(SYSCTL_TEMP, &val, &len, NULL, 0) != 0)
		return (-1);

	/* Convert decikelvin to millidegrees C */
	return ((val - 2731) * 100);
}

static int
set_pwm(const char *name, int pwm)
{

	return (sysctlbyname(name, NULL, NULL, &pwm, sizeof(pwm)));
}

static int
compute_pwm(int temp_mc)
{

	if (temp_mc <= TEMP_LOW_MC)
		return (PWM_MIN);
	if (temp_mc >= TEMP_HIGH_MC)
		return (PWM_MAX);

	return (PWM_MIN + (temp_mc - TEMP_LOW_MC) *
	    (PWM_MAX - PWM_MIN) / (TEMP_HIGH_MC - TEMP_LOW_MC));
}

static void
set_fans(int pwm)
{

	set_pwm(SYSCTL_FAN0_PWM, pwm);
	set_pwm(SYSCTL_FAN1_PWM, pwm);
}

static void
usage(void)
{

	fprintf(stderr, "usage: fand [-d]\n");
	fprintf(stderr, "  -d  daemonize\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int dflag, ch, temp_mc, pwm, last_pwm;

	dflag = 0;
	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		default:
			usage();
		}
	}

	/* Verify sysctls exist */
	temp_mc = read_temp_mc();
	if (temp_mc < 0)
		errx(1, "cannot read %s", SYSCTL_TEMP);
	if (set_pwm(SYSCTL_FAN0_PWM, PWM_MIN) != 0)
		errx(1, "cannot write %s", SYSCTL_FAN0_PWM);
	if (set_pwm(SYSCTL_FAN1_PWM, PWM_MIN) != 0)
		errx(1, "cannot write %s", SYSCTL_FAN1_PWM);

	if (dflag && daemon(0, 0) != 0)
		err(1, "daemon");

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	last_pwm = -1;

	while (running) {
		temp_mc = read_temp_mc();
		if (temp_mc < 0) {
			/* Sensor failure — full speed for safety */
			set_fans(PWM_MAX);
			last_pwm = PWM_MAX;
			sleep(POLL_INTERVAL);
			continue;
		}

		pwm = compute_pwm(temp_mc);

		if (last_pwm < 0 || abs(pwm - last_pwm) >= 5) {
			fprintf(stderr, "fand: %d.%d°C -> PWM %d (%d%%)\n",
			    temp_mc / 1000, (temp_mc % 1000) / 100,
			    pwm, pwm * 100 / 255);
			set_fans(pwm);
			last_pwm = pwm;
		}

		sleep(POLL_INTERVAL);
	}

	/* Safety: full speed on exit */
	fprintf(stderr, "fand: shutting down, fans to 100%%\n");
	set_fans(PWM_MAX);

	return (0);
}
