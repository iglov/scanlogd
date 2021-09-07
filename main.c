/*
 * Copyright (c) 1998-2012 by Solar Designer
 * See LICENSE
 */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "params.h"
#include "in.h"
#include "process_ipv4.h"

clock_t scan_delay_threshold, log_delay_threshold;
/*
 * Simple, but we only expect errors at startup, so this should suffice.
 */
void pexit(char *name)
{
	perror(name);
	exit(1);
}

#ifdef SCANLOGD_USER
static void drop_root(void)
{
	struct passwd *pw;
	gid_t groups[2];

	errno = 0;
	if (!(pw = getpwnam(SCANLOGD_USER))) {
		fprintf(stderr,
			"getpwnam(\"" SCANLOGD_USER "\"): %s\n",
			errno ? strerror(errno) : "No such user");
		exit(1);
	}

#ifdef SCANLOGD_CHROOT
	if (chroot(SCANLOGD_CHROOT)) return pexit("chroot");
	if (chdir("/")) return pexit("chdir");
#endif

	groups[0] = groups[1] = pw->pw_gid;
	if (setgroups(1, groups)) pexit("setgroups");
	if (setgid(pw->pw_gid)) pexit("setgid");
	if (setuid(pw->pw_uid)) pexit("setuid");
}
#elif defined(SCANLOGD_CHROOT)
#warning SCANLOGD_CHROOT makes no sense without SCANLOGD_USER; ignored.
#endif

/*
 * Hmm, what could this be?
 */
int main(void)
{
	int dev_null_fd;
	clock_t clk_tck;

/* Initialize the packet capture interface */
	if (in_init()) return 1;

/* Prepare for daemonizing */
	chdir("/");
	setsid();

/* Must do these before chroot'ing */
	tzset();
	openlog(SYSLOG_IDENT, LOG_NDELAY, SYSLOG_FACILITY);
	dev_null_fd = open("/dev/null", O_RDONLY);

/* Also do this early - who knows what this system's sysconf() relies upon */
#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	clk_tck = sysconf(_SC_CLK_TCK);
#else
	clk_tck = CLK_TCK;
#endif
	scan_delay_threshold = SCAN_DELAY_THRESHOLD * clk_tck;
	log_delay_threshold = LOG_DELAY_THRESHOLD * clk_tck;

/* We can drop root now */
#ifdef SCANLOGD_USER
	drop_root();
#endif
#if 0
/* Become a daemon */
	switch (fork()) {
	case -1:
		pexit("fork");

	case 0:
		break;

	default:
/* in_init() could have registered an atexit(3) function to restore the
 * interface, but this is not a real exit, yet (in fact, we're starting
 * up), so we use _exit(2) rather than exit(3) here */
		_exit(0);
	}

	setsid();

/* Just assume that stdin, stdout, and stderr fd's were open at startup and
 * thus are indeed not allocated to anything else. */
	if (dev_null_fd >= 0) {
		dup2(dev_null_fd, STDIN_FILENO);
		dup2(dev_null_fd, STDOUT_FILENO);
		dup2(dev_null_fd, STDERR_FILENO);
		if (dev_null_fd >= 3) close(dev_null_fd);
	}
#endif
	process_ipv4_init();

/* Let's start */
	in_run(process_packet_ipv4);

/* We shouldn't reach this */
	return 1;
}
