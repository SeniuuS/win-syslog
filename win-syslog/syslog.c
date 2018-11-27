/*
* Copyright (c) 1983, 1988, 1993
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
* 4. Neither the name of the University nor the names of its contributors
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
*/

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <locale.h>
#include <stdarg.h>
#include <Windows.h>
#include <math.h>
#include "syslog.h"

#pragma comment(lib, "advapi32.lib")

static int	LogStat;		/* status bits, set by openlog() */
static const char *LogTag;		/* string to tag the entry with */
static int	LogFacility = LOG_USER;	/* default facility code */
static int	LogMask = 0xff;		/* mask of priorities to be logged */

static HANDLE hEventLog = NULL;

static WORD
convertLogType(int flag) {
	switch (flag) {
		case LOG_EMERG:
		case LOG_ALERT:
		case LOG_CRIT:
		case LOG_ERR:
			return EVENTLOG_ERROR_TYPE;
		case LOG_WARNING:
			return EVENTLOG_WARNING_TYPE;
		case LOG_INFO:
		case LOG_NOTICE:
		case LOG_DEBUG:
			return EVENTLOG_INFORMATION_TYPE;
		default:
			return NULL;
	}
}

/* ctowc -- convert a char* to a wchar_t* */
static wchar_t*
ctowc(char *str) {
	size_t wn = mbstowcs(NULL, str, 0);
	wchar_t *buf = malloc(wn * sizeof *buf);
	wn = mbstowcs(buf, str, wn + 1);
	return buf;
}

void
vsyslog_chk(int pri, int flag, const char *fmt, va_list ap)
{
	LPWSTR pInsertStrings[2] = { NULL, NULL };
	WORD errorType = convertLogType(pri);

	pInsertStrings[0] = ctowc((char *)fmt);

#define	INTERNALLOG	LOG_ERR|LOG_CONS|LOG_PERROR|LOG_PID
	/* Check for invalid bits. */
	if (pri & ~(LOG_PRIMASK | LOG_FACMASK)) {
		syslog(INTERNALLOG,
			"syslog: unknown facility/priority: %x", pri);
		pri &= LOG_PRIMASK | LOG_FACMASK;
	}

	/* Check priority against setlogmask values. */
	if ((LOG_MASK(LOG_PRI(pri)) & LogMask) == 0)
		return;

	/* Set default facility if none specified. */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	if (LogStat & LOG_PID) {
		int pid = _getpid();
		if (pid != 0) {
			int pidLength = floor(log10(abs(pid))) + 1;
			char *buf = malloc((strlen("PID : [") + pidLength + strlen("]")) * sizeof *buf);
			sprintf(buf, "PID : [%d]", pid);
			pInsertStrings[1] = ctowc(buf);
		}
	}

	ReportEvent(hEventLog, errorType, 1, 256, NULL, 2, 0, (LPCWSTR*)pInsertStrings, NULL);
}

/* program_name - get the program name */
char*
program_name() {
	char filename[MAX_PATH];
	DWORD size = GetModuleFileNameA(NULL, filename, MAX_PATH);
	return filename;
}

/* openlog -- register the EventSource to write in Event Log */
void
openlog(const char *ident, int logstat, int logfac)
{
	if (ident != NULL)
		LogTag = ident;
	else
		LogTag = program_name();

	if (LogTag) {
		LogStat = logstat;
		if (logfac != 0 && (logfac &~LOG_FACMASK) == 0)
			LogFacility = logfac;

		hEventLog = RegisterEventSource(NULL, ctowc((char *)LogTag));
		if (hEventLog == NULL) {
			wprintf(L"RegisterEventSource failed with 0x%x.\n", GetLastError());
		}
	}
	else {
		wprintf(L"No program name found. Logs are disabled.");
	}
}

/* closelog -- unregister the EventSource handle */
void
closelog(void)
{
	if (hEventLog)
		DeregisterEventSource(hEventLog);
	LogTag = NULL;
}

/* setlogmask -- set the log mask level */
int
setlogmask(int pmask)
{
	int omask;

	omask = LogMask;
	if (pmask != 0)
		LogMask = pmask;
	return (omask);
}

/*
* syslog, vsyslog --
*	print message on event log of windows
*/
void
syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog_chk(pri, -1, fmt, ap);
	va_end(ap);
}