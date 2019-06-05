/* omsqlite.c
 * This is the implementation of the build-in output module for SQLite3.
 *
 * NOTE: read comments in module-template.h to understand how this file works!
 *
 * File begun on 2019-06-05 by jbatista (converted from ompgsql.c)
 *
 * omsqlite.c Copyright 2019 Joao Batista.
 * ompgsql.c Copyright 2007, 2013 Rainer Gerhards and Adiscon GmbH.
 *
 * The following link my be useful for the not-so-sqlite literate
 * when setting up a test environment:
 * https://www.sqlite.org/quickstart.html
 *
 * This file is part of rsyslog.
 *
 * Rsyslog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Rsyslog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Rsyslog.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"

#include <sqlite3.h>

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)

#ifndef MAXFILENAMELEN
#define MAXFILENAMELEN 255
#endif//MAXFILENAMELEN

#ifndef ConnStatusType
#define ConnStatusType int
#endif//ConnStatusType

typedef struct _instanceData {
	sqlite3* f_hsqlite;			/* handle to SQLite3 */
	char f_path[MAXFILENAMELEN + 1];	/* file path to SQLite3 DB */ 
	ConnStatusType eLastSqliteStatus; 	/* last status from sqlite3 */
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;

typedef struct configSettings_s {
	EMPTY_STRUCT
} configSettings_t;
static configSettings_t __attribute__((unused)) cs;

static pthread_mutex_t mutDoAct = PTHREAD_MUTEX_INITIALIZER;

BEGINinitConfVars		/* (re)set config variables to default values */
CODESTARTinitConfVars 
ENDinitConfVars

static rsRetVal writeSqlite(uchar *psz, instanceData *pData);

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

/* The following function is responsible for closing an SQLite3 connection.
 */
static void closeSQLite(instanceData *pData)
{
	assert(pData != NULL);

	if(pData->f_hsqlite != NULL) {	/* just to be on the safe side... */
        sqlite3_close(pData->f_hsqlite);
		pData->f_hsqlite = NULL;
	}
}

BEGINfreeInstance
CODESTARTfreeInstance
	closeSQLite(pData);
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	/* nothing special here */
ENDdbgPrintInstInfo


/* log a database error with descriptive message.
 * We check if we have a valid handle. If not, we simply
 * report an error, but can not be specific. RGerhards, 2007-01-30
 */
static void reportDBError(instanceData *pData, int bSilent)
{
	char errMsg[512];
	ConnStatusType eSqliteStatus;

	assert(pData != NULL);
	bSilent=0;

	/* output log message */
	errno = 0;
	if(pData->f_hsqlite == NULL) {
		errmsg.LogError(0, NO_ERRCODE, "unknown DB error occured - could not obtain SQLite3 handle");
	} else { /* we can ask sqlite for the error description... */
		eSqliteStatus = sqlite3_errcode(pData->f_hsqlite);
		snprintf(errMsg, sizeof(errMsg), "db error (%d): %s\n", eSqliteStatus,
				sqlite3_errmsg(pData->f_hsqlite));
		if(bSilent || eSqliteStatus == pData->eLastSqliteStatus)
			dbgprintf("sqlite, DBError(silent): %s\n", errMsg);
		else {
			pData->eLastSqliteStatus = eSqliteStatus;
			errmsg.LogError(0, NO_ERRCODE, "%s", errMsg);
		}
	}

	return;
}

/* The following function is responsible for initializing a Sqlite connection. */
static rsRetVal initSqlite(instanceData *pData, int bSilent)
{
	DEFiRet;

	assert(pData != NULL);
	assert(pData->f_hsqlite == NULL);

	dbgprintf("file_path=%s\n",pData->f_path);

	/* Connect to database */
	if((sqlite3_open(pData->f_path, &(pData->f_hsqlite))) != SQLITE_OK) {
		reportDBError(pData, bSilent);
		closeSQLite(pData); /* ignore any error we may get */
		iRet = RS_RET_SUSPENDED;
	}

	RETiRet;
}

/* try the insert into sqlite and return if that failed (1) or not (0). 
 * We do not use the standard IRET calling convention
 */
static inline int
tryExec(uchar *pszCmd, instanceData *pData)
{
    int rc;
    char* zErrMsg = 0;

	/* try insert */
	rc = sqlite3_exec(pData->f_hsqlite, (char*)pszCmd, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        dbgprintf("sqlite query execution failed: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

	return (rc == SQLITE_OK ? 0 : 1);
}


/* The following function writes the current log entry to an established SQLite3 session.
 * Enhanced function to take care of the returned error value (if there is such). 
 */
static rsRetVal
writeSqlite(uchar *psz, instanceData *pData)
{
	int bHadError = 0;
	DEFiRet;

	assert(psz != NULL);
	assert(pData != NULL);

	dbgprintf("writeSqlite: %s\n", psz);

	bHadError = tryExec(psz, pData); /* try insert */

	if(bHadError || (sqlite3_errcode(pData->f_hsqlite) != SQLITE_OK)) {
        /* TODO - support transactions */
		{
			closeSQLite(pData); /* close the current handle */
			CHKiRet(initSqlite(pData, 0)); /* try to re-open */
			bHadError = tryExec(psz, pData); /* retry */
		}
		if(bHadError || (sqlite3_errcode(pData->f_hsqlite) != SQLITE_OK)) {
			/* we failed, giving up for now */
			reportDBError(pData, 0);
			closeSQLite(pData); /* free resources */
			ABORT_FINALIZE(RS_RET_SUSPENDED);
		}
	}

finalize_it:
	if(iRet == RS_RET_OK) {
		pData->eLastSqliteStatus = SQLITE_OK; /* reset error for error suppression */
	}

	RETiRet;
}

BEGINtryResume
CODESTARTtryResume
	if(pWrkrData->pData->f_hsqlite == NULL) {
		iRet = initSqlite(pWrkrData->pData, 1);
		if(iRet == RS_RET_OK) {
			/* the code above seems not to actually connect to the database. As such, we do a
			 * dummy statement (a pointless select...) to verify the connection and return
			 * success only when that statement succeeds. 
			 */
			iRet = writeSqlite((uchar*)"select 1", pWrkrData->pData);
		}

	}
ENDtryResume

#if 0 /* re-enable when TX support is added again */
BEGINbeginTransaction
CODESTARTbeginTransaction
	dbgprintf("omsqlite: beginTransaction\n");
	if(pWrkrData->pData->f_hsqlite == NULL)
	       initSqlite(pWrkrData->pData, 0);
	iRet = writeSqlite((uchar*) "begin", pWrkrData->pData); /* TODO: make user-configurable */
ENDbeginTransaction
#endif

BEGINdoAction
CODESTARTdoAction
	pthread_mutex_lock(&mutDoAct);
	dbgprintf("\n");
	CHKiRet(writeSqlite(ppString[0], pWrkrData->pData));
	if(bCoreSupportsBatching)
		iRet = RS_RET_DEFER_COMMIT;
finalize_it:
	pthread_mutex_unlock(&mutDoAct);
ENDdoAction


#if 0 /* re-enable when TX support is added again */
BEGINendTransaction
CODESTARTendTransaction
	iRet = writeSqlite((uchar*) "commit;", pWrkrData->pData); /* TODO: make user-configurable */
ENDendTransaction
#endif


BEGINparseSelectorAct
	int iSqlitePropErr = 0;
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
	/* First, check if this config line is actually for us.
	 * The first test [*p == '>'] can be skipped if a module shall only
	 * support the newer selection syntax [:modname:]. This is in fact
	 * recommended for new modules. Please note that over time this part
	 * will be handled by rsyslogd itself, but for the time being it is
	 * a good compromise to do it at the module level. rgerhards, 2007-10-15
	 */

	if(!strncmp((char*) p, ":omsqlite:", sizeof(":omsqlite:") - 1)) {
		p += sizeof(":omsqlite:") - 1; /* eat indicator sequence (-1 because of '\0'!) */
	} else {
		ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
	}

	/* ok, if we reach this point, we have something for us */
	if((iRet = createInstance(&pData)) != RS_RET_OK)
		goto finalize_it;

	/* support for sqlite
	 * :omsqlite:path
	 * Now we read the SQLite connection properties and verify that the properties are valid.
	 */
	if(getSubString(&p, pData->f_path, MAXFILENAMELEN + 1, '\0')) {
		iSqlitePropErr++;
    }
	dbgprintf("%p:%s\n",p,p);

	/* now check for template
	 * We specify that the SQL option must be present in the template.
	 * This is for your own protection (prevent SQL injection).
	 */
	if(*(p-1) == ';')
		--p;	/* TODO: the whole parsing of the MySQL module needs to be re-thought - but this here
                 *       is clean enough for the time being -- rgerhards, 2007-07-30
                 *       kept it for pgsql -- sur5r, 2007-10-19
                 *       kept it for sqlite -- jbatista, 2019-06-05
                 */
	CHKiRet(cflineParseTemplateName(&p, *ppOMSR, 0, OMSR_RQD_TPL_OPT_SQL, (uchar*) " StdSqliteFmt"));
	
	/* If we detect invalid properties we disable logging, 
	 * because right properties are vital at this place.  
	 * Retries make no sense. 
	 */
	if (iSqlitePropErr) { 
		errmsg.LogError(0, RS_RET_INVALID_PARAMS, "Trouble with SQLite connection properties. -SQLite logging disabled");
		ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
	}

CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

BEGINmodExit
CODESTARTmodExit
ENDmodExit

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
/* CODEqueryEtryPt_TXIF_OMOD_QUERIES currently no TX support! */ /* we support the transactional interface! */
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
INITLegCnfVars
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	INITChkCoreFeature(bCoreSupportsBatching, CORE_FEATURE_BATCHING);

	/* TODO: transaction support missing for v8 */
	bCoreSupportsBatching= 0;
	DBGPRINTF("omsqlite: transactions are not yet supported on v8\n");

	DBGPRINTF("omsqlite: module compiled with rsyslog version %s.\n", VERSION);
	DBGPRINTF("omsqlite: %susing transactional output interface.\n", bCoreSupportsBatching ? "" : "not ");
ENDmodInit
/* vi:set ai:
 */
