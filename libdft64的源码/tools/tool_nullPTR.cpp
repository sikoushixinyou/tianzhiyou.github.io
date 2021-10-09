#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <set>
#include <unistd.h>
using namespace std;
#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"

/* default path for the log file (audit) */
#define LOGFILE_DFL	"tool_nullPTR.log"

#define	TAG 	0xFFU

/* thread context */
extern thread_ctx_t *threads_ctx;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* log file path (auditing) */
static KNOB<string> logpath(KNOB_MODE_WRITEONCE, "pintool", "l", LOGFILE_DFL, "");

/* 
 * DTA/DFT alert
 *
 * @addr_ins:	address of the offending instruction
 */
static void PIN_FAST_ANALYSIS_CALL alert(ADDRINT addr_ins)
{
	printf("Null Pointer Detected!\n");
	/* log file */
	FILE *logfile;

	/* auditing */
	if (likely((logfile = fopen(logpath.Value().c_str(), "a")) != NULL)) {
		/* hilarious :) */
		(void)fprintf(logfile, " ____ ____ ____ ____\n");
		(void)fprintf(logfile, "||W |||A |||R |||N ||\n");
		(void)fprintf(logfile, "||__|||__|||__|||__||\t");
		(void)fprintf(logfile, "[%d]: 0x%08lx  NULL Pointer Dreference\n",
							getpid(), addr_ins);

		(void)fprintf(logfile, "|/__\\|/__\\|/__\\|/__\\|\n");
		
		/* cleanup */
		(void)fclose(logfile);
	}
	else
		/* failed */
		LOG(string(__func__) +
			": failed while trying to open " +
			logpath.Value().c_str() + " (" +
			string(strerror(errno)) + ")\n");

	/* terminate */
	exit(EXIT_FAILURE);
}

/*
 * PTR assertion (taint-sink, DFT-sink)
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_ptr(ADDRINT ptr)
{
	int flag;
	if(ptr == 0)
		flag = 1;
	else
		flag = 0;
	
	return flag;
}

/*
 * instrument the movsb/movsw/movsd/movsq instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void dta_instrument_movsx(INS ins)
{
	INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_ptr,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_PTR,
					IARG_END);
		
	INS_InsertThenCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)alert,
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_END);
}


/*
 * instrument the mov/bsf/bsr instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void dta_instrument_mov(INS ins)
{
	if(INS_IsMemoryWrite(ins))
	{
		INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_ptr,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_PTR,
					IARG_END);
		
	    INS_InsertThenCall(ins,
			        IPOINT_BEFORE,
			        (AFUNPTR)alert,
			        IARG_FAST_ANALYSIS_CALL,
			        IARG_INST_PTR,
			        IARG_END);
	}
}


/* 
 * DTA
 *
 * used for demonstrating how to implement
 * a practical dynamic taint analysis (DTA)
 * tool using libdft
 */
int
main(int argc, char **argv)
{
	/* initialize symbol processing */
	PIN_InitSymbols();
	
	/* initialize Pin; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* Pin initialization failed */
		goto err;

	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;
	
	/* 
	 * handle control transfer instructions
	 *
	 * instrument the branch instructions, accordingly,
	 * for installing taint-sinks (DFT-logic) that check
	 * for tainted targets (i.e., tainted operands or
	 * tainted branch targets) -- For brevity I omitted
	 * checking the result of each instrumentation for
	 * success or failure
	 */

	/* instrument MOVSB */
	(void)ins_set_post(&ins_desc[XED_ICLASS_MOVSB],
			dta_instrument_movsx);
	
	/* instrument MOVSW */
	(void)ins_set_post(&ins_desc[XED_ICLASS_MOVSW],
			dta_instrument_movsx);

	/* instrument MOVSD */
	(void)ins_set_post(&ins_desc[XED_ICLASS_MOVSD],
			dta_instrument_movsx);
	
	/* instrument MOVSQ */
	(void)ins_set_post(&ins_desc[XED_ICLASS_MOVSQ],
			dta_instrument_movsx);
	
	/* instrument MOV */
	(void)ins_set_post(&ins_desc[XED_ICLASS_MOV],
			dta_instrument_mov);
	
	/* instrument BSF */
	(void)ins_set_post(&ins_desc[XED_ICLASS_BSF],
			dta_instrument_mov);
	
	/* instrument BSF */
	(void)ins_set_post(&ins_desc[XED_ICLASS_BSF],
			dta_instrument_mov);
	

	/* start Pin */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}