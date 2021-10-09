#include "branch_pred.h"
#include "pin.H"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
using namespace std;
/*
 * trace inspection (instrumentation function)
 *
 * traverse the basic blocks (BBLs) on the trace and
 * inspect every instruction for instrumenting it
 * accordingly --- dummy version; simply counts the
 * number of instructions inside the trace
 *
 * @trace:      instructions trace; given by PIN
 */
static void trace_inspect(TRACE trace, VOID *v) {
  /* iterators */
  BBL bbl;
  INS ins;

  /* instruction counter */
  size_t ins_ct = 0;

  /* traverse all the BBLs in the trace */
  for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    /* traverse all the instructions in the BBL */
    for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
      /* analyze the instruction; dummy */
      ins_ct++;
  }
}

/*
 * NullPin
 *
 * used for estimating the overhead of Pin
 */
int main(int argc, char **argv) {
  /* initialize symbol processing */
  PIN_InitSymbols();

  /* initialize PIN; optimized branch */
  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  /* register trace_ins() to be called for every trace */
  TRACE_AddInstrumentFunction(trace_inspect, NULL);

  PIN_StartProgram();

  return 0;
}
