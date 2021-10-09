#include "branch_pred.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "syscall_hook.h"

#include <stdio.h>
#include <stdlib.h>
using namespace std;
/*
 * DummyTool (i.e, libdft)
 *
 * used for demonstrating libdft
 */
int main(int argc, char **argv) {
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

  hook_file_syscall();
  /* start Pin */
  PIN_StartProgram();

  /* typically not reached; make the compiler happy */
  return EXIT_SUCCESS;

err: /* error handling */

  /* return */
  return EXIT_FAILURE;
}
