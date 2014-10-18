/*
   american fuzzy lop - debug / error handling macros
   --------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H

#include "types.h"
#include "config.h"

#ifdef USE_COLOR
#  define cBLK "\x1b[0;30m"
#  define cRED "\x1b[0;31m"
#  define cGRN "\x1b[0;32m"
#  define cBRN "\x1b[0;33m"
#  define cBLU "\x1b[0;34m"
#  define cMGN "\x1b[0;35m"
#  define cCYA "\x1b[0;36m"
#  define cNOR "\x1b[0;37m"
#  define cGRA "\x1b[1;30m"
#  define cLRD "\x1b[1;31m"
#  define cLGN "\x1b[1;32m"
#  define cYEL "\x1b[1;33m"
#  define cLBL "\x1b[1;34m"
#  define cPIN "\x1b[1;35m"
#  define cLCY "\x1b[1;36m"
#  define cBRI "\x1b[1;37m"
#  define cRST "\x1b[0m"
#else
#  define cBLK ""
#  define cRED ""
#  define cGRN ""
#  define cBRN ""
#  define cBLU ""
#  define cMGN ""
#  define cCYA ""
#  define cNOR ""
#  define cGRA ""
#  define cLRD ""
#  define cLGN ""
#  define cYEL ""
#  define cLBL ""
#  define cPIN ""
#  define cLCY ""
#  define cBRI ""
#  define cRST ""
#endif /* ^USE_COLOR */

#define TERM_HOME     "\x1b[H"
#define TERM_CLEAR    TERM_HOME "\x1b[2J"
#define cEOL          "\x1b[0K"

#define ERRORF(x...)  fprintf(stderr, x)
#define SAYF(x...)    printf(x)

#define WARNF(x...) do { \
    ERRORF(cYEL "[!] " cBRI "WARNING: " cNOR x); \
    ERRORF(cRST "\n"); \
  } while (0)

#define OKF(x...) do { \
    ERRORF(cLGN "[+] " cNOR x); \
    ERRORF(cRST "\n"); \
  } while (0)

#define ACTF(x...) do { \
    ERRORF(cLBL "[*] " cNOR x); \
    ERRORF(cRST "\n"); \
  } while (0)

#define FATAL(x...) do { \
    ERRORF(cLRD "\n[-] PROGRAM ABORT : " cBRI x); \
    ERRORF(cLRD "\n         Location : " cNOR "%s(), %s:%u\n\n" cRST, \
           __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } while (0)

#define ABORT(x...) do { \
    ERRORF(cLRD "\n[-] PROGRAM ABORT : " cBRI x); \
    ERRORF(cLRD "\n    Stop location : " cNOR "%s(), %s:%u\n\n" cRST, \
           __FUNCTION__, __FILE__, __LINE__); \
    abort(); \
  } while (0)

#define PFATAL(x...) do { \
    ERRORF(cLRD "\n[-]  SYSTEM ERROR : " cBRI x); \
    ERRORF(cLRD "\n    Stop location : " cNOR "%s(), %s:%u\n", \
           __FUNCTION__, __FILE__, __LINE__); \
    perror(cLRD "       OS message " cNOR); \
    ERRORF(cRST "\n"); \
    exit(1); \
  } while (0)

#endif /* ! _HAVE_DEBUG_H */
