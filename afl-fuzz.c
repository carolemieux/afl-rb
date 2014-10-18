/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/resource.h>

static u8 *in_dir,                    /* Directory with initial testcases */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir,                   /* Working & output directory       */
          *use_banner,                /* Display banner                   */
          *in_bitmap;                 /* Input bitmap                     */

static u32 exec_tmout = EXEC_TIMEOUT, /* Configurable exec timeout (ms)   */
           mem_limit = MEM_LIMIT;     /* Memory cap for child (MB)        */

static u8  skip_deterministic,        /* Skip deterministic stages?       */
           use_splicing,              /* Recombine input files?           */
           dumb_mode,                 /* Allow non-instrumented code?     */
           score_changed,             /* Path scoring changed?            */
           kill_signal,               /* Signal that killed the child     */
           resuming_fuzz,             /* Resuming fuzzing job?            */
           option_t_given;            /* Called with -t?                  */

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom,               /* Persistent fd for /dev/urandom   */
           dev_null,                  /* Persistent fd for /dev/null      */
           fsrv_ctl,                  /* Fork server control pipe         */
           fsrv_st;                   /* Fork server status pipe          */

static s32 forksrv_pid,               /* PID of the fork server           */
           child_pid = -1;            /* PID of the fuzzed program        */

static u8* trace_bits;                /* SHM with instrumentation bitmap  */
static u8  virgin_bits[MAP_SIZE];     /* Regions yet untouched by fuzzing */

static s32 shm_id;                    /* ID of the SHM region             */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                   clear_screen,      /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */

static u32 unique_queued,             /* Total number of queued testcases */
           variable_queued,           /* Testcases with variable behavior */
           initial_queued,            /* Total number of initial inputs   */
           now_processing,            /* Current queue entry ID           */
           queued_later,              /* Items queued after 1st cycle     */
           pending_queued,            /* Queued but not done yet          */
           pending_redundant,         /* Queued and found redundant       */
           cur_depth,                 /* Current path depth               */
           max_depth,                 /* Max path depth                   */
           redundant_paths,           /* Seemingly redundant paths        */
           current_abandoned;         /* Abandoned inputs in cur cycle    */

static u64 total_crashes,             /* Total number of crashes          */
           unique_crashes,            /* Crashes with unique signatures   */
           total_hangs,               /* Total number of hangs            */
           unique_hangs,              /* Hangs with unique signatures     */
           total_execs,               /* Total execvp() calls             */
           start_time,                /* Unix start time (ms)             */
           last_path_time,            /* Time for most recent path (ms)   */
           last_crash_time,           /* Time for most recent crash (ms)  */
           queue_cycle;               /* Queue round counter              */

static u32 subseq_hangs;              /* Number of hangs in a row         */

static u8 *stage_name = "init",       /* Name of the current fuzz stage   */
          *stage_short;               /* Short stage name                 */

static s32 stage_cur, stage_max = 1;  /* Stage progression                */
static s32 splicing_with = -1;        /* Splicing with which test case?   */

static s32 stage_cur_byte,            /* Byte offset of current stage op  */
           stage_cur_val;             /* Value used for stage op          */
static u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[14],           /* Patterns found per fuzz stage    */
           stage_cycles[14];          /* Execs per fuzz stage             */

static u32 rand_cnt = RESEED_RNG;     /* Random number counter            */

static u64 total_cal_us,              /* Total calibration time (us)      */
           total_cal_cycles;          /* Total calibration cycles         */

static u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
           total_bitmap_entries;      /* Number of bitmaps counted        */

struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_done,                       /* Calibration completed?           */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      det_done,                       /* Deterministic stages done?       */
      var_detected,                   /* Variable behavior?               */
      redundant;                      /* Found to be redundant?           */

  u32 bitmap_size;                    /* Number of bits set in bitmap     */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_bits;                     /* Trace bits, if kept              */
  u32 tc_ref;                         /* Trace bits ref count             */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_1k;        /* 1000 elements ahead              */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top, /* Top of the list                  */
                          *queue_p1k; /* Previous 1k marker               */

static struct queue_entry*
  top_rated[MAP_SIZE << 3];           /* Top entries for every bitmap bit */

/* Interesting values, as per config.h */

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* Fuzzing stages */

enum {
  STAGE_FLIP1,
  STAGE_FLIP2,
  STAGE_FLIP4,
  STAGE_FLIP8,
  STAGE_FLIP16,
  STAGE_FLIP32,
  STAGE_ARITH8,
  STAGE_ARITH16,
  STAGE_ARITH32,
  STAGE_INTEREST8,
  STAGE_INTEREST16,
  STAGE_INTEREST32,
  STAGE_HAVOC,
  STAGE_SPLICE
};

/* Stage value types */

enum {
  STAGE_VAL_NONE,
  STAGE_VAL_LE,
  STAGE_VAL_BE
};


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}


/* Generate a random number (from 0 to limit - 1) */

static inline u32 UR(u32 limit) {

  if (!rand_cnt--) {

    u32 seed[2];

    if (read(dev_urandom, &seed, sizeof(seed)) != sizeof(seed))
      PFATAL("Short read from /dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;


}


#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. */

static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) f_loc = pos;
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif /* !IGNORE_FINDS */


/* Describe integer. Uses 16 cyclic static buffers for return values. */

static u8* DI(u64 val) {

  static u8 tmp[16][32];
  static u8 cur;

  cur = (cur + 1) % 16;

  if (val < 10000) {
    sprintf(tmp[cur], "%llu", val);
    return tmp[cur];
  }

  if (val < 1000000) {
    sprintf(tmp[cur], "%0.01fk", ((double)val) / 1000);
    return tmp[cur];
  }

  if (val < 1000000000) {
    sprintf(tmp[cur], "%0.02fM", ((double)val) / 1000000);
    return tmp[cur];
  }

  sprintf(tmp[cur], "%0.03fG", ((double)val) / 1000000000);
  return tmp[cur];

}


/* Mark deterministic checks as done. */

static void add_det_done(struct queue_entry* q) {

  u8* fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  q->det_done = 1;

}


/* Append new test case to the queue. */

static void add_to_queue(u8* fname, u32 len, u8 det_done) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname    = fname;
  q->len      = len;
  q->depth    = cur_depth + 1;
  q->det_done = det_done;

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else queue_p1k = queue = queue_top = q;

  unique_queued++;
  pending_queued++;

  if (!(unique_queued % 1000)) {

    queue_p1k->next_1k = q;
    queue_p1k = q;

  }

  if (queue_cycle > 1) queued_later++;

  last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

static void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_bits);
    ck_free(q);
    q = n;

  }

}


/* Write bitmap to file. */

static inline void write_bitmap(void) {

  u8* fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  s32 fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  if (write(fd, virgin_bits, MAP_SIZE) != MAP_SIZE)
    PFATAL("Short write to '%s'", fname);

  close(fd);
  ck_free(fname);

}


/* Read bitmap from file. */

static inline void read_bitmap(u8* fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  if (read(fd, virgin_bits, MAP_SIZE) != MAP_SIZE)
    PFATAL("Short read from '%s'", fname);

  close(fd);

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if new coverage
   is solely count-based, or 2 if it yields new tuples. */

static inline u8 has_new_bits(void) {

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_bits;

  u32  i = (MAP_SIZE >> 2);
  u8   ret = 0;

  while (i--) {

    if (*current & *virgin) {

      if (ret < 2) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        if ((cur[0] && vir[0] == 255) || (cur[1] && vir[1] == 255) ||
            (cur[2] && vir[2] == 255) || (cur[3] && vir[3] == 255)) ret = 2;
        else ret = 1;

      }

      *virgin &= ~*current;
    }

    current++;
    virgin++;

  }

  if (ret) write_bitmap();

  return ret;

}


/* Count the number of bits set in the provided bitmap. */

static inline u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;

  }

  return ret;

}


/* Count the number of non-255 bytes in the provided bitmap. */

static inline u32 count_non_255_bytes(u8* mem) {

  u32 i  = MAP_SIZE;
  u32 ret = 0;

  while (i--) if (*(mem++) != 255) ret++;

  return ret;

}


/* Destructively simplify trace by eliminating hit count information. */

static void simplify_trace(u8* mem) {

  u32 i = MAP_SIZE;

  while (i--) {
    if (*mem) *mem = 1;
    mem++;
  }

}


/* (Destructively) classify execution counts in a trace. We put the counts
   into several buckets: 1, 2, 3, 4 to 7, 8 to 15, 16 to 31, 32 to 127, and
   128+. */

static void classify_counts(u8* mem) {

  u32 i = MAP_SIZE;

  while (i--) {
    switch (*mem) {
      case 3:           *mem = (1 << 2); break;
      case 4 ... 7:     *mem = (1 << 3); break;
      case 8 ... 15:    *mem = (1 << 4); break;
      case 16 ... 31:   *mem = (1 << 5); break;
      case 32 ... 127:  *mem = (1 << 6); break;
      case 128 ... 255: *mem = (1 << 7); break;
    }
    mem++;
  }

}


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {
  shmctl(shm_id, IPC_RMID, NULL);
}


/* Update bitmap scorecard based on a new queue entry and fresh trace_bits[].
   This is called only once per new path. */

static void update_bitmap_score(struct queue_entry* q) {

  u32 i;

  for (i = 0; i < (MAP_SIZE << 3); i++)
    if (trace_bits[i >> 3] & (1 << (i & 7))) {

       if (top_rated[i]) {

         if (top_rated[i]->bitmap_size >= q->bitmap_size) continue;

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_bits);
           top_rated[i]->trace_bits = 0;
         }

       }

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_bits) {
         q->trace_bits = ck_alloc(MAP_SIZE);
         memcpy(q->trace_bits, trace_bits, MAP_SIZE);
       }

       score_changed = 1;

     }

}


/* Go through the scorecard and cull queue entries that don't seem useful. 
   This is not the best algorithm, but it's simple and fast; use
   experimental/minimize/ for a slower but better approach. */

static void cull_queue(void) {

  struct queue_entry* q;
  u8 temp_v[MAP_SIZE];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE);

  q = queue;

  redundant_paths = unique_queued;
  pending_redundant = pending_queued;

  while (q) {
    q->redundant = 1;
    q = q->next;
  }

  for (i = 0; i < (MAP_SIZE << 3); i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE;

      while (j--) temp_v[j] &= ~top_rated[i]->trace_bits[j];

      if (top_rated[i]->redundant) {

        top_rated[i]->redundant = 0;
        redundant_paths--;

        if (!top_rated[i]->was_fuzzed) pending_redundant--;

      }

    }

}


/* Configure shared memory and virgin_bits. */

static void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on. */

  if (!dumb_mode)
    setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}


/* Read all testcases from the input directory, then queue them for testing. */

static void read_testcases(void) {

  struct dirent **nl;
  s32 nl_cnt = scandir(in_dir, &nl, NULL, alphasort);
  u32 i;

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  if (nl_cnt < 0) PFATAL("Unable to open '%s'", in_dir);

  for (i = 0; i < nl_cnt; i++) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/%s", in_dir, nl[i]->d_name);
    u8  det_done = 0;

    free(nl[i]); /* not tracked */
 
    if (stat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      ck_free(dfn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big", fn);

    if (!st.st_size) 
      FATAL("Test case '%s' has zero length, doesn't seem useful", fn);

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. */

    if (!access(dfn, F_OK)) det_done = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, det_done);

  }

  free(nl); /* not tracked */

  if (!unique_queued) FATAL("No usable test cases in '%s'", in_dir);

  last_path_time = 0;
  initial_queued = unique_queued;

}


/* Spin up fork server (instrumented mode only). */

static void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

    setrlimit(RLIMIT_AS, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null, 1);
    dup2(dev_null, 2);

    if (out_file) {

      dup2(dev_null, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    close(dev_null);

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    /* This should improve performance a bit. */

    setenv("LD_BIND_NOW", "1", 0);

    execvp(argv[0], argv);

    /* Use a distinctive return value to tell the parent about execvp()
       falling through. */

    exit(EXEC_FAIL);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl = ctl_pipe[1];
  fsrv_st  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) return;

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, WUNTRACED) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) 
    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  if (WEXITSTATUS(status) == EXEC_FAIL)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  FATAL("No instrumentation detected (you can always try -n)");

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

#define FAULT_NONE   0
#define FAULT_HANG   1
#define FAULT_CRASH  2
#define FAULT_ERROR  3

/* These are used only by calibrate_case() later on. */

#define FAULT_NOINST 4
#define FAULT_NOBITS 5

static u8 run_target(char** argv) {

  static struct itimerval it;
  int status;

  child_timed_out = 0;

  memset(trace_bits, 0, MAP_SIZE);

  if (dumb_mode) {

    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {

      struct rlimit r;

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null, 1);
      dup2(dev_null, 2);

      if (out_file) {

        dup2(dev_null, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);

      }

      close(dev_null);

      execvp(argv[0], argv);

      /* Use a distinctive return value to tell the parent about execvp()
         falling through. */

      exit(EXEC_FAIL);

    }

  } else {

    /* Simply tell fork server to have at it, read back PID. */

    if (!forksrv_pid) init_forkserver(argv);

    if (write(fsrv_ctl, &status, 4) != 4) {
      if (stop_soon) return 0;
      PFATAL("Unable to request new process from fork server");
    }

    if (read(fsrv_st, &child_pid, 4) != 4) {
      if (stop_soon) return 0;
      PFATAL("Unable to request new process from fork server");
    }

    if (child_pid <= 0) PFATAL("Fork server is misbehaving, sorry");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  if (dumb_mode) {

    if (waitpid(child_pid, &status, WUNTRACED) <= 0) PFATAL("waitpid() failed");

  } else {

    if (read(fsrv_st, &status, 4) != 4) {

      if (stop_soon) return 0;
      PFATAL("Unable to communicate with fork server");

    }

  }

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  classify_counts(trace_bits);

  total_execs++;

  /* Report outcome to caller. */

  if (child_timed_out) return FAULT_HANG;

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

  if (WEXITSTATUS(status) == EXEC_FAIL) return FAULT_ERROR;

  return FAULT_NONE;

}


/* Calibrate a new test case. */

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap) {

  u8  fault, new_bits = 0;
  u32 i, cksum, cal_cycles = CAL_CYCLES, old_tmout = exec_tmout;
  u64 start_us, stop_us;

  /* Be a bit more generous about timeouts at this point. */

  if (option_t_given)
    exec_tmout = exec_tmout * CAL_TMOUT_PERC / 100;

  if (!out_file) {

    /* We need to do it this way, rather than just opening out_fd to point
       to q->fname, because we don't want to confuse fork server too much. */

    if (lseek(out_fd, 0, SEEK_SET)) PFATAL("lseek() failed");

    if (use_mem) {

      if (write(out_fd, use_mem, q->len) != q->len) 
        PFATAL("Short write to output file");

    } else {

      u8* mem = ck_alloc(q->len);
      s32 fd = open(q->fname, O_RDONLY);

      if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

      if (read(fd, mem, q->len) != q->len)
        FATAL("Short read from '%s'", q->fname);

      if (write(out_fd, mem, q->len) != q->len) 
        PFATAL("Short write to output file");

      ck_free(mem);
      close(fd);

    }
      
    if (ftruncate(out_fd, q->len)) PFATAL("ftruncate() failed");
    if (lseek(out_fd, 0, SEEK_SET)) PFATAL("lseek() failed");

  } else {

    unlink(out_file); /* Ignore errors. */
    if (link(q->fname, out_file)) PFATAL("link() failed");

  }

  start_us = get_cur_time_us();

  /* Initial run... */

  fault = run_target(argv);

  if (stop_soon || fault) goto abort_calibration;

  if (!dumb_mode) {

    if (!count_bits(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    if (has_new_bits()) new_bits = 1;

  }

  cksum = hash32(trace_bits, MAP_SIZE, 0xa5b35705);

  /* Additional runs to detect variable paths and better estimate
     execution speed. */

  for (i = 1; i < cal_cycles; i++) {

    u32 new_cksum;

    if (!out_file) lseek(out_fd, 0, SEEK_SET);

    fault = run_target(argv);

    if (stop_soon || fault) goto abort_calibration;

    new_cksum = hash32(trace_bits, MAP_SIZE, 0xa5b35705);

    if (cksum != new_cksum) {

      if (!q->var_detected) {

        q->var_detected = 1;
        variable_queued++;
        cal_cycles = CAL_CYCLES_LONG;

        if (!strstr(q->fname, ",+var")) {

          u8* new_fn = alloc_printf("%s,+var", q->fname);

          if (rename(q->fname, new_fn))
            PFATAL("Unable to rename '%s'", q->fname);

          ck_free(q->fname);
          q->fname = new_fn;

        }

      }

      if (has_new_bits()) new_bits = 1;

    }

  }

  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += cal_cycles;

  q->exec_us = (stop_us - start_us) / cal_cycles;

  q->bitmap_size = count_bits(trace_bits);
  q->handicap    = handicap;
  q->cal_done    = 1;

  update_bitmap_score(q);

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  if (!dumb_mode && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  exec_tmout = old_tmout;
  return fault;

}



/* Perform dry run of all test cases to confirm that the app is working as
   expected. */

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;
  u32 id = 0;

  while (q) {

    u8  res;
    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Verifying test case '%s'...", fn);

    res = calibrate_case(argv, q, 0, 0);
    if (stop_soon) return;

    switch (res) {

      case FAULT_HANG:   FATAL("Test case '%s' results in a hang (adjusting -t "
                               "may help)", fn);

      case FAULT_CRASH:  FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:  FATAL("Unable to execute target application ('%s')",
                               argv[0]);

      case FAULT_NOINST: FATAL("No instrumentation detected (you can always "
                               "try -n)");

      case FAULT_NOBITS: WARNF("No new instrumentation output, test case may "
                               "be redundant.");

    }

    if (q->var_detected) WARNF("Instrumentation output varies across runs.");

    q = q->next;
    id++;

  }

}


/* Creates hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(void) {

  struct queue_entry* q = queue;
  u32 id = 0;

  while (q) {

    u8  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) rsl = q->fname; else rsl++;

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name. */

    if (!strncmp(rsl, "id:", 3) && sscanf(rsl + 3, "%06u", &orig_id) == 1 &&
        orig_id == id) {

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

    } else {

      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, rsl);

    }

    ACTF("Pivoting '%s' to '%s'...", rsl, strrchr(nfn, '/') + 1);

    /* Pivot to the new queue entry. */

    if (link(q->fname, nfn)) PFATAL("link() failed");
    ck_free(q->fname);
    q->fname = nfn;

    /* Update metadata if we had det_done set organically when we first
       read the test case. */

    if (q->det_done) add_det_done(q);

    q = q->next;
    id++;

  }

}



/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (write(fd, mem, len) != len) 
    PFATAL("Short write to output file");

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* Check and update number of entries in a crash or hang directory. */

static u8 check_update_count(u8* dir) {

  u8* fn = alloc_printf("%s/.count", dir);
  s32 fd = open(fn, O_RDWR | O_CREAT, 0600);
  u32 cnt;

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  if (read(fd, &cnt, 4) != 4) cnt = 1;

  cnt++;

  lseek(fd, 0, SEEK_SET);

  if (write(fd, &cnt, 4) != 4) PFATAL("Short write to '%s'", fn);

  close(fd);
  ck_free(fn);

  return (cnt > KEEP_SAMPLES);

}


/* Construct op descriptor for file name. */

static u8* describe_op(u8 hnb) {

  static u8 ret[256];

  sprintf(ret, "src:%06u", now_processing);

  if (splicing_with >= 0)
    sprintf(ret + strlen(ret), "+%06u", splicing_with);

  sprintf(ret + strlen(ret), ",op:%s", stage_short);

  if (stage_cur_byte >= 0) {

    sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

    if (stage_val_type != STAGE_VAL_NONE)
      sprintf(ret + strlen(ret), ",val:%s%+d", 
              (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
              stage_cur_val);

  } else sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}


/* Check if the result of a test run is interesting, save or queue the input
   test case for further analysis if so. */

static void save_if_interesting(void* mem, u32 len, u8 fault) {

  u8  *fn = "", *dir;
  u8  hnb;
  s32 fd;
  u32 hash = 0;

  switch (fault) {

    case FAULT_NONE:

      if (!(hnb = has_new_bits())) return;

      fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, unique_queued,
                        describe_op(hnb));

      add_to_queue(fn, len, 0);

      queue_top->bitmap_size = count_bits(trace_bits);
      update_bitmap_score(queue_top);      

      break;

    case FAULT_HANG:

      if (unique_hangs >= KEEP_UNIQUE_HANG) return;

      if (!dumb_mode) {
        simplify_trace(trace_bits);
        hash = hash32(trace_bits, MAP_SIZE, 0xa5be5705);
      }

      dir = alloc_printf("%s/hangs/hash:%08x", out_dir, hash);

      total_hangs++;

      if (!mkdir(dir, 0700) || dumb_mode) {

        unique_hangs++;

      } else {

        if (check_update_count(dir)) {
          ck_free(dir);
          return;
        }

      }

      fn = alloc_printf("%s/id:%06llu,%s", dir, total_hangs,
                        describe_op(0));

      ck_free(dir);
      break;

    case FAULT_CRASH:

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return;

      if (!dumb_mode) {
        simplify_trace(trace_bits);
        hash = hash32(trace_bits, MAP_SIZE, 0xa5be5705);
      }

      dir = alloc_printf("%s/crashes/sig:%02u,hash:%08x", out_dir,
                         kill_signal, hash);

      total_crashes++;

      if (!mkdir(dir, 0700) || dumb_mode) {
 
        unique_crashes++;
        last_crash_time = get_cur_time();

      } else {

        if (check_update_count(dir)) {
          ck_free(dir);
          return;
        }

      }

      fn = alloc_printf("%s/id:%06llu,%s", dir, total_crashes,
                        describe_op(0));

      ck_free(dir);
      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

  }

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'\n", fn);

  if (write(fd, mem, len) != len) PFATAL("Short write to '%s'", fn);

  if (fault) ck_free(fn);

  close(fd);

}


/* Display some fuzzing stats. */

static void show_stats(void) {

  s64 cur_ms, run_time;

  u32 run_d, run_h, run_m;
  double run_s, avg_exec;

  u32 t_bytes = count_non_255_bytes(virgin_bits);
  u32 t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  cur_ms   = get_cur_time();
  run_time = cur_ms - start_time;

  if (!run_time) run_time = 1;

  run_d = run_time / 1000 / 60 / 60 / 24;
  run_h = (run_time / 1000 / 60 / 60) % 24;
  run_m = (run_time / 1000 / 60) % 60;
  run_s = ((double)(run_time % 60000)) / 1000;

  if (clear_screen) {

    SAYF(TERM_CLEAR);
    clear_screen = 0;

  }

  SAYF(TERM_HOME cGRA
       ">>> " cYEL " afl-fuzz " cLCY VERSION cLGN " (%s)" cGRA " <<<\n\n"

#ifdef IGNORE_FINDS

       cLRD "*** IGNORE_FINDS MODE ENABLED ***\n"
#ifdef COVERAGE_ONLY
       cPIN "*** COVERAGE_ONLY MODE ENABLED ***\n"
#endif /* COVERAGE_ONLY */
       "\n"

#else

#ifdef COVERAGE_ONLY
       cPIN "*** COVERAGE_ONLY MODE ENABLED ***\n\n"
#endif /* COVERAGE_ONLY */

#endif /* IGNORE_FINDS */

       cCYA "Queue cycle: " cBRI "%s\n\n"

       cGRA 
       "    Overall run time : " cNOR "%u day%s, %u hr%s, %u min, %0.02f sec"
       cEOL "\n", use_banner, DI(queue_cycle),
       run_d, (run_d == 1) ? "" : "s", run_h, (run_h == 1) ? "" : "s",
       run_m, run_s);

  SAYF(cGRA
       "      Problems found : %s%s " cNOR "crashes (%s%s unique), "
       "%s hangs (%s%s unique)" cEOL "\n",
       total_crashes ? cLRD : cNOR, DI(total_crashes), DI(unique_crashes),
       (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "",
       DI(total_hangs), DI(unique_hangs),
       (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  if (last_path_time) {

    s64 path_diff;
    u32 path_d, path_h, path_m;
    double path_s;

    path_diff = cur_ms - last_path_time;

    path_d = path_diff / 1000 / 60 / 60 / 24;
    path_h = (path_diff / 1000 / 60 / 60) % 24;
    path_m = (path_diff / 1000 / 60) % 60;

    path_s = ((double)(path_diff % 60000)) / 1000;

    SAYF(cGRA
         "       Last new path : " cNOR "%u day%s, %u hr%s, %u min, %0.02f sec"
         " ago" cEOL "\n", 
         path_d, (path_d == 1) ? "" : "s", path_h, (path_h == 1) ? "" : "s",
         path_m, path_s);

  } else {

    if (resuming_fuzz || queue_cycle == 1 || dumb_mode)
      SAYF(cGRA
           "       Last new path : " cNOR "none seen yet\n");
    else
      SAYF(cGRA
           "       Last new path : " cNOR "none " cLRD "(odd, is the target invoked correctly?)" cNOR "\n");

  }

  if (last_crash_time) {

    s64 crash_diff;
    u32 crash_d, crash_h, crash_m;
    double crash_s;

    crash_diff = cur_ms - last_crash_time;

    crash_d = crash_diff / 1000 / 60 / 60 / 24;
    crash_h = (crash_diff / 1000 / 60 / 60) % 24;
    crash_m = (crash_diff / 1000 / 60) % 60;

    crash_s = ((double)(crash_diff % 60000)) / 1000;

    SAYF(cGRA
         "   Last unique crash : " cNOR "%u day%s, %u hr%s, %u min, %0.02f sec"
         " ago" cEOL "\n", 
         crash_d, (crash_d == 1) ? "" : "s", crash_h, (crash_h == 1) ? "" : "s",
         crash_m, crash_s);

  } else {

    SAYF(cGRA
         "   Last unique crash : " cNOR "none seen yet\n");

  }

  SAYF(cCYA "\nIn-depth stats:\n\n" cGRA
       "      Cycle progress : " cNOR "%s%s/%s+%s done (%0.02f%%), %s timeouts"
       cEOL "\n", DI(now_processing), queue_cur->redundant ? "r" : "",
       DI(unique_queued - redundant_paths), DI(redundant_paths),
       ((double)now_processing) * 100 / unique_queued, DI(current_abandoned));

  SAYF(cGRA
       "       Path topology : " cNOR "%s level%s, %s+%s pending, %s latent,"
       " %s%s" cNOR " variable" cEOL "\n", DI(max_depth),
        (max_depth == 1) ? "" : "s", DI(pending_queued - pending_redundant),
        DI(pending_redundant), DI(queued_later), variable_queued ? cLRD : "",
        DI(variable_queued));

  SAYF(cGRA
       "       Current stage : " cNOR "%s, %s/%s done (%0.02f%%)" cEOL "\n",
       stage_name, DI(stage_cur), DI(stage_max), ((double)stage_cur) * 100 /
       stage_max);

  avg_exec = ((double)total_execs) * 1000 / run_time;

  SAYF(cGRA
       "    Execution cycles : " cNOR "%s (%0.02f per second%s)" cEOL "\n",
       DI(total_execs), avg_exec, avg_exec < 100 ? cLRD " - slow!" cNOR : "");

  SAYF(cGRA
       "      Bitmap density : " cNOR "%s tuples seen (%0.02f%%), %0.02f "
       "bits/tuple" cEOL "\n", DI(t_bytes), ((double)t_bytes) * 100 / MAP_SIZE,
       ((double)t_bits) / t_bytes);

  SAYF(cGRA
       "  Fuzzing efficiency : " cNOR "path = %0.02f, crash = %0.02f, hang = %0.02f ppm"
       cRST cEOL "\n", ((double)unique_queued - initial_queued) * 1000000 / total_execs,
       ((double)unique_crashes) * 1000000 / total_execs,
       ((double)unique_hangs) * 1000000 / total_execs);

  SAYF(cGRA "\n"
       "     Bit flip yields : " cNOR "%s/%s, %s/%s, %s/%s" cEOL "\n",
       DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
       DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
       DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));

  SAYF(cGRA
       "    Byte flip yields : " cNOR "%s/%s, %s/%s, %s/%s" cEOL "\n",
       DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
       DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
       DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(cGRA
       "  Arithmetics yields : " cNOR "%s/%s, %s/%s, %s/%s" cEOL "\n",
       DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
       DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
       DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(cGRA
       "    Known int yields : " cNOR "%s/%s, %s/%s, %s/%s" cEOL "\n",
       DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
       DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
       DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(cGRA
       "  Havoc stage yields : " cNOR "%s/%s, %s/%s" cRST
       cEOL "\n\n", DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
       DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

  fflush(stdout);

}


/* Show initialization stats. */

static void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = total_cal_us / total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    q = q->next;

  }

  if (avg_us > 10000) 
    WARNF(cLRD "The targeted binary is pretty slow! Consider using -d.");

  SAYF("\n"
       cGRA "  Test case count : " cNOR "%u unique, %u variable, %u total\n"
       cGRA "     Bitmap range : " cNOR "%u to %u bits (average: %0.02f bits)\n"
       cGRA "      Exec timing : " cNOR "%s to %s us (average: %s us)\n\n",
       unique_queued - redundant_paths, variable_queued, unique_queued,
       min_bits, max_bits, ((double)total_bitmap_size) / total_bitmap_entries,
       DI(min_us), DI(max_us), DI(avg_us));

  if (!option_t_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, plus 50 ms. */

    exec_tmout = 50 + MAX(avg_us * 5 / 1000, max_us / 1000);
    exec_tmout = exec_tmout / 50 * 50;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         exec_tmout);

    option_t_given = 1;

  }

  OKF("All set and ready to roll!");

}


/* Write a modified test case, run program, process results. Handle
   error conditions. */

static u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  write_to_testcase(out_buf, len);

  fault = run_target(argv);

  if (stop_soon) return 1;

  if (fault == FAULT_HANG) {

    if (subseq_hangs++ > HANG_LIMIT) {
      current_abandoned++;
      return 1;
    }

  } else subseq_hangs = 0;

  /* This handles FAULT_ERROR for us: */

  save_if_interesting(out_buf, len, fault);

  if (!(stage_cur % 100) || stage_cur + 1 == stage_max) show_stats();

  return 0;

}


/* Helper to choose random block len for block operations. Doesn't return
   zero (max_len must be > 0). */

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;

  switch (UR(3)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: min_value = HAVOC_BLK_MEDIUM;
             max_value = HAVOC_BLK_LARGE;


  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

}


/* Calculate case desirability score to adjust the length of havoc fuzzing. */

static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed by a factor of 0.1x to 3x. Fast
     inputs are less expensive to fuzz, so let's give them extra air time. */

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size, based on the theory that fuzzing inputs
     with better code coverage is more productive. The factor is 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomes are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {
    perf_score *= 4;
    q->handicap -= 4;
  } else if (q->handicap) {
    perf_score *= 2;
    q->handicap--;
  }

  /* Final adjustment based on input depth, under the assumption that fuzzing 
     deeper test cases is more likely to reveal stuff that can't be 
     discovered with traditional fuzzers. */

  if (q->depth > 3) perf_score *= 2;
  if (q->depth > 6) perf_score *= 2;
  if (q->depth > 12) perf_score *= 2;

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;

}


/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... */

static void fuzz_one(char** argv) {

  s32 len, fd, temp_len;
  s32 i, j;

  u8  *in_buf, *out_buf, *orig_in;

  u64 havoc_queued;
  u64 orig_hit_cnt, new_hit_cnt;

  u32 splice_cycle = 0;
  u32 perf_score = 100;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't already calibrated
     in perform_dry_run(), which is called only for the initial -i data. */

  if (!queue_cur->cal_done) return;

#else

  if (pending_queued != pending_redundant) {

    /* If we have any non-redundant, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or redundant
       cases. */

    if ((queue_cur->was_fuzzed || queue_cur->redundant) &&
        UR(100) < SKIP_TO_NEW_PROB) return;

  } else {

    /* Otherwise, still possibly skip redundant cases, albeit less often. */

    if (queue_cur->redundant && UR(100) < SKIP_RED_PROB) return;

  }

#endif /* ^IGNORE_FINDS */

  /* Read the test case into memory. */

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  in_buf  = ck_alloc(len),
  out_buf = ck_alloc(len);
  orig_in = in_buf;

  if (read(fd, in_buf, len) != len)
    PFATAL("Short read from '%s'", queue_cur->fname);

  close(fd);

  memcpy(out_buf, in_buf, len);

  subseq_hangs = 0;

  cur_depth = queue_cur->depth;

  /***************
   * CALIBRATION *
   ***************/

  if (!queue_cur->cal_done) {

    u8 res = calibrate_case(argv, queue_cur, in_buf, queue_cycle);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon || (res != FAULT_NONE && res != FAULT_NOBITS)) {
      current_abandoned++;
      goto abandon_entry;
    }

  }

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  perf_score = calculate_score(queue_cur);

  /* Do not repeat deterministic stages for entries that already went through
     any deterministic phases (even if we bailed out early due to timeouts). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->det_done)
    goto havoc_stage;

  /******************
   * SIMPLE BITFLIP *
   ******************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  stage_name  = "bitflip 1/1";
  stage_short = "flip1";
  stage_max   = len << 3;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = unique_queued + unique_crashes;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    out_buf[stage_cur] ^= 0xFF;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  if (len < 2) goto skip_bitflip;

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      stage_cur_val = j;
      out_buf[i] += j;

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      stage_cur_val = -j;
      out_buf[i] -= 2 * j;

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      out_buf[i] += j;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      /* Try little endian addition and subtraction first. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. */

      stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  if (len < 4) goto skip_arith;

  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      /* Little endian first. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xffff) + j > 0xffff) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig & 0xffff) < j) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;
 
      if ((SWAP32(orig) & 0xffff) + j > 0xffff) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((SWAP32(orig) & 0xffff) < j) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name  = "interest 8/8";
  stage_short = "int8";
  stage_cur   = 0;
  stage_max   = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      if (interesting_8[j] == orig) {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  if (len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      if (interesting_16[j] != orig) {

        stage_val_type = STAGE_VAL_LE;

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if (SWAP16(interesting_16[j]) != interesting_16[j] && 
          SWAP16(interesting_16[j]) != orig) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u16*)(out_buf + i) = orig;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4) goto skip_interest;

  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      stage_cur_val = interesting_32[j];

      if (interesting_32[j] != orig) {

        stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if (SWAP32(interesting_32[j]) != interesting_32[j] && 
          SWAP32(interesting_32[j]) != orig) {

        stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u32*)(out_buf + i) = orig;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're done with deterministic steps. */

  if (!queue_cur->det_done) add_det_done(queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  if (!splice_cycle) {

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = HAVOC_CYCLES * perf_score / 100;

  } else {

    static u8 tmp[32];
    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / 100;

  }

  temp_len = len;

  orig_hit_cnt = unique_queued + unique_crashes;

  havoc_queued = unique_queued;
 
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << UR(HAVOC_STACK_POW2 + 1);

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {

      switch (UR(15)) {

        case 0:

          /* Flip a single bit */

          FLIP_BIT(out_buf, UR(temp_len << 3));
          break;

        case 1: 

          /* Set byte to interesting value */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value */

          if (temp_len < 2) break;

          if (UR(2)) {

            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value */

          if (temp_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;

        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(temp_len - 1);

            del_from = UR(temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

        case 13: {

            /* Clone bytes or insert a block of constant bytes. */

            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            clone_len  = choose_block_len(temp_len);

            clone_from = UR(temp_len - clone_len + 1);
            clone_to   = UR(temp_len);

            new_buf = ck_alloc(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (UR(4))
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to, UR(256), clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

            break;

          }

        case 14: {

            /* Overwrite bytes with a randomly selected chunk or fixed bytes. */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to, UR(256), copy_len);

            break;

          }

      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* Run for a bit longer when new finds are being made. */

    if (unique_queued != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = unique_queued;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      unique_queued > 1 && queue_cur->len > 1) {

    u32 tid, split_at;
    struct queue_entry* target;
    u8* new_buf;
    s32 f_diff, l_diff;

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. */

    do { tid = UR(unique_queued); } while (tid == now_processing);

    splicing_with = tid;
    target = queue;

    while (tid >= 1000) { target = target->next_1k; tid -= 1000; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    new_buf = ck_alloc(target->len);

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    if (read(fd, new_buf, target->len) != target->len)
      PFATAL("Short read from '%s'", target->fname);

    close(fd);

    /* Find a location to splice files: somewhere between the first and
       last differing byte. Bail out if the difference is just a single byte. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;

  }

#endif /* !IGNORE_FINDS */

abandon_entry:

  splicing_with = -1;

  /* Update pending_queued count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (queue_cur->cal_done && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;
    pending_queued--;
    if (queue_cur->redundant) pending_redundant--;
  }

  if (in_buf != orig_in) ck_free(orig_in);

  ck_free(in_buf);
  ck_free(out_buf);

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);

}


/* Handle timeout. */

static void handle_timeout(int sig) {

  child_timed_out = 1; 

  if (child_pid > 0) {

    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    kill(forksrv_pid, SIGKILL);

  }

}


/* Do a PATH search and find target binary to see that it exists and looks
   reasonably fine. */

static void check_binary(u8* fname) {

  u8 *use_file = 0, *env_path = 0;
  struct stat st;

  s32 fd;
  u8 file_hdr[2];

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    use_file = ck_strdup(fname);

    if (!stat(use_file, &st) && !S_ISREG(st.st_mode) && (st.st_mode & 0111))
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        use_file = alloc_printf("%s/%s", cur_elem, fname);
      else
        use_file = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(use_file, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0111))
        break;

      ck_free(use_file);
      use_file = 0;

    }

    if (!use_file) FATAL("Program '%s' not found or not executable", fname);

  }

  fd = open(use_file, O_RDONLY);

  if (fd >= 0 && read(fd, file_hdr, 2) == 2 && file_hdr[0] == '#' &&
      file_hdr[1] == '!')
    FATAL("Program '%s' looks like a shell script - this is not what you "
          "want!", fname);

  if (fd >= 0) close(fd);

  ck_free(use_file);

}


/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/traced_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for captured crashes\n\n"

       "Execution control settings:\n\n"

       "  -f file       - input file used by the traced application\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n\n"
      
       "Fuzzing behavior settings:\n\n"

       "  -d            - skip all deterministic fuzzing stages\n"
       "  -n            - fuzz non-instrumented binaries (dumb mode)\n\n"

       "Other stuff:\n\n"

       "  -T text       - show a specific text banner on the screen\n\n"

       "For additional tips, please consult the provided documentation.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT);

  exit(1);

}


/* Prepare output directories. */

static void setup_dirs(void) {

  u8* tmp;

  if (mkdir(out_dir, 0700) && errno != EEXIST)
    PFATAL("Unable to create '%s'", out_dir);

  tmp = alloc_printf("%s/queue", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

  tmp = alloc_printf("%s/queue/.state/", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

  tmp = alloc_printf("%s/crashes", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

  tmp = alloc_printf("%s/hangs", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

}


/* Setup the output file for fuzzed data. */

static void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Handle screen resize. */

static void handle_resize(int sig) {
  clear_screen = 1;
}



/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u64 prev_queued = 0;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cNOR " (" __DATE__ " " __TIME__ 
       ") by <lcamtuf@google.com>\n");

  signal(SIGHUP,   handle_stop_sig);
  signal(SIGINT,   handle_stop_sig);
  signal(SIGTERM,  handle_stop_sig);
  signal(SIGALRM,  handle_timeout);
  signal(SIGWINCH, handle_resize);

  signal(SIGTSTP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  while ((opt = getopt(argc,argv,"+i:o:f:m:t:T:dnB:")) > 0)

    switch (opt) {

      case 'i':

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;
        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 't':

        exec_tmout = atoi(optarg);
        if (exec_tmout < 20) FATAL("Bad or dangerously low value of -t");
        option_t_given = 1;
        break;

      case 'm':

        mem_limit = atoi(optarg);
        if (mem_limit < 10) FATAL("Bad or dangerously low value of -m");
        break;

      case 'd':

        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B':

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and you
           want to start a new process seeded just with that case - but you
           don't want the fuzzer to create new test cases for paths already
           discovered by the earlier run. */

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'n':

        dumb_mode = 1;
        break;

      case 'T':

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  if (!use_banner) {

    u8* trim = strrchr(argv[optind], '/');

    if (!trim) use_banner = argv[optind]; 
    else use_banner = trim + 1;

  }

  dev_null = open("/dev/null", O_RDWR);
  if (dev_null < 0) PFATAL("Unable to open /dev/null");

  dev_urandom = open("/dev/urandom", O_RDONLY);
  if (dev_urandom < 0) PFATAL("Unable to open /dev/urandom");

  start_time = get_cur_time();

  setup_shm();

  setup_dirs();

  read_testcases();

  pivot_inputs();

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  perform_dry_run(argv + optind);

  cull_queue();

  show_init_stats();

  if (!stop_soon) {
    sleep(4);
    start_time += 4000;
  }

  if (!stop_soon) SAYF(TERM_CLEAR);

  while (!stop_soon) {

    cull_queue();

    if (!queue_cur) {

      queue_cycle++;
      now_processing    = 0;
      current_abandoned = 0;
      queue_cur         = queue;

      show_stats();

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (unique_queued == prev_queued) use_splicing = 1;
      prev_queued = unique_queued;

    }

    fuzz_one(argv + optind);

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    now_processing++;

  }

  if (queue_cur) show_stats();

  if (stop_soon) SAYF(cLRD "\n+++ Testing aborted by user +++\n" cRST);

  write_bitmap();

  destroy_queue();
  alloc_report();

  OKF("We're done here. Have a nice day!");

  exit(0);

}

