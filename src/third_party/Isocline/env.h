/* ----------------------------------------------------------------------------
  Copyright (c) 2021, Daan Leijen
  This is free software; you can redistribute it and/or modify it
  under the terms of the MIT License. A copy of the license can be
  found in the "LICENSE" file at the root of this distribution.
-----------------------------------------------------------------------------*/
#pragma once
#ifndef IC_ENV_H
#define IC_ENV_H

#include "isocline.h"
#include "common.h"
#include "term.h"
#include "tty.h"
#include "stringbuf.h"
#include "history.h"
#include "completions.h"
#include "bbcode.h"

//-------------------------------------------------------------
// Environment
//-------------------------------------------------------------

struct ic_env_s {
  alloc_t*        mem;              // potential custom allocator
  ic_env_t*       next;             // next environment (used for proper deallocation)
  term_t*         term;             // terminal
  tty_t*          tty;              // keyboard (NULL if stdin is a pipe, file, etc)
  completions_t*  completions;      // current completions
  history_t*      history;          // edit history
  bbcode_t*       bbcode;           // print with bbcodes
  const char*     prompt_marker;    // the prompt marker (defaults to "> ")
  const char*     cprompt_marker;   // prompt marker for continuation lines (defaults to `prompt_marker`)
  ic_highlight_fun_t* highlighter;  // highlight callback
  void*           highlighter_arg;  // user state for the highlighter.
  const char*     match_braces;     // matching braces, e.g "()[]{}"
  const char*     auto_braces;      // auto insertion braces, e.g "()[]{}\"\"''"
  const char*     line_prefix;      // fixed prefix displayed after line breaks
  const char*     history_search_prompt; // prompt text shown during incremental history search
  char            multiline_eol;    // character used for multiline input ("\") (set to 0 to disable)
  bool            initialized;      // are we initialized?
  bool            noedit;           // is rich editing possible (tty != NULL)
  bool            singleline_only;  // allow only single line editing?
  bool            complete_nopreview; // do not show completion preview for each selection in the completion menu?
  bool            complete_autotab; // try to keep completing after a completion?
  bool            complete_nosort;  // do not sort completion items?
  long            complete_max_items;   // maximum number of completions to generate/show
  long            complete_max_columns; // maximum number of columns in the completion menu
  long            complete_max_rows;    // maximum number of rows in the completion menu
  bool            complete_number_pick; // allow selecting items with number keys
  bool            complete_auto_fill;   // auto-complete single/prefix matches
  const char*     complete_select_sign; // custom indicator for selected item
  const char*     completion_page_marker; // optional marker appended to completion page info
  bool            edit_active;      // is an editline session currently active?
  bool            refresh_request;  // request a soft refresh on next key cycle
  volatile long   async_lock;       // spin lock for async queues
  struct ic_async_msg_s* async_print_head; // queued async print messages
  struct ic_async_msg_s* async_print_tail; // queued async print messages
  bool            no_multiline_indent; // indent continuation lines to line up under the initial prompt 
  bool            no_help;          // show short help line for history search etc.
  bool            no_hint;          // allow hinting?
  bool            no_highlight;     // enable highlighting?
  bool            no_bracematch;    // enable brace matching?
  bool            no_autobrace;     // enable automatic brace insertion?
  bool            no_lscolors;      // use LSCOLORS/LS_COLORS to colorize file name completions?
  long            hint_delay;       // delay before displaying a hint in milliseconds
  long            hint_search_delay; // delay before running hint completion search in milliseconds
  long            highlight_delay;  // delay before applying syntax highlighting in milliseconds
};

ic_private char*        ic_editline(ic_env_t* env, const char* prompt_text,
                                    const char* initial_text);

ic_private ic_env_t*    ic_get_env(void);
ic_private const char*  ic_env_get_auto_braces(ic_env_t* env);
ic_private const char*  ic_env_get_match_braces(ic_env_t* env);
ic_private bool         ic_env_async_print_push(ic_env_t* env, const char* s);
ic_private char*        ic_env_async_print_pop(ic_env_t* env);
ic_private bool         ic_env_async_print_pending(ic_env_t* env);

#endif // IC_ENV_H
