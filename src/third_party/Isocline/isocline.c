/* ----------------------------------------------------------------------------
  Copyright (c) 2021, Daan Leijen
  This is free software; you can redistribute it and/or modify it
  under the terms of the MIT License. A copy of the license can be
  found in the "LICENSE" file at the root of this distribution.
-----------------------------------------------------------------------------*/

//-------------------------------------------------------------
// Usually we include all sources one file so no internal
// symbols are public in the libray.
//
// You can compile the entire library just as:
// $ gcc -c src/isocline.c
//-------------------------------------------------------------
#if !defined(IC_SEPARATE_OBJS)
#ifndef _CRT_NONSTDC_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS // for msvc
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS // for msvc
#endif
#define _XOPEN_SOURCE 700 // for wcwidth
#define _DEFAULT_SOURCE // ensure usleep stays visible with _XOPEN_SOURCE >= 700
#include "attr.c"
#include "bbcode.c"
#include "common.c"
#include "completers.c"
#include "completions.c"
#include "editline.c"
#include "highlight.c"
#include "history.c"
#include "stringbuf.c"
#include "term.c"
#include "tty.c"
#include "tty_esc.c"
#include "undo.c"
#endif

//-------------------------------------------------------------
// includes
//-------------------------------------------------------------
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sched.h>
#endif

#include "Isocline/common.h"
#include "Isocline/env.h"
#include "Isocline/isocline.h"

#define IC_DEFAULT_COMPLETION_MAX_COLUMNS (4)
#define IC_DEFAULT_COMPLETION_MAX_ROWS (9)

/** Runtime profile that owns one independent Isocline environment. */
struct ic_profile_s {
  ic_env_t *env;
  char name[128];
  struct ic_profile_s *next;
};

/** Linked list of registered runtime profiles. */
static ic_profile_t *ic_profiles = NULL;
/** Current active runtime profile. */
static ic_profile_t *ic_current_profile = NULL;
/** Lazily created default runtime profile. */
static ic_profile_t *ic_default_profile = NULL;
static long ic_profile_seq = 0;
/** Ensure atexit registration happens once. */
static bool ic_atexit_registered = false;
/** Optional custom allocation callbacks used for new profiles. */
static ic_malloc_fun_t *ic_custom_malloc = NULL;
static ic_realloc_fun_t *ic_custom_realloc = NULL;
static ic_free_fun_t *ic_custom_free = NULL;

typedef struct ic_async_msg_s {
  char *text;
  struct ic_async_msg_s *next;
} ic_async_msg_t;

static void ic_async_lock_(volatile long *lk) {
  if (lk == NULL)
    return;
#if defined(_WIN32)
  while (InterlockedExchange((volatile LONG *)lk, 1L) != 0L) {
    Sleep(0);
  }
#else
  while (__sync_lock_test_and_set(lk, 1L) != 0L) {
    sched_yield();
  }
#endif
}

static void ic_async_unlock_(volatile long *lk) {
  if (lk == NULL)
    return;
#if defined(_WIN32)
  InterlockedExchange((volatile LONG *)lk, 0L);
#else
  __sync_lock_release(lk);
#endif
}

ic_private bool ic_env_async_print_push(ic_env_t *env, const char *s) {
  if (env == NULL || env->mem == NULL || s == NULL)
    return false;
  ic_async_msg_t *msg = mem_zalloc_tp(env->mem, ic_async_msg_t);
  if (msg == NULL)
    return false;
  msg->text = mem_strdup(env->mem, s);
  if (msg->text == NULL) {
    mem_free(env->mem, msg);
    return false;
  }
  msg->next = NULL;

  ic_async_lock_(&env->async_lock);
  if (env->async_print_tail == NULL) {
    env->async_print_head = msg;
    env->async_print_tail = msg;
  } else {
    env->async_print_tail->next = msg;
    env->async_print_tail = msg;
  }
  ic_async_unlock_(&env->async_lock);
  return true;
}

ic_private char *ic_env_async_print_pop(ic_env_t *env) {
  if (env == NULL || env->mem == NULL)
    return NULL;
  ic_async_msg_t *msg = NULL;
  char *text = NULL;
  ic_async_lock_(&env->async_lock);
  msg = env->async_print_head;
  if (msg != NULL) {
    env->async_print_head = msg->next;
    if (env->async_print_head == NULL) {
      env->async_print_tail = NULL;
    }
  }
  ic_async_unlock_(&env->async_lock);
  if (msg == NULL)
    return NULL;
  text = msg->text;
  mem_free(env->mem, msg);
  return text;
}

ic_private bool ic_env_async_print_pending(ic_env_t *env) {
  if (env == NULL)
    return false;
  bool pending = false;
  ic_async_lock_(&env->async_lock);
  pending = (env->async_print_head != NULL);
  ic_async_unlock_(&env->async_lock);
  return pending;
}

//-------------------------------------------------------------
// Readline
//-------------------------------------------------------------

static char *ic_getline(alloc_t *mem);

ic_public char *ic_readline(const char *prompt_text) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  if (!env->noedit) {
    // terminal editing enabled
    return ic_editline(env, prompt_text, NULL, false); // in editline.c
  } else {
    // no editing capability (pipe, dumb terminal, etc)
    if (env->tty != NULL && env->term != NULL) {
      // if the terminal is not interactive, but we are reading from the tty
      // (keyboard), we display a prompt
      term_start_raw(env->term); // set utf8 mode on windows
      if (prompt_text != NULL) {
        term_write(env->term, prompt_text);
      }
      term_write(env->term, env->prompt_marker);
      term_end_raw(env->term, false);
    }
    // read directly from stdin
    return ic_getline(env->mem);
  }
}

/** Read input with an initial pre-filled value. */
ic_public char *ic_readline_ex(const char *prompt_text,
                               const char *initial_text) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  if (!env->noedit) {
    // terminal editing enabled
    return ic_editline(env, prompt_text, initial_text, false); // in editline.c
  }
  // no editing capability (pipe, dumb terminal, etc)
  if (env->tty != NULL && env->term != NULL) {
    term_start_raw(env->term);
    if (prompt_text != NULL) {
      term_write(env->term, prompt_text);
    }
    term_write(env->term, env->prompt_marker);
    term_end_raw(env->term, false);
  }
  return ic_getline(env->mem);
}

ic_public char *ic_readline_secure(const char *prompt_text,
                                   const char *initial_text) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  if (!env->noedit) {
    return ic_editline(env, prompt_text, initial_text, true);
  }
  if (env->tty != NULL && env->term != NULL) {
    term_start_raw(env->term);
    if (prompt_text != NULL) {
      term_write(env->term, prompt_text);
    }
    term_write(env->term, env->prompt_marker);
    term_end_raw(env->term, false);
  }
  return ic_getline(env->mem);
}

//-------------------------------------------------------------
// Read a line from the stdin stream if there is no editing
// support (like from a pipe, file, or dumb terminal).
//-------------------------------------------------------------

static char *ic_getline(alloc_t *mem) {
  // read until eof or newline
  stringbuf_t *sb = sbuf_new(mem);
  int c;
  while (true) {
    c = fgetc(stdin);
    if (c == EOF || c == '\n') {
      break;
    } else {
      sbuf_append_char(sb, (char)c);
    }
  }
  return sbuf_free_dup(sb);
}

//-------------------------------------------------------------
// Formatted output
//-------------------------------------------------------------

ic_public void ic_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  ic_vprintf(fmt, ap);
  va_end(ap);
}

ic_public void ic_vprintf(const char *fmt, va_list args) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->bbcode == NULL)
    return;
  bbcode_vprintf(env->bbcode, fmt, args);
}

ic_public void ic_print(const char *s) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->bbcode == NULL)
    return;
  bbcode_print(env->bbcode, s);
}

ic_public void ic_println(const char *s) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->bbcode == NULL)
    return;
  bbcode_println(env->bbcode, s);
}

ic_private ic_env_t *ic_get_env_for_profile(ic_profile_t *profile) {
  if (profile == NULL) {
    profile = ic_profile_current();
  }
  if (profile == NULL) {
    return NULL;
  }
  for (ic_profile_t *it = ic_profiles; it != NULL; it = it->next) {
    if (it == profile) {
      return profile->env;
    }
  }
  return NULL;
}

void ic_style_def_p(ic_profile_t *profile, const char *name, const char *fmt) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL || env->bbcode == NULL)
    return;
  bbcode_style_def(env->bbcode, name, fmt);
}

void ic_style_def(const char *name, const char *fmt) {
  ic_style_def_p(ic_profile_current(), name, fmt);
}

void ic_style_open_p(ic_profile_t *profile, const char *fmt) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL || env->bbcode == NULL)
    return;
  bbcode_style_open(env->bbcode, fmt);
}

void ic_style_open(const char *fmt) {
  ic_style_open_p(ic_profile_current(), fmt);
}

void ic_style_close_p(ic_profile_t *profile) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL || env->bbcode == NULL)
    return;
  bbcode_style_close(env->bbcode, NULL);
}

void ic_style_close(void) { ic_style_close_p(ic_profile_current()); }

//-------------------------------------------------------------
// Interface
//-------------------------------------------------------------

ic_public bool ic_async_stop(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return false;
  if (env->tty == NULL)
    return false;
  return tty_async_stop(env->tty);
}

/** Request a soft refresh of the current input line asynchronously. */
ic_public bool ic_request_refresh_async(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return false;
  if (env->tty == NULL || !env->edit_active)
    return false;
  env->refresh_request = true;
  if (!tty_async_complete(env->tty)) {
    env->refresh_request = false;
    return false;
  }
  return true;
}

ic_public bool ic_print_async(const char *s) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || s == NULL)
    return false;
  if (env->bbcode == NULL || env->term == NULL)
    return false;
  if (!env->edit_active || env->tty == NULL) {
    bbcode_print(env->bbcode, s);
    return true;
  }
  if (!ic_env_async_print_push(env, s))
    return false;
  env->refresh_request = true;
  if (!tty_async_complete(env->tty)) {
    env->refresh_request = false;
    return false;
  }
  return true;
}

ic_public bool ic_is_editline_active(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return false;
  return env->edit_active;
}

/** Request the completion menu to open on the next key processing cycle. */
ic_public bool ic_open_completion_menu(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return false;
  if (env->tty == NULL)
    return false;
  tty_code_pushback(env->tty, KEY_EVENT_COMPLETE);
  return true;
}

/** Request the completion menu asynchronously in a thread-safe way. */
ic_public bool ic_request_completion_menu_async(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return false;
  if (env->tty == NULL)
    return false;
  return tty_async_complete(env->tty);
}

static void set_prompt_marker(ic_env_t *env, const char *prompt_marker,
                              const char *cprompt_marker) {
  if (prompt_marker == NULL)
    prompt_marker = "> ";
  if (cprompt_marker == NULL)
    cprompt_marker = prompt_marker;
  mem_free(env->mem, env->prompt_marker);
  mem_free(env->mem, env->cprompt_marker);
  env->prompt_marker = mem_strdup(env->mem, prompt_marker);
  env->cprompt_marker = mem_strdup(env->mem, cprompt_marker);
}

ic_public const char *ic_get_prompt_marker(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  return env->prompt_marker;
}

ic_public const char *ic_get_continuation_prompt_marker(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  return env->cprompt_marker;
}

ic_public void ic_set_prompt_marker_p(ic_profile_t *profile,
                                      const char *prompt_marker,
                                      const char *cprompt_marker) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  set_prompt_marker(env, prompt_marker, cprompt_marker);
}

ic_public void ic_set_prompt_marker(const char *prompt_marker,
                                    const char *cprompt_marker) {
  ic_set_prompt_marker_p(ic_profile_current(), prompt_marker, cprompt_marker);
}

ic_public bool ic_enable_multiline_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->singleline_only;
  env->singleline_only = !enable;
  return !prev;
}

ic_public bool ic_enable_multiline(bool enable) {
  return ic_enable_multiline_p(ic_profile_current(), enable);
}

ic_public bool ic_enable_beep_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  return term_enable_beep(env->term, enable);
}

ic_public bool ic_enable_beep(bool enable) {
  return ic_enable_beep_p(ic_profile_current(), enable);
}

ic_public bool ic_enable_color_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  return term_enable_color(env->term, enable);
}

ic_public bool ic_enable_color(bool enable) {
  return ic_enable_color_p(ic_profile_current(), enable);
}

ic_public bool ic_enable_history_duplicates_p(ic_profile_t *profile,
                                              bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  return history_enable_duplicates(env->history, enable);
}

ic_public bool ic_enable_history_duplicates(bool enable) {
  return ic_enable_history_duplicates_p(ic_profile_current(), enable);
}

ic_public void ic_set_history_p(ic_profile_t *profile, const char *fname,
                                long max_entries) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  history_load_from(env->history, fname, max_entries);
}

ic_public void ic_set_history(const char *fname, long max_entries) {
  ic_set_history_p(ic_profile_current(), fname, max_entries);
}

ic_public void ic_history_remove_last_p(ic_profile_t *profile) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  history_remove_last(env->history);
}

ic_public void ic_history_remove_last(void) {
  ic_history_remove_last_p(ic_profile_current());
}

ic_public void ic_history_add_p(ic_profile_t *profile, const char *entry) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  history_push(env->history, entry);
}

ic_public void ic_history_add(const char *entry) {
  ic_history_add_p(ic_profile_current(), entry);
}

ic_public void ic_history_clear_p(ic_profile_t *profile) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  history_clear(env->history);
}

ic_public void ic_history_clear(void) {
  ic_history_clear_p(ic_profile_current());
}

ic_public long ic_history_count(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return 0;
  return (long)history_count(env->history);
}

ic_public const char *ic_history_get(long index) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  if (index < 0)
    return NULL;
  return history_get(env->history, (ssize_t)index);
}

ic_public bool ic_enable_auto_tab_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->complete_autotab;
  env->complete_autotab = enable;
  return prev;
}

ic_public bool ic_enable_auto_tab(bool enable) {
  return ic_enable_auto_tab_p(ic_profile_current(), enable);
}

ic_public bool ic_enable_completion_preview_p(ic_profile_t *profile,
                                              bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->complete_nopreview;
  env->complete_nopreview = !enable;
  return !prev;
}

ic_public bool ic_enable_completion_preview(bool enable) {
  return ic_enable_completion_preview_p(ic_profile_current(), enable);
}

/** Enable or disable automatic sorting of completion items. */
ic_public bool ic_enable_completion_sort_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->complete_nosort;
  env->complete_nosort = !enable;
  return !prev;
}

/** Enable or disable automatic sorting of completion items. */
ic_public bool ic_enable_completion_sort(bool enable) {
  return ic_enable_completion_sort_p(ic_profile_current(), enable);
}

/** Set the maximum number of completion items to generate/show. */
ic_public long ic_set_completion_max_items_p(ic_profile_t *profile,
                                             long max_items) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return 0;
  long prev = env->complete_max_items;
  if (max_items <= 0) {
    max_items = IC_MAX_COMPLETIONS_TO_SHOW;
  }
  if (max_items > IC_MAX_COMPLETIONS_TO_SHOW) {
    max_items = IC_MAX_COMPLETIONS_TO_SHOW;
  }
  env->complete_max_items = max_items;
  return prev;
}

/** Set the maximum number of completion items to generate/show. */
ic_public long ic_set_completion_max_items(long max_items) {
  return ic_set_completion_max_items_p(ic_profile_current(), max_items);
}

/** Set the maximum number of columns in the completion menu. */
ic_public long ic_set_completion_max_columns_p(ic_profile_t *profile,
                                               long max_columns) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return 0;
  long prev = env->complete_max_columns;
  if (max_columns <= 0) {
    max_columns = IC_DEFAULT_COMPLETION_MAX_COLUMNS;
  }
  if (max_columns < 1) {
    max_columns = 1;
  }
  env->complete_max_columns = max_columns;
  return prev;
}

/** Set the maximum number of columns in the completion menu. */
ic_public long ic_set_completion_max_columns(long max_columns) {
  return ic_set_completion_max_columns_p(ic_profile_current(), max_columns);
}

/** Set the maximum number of rows in the completion menu. */
ic_public long ic_set_completion_max_rows_p(ic_profile_t *profile,
                                            long max_rows) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return 0;
  long prev = env->complete_max_rows;
  if (max_rows == 0) {
    max_rows = IC_DEFAULT_COMPLETION_MAX_ROWS;
  }
  if (max_rows > 0 && max_rows < 3) {
    max_rows = 3;
  }
  env->complete_max_rows = max_rows;
  return prev;
}

/** Set the maximum number of rows in the completion menu. */
ic_public long ic_set_completion_max_rows(long max_rows) {
  return ic_set_completion_max_rows_p(ic_profile_current(), max_rows);
}

/** Enable or disable selecting completion items by number keys. */
ic_public bool ic_enable_completion_number_pick_p(ic_profile_t *profile,
                                                  bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->complete_number_pick;
  env->complete_number_pick = enable;
  return prev;
}

/** Enable or disable selecting completion items by number keys. */
ic_public bool ic_enable_completion_number_pick(bool enable) {
  return ic_enable_completion_number_pick_p(ic_profile_current(), enable);
}

/** Enable or disable automatic completion for single/prefix matches. */
ic_public bool ic_enable_completion_auto_fill_p(ic_profile_t *profile,
                                                bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->complete_auto_fill;
  env->complete_auto_fill = enable;
  return prev;
}

/** Enable or disable automatic completion for single/prefix matches. */
ic_public bool ic_enable_completion_auto_fill(bool enable) {
  return ic_enable_completion_auto_fill_p(ic_profile_current(), enable);
}

/** Set a custom indicator string for the selected completion item. */
ic_public void ic_set_completion_select_sign_p(ic_profile_t *profile,
                                               const char *sign) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  mem_free(env->mem, env->complete_select_sign);
  env->complete_select_sign = NULL;
  if (sign != NULL && sign[0] != 0) {
    env->complete_select_sign = mem_strdup(env->mem, sign);
  }
}

/** Set a custom indicator string for the selected completion item. */
ic_public void ic_set_completion_select_sign(const char *sign) {
  ic_set_completion_select_sign_p(ic_profile_current(), sign);
}

/** Set an optional marker appended to the completion page info line. */
ic_public void ic_set_completion_page_marker_p(ic_profile_t *profile,
                                               const char *marker) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  mem_free(env->mem, env->completion_page_marker);
  env->completion_page_marker = NULL;
  if (marker != NULL && marker[0] != 0) {
    env->completion_page_marker = mem_strdup(env->mem, marker);
  }
}

/** Set an optional marker appended to the completion page info line. */
ic_public void ic_set_completion_page_marker(const char *marker) {
  ic_set_completion_page_marker_p(ic_profile_current(), marker);
}

ic_public bool ic_enable_multiline_indent_p(ic_profile_t *profile,
                                            bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->no_multiline_indent;
  env->no_multiline_indent = !enable;
  return !prev;
}

ic_public bool ic_enable_multiline_indent(bool enable) {
  return ic_enable_multiline_indent_p(ic_profile_current(), enable);
}

/** Set the fixed line prefix used on continuation lines. */
ic_public void ic_set_line_prefix_p(ic_profile_t *profile, const char *prefix) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  mem_free(env->mem, env->line_prefix);
  if (prefix == NULL)
    prefix = "";
  env->line_prefix = mem_strdup(env->mem, prefix);
}

/** Set the fixed line prefix used on continuation lines. */
ic_public void ic_set_line_prefix(const char *prefix) {
  ic_set_line_prefix_p(ic_profile_current(), prefix);
}

/** Get the current line prefix (may be empty). */
ic_public const char *ic_get_line_prefix(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  return (env->line_prefix == NULL ? "" : env->line_prefix);
}

/** Set prompt text used by incremental history search (Ctrl+R). */
ic_public void ic_set_history_search_prompt_p(ic_profile_t *profile,
                                              const char *prompt_text) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  mem_free(env->mem, env->history_search_prompt);
  if (prompt_text == NULL || prompt_text[0] == 0) {
    prompt_text = "history search";
  }
  env->history_search_prompt = mem_strdup(env->mem, prompt_text);
}

/** Set prompt text used by incremental history search (Ctrl+R). */
ic_public void ic_set_history_search_prompt(const char *prompt_text) {
  ic_set_history_search_prompt_p(ic_profile_current(), prompt_text);
}

ic_public bool ic_enable_hint_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->no_hint;
  env->no_hint = !enable;
  return !prev;
}

ic_public bool ic_enable_hint(bool enable) {
  return ic_enable_hint_p(ic_profile_current(), enable);
}

ic_public long ic_set_hint_delay_p(ic_profile_t *profile, long delay_ms) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  long prev = env->hint_delay;
  env->hint_delay = (delay_ms < 0 ? 0 : (delay_ms > 5000 ? 5000 : delay_ms));
  return prev;
}

ic_public long ic_set_hint_delay(long delay_ms) {
  return ic_set_hint_delay_p(ic_profile_current(), delay_ms);
}

/** Set delay before running hint completion search. */
ic_public long ic_set_hint_search_delay_p(ic_profile_t *profile,
                                          long delay_ms) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  long prev = env->hint_search_delay;
  env->hint_search_delay =
      (delay_ms < 0 ? 0 : (delay_ms > 5000 ? 5000 : delay_ms));
  return prev;
}

/** Set delay before running hint completion search. */
ic_public long ic_set_hint_search_delay(long delay_ms) {
  return ic_set_hint_search_delay_p(ic_profile_current(), delay_ms);
}

ic_public void ic_set_tty_esc_delay_p(ic_profile_t *profile,
                                      long initial_delay_ms,
                                      long followup_delay_ms) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  if (env->tty == NULL)
    return;
  tty_set_esc_delay(env->tty, initial_delay_ms, followup_delay_ms);
}

ic_public void ic_set_tty_esc_delay(long initial_delay_ms,
                                    long followup_delay_ms) {
  ic_set_tty_esc_delay_p(ic_profile_current(), initial_delay_ms,
                         followup_delay_ms);
}

ic_public bool ic_enable_highlight_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->no_highlight;
  env->no_highlight = !enable;
  return !prev;
}

ic_public bool ic_enable_highlight(bool enable) {
  return ic_enable_highlight_p(ic_profile_current(), enable);
}

ic_public long ic_set_highlight_delay_p(ic_profile_t *profile, long delay_ms) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return 0;
  long prev = env->highlight_delay;
  env->highlight_delay =
      (delay_ms < 0 ? 0 : (delay_ms > 5000 ? 5000 : delay_ms));
  return prev;
}

ic_public long ic_set_highlight_delay(long delay_ms) {
  return ic_set_highlight_delay_p(ic_profile_current(), delay_ms);
}

ic_public bool ic_enable_inline_help_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->no_help;
  env->no_help = !enable;
  return !prev;
}

ic_public bool ic_enable_inline_help(bool enable) {
  return ic_enable_inline_help_p(ic_profile_current(), enable);
}

ic_public bool ic_enable_brace_matching_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->no_bracematch;
  env->no_bracematch = !enable;
  return !prev;
}

ic_public bool ic_enable_brace_matching(bool enable) {
  return ic_enable_brace_matching_p(ic_profile_current(), enable);
}

ic_public void ic_set_matching_braces_p(ic_profile_t *profile,
                                        const char *brace_pairs) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  mem_free(env->mem, env->match_braces);
  env->match_braces = NULL;
  if (brace_pairs != NULL) {
    ssize_t len = ic_strlen(brace_pairs);
    if (len > 0 && (len % 2) == 0) {
      env->match_braces = mem_strdup(env->mem, brace_pairs);
    }
  }
}

ic_public void ic_set_matching_braces(const char *brace_pairs) {
  ic_set_matching_braces_p(ic_profile_current(), brace_pairs);
}

ic_public bool ic_enable_brace_insertion_p(ic_profile_t *profile, bool enable) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  bool prev = env->no_autobrace;
  env->no_autobrace = !enable;
  return !prev;
}

ic_public bool ic_enable_brace_insertion(bool enable) {
  return ic_enable_brace_insertion_p(ic_profile_current(), enable);
}

ic_public void ic_set_insertion_braces_p(ic_profile_t *profile,
                                         const char *brace_pairs) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  mem_free(env->mem, env->auto_braces);
  env->auto_braces = NULL;
  if (brace_pairs != NULL) {
    ssize_t len = ic_strlen(brace_pairs);
    if (len > 0 && (len % 2) == 0) {
      env->auto_braces = mem_strdup(env->mem, brace_pairs);
    }
  }
}

ic_private const char *ic_env_get_match_braces(ic_env_t *env) {
  return (env->match_braces == NULL ? "()[]{}" : env->match_braces);
}

ic_private const char *ic_env_get_auto_braces(ic_env_t *env) {
  return (env->auto_braces == NULL ? "()[]{}\"\"''" : env->auto_braces);
}

ic_public void ic_set_insertion_braces(const char *brace_pairs) {
  ic_set_insertion_braces_p(ic_profile_current(), brace_pairs);
}

ic_public void ic_set_default_highlighter_p(ic_profile_t *profile,
                                            ic_highlight_fun_t *highlighter,
                                            void *arg) {
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return;
  env->highlighter = highlighter;
  env->highlighter_arg = arg;
}

ic_public bool ic_get_default_highlighter_p(ic_profile_t *profile,
                                            ic_highlight_fun_t **highlighter,
                                            void **arg) {
  if (highlighter != NULL)
    *highlighter = NULL;
  if (arg != NULL)
    *arg = NULL;
  ic_env_t *env = ic_get_env_for_profile(profile);
  if (env == NULL)
    return false;
  if (highlighter != NULL)
    *highlighter = env->highlighter;
  if (arg != NULL)
    *arg = env->highlighter_arg;
  return true;
}

ic_public void ic_set_default_highlighter(ic_highlight_fun_t *highlighter,
                                          void *arg) {
  ic_set_default_highlighter_p(ic_profile_current(), highlighter, arg);
}

ic_public void ic_free(void *p) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  mem_free(env->mem, p);
}

ic_public void *ic_malloc(size_t sz) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  return mem_malloc(env->mem, to_ssize_t(sz));
}

ic_public const char *ic_strdup(const char *s) {
  if (s == NULL)
    return NULL;
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return NULL;
  ssize_t len = ic_strlen(s);
  char *p = mem_malloc_tp_n(env->mem, char, len + 1);
  if (p == NULL)
    return NULL;
  ic_memcpy(p, s, len);
  p[len] = 0;
  return p;
}

//-------------------------------------------------------------
// Terminal
//-------------------------------------------------------------

ic_public void ic_term_init(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_start_raw(env->term);
}

ic_public void ic_term_done(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_end_raw(env->term, false);
}

ic_public void ic_term_flush(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_flush(env->term);
}

ic_public void ic_term_set_cursor_visible(bool visible) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_write(env->term, visible ? "\x1b[?25h" : "\x1b[?25l");
  term_flush(env->term);
}

ic_public void ic_term_write(const char *s) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_write(env->term, s);
}

ic_public void ic_term_write_bbcode(const char *s) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->bbcode == NULL)
    return;
  bbcode_print(env->bbcode, s);
}

ic_public void ic_term_writeln(const char *s) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_writeln(env->term, s);
}

ic_public void ic_term_writef(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  ic_term_vwritef(fmt, ap);
  va_end(ap);
}

ic_public void ic_term_vwritef(const char *fmt, va_list args) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_vwritef(env->term, fmt, args);
}

ic_public void ic_term_reset(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL)
    return;
  term_attr_reset(env->term);
}

ic_public void ic_term_style(const char *style) {
  ic_env_t *env = ic_get_env();
  if (env == NULL)
    return;
  if (env->term == NULL || env->bbcode == NULL)
    return;
  term_set_attr(env->term, bbcode_style(env->bbcode, style));
}

ic_public int ic_term_get_color_bits(void) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->term == NULL)
    return 4;
  return term_get_color_bits(env->term);
}

ic_public void ic_term_bold(bool enable) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->term == NULL)
    return;
  term_bold(env->term, enable);
}

ic_public void ic_term_underline(bool enable) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->term == NULL)
    return;
  term_underline(env->term, enable);
}

ic_public void ic_term_italic(bool enable) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->term == NULL)
    return;
  term_italic(env->term, enable);
}

ic_public void ic_term_reverse(bool enable) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->term == NULL)
    return;
  term_reverse(env->term, enable);
}

ic_public void ic_term_color_ansi(bool foreground, int ansi_color) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->term == NULL)
    return;
  ic_color_t color = color_from_ansi256(ansi_color);
  if (foreground) {
    term_color(env->term, color);
  } else {
    term_bgcolor(env->term, color);
  }
}

ic_public void ic_term_color_rgb(bool foreground, uint32_t hcolor) {
  ic_env_t *env = ic_get_env();
  if (env == NULL || env->term == NULL)
    return;
  ic_color_t color = ic_rgb(hcolor);
  if (foreground) {
    term_color(env->term, color);
  } else {
    term_bgcolor(env->term, color);
  }
}

//-------------------------------------------------------------
// Initialize
//-------------------------------------------------------------

static void ic_atexit(void);
static void ic_register_atexit_(void);
static void ic_ensure_default_profile_(void);
static ic_profile_t *ic_profile_create_internal_(ic_malloc_fun_t *_malloc,
                                                 ic_realloc_fun_t *_realloc,
                                                 ic_free_fun_t *_free);
static bool ic_profile_contains_(const ic_profile_t *profile);
static bool ic_profile_unregister_(ic_profile_t *profile);
static void ic_profile_set_name_internal_(ic_profile_t *profile,
                                          const char *name);

static void ic_env_free(ic_env_t *env) {
  if (env == NULL)
    return;
  char *async_msg = NULL;
  while ((async_msg = ic_env_async_print_pop(env)) != NULL) {
    mem_free(env->mem, async_msg);
  }
  history_save(env->history);
  history_free(env->history);
  completions_free(env->completions);
  bbcode_free(env->bbcode);
  term_free(env->term);
  tty_free(env->tty);
  mem_free(env->mem, env->line_prefix);
  mem_free(env->mem, env->history_search_prompt);
  mem_free(env->mem, env->cprompt_marker);
  mem_free(env->mem, env->prompt_marker);
  mem_free(env->mem, env->match_braces);
  mem_free(env->mem, env->auto_braces);
  mem_free(env->mem, env->complete_select_sign);
  mem_free(env->mem, env->completion_page_marker);
  env->prompt_marker = NULL;

  // and deallocate ourselves
  alloc_t *mem = env->mem;
  mem_free(mem, env);

  // and finally the custom memory allocation structure
  mem_free(mem, mem);
}

static ic_env_t *ic_env_create(ic_malloc_fun_t *_malloc,
                               ic_realloc_fun_t *_realloc,
                               ic_free_fun_t *_free) {
  if (_malloc == NULL)
    _malloc = &malloc;
  if (_realloc == NULL)
    _realloc = &realloc;
  if (_free == NULL)
    _free = &free;
  // allocate
  alloc_t *mem = (alloc_t *)_malloc(sizeof(alloc_t));
  if (mem == NULL)
    return NULL;
  mem->malloc = _malloc;
  mem->realloc = _realloc;
  mem->free = _free;
  ic_env_t *env = mem_zalloc_tp(mem, ic_env_t);
  if (env == NULL) {
    mem->free(mem);
    return NULL;
  }
  env->mem = mem;

  // Initialize
  env->tty = tty_new(env->mem, -1); // can return NULL
  env->term = term_new(env->mem, env->tty, false, false, -1);
  env->history = history_new(env->mem);
  env->completions = completions_new(env->mem);
  env->bbcode = bbcode_new(env->mem, env->term);
  env->hint_delay = 400;
  env->hint_search_delay = 0;
  env->highlight_delay = 0;
  env->complete_max_items = IC_MAX_COMPLETIONS_TO_SHOW;
  env->complete_max_columns = IC_DEFAULT_COMPLETION_MAX_COLUMNS;
  env->complete_max_rows = IC_DEFAULT_COMPLETION_MAX_ROWS;
  env->complete_number_pick = true;
  env->complete_auto_fill = true;
  env->complete_select_sign = NULL;
  env->line_prefix = mem_strdup(env->mem, "");
  env->history_search_prompt = mem_strdup(env->mem, "history search");

  if (env->tty == NULL || env->term == NULL || env->completions == NULL ||
      env->history == NULL || env->bbcode == NULL ||
      !term_is_interactive(env->term)) {
    env->noedit = true;
  }
  env->multiline_eol = '\\';

  bbcode_style_def(env->bbcode, "ic-prompt", "ansi-green");
  bbcode_style_def(env->bbcode, "ic-info", "ansi-darkgray");
  bbcode_style_def(env->bbcode, "ic-comp-order", "ansi-darkgray");
  bbcode_style_def(env->bbcode, "ic-comp-help", "ansi-darkgray");
  bbcode_style_def(env->bbcode, "ic-diminish", "ansi-lightgray");
  bbcode_style_def(env->bbcode, "ic-emphasis", "#ffffd7");
  bbcode_style_def(env->bbcode, "ic-hint", "ansi-darkgray");
  bbcode_style_def(env->bbcode, "ic-error", "#d70000");
  bbcode_style_def(env->bbcode, "ic-bracematch",
                   "ansi-white"); //  color = #F7DC6F" );

  bbcode_style_def(env->bbcode, "keyword", "#569cd6");
  bbcode_style_def(env->bbcode, "control", "#c586c0");
  bbcode_style_def(env->bbcode, "number", "#b5cea8");
  bbcode_style_def(env->bbcode, "string", "#ce9178");
  bbcode_style_def(env->bbcode, "comment", "#6A9955");
  bbcode_style_def(env->bbcode, "type", "darkcyan");
  bbcode_style_def(env->bbcode, "constant", "#569cd6");

  set_prompt_marker(env, NULL, NULL);
  return env;
}

/**
 * @brief Register a process-exit cleanup once.
 */
static void ic_register_atexit_(void) {
  if (!ic_atexit_registered) {
    atexit(&ic_atexit);
    ic_atexit_registered = true;
  }
}

/**
 * @brief Create a profile and its environment.
 */
static ic_profile_t *ic_profile_create_internal_(ic_malloc_fun_t *_malloc,
                                                 ic_realloc_fun_t *_realloc,
                                                 ic_free_fun_t *_free) {
  ic_env_t *env = ic_env_create(_malloc, _realloc, _free);
  if (env == NULL) {
    return NULL;
  }
  ic_profile_t *profile = (ic_profile_t *)malloc(sizeof(ic_profile_t));
  if (profile == NULL) {
    ic_env_free(env);
    return NULL;
  }
  profile->env = env;
  profile->name[0] = 0;
  profile->next = NULL;
  return profile;
}

static void ic_profile_set_name_internal_(ic_profile_t *profile,
                                          const char *name) {
  if (profile == NULL) {
    return;
  }
  if (name == NULL) {
    name = "";
  }
  if (!ic_strncpy(profile->name, (ssize_t)(sizeof(profile->name)), name,
                  (ssize_t)(sizeof(profile->name) - 1))) {
    profile->name[sizeof(profile->name) - 1] = 0;
  }
}

/**
 * @brief Return true when profile belongs to the global profile list.
 */
static bool ic_profile_contains_(const ic_profile_t *profile) {
  if (profile == NULL) {
    return false;
  }
  for (const ic_profile_t *it = ic_profiles; it != NULL; it = it->next) {
    if (it == profile) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Remove profile from the global profile list.
 */
static bool ic_profile_unregister_(ic_profile_t *profile) {
  if (profile == NULL) {
    return false;
  }
  ic_profile_t *prev = NULL;
  ic_profile_t *it = ic_profiles;
  while (it != NULL) {
    if (it == profile) {
      if (prev == NULL) {
        ic_profiles = it->next;
      } else {
        prev->next = it->next;
      }
      it->next = NULL;
      return true;
    }
    prev = it;
    it = it->next;
  }
  return false;
}

/**
 * @brief Ensure there is always a default profile for backward-compatible APIs.
 */
static void ic_ensure_default_profile_(void) {
  if (ic_default_profile != NULL) {
    if (ic_current_profile == NULL) {
      ic_current_profile = ic_default_profile;
    }
    return;
  }

  ic_profile_t *profile = ic_profile_create_internal_(
      ic_custom_malloc, ic_custom_realloc, ic_custom_free);
  if (profile == NULL) {
    return;
  }
  profile->next = ic_profiles;
  ic_profiles = profile;
  ic_default_profile = profile;
  ic_current_profile = profile;
  ic_profile_set_name_internal_(profile, "default");
  ic_register_atexit_();
}

/**
 * @brief Free all profiles at process exit.
 */
static void ic_atexit(void) {
  ic_profile_t *it = ic_profiles;
  while (it != NULL) {
    ic_profile_t *next = it->next;
    ic_env_free(it->env);
    free(it);
    it = next;
  }
  ic_profiles = NULL;
  ic_current_profile = NULL;
  ic_default_profile = NULL;
}

/**
 * @brief Create a new runtime-only profile with isolated Isocline state.
 */
ic_public ic_profile_t *ic_profile_new(void) {
  ic_profile_t *profile = ic_profile_create_internal_(
      ic_custom_malloc, ic_custom_realloc, ic_custom_free);
  if (profile == NULL) {
    return NULL;
  }

  profile->next = ic_profiles;
  ic_profiles = profile;
  {
    char pname[64];
    ic_profile_seq++;
    snprintf(pname, sizeof(pname), "profile-%ld", ic_profile_seq);
    ic_profile_set_name_internal_(profile, pname);
  }
  if (ic_default_profile == NULL) {
    ic_default_profile = profile;
    ic_profile_set_name_internal_(profile, "default");
  }
  if (ic_current_profile == NULL) {
    ic_current_profile = profile;
  }
  ic_register_atexit_();
  return profile;
}

/**
 * @brief Destroy a profile and release its isolated Isocline state.
 */
ic_public void ic_profile_free(ic_profile_t *profile) {
  if (profile == NULL) {
    return;
  }
  if (!ic_profile_unregister_(profile)) {
    return;
  }

  if (ic_current_profile == profile) {
    ic_current_profile =
        (ic_default_profile != profile ? ic_default_profile : NULL);
    if (ic_current_profile == NULL) {
      ic_current_profile = ic_profiles;
    }
  }
  if (ic_default_profile == profile) {
    ic_default_profile = ic_profiles;
  }

  ic_env_free(profile->env);
  free(profile);

  if (ic_current_profile == NULL) {
    ic_ensure_default_profile_();
  }
}

/**
 * @brief Switch active profile used by all `ic_*` APIs.
 */
ic_public bool ic_profile_use(ic_profile_t *profile) {
  if (profile == NULL) {
    ic_ensure_default_profile_();
    if (ic_default_profile == NULL) {
      return false;
    }
    ic_current_profile = ic_default_profile;
    return true;
  }
  if (!ic_profile_contains_(profile)) {
    return false;
  }
  ic_current_profile = profile;
  return true;
}

/**
 * @brief Get current active profile.
 */
ic_public ic_profile_t *ic_profile_current(void) {
  ic_ensure_default_profile_();
  return ic_current_profile;
}

ic_public void ic_profile_set_name(ic_profile_t *profile, const char *name) {
  if (profile == NULL) {
    return;
  }
  if (!ic_profile_contains_(profile)) {
    return;
  }
  ic_profile_set_name_internal_(profile, name);
}

ic_public const char *ic_profile_get_name(const ic_profile_t *profile) {
  if (profile == NULL) {
    return "";
  }
  return profile->name;
}

/**
 * @brief Get active environment for legacy global API calls.
 */
ic_private ic_env_t *ic_get_env(void) { return ic_get_env_for_profile(NULL); }

/**
 * @brief Set custom allocators for all subsequently created profiles.
 */
ic_public void ic_init_custom_alloc(ic_malloc_fun_t *_malloc,
                                    ic_realloc_fun_t *_realloc,
                                    ic_free_fun_t *_free) {
  assert(ic_profiles == NULL);
  if (ic_profiles != NULL) {
    return;
  }
  ic_custom_malloc = _malloc;
  ic_custom_realloc = _realloc;
  ic_custom_free = _free;
  ic_ensure_default_profile_();
}

/**
 * @brief Deprecated compatibility alias.
 */
ic_public void ic_init_custom_malloc(ic_malloc_fun_t *_malloc,
                                     ic_realloc_fun_t *_realloc,
                                     ic_free_fun_t *_free) {
  ic_init_custom_alloc(_malloc, _realloc, _free);
}
