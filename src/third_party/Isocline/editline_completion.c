/* ----------------------------------------------------------------------------
  Copyright (c) 2021, Daan Leijen
  This is free software; you can redistribute it and/or modify it
  under the terms of the MIT License. A copy of the license can be
  found in the "LICENSE" file at the root of this distribution.
-----------------------------------------------------------------------------*/

//-------------------------------------------------------------
// Completion menu: this file is included in editline.c
//-------------------------------------------------------------

// return true if anything changed
static bool edit_complete(ic_env_t* env, editor_t* eb, ssize_t idx) {
  editor_start_modify(eb);
  ssize_t newpos = completions_apply(env->completions, idx, eb->input, eb->pos);
  if (newpos < 0) {
    editor_undo_restore(eb,false);
    return false;
  }
  eb->pos = newpos;
  edit_refresh(env,eb);  
  return true;
}

static bool edit_complete_longest_prefix(ic_env_t* env, editor_t* eb ) {
  editor_start_modify(eb);
  ssize_t newpos = completions_apply_longest_prefix( env->completions, eb->input, eb->pos );
  if (newpos < 0) {
    editor_undo_restore(eb,false);
    return false;
  }
  eb->pos = newpos;
  edit_refresh(env,eb);
  return true;
}

ic_private void sbuf_append_tagged( stringbuf_t* sb, const char* tag, const char* content ) {
  sbuf_appendf(sb, "[%s]", tag);  
  sbuf_append(sb,content);
  sbuf_append(sb,"[/]");
}

/** Return the number of decimal digits needed to display a positive value. */
static ssize_t edit_completion_digits(ssize_t value) {
  if (value <= 0) return 1;
  ssize_t digits = 1;
  while (value >= 10) {
    value /= 10;
    digits++;
  }
  return digits;
}

/** Append `count` spaces to the string buffer. */
static void sbuf_append_spaces(stringbuf_t* sb, ssize_t count) {
  while (count > 0) {
    sbuf_append_char(sb, ' ');
    count--;
  }
}

/** Measure visible display/help widths for one completion index. */
static void edit_completion_item_widths(ic_env_t* env, ssize_t idx,
                                        ssize_t* out_name_width,
                                        ssize_t* out_help_width) {
  if (out_name_width != NULL) *out_name_width = 0;
  if (out_help_width != NULL) *out_help_width = 0;
  const char* help = NULL;
  const char* display = completions_get_display(env->completions, idx, &help);
  if (display == NULL) return;
  if (out_name_width != NULL) {
    *out_name_width = bbcode_column_width(env->bbcode, display);
  }
  if (out_help_width != NULL && help != NULL && help[0] != 0) {
    *out_help_width = bbcode_column_width(env->bbcode, help);
  }
}

/** Append one completion entry with aligned display/help columns and numbering. */
static void editor_append_completion(ic_env_t* env, editor_t* eb, ssize_t idx,
                                     ssize_t number_width, ssize_t number, const char* indicator,
                                     ssize_t display_width, ssize_t help_width, bool selected ) {
  const char* help = NULL;
  const char* display = completions_get_display(env->completions, idx, &help);
  if (display == NULL) return;
  if (indicator == NULL) indicator = "";
  sbuf_append(eb->extra, "[ic-comp-order]");
  sbuf_append(eb->extra, indicator);
  sbuf_appendf(eb->extra, "%*zd ", (int)number_width, number);
  sbuf_append(eb->extra, "[/]");
  if (selected) {
    sbuf_append(eb->extra, "[ic-emphasis]");
  }
  sbuf_append(eb->extra, display);
  if (selected) { sbuf_append(eb->extra,"[/ic-emphasis]"); }

  const ssize_t display_used = bbcode_column_width(env->bbcode, display);
  if (display_width > display_used) {
    sbuf_append_spaces(eb->extra, display_width - display_used);
  }

  const bool has_help = (help != NULL && help[0] != 0);
  if (help_width > 0 || has_help) {
    sbuf_append(eb->extra, "  ");
    ssize_t used_help_width = 0;
    if (has_help) {
      sbuf_append_tagged(eb->extra, "ic-comp-help", help );
      used_help_width = bbcode_column_width(env->bbcode, help);
    }
    const ssize_t target_help_width = (help_width > 0 ? help_width : used_help_width);
    if (target_help_width > used_help_width) {
      sbuf_append_spaces(eb->extra, target_help_width - used_help_width);
    }
  }
}

static ssize_t edit_completions_max_width( ic_env_t* env, ssize_t count ) {
  ssize_t max_width = 0;
  for( ssize_t i = 0; i < count; i++) {
    const char* help = NULL;
    ssize_t w = bbcode_column_width(env->bbcode, completions_get_display(env->completions, i, &help));
    if (help != NULL) {
      w += 2 + bbcode_column_width(env->bbcode, help);
    }
    if (w > max_width) {
      max_width = w;
    }
  }
  return max_width;
}

static void edit_completion_menu(ic_env_t* env, editor_t* eb, bool more_available) {
  ssize_t count = completions_count(env->completions);
  ssize_t twidth = term_get_width(env->term) - 1;
  if (twidth < 20) twidth = 20;

  long max_items = env->complete_max_items;
  if (max_items <= 0) max_items = IC_MAX_COMPLETIONS_TO_SHOW;
  if (max_items > IC_MAX_COMPLETIONS_TO_SHOW) max_items = IC_MAX_COMPLETIONS_TO_SHOW;

  const ssize_t default_max_rows = 9;
  ssize_t max_rows = env->complete_max_rows;
  if (max_rows == 0) max_rows = default_max_rows;
  if (max_rows > 0 && max_rows < 3) max_rows = 3;
  const char* indicator_on = env->complete_select_sign;
  if (indicator_on == NULL || indicator_on[0] == 0) {
    indicator_on = (tty_is_utf8(env->tty) ? "\xE2\x86\x92" : "*");
  }
  ssize_t indicator_width = bbcode_column_width(env->bbcode, indicator_on);
  if (indicator_width < 1) indicator_width = 1;
  char indicator_off_buf[32];
  char* indicator_off = indicator_off_buf;
  if (indicator_width < (ssize_t)sizeof(indicator_off_buf)) {
    ic_memset(indicator_off_buf, ' ', indicator_width);
    indicator_off_buf[indicator_width] = 0;
  }
  else {
    indicator_off = mem_malloc_tp_n(env->mem, char, indicator_width + 1);
    if (indicator_off != NULL) {
      ic_memset(indicator_off, ' ', indicator_width);
      indicator_off[indicator_width] = 0;
    }
    else {
      indicator_off = indicator_off_buf;
      indicator_off_buf[0] = ' ';
      indicator_off_buf[1] = 0;
      indicator_width = 1;
    }
  }

  ssize_t columns = 1;
  ssize_t rows = 1;
  ssize_t number_width = 1;
  ssize_t items_per_page = 1;
  ssize_t page_count = 1;
  ssize_t selected = (env->complete_nopreview ? 0 : -1); // select first or none
  ssize_t page = (selected >= 0 ? selected : 0);
  code_t c = 0;

layout:
  if (count <= 0) {
    completions_clear(env->completions);
    edit_refresh(env,eb);
    c = 0;
    goto done;
  }
  ssize_t max_columns = env->complete_max_columns;
  if (max_columns <= 0) max_columns = 1;
  if (max_columns > count) max_columns = count;
  ssize_t use_max_rows = max_rows;
  if (use_max_rows < 0) use_max_rows = count;
  ssize_t max_item_width = edit_completions_max_width(env, count);
  columns = 1;
  rows = 1;
  number_width = 1;
  for (ssize_t col_count = max_columns; col_count >= 1; col_count--) {
    ssize_t r = (count + col_count - 1) / col_count;
    if (r > use_max_rows) r = use_max_rows;
    if (r < 1) r = 1;
    ssize_t this_items_per_page = r * col_count;
    ssize_t num_width = edit_completion_digits(this_items_per_page);
    ssize_t prefix_width = num_width + indicator_width + 1;
    ssize_t cw = prefix_width + max_item_width;
    ssize_t total_width = col_count * cw + (col_count - 1) * 2;
    if (total_width <= twidth || col_count == 1) {
      columns = col_count;
      rows = r;
      number_width = num_width;
      break;
    }
  }
  items_per_page = rows * columns;
  if (items_per_page < 1) items_per_page = 1;
  page_count = (count + items_per_page - 1) / items_per_page;
  if (page_count < 1) page_count = 1;
  if (selected >= count) selected = count - 1;
  if (selected >= 0) {
    page = selected / items_per_page;
  }
  if (page < 0) page = 0;
  if (page >= page_count) page = page_count - 1;

again:
  ssize_t page_start = page * items_per_page;
  ssize_t page_end = page_start + items_per_page;
  if (page_end > count) page_end = count;
  ssize_t items_on_page = page_end - page_start;
  ssize_t rows_page = rows;
  ssize_t needed_rows = (items_on_page + columns - 1) / columns;
  if (needed_rows < rows_page) rows_page = needed_rows;
  if (rows_page < 1) rows_page = 1;

  ssize_t* col_display_widths = mem_malloc_tp_n(env->mem, ssize_t, columns);
  ssize_t* col_help_widths = mem_malloc_tp_n(env->mem, ssize_t, columns);
  if (col_display_widths == NULL || col_help_widths == NULL) {
    if (col_display_widths != NULL) mem_free(env->mem, col_display_widths);
    if (col_help_widths != NULL) mem_free(env->mem, col_help_widths);
    col_display_widths = NULL;
    col_help_widths = NULL;
  }
  if (col_display_widths != NULL && col_help_widths != NULL) {
    for (ssize_t col = 0; col < columns; col++) {
      col_display_widths[col] = 0;
      col_help_widths[col] = 0;
      for (ssize_t row = 0; row < rows_page; row++) {
        ssize_t idx = page_start + row + col * rows_page;
        if (idx >= page_end) break;
        ssize_t name_width = 0;
        ssize_t help_width = 0;
        edit_completion_item_widths(env, idx, &name_width, &help_width);
        if (name_width > col_display_widths[col]) col_display_widths[col] = name_width;
        if (help_width > col_help_widths[col]) col_help_widths[col] = help_width;
      }
    }
  }

  sbuf_clear(eb->extra);
  for (ssize_t row = 0; row < rows_page; row++) {
    if (row > 0) sbuf_append(eb->extra, "\n");
    for (ssize_t col = 0; col < columns; col++) {
      ssize_t idx = page_start + row + col * rows_page;
      if (idx >= page_end) break;
      if (col > 0) sbuf_append(eb->extra, "  ");
      ssize_t number = (idx - page_start) + 1;
      const char* indicator = (idx == selected ? indicator_on : indicator_off);
      const ssize_t display_width =
          (col_display_widths != NULL ? col_display_widths[col] : 0);
      const ssize_t help_width =
          (col_help_widths != NULL ? col_help_widths[col] : 0);
      editor_append_completion(env, eb, idx, number_width, number, indicator,
                               display_width, help_width, (idx == selected));
    }
  }
  if (col_display_widths != NULL) mem_free(env->mem, col_display_widths);
  if (col_help_widths != NULL) mem_free(env->mem, col_help_widths);
  if (page_count > 1 ||
      (env->completion_page_marker != NULL &&
       env->completion_page_marker[0] != 0)) {
    sbuf_appendf(eb->extra, "\n[ic-info]Page %zd/%zd", page + 1, page_count);
    if (env->completion_page_marker != NULL &&
        env->completion_page_marker[0] != 0) {
      sbuf_appendf(eb->extra, " %s", env->completion_page_marker);
    }
    sbuf_append(eb->extra, "[/]");
  }
  if (more_available) {
    sbuf_appendf(eb->extra, "\n[ic-info](showing first %zd completions)[/]", count);
  }
  if (!env->complete_nopreview && selected >= page_start && selected < page_end) {
    edit_complete(env,eb,selected);
    editor_undo_restore(eb,false);
  }
  else {
    edit_refresh(env, eb);
  }

  // read here; if not a valid key, push it back and return to main event loop
  c = tty_read(env->tty);
  if (tty_term_resize_event(env->tty)) {
    edit_resize(env, eb);
  }
  sbuf_clear(eb->extra);

  if (c == KEY_EVENT_COMPLETE && env->refresh_request) {
    edit_process_refresh_request(env, eb);
    c = 0;
    goto done;
  }
  
  // direct selection?
  if (env->complete_number_pick && c >= '1' && c <= '9') {
    ssize_t i = (c - '1');
    if (i < items_on_page) {
      selected = page_start + i;
      c = KEY_ENTER;
    }
  }

  // process commands
  if (c == KEY_TAB || c == KEY_SHIFT_TAB) {
    if (count <= 0) {
      completions_clear(env->completions);
      edit_refresh(env,eb);
      c = 0;
    }
    else if (count == 1) {
      c = 0;
      edit_complete(env, eb, 0);
    }
    else if (edit_complete_longest_prefix(env, eb)) {
      c = 0;
    }
    else if (page_count > 1) {
      ssize_t sel_offset =
          (selected >= page_start && selected < page_end ? selected - page_start
                                                          : -1);
      if (c == KEY_SHIFT_TAB) {
        page = (page > 0 ? page - 1 : page_count - 1);
      } else {
        page = (page + 1 < page_count ? page + 1 : 0);
      }
      if (sel_offset >= 0) {
        ssize_t new_start = page * items_per_page;
        ssize_t new_end = new_start + items_per_page;
        if (new_end > count) new_end = count;
        if (sel_offset >= new_end - new_start)
          sel_offset = new_end - new_start - 1;
        selected = (sel_offset >= 0 ? new_start + sel_offset : -1);
      }
      goto again;
    } else {
      goto again;
    }
  }
  else if (c == KEY_LEFT || c == KEY_RIGHT) {
    if (c == KEY_RIGHT) {
      edit_cursor_right(env, eb);
    }
    else {
      edit_cursor_left(env, eb);
    }
    count = completions_generate(env, env->completions, sbuf_string(eb->input), eb->pos, max_items, IC_COMPLETION_SOURCE_TAB);
    more_available = (count >= max_items);
    if (!env->complete_nosort) {
      completions_sort(env->completions);
    }
    selected = (env->complete_nopreview ? 0 : -1);
    page = 0;
    goto layout;
  }
  else if (c == KEY_CTRL_LEFT || c == KEY_CTRL_RIGHT) {
    if (page_count > 0) {
      ssize_t sel_offset = (selected >= page_start && selected < page_end ? selected - page_start : -1);
      if (c == KEY_CTRL_RIGHT) {
        if (page + 1 < page_count) {
          page++;
        }
        else {
          page = 0;
        }
      }
      else {
        if (page > 0) {
          page--;
        }
        else {
          page = page_count - 1;
        }
      }
      if (sel_offset >= 0) {
        ssize_t new_start = page * items_per_page;
        ssize_t new_end = new_start + items_per_page;
        if (new_end > count) new_end = count;
        if (sel_offset >= new_end - new_start) sel_offset = new_end - new_start - 1;
        selected = (sel_offset >= 0 ? new_start + sel_offset : -1);
      }
    }
    goto again;
  }
  else if (c == KEY_DOWN || c == KEY_UP) {
    if (items_on_page > 0) {
      if (selected < page_start || selected >= page_end) {
        selected = (c == KEY_UP ? page_end - 1 : page_start);
      }
      else if (c == KEY_DOWN) {
        selected++;
        if (selected >= page_end) selected = page_start;
      }
      else {
        selected--;
        if (selected < page_start) selected = page_end - 1;
      }
      goto again;
    }
  }
  else if (c == KEY_F1) {
    edit_show_help(env, eb);
    goto again;
  }
  else if (c == KEY_ESC || c == KEY_BELL) {
    completions_clear(env->completions);
    edit_refresh(env,eb);
    c = 0; // ignore and return
  }
  else if (selected >= 0 && c == KEY_ENTER) {
    // select the current entry
    assert(selected < count);
    c = 0;
    edit_complete(env, eb, selected);
    if (env->complete_autotab) {
      tty_code_pushback(env->tty,KEY_EVENT_AUTOTAB); // immediately try to complete again        
    }
  }
  else {
    char chr = 0;
    unicode_t uchr = 0;
    bool is_text = false;
    if (code_is_ascii_char(c, &chr)) {
      is_text = true;
    }
    else if (code_is_unicode(c, &uchr) && !code_is_virt_key(c)) {
      is_text = true;
    }

    if (is_text) {
      // if a completion is selected, accept it and continue typing
      if (selected >= 0 && selected < count) {
        edit_complete(env, eb, selected);
      }
    }
    else if ((c == KEY_PAGEDOWN || c == KEY_LINEFEED) && count > items_per_page) {
      // show all completions
      c = 0;
      rowcol_t rc;
      edit_get_rowcol(env,eb,&rc);
      edit_clear(env,eb);
      edit_write_prompt(env,eb,0,false);
      term_writeln(env->term, "");
      for(ssize_t i = 0; i < count; i++) {
        const char* display = completions_get_display(env->completions, i, NULL);
        if (display != NULL) {
          bbcode_println(env->bbcode, display);
        }
      }
      if (more_available) {
        bbcode_println(env->bbcode, "[ic-info]... and more.[/]");
      }
      else {
        bbcode_printf(env->bbcode, "[ic-info](%zd possible completions)[/]\n", count );
      }
      for(ssize_t i = 0; i < rc.row+1; i++) {
        term_write(env->term, " \n");
      }
      eb->cur_rows = 0;
      edit_refresh(env,eb);
    }
    else {
      edit_refresh(env,eb);
    }
  }
done:
  if (indicator_off != indicator_off_buf) {
    mem_free(env->mem, indicator_off);
  }
  // done
  completions_clear(env->completions);
  if (c != 0) tty_code_pushback(env->tty,c);
}

static void edit_generate_completions(ic_env_t* env, editor_t* eb, bool autotab) {
  debug_msg( "edit: complete: %zd: %s\n", eb->pos, sbuf_string(eb->input) );
  if (eb->pos < 0) return;
  long max_items = env->complete_max_items;
  if (max_items <= 0) max_items = IC_MAX_COMPLETIONS_TO_SHOW;
  if (max_items > IC_MAX_COMPLETIONS_TO_SHOW) max_items = IC_MAX_COMPLETIONS_TO_SHOW;
  ssize_t count = completions_generate(env, env->completions, sbuf_string(eb->input), eb->pos, max_items, IC_COMPLETION_SOURCE_TAB);
  bool more_available = (count >= max_items);
  if (count <= 0) {
    // no completions: keep input unchanged
  }
  else if (count == 1) {
    // complete immediately for a single match
    if (edit_complete(env,eb,0 /*idx*/) && env->complete_autotab) {
      tty_code_pushback(env->tty,KEY_EVENT_AUTOTAB);
    }
  }
  else {
    //term_beep(env->term); 
    if (!autotab) {
      if (edit_complete_longest_prefix(env,eb)) {
        return;
      }
    }
    if (!env->complete_nosort) {
      completions_sort(env->completions);
    }
    edit_completion_menu( env, eb, more_available);    
  }
}
