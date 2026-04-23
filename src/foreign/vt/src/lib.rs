use std::cmp::{max, min};
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, GridCell};
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, NamedColor, Processor};

#[repr(C)]
pub struct AmsVtSnapshot {
    rows: i32,
    cols: i32,
    cursor_row: i32,
    cursor_col: i32,
    history_lines: u64,
    total_lines: u64,
    display_offset: u64,
    damage_serial: u64,
    rendered_main_rows: u64,
    in_alternate_screen: u8,
    cursor_visible: u8,
}

#[derive(Clone, Copy)]
struct AmsVtSize {
    rows: usize,
    cols: usize,
}

impl Dimensions for AmsVtSize {
    fn total_lines(&self) -> usize {
        self.rows
    }

    fn screen_lines(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.cols
    }
}

struct AmsVtEvents;

impl EventListener for AmsVtEvents {
    fn send_event(&self, _event: Event) {}
}

pub struct AmsVtHandle {
    term: Term<AmsVtEvents>,
    processor: Processor,
    rows: usize,
    cols: usize,
    damage_serial: u64,
}

fn normalized_size(rows: i32, cols: i32) -> AmsVtSize {
    AmsVtSize {
        rows: max(rows, 1) as usize,
        cols: max(cols, 1) as usize,
    }
}

fn line_bounds(cols: usize, line: Line) -> (Point, Point) {
    (Point::new(line, Column(0)), Point::new(line, Column(cols)))
}

fn buffer_index_to_line(history_lines: u64, index: u64) -> Line {
    if index < history_lines {
        Line(index as i32 - history_lines as i32)
    } else {
        Line((index - history_lines) as i32)
    }
}

fn empty_c_string() -> *mut c_char {
    CString::new("")
        .expect("static empty string has no nul")
        .into_raw()
}

fn into_c_string(mut text: String) -> *mut c_char {
    if text.as_bytes().contains(&0) {
        text = text.replace('\0', "");
    }

    match CString::new(text) {
        Ok(value) => value.into_raw(),
        Err(_) => empty_c_string(),
    }
}

fn handle_ref<'a>(handle: *const AmsVtHandle) -> Option<&'a AmsVtHandle> {
    if handle.is_null() {
        None
    } else {
        unsafe { handle.as_ref() }
    }
}

fn handle_mut<'a>(handle: *mut AmsVtHandle) -> Option<&'a mut AmsVtHandle> {
    if handle.is_null() {
        None
    } else {
        unsafe { handle.as_mut() }
    }
}

fn make_config(scrollback_limit: u64) -> Config {
    let mut config = Config::default();
    config.scrolling_history = min(scrollback_limit, i32::MAX as u64) as usize;
    config
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CellStyle {
    fg: Color,
    bg: Color,
    flags: Flags,
}

impl Default for CellStyle {
    fn default() -> Self {
        Self {
            fg: Color::Named(NamedColor::Foreground),
            bg: Color::Named(NamedColor::Background),
            flags: Flags::empty(),
        }
    }
}

impl From<&Cell> for CellStyle {
    fn from(cell: &Cell) -> Self {
        Self {
            fg: cell.fg,
            bg: cell.bg,
            flags: cell.flags
                & (Flags::INVERSE
                    | Flags::BOLD
                    | Flags::ITALIC
                    | Flags::ALL_UNDERLINES
                    | Flags::DIM
                    | Flags::HIDDEN
                    | Flags::STRIKEOUT),
        }
    }
}

fn ansi_color_code(out: &mut Vec<String>, color: Color, foreground: bool) {
    let base = if foreground { 30 } else { 40 };
    let bright_base = if foreground { 90 } else { 100 };
    match color {
        Color::Named(NamedColor::Foreground) if foreground => out.push("39".to_owned()),
        Color::Named(NamedColor::Background) if !foreground => out.push("49".to_owned()),
        Color::Named(NamedColor::Black) => out.push(format!("{}", base)),
        Color::Named(NamedColor::Red) => out.push(format!("{}", base + 1)),
        Color::Named(NamedColor::Green) => out.push(format!("{}", base + 2)),
        Color::Named(NamedColor::Yellow) => out.push(format!("{}", base + 3)),
        Color::Named(NamedColor::Blue) => out.push(format!("{}", base + 4)),
        Color::Named(NamedColor::Magenta) => out.push(format!("{}", base + 5)),
        Color::Named(NamedColor::Cyan) => out.push(format!("{}", base + 6)),
        Color::Named(NamedColor::White) => out.push(format!("{}", base + 7)),
        Color::Named(NamedColor::BrightBlack) => out.push(format!("{}", bright_base)),
        Color::Named(NamedColor::BrightRed) => out.push(format!("{}", bright_base + 1)),
        Color::Named(NamedColor::BrightGreen) => out.push(format!("{}", bright_base + 2)),
        Color::Named(NamedColor::BrightYellow) => out.push(format!("{}", bright_base + 3)),
        Color::Named(NamedColor::BrightBlue) => out.push(format!("{}", bright_base + 4)),
        Color::Named(NamedColor::BrightMagenta) => out.push(format!("{}", bright_base + 5)),
        Color::Named(NamedColor::BrightCyan) => out.push(format!("{}", bright_base + 6)),
        Color::Named(NamedColor::BrightWhite) => out.push(format!("{}", bright_base + 7)),
        Color::Indexed(index) => {
            out.push(format!("{};5;{}", if foreground { 38 } else { 48 }, index));
        }
        Color::Spec(rgb) => {
            out.push(format!(
                "{};2;{};{};{}",
                if foreground { 38 } else { 48 },
                rgb.r,
                rgb.g,
                rgb.b
            ));
        }
        _ if foreground => out.push("39".to_owned()),
        _ => out.push("49".to_owned()),
    }
}

fn push_sgr(out: &mut String, style: CellStyle) {
    let mut codes = vec!["0".to_owned()];
    if style.flags.contains(Flags::BOLD) {
        codes.push("1".to_owned());
    }
    if style.flags.contains(Flags::DIM) {
        codes.push("2".to_owned());
    }
    if style.flags.contains(Flags::ITALIC) {
        codes.push("3".to_owned());
    }
    if style.flags.intersects(Flags::ALL_UNDERLINES) {
        codes.push("4".to_owned());
    }
    if style.flags.contains(Flags::INVERSE) {
        codes.push("7".to_owned());
    }
    if style.flags.contains(Flags::HIDDEN) {
        codes.push("8".to_owned());
    }
    if style.flags.contains(Flags::STRIKEOUT) {
        codes.push("9".to_owned());
    }
    ansi_color_code(&mut codes, style.fg, true);
    ansi_color_code(&mut codes, style.bg, false);
    out.push_str("\x1b[");
    out.push_str(&codes.join(";"));
    out.push('m');
}

fn line_render_width(vt: &AmsVtHandle, line: Line) -> usize {
    let row = &vt.term.grid()[line];
    let wrapline = row[Column(vt.cols - 1)].flags.contains(Flags::WRAPLINE);
    if wrapline {
        return vt.cols;
    }
    row.into_iter()
        .rposition(|cell| !cell.is_empty())
        .map_or(0, |index| index + 1)
}

fn visible_line_render_width(vt: &AmsVtHandle, line: Line) -> usize {
    let width = line_render_width(vt, line);
    let cursor = vt.term.grid().cursor.point;
    if cursor.line != line {
        return width;
    }

    max(width, min(vt.cols, cursor.column.0))
}

fn render_line_ansi_with_width(vt: &AmsVtHandle, line: Line, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    let row = &vt.term.grid()[line];
    let mut out = String::new();
    let mut active_style = CellStyle::default();
    for column in 0..width {
        let cell = &row[Column(column)];
        if cell
            .flags
            .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
        {
            continue;
        }

        let style = CellStyle::from(cell);
        if style != active_style {
            push_sgr(&mut out, style);
            active_style = style;
        }

        out.push(if cell.flags.contains(Flags::HIDDEN) {
            ' '
        } else {
            cell.c
        });
        if let Some(chars) = cell.zerowidth() {
            for ch in chars {
                out.push(*ch);
            }
        }
    }
    if active_style != CellStyle::default() {
        out.push_str("\x1b[0m");
    }
    out
}

fn render_line_ansi(vt: &AmsVtHandle, line: Line) -> String {
    render_line_ansi_with_width(vt, line, line_render_width(vt, line))
}

fn line_is_wrapped(vt: &AmsVtHandle, line: Line) -> bool {
    vt.term.grid()[line][Column(vt.cols - 1)]
        .flags
        .contains(Flags::WRAPLINE)
}

fn main_replay_row_count(vt: &AmsVtHandle) -> u64 {
    let grid = vt.term.grid();
    let history_lines = grid.history_size() as u64;
    let total_lines = history_lines + vt.rows as u64;
    if total_lines == 0 {
        return 0;
    }

    let cursor = grid.cursor.point;
    let cursor_index = history_lines + max(0, cursor.line.0) as u64;
    let mut last_index = if cursor.column.0 > 0 {
        Some(cursor_index)
    } else {
        None
    };

    for index in 0..total_lines {
        let line = buffer_index_to_line(history_lines, index);
        if line_render_width(vt, line) > 0 {
            last_index = Some(index);
        }
    }

    last_index.map_or(0, |index| index + 1)
}

fn visible_frame_row_count(vt: &AmsVtHandle) -> usize {
    if vt.rows == 0 {
        return 0;
    }

    let grid = vt.term.grid();
    let cursor = grid.cursor.point;
    let mut last_line = if cursor.column.0 > 0 {
        Some(max(0, cursor.line.0) as usize)
    } else {
        None
    };

    for row in 0..vt.rows {
        if line_render_width(vt, Line(row as i32)) > 0 {
            last_line = Some(row);
        }
    }

    last_line.map_or(0, |line| line + 1)
}

#[no_mangle]
pub extern "C" fn AmsVtCreate(rows: i32, cols: i32, scrollback_limit: u64) -> *mut AmsVtHandle {
    let size = normalized_size(rows, cols);
    let config = make_config(scrollback_limit);
    let term = Term::new(config, &size, AmsVtEvents);

    Box::into_raw(Box::new(AmsVtHandle {
        term,
        processor: Processor::new(),
        rows: size.rows,
        cols: size.cols,
        damage_serial: 0,
    }))
}

#[no_mangle]
pub extern "C" fn AmsVtFree(handle: *mut AmsVtHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

#[no_mangle]
pub extern "C" fn AmsVtResize(handle: *mut AmsVtHandle, rows: i32, cols: i32) {
    let Some(vt) = handle_mut(handle) else {
        return;
    };

    let size = normalized_size(rows, cols);
    vt.term.resize(size);
    vt.rows = size.rows;
    vt.cols = size.cols;
    vt.damage_serial = vt.damage_serial.wrapping_add(1);
}

#[no_mangle]
pub extern "C" fn AmsVtFeed(handle: *mut AmsVtHandle, data: *const u8, len: usize) {
    let Some(vt) = handle_mut(handle) else {
        return;
    };
    if data.is_null() || len == 0 {
        return;
    }

    let bytes = unsafe { slice::from_raw_parts(data, len) };
    vt.processor.advance(&mut vt.term, bytes);
    vt.damage_serial = vt.damage_serial.wrapping_add(1);
}

#[no_mangle]
pub extern "C" fn AmsVtGetSnapshot(handle: *const AmsVtHandle) -> AmsVtSnapshot {
    let Some(vt) = handle_ref(handle) else {
        return AmsVtSnapshot {
            rows: 0,
            cols: 0,
            cursor_row: 0,
            cursor_col: 0,
            history_lines: 0,
            total_lines: 0,
            display_offset: 0,
            damage_serial: 0,
            rendered_main_rows: 0,
            in_alternate_screen: 0,
            cursor_visible: 0,
        };
    };

    let grid = vt.term.grid();
    let cursor = grid.cursor.point;
    let history_lines = grid.history_size() as u64;

    AmsVtSnapshot {
        rows: vt.rows as i32,
        cols: vt.cols as i32,
        cursor_row: cursor.line.0,
        cursor_col: cursor.column.0 as i32,
        history_lines,
        total_lines: history_lines + vt.rows as u64,
        display_offset: grid.display_offset() as u64,
        damage_serial: vt.damage_serial,
        rendered_main_rows: if vt.term.mode().contains(TermMode::ALT_SCREEN) {
            0
        } else {
            main_replay_row_count(vt)
        },
        in_alternate_screen: u8::from(vt.term.mode().contains(TermMode::ALT_SCREEN)),
        cursor_visible: u8::from(vt.term.mode().contains(TermMode::SHOW_CURSOR)),
    }
}

#[no_mangle]
pub extern "C" fn AmsVtRenderLogicalLineUtf8(handle: *const AmsVtHandle, line: i32) -> *mut c_char {
    let Some(vt) = handle_ref(handle) else {
        return ptr::null_mut();
    };
    if vt.cols == 0 {
        return empty_c_string();
    }
    let history_lines = vt.term.grid().history_size() as i32;
    if line < -history_lines || line >= vt.rows as i32 {
        return ptr::null_mut();
    }

    let line = Line(line);
    let (start, end) = line_bounds(vt.cols, line);
    into_c_string(vt.term.bounds_to_string(start, end))
}

#[no_mangle]
pub extern "C" fn AmsVtRenderBufferLineUtf8(handle: *const AmsVtHandle, index: u64) -> *mut c_char {
    let Some(vt) = handle_ref(handle) else {
        return ptr::null_mut();
    };

    let history_lines = vt.term.grid().history_size() as u64;
    let total_lines = history_lines + vt.rows as u64;
    if index >= total_lines {
        return ptr::null_mut();
    }

    let line = buffer_index_to_line(history_lines, index);

    let (start, end) = line_bounds(vt.cols, line);
    into_c_string(vt.term.bounds_to_string(start, end))
}

#[no_mangle]
pub extern "C" fn AmsVtRenderMainReplayAnsiUtf8(handle: *const AmsVtHandle) -> *mut c_char {
    let Some(vt) = handle_ref(handle) else {
        return ptr::null_mut();
    };
    if vt.term.mode().contains(TermMode::ALT_SCREEN) {
        return empty_c_string();
    }

    let history_lines = vt.term.grid().history_size() as u64;
    let rows = main_replay_row_count(vt);
    let mut out = String::new();
    for index in 0..rows {
        let line = buffer_index_to_line(history_lines, index);
        out.push_str(&render_line_ansi(vt, line));
        if index + 1 < rows {
            if !line_is_wrapped(vt, line) {
                out.push_str("\r\n");
            }
        }
    }
    into_c_string(out)
}

#[no_mangle]
pub extern "C" fn AmsVtRenderVisibleFrameAnsiUtf8(handle: *const AmsVtHandle) -> *mut c_char {
    let Some(vt) = handle_ref(handle) else {
        return ptr::null_mut();
    };

    let rows = visible_frame_row_count(vt);
    let mut out = String::new();
    for index in 0..rows {
        let line = Line(index as i32);
        let width = visible_line_render_width(vt, line);
        out.push_str(&render_line_ansi_with_width(vt, line, width));
        out.push_str("\x1b[K");
        if index + 1 < rows && !line_is_wrapped(vt, line) {
            out.push_str("\r\n");
        }
    }
    into_c_string(out)
}

#[no_mangle]
pub extern "C" fn AmsVtFreeString(text: *mut c_char) {
    if !text.is_null() {
        unsafe {
            drop(CString::from_raw(text));
        }
    }
}
