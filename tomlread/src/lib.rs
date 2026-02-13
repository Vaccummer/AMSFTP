use atomicwrites::{AllowOverwrite, AtomicFile, Error as AtomicError};
use libc::c_char;
use serde_json::{Map, Value as J};
use std::{
    ffi::{CStr, CString},
    fs,
    io::Write,
    ptr,
};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};

pub struct ConfigHandle {
    doc: DocumentMut,
    schema: J,
    json: String,
    src_path: String,
}

fn cstr_to_str<'a>(p: *const c_char) -> Result<&'a str, String> {
    if p.is_null() {
        return Err("null pointer".into());
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|e| format!("invalid utf-8: {e}"))
}

fn to_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn cfgffi_free_string(p: *mut c_char) {
    if p.is_null() {
        return;
    }
    unsafe { drop(CString::from_raw(p)) };
}

#[no_mangle]
pub extern "C" fn cfgffi_free_handle(h: *mut ConfigHandle) {
    if h.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(h)) };
}

#[no_mangle]
pub extern "C" fn cfgffi_get_json(h: *const ConfigHandle) -> *mut c_char {
    if h.is_null() {
        return ptr::null_mut();
    }
    let h = unsafe { &*h };
    to_c_string(h.json.clone())
}

#[no_mangle]
pub extern "C" fn cfgffi_get_toml(h: *const ConfigHandle) -> *mut c_char {
    if h.is_null() {
        return ptr::null_mut();
    }
    let h = unsafe { &*h };
    to_c_string(h.doc.to_string())
}

#[no_mangle]
pub extern "C" fn cfgffi_read(
    path: *const c_char,
    schema_json: *const c_char,
    out_err: *mut *mut c_char,
) -> *mut ConfigHandle {
    let set_err = |msg: String| {
        if !out_err.is_null() {
            unsafe { *out_err = to_c_string(msg) };
        }
    };

    let path = match cstr_to_str(path) {
        Ok(s) => s,
        Err(e) => {
            set_err(e);
            return ptr::null_mut();
        }
    };

    let schema_str = match cstr_to_str(schema_json) {
        Ok(s) => s,
        Err(e) => {
            set_err(e);
            return ptr::null_mut();
        }
    };

    let schema: J = match serde_json::from_str(schema_str) {
        Ok(v) => v,
        Err(e) => {
            set_err(format!("schema json parse error: {e}"));
            return ptr::null_mut();
        }
    };

    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            set_err(format!("read file error: {e}"));
            return ptr::null_mut();
        }
    };

    let mut doc: DocumentMut = match text.parse() {
        Ok(d) => d,
        Err(e) => {
            set_err(format!("toml parse error: {e}"));
            return ptr::null_mut();
        }
    };

    filter_toml_item_by_schema(doc.as_item_mut(), &schema);

    let json_val = toml_item_to_json(doc.as_item());
    let json = match serde_json::to_string_pretty(&json_val) {
        Ok(s) => s,
        Err(e) => {
            set_err(format!("toml->json error: {e}"));
            return ptr::null_mut();
        }
    };

    let h = Box::new(ConfigHandle {
        doc,
        schema,
        json,
        src_path: path.to_string(),
    });
    Box::into_raw(h)
}

#[no_mangle]
pub extern "C" fn cfgffi_write(
    h: *mut ConfigHandle,
    out_path: *const c_char,
    new_json: *const c_char,
    out_err: *mut *mut c_char,
) -> i32 {
    let set_err = |msg: String| {
        if !out_err.is_null() {
            unsafe { *out_err = to_c_string(msg) };
        }
    };

    if h.is_null() {
        set_err("null handle".into());
        return 1;
    }
    let h = unsafe { &mut *h };

    let out_path = match cstr_to_str(out_path) {
        Ok(s) => s,
        Err(e) => {
            set_err(e);
            return 2;
        }
    };

    let new_json_str = match cstr_to_str(new_json) {
        Ok(s) => s,
        Err(e) => {
            set_err(e);
            return 3;
        }
    };

    let mut j: J = match serde_json::from_str(new_json_str) {
        Ok(v) => v,
        Err(e) => {
            set_err(format!("new_json parse error: {e}"));
            return 4;
        }
    };

    // 写回前按 schema 过滤（避免引入未知字段）
    filter_json_by_schema(&mut j, &h.schema);

    // 应用更新：允许新增，但新增追加到末尾
    apply_json_updates_append_new(h.doc.as_item_mut(), &j);
    // Hide intermediate parent tables when they only contain nested tables.
    // This keeps output compact for path-shaped maps (for example known_hosts).
    normalize_toml_layout(h.doc.as_item_mut());

    if let Err(e) = write_atomic(out_path, h.doc.to_string()) {
        set_err(format!("write file error: {e}"));
        return 5;
    }

    let json_val = toml_item_to_json(h.doc.as_item());
    h.json = serde_json::to_string_pretty(&json_val).unwrap_or_else(|_| "{}".into());

    0
}

#[no_mangle]
pub extern "C" fn cfgffi_write_inplace(
    h: *mut ConfigHandle,
    new_json: *const c_char,
    out_err: *mut *mut c_char,
) -> i32 {
    if h.is_null() {
        if !out_err.is_null() {
            unsafe { *out_err = to_c_string("null handle".into()) };
        }
        return 1;
    }
    let out_path = {
        let hh = unsafe { &mut *h };
        hh.src_path.clone()
    };
    let c_out_path = CString::new(out_path).unwrap();
    cfgffi_write(h, c_out_path.as_ptr(), new_json, out_err)
}

#[no_mangle]
pub extern "C" fn cfgffi_debug_order(
    path: *const c_char,
    schema_json: *const c_char,
    out_err: *mut *mut c_char,
) -> *mut c_char {
    let set_err = |msg: String| {
        if !out_err.is_null() {
            unsafe { *out_err = to_c_string(msg) };
        }
    };

    let path = match cstr_to_str(path) {
        Ok(s) => s,
        Err(e) => {
            set_err(e);
            return ptr::null_mut();
        }
    };

    let schema_str = match cstr_to_str(schema_json) {
        Ok(s) => s,
        Err(e) => {
            set_err(e);
            return ptr::null_mut();
        }
    };

    let schema: J = match serde_json::from_str(schema_str) {
        Ok(v) => v,
        Err(e) => {
            set_err(format!("schema json parse error: {e}"));
            return ptr::null_mut();
        }
    };

    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            set_err(format!("read file error: {e}"));
            return ptr::null_mut();
        }
    };

    let mut doc: DocumentMut = match text.parse() {
        Ok(d) => d,
        Err(e) => {
            set_err(format!("toml parse error: {e}"));
            return ptr::null_mut();
        }
    };

    filter_toml_item_by_schema(doc.as_item_mut(), &schema);

    let before_keys = toml_item_key_order(doc.as_item());
    let json_val = toml_item_to_json(doc.as_item());
    let after_keys = json_key_order(&json_val);

    let same = before_keys == after_keys;
    let msg = serde_json::json!({
        "same": same,
        "before": before_keys,
        "after": after_keys
    })
    .to_string();

    to_c_string(msg)
}

/* Write file with an atomic replace to avoid partial writes on crash. */
fn write_atomic(path: &str, content: String) -> std::io::Result<()> {
    let af = AtomicFile::new(path, AllowOverwrite);
    af.write(|f| {
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })
    .map_err(|e: AtomicError<std::io::Error>| match e {
        AtomicError::Internal(err) => err,
        AtomicError::User(err) => err,
    })
}

/* ---------------- Schema helpers ---------------- */

fn schema_type(schema: &J) -> Option<&str> {
    schema.get("type")?.as_str()
}
fn schema_properties(schema: &J) -> Option<&serde_json::Map<String, J>> {
    schema.get("properties")?.as_object()
}
fn schema_additional(schema: &J) -> Option<&J> {
    schema.get("additionalProperties")
}
fn schema_items(schema: &J) -> Option<&J> {
    schema.get("items")
}

/* ---------------- read: filter TOML ---------------- */

fn filter_toml_item_by_schema(item: &mut Item, schema: &J) {
    match item {
        Item::Table(t) => filter_toml_table_by_schema(t, schema),
        Item::ArrayOfTables(aot) => {
            let items_schema = schema_items(schema).unwrap_or(&J::Null);
            for t in aot.iter_mut() {
                filter_toml_table_by_schema(t, items_schema);
            }
        }
        Item::Value(v) => {
            if let Value::Array(arr) = v {
                if schema_type(schema) == Some("array") {
                    if let Some(it_schema) = schema_items(schema) {
                        filter_toml_array_by_schema(arr, it_schema);
                    }
                }
            }
        }
        _ => {}
    }
}

fn filter_toml_array_by_schema(arr: &mut Array, item_schema: &J) {
    for it in arr.iter_mut() {
        if let toml_edit::Value::InlineTable(inl) = it {
            let mut table = Table::new();
            for (k, v) in inl.iter() {
                table.insert(k, Item::Value(v.clone()));
            }
            filter_toml_table_by_schema(&mut table, item_schema);

            inl.clear();
            for (k, v) in table.iter() {
                if let Item::Value(vv) = v {
                    inl.insert(k, vv.clone());
                }
            }
        }
    }
}

fn filter_toml_table_by_schema(table: &mut Table, schema: &J) {
    let is_obj = match schema_type(schema) {
        Some("object") => true,
        None => schema_properties(schema).is_some(),
        _ => false,
    };
    if !is_obj {
        return;
    }

    let props = schema_properties(schema);
    let additional = schema_additional(schema);

    if matches!(additional, Some(J::Bool(false))) {
        if let Some(p) = props {
            let mut to_remove = Vec::new();
            for (k, _) in table.iter() {
                if !p.contains_key(k) {
                    to_remove.push(k.to_string());
                }
            }
            for k in to_remove {
                table.remove(&k);
            }
        } else {
            let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
            for k in keys {
                table.remove(&k);
            }
        }
    }

    let add_schema_obj = match additional {
        Some(J::Object(_)) => additional,
        _ => None,
    };

    let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
    for k in keys {
        let child_schema = if let Some(p) = props.and_then(|m| m.get(&k)) {
            p
        } else if let Some(s) = add_schema_obj {
            s
        } else {
            continue;
        };

        if let Some(child) = table.get_mut(&k) {
            filter_toml_item_by_schema(child, child_schema);
        }
    }
}

/* ---------------- write: filter JSON ---------------- */

fn filter_json_by_schema(j: &mut J, schema: &J) {
    match j {
        J::Object(obj) => {
            let is_obj = match schema_type(schema) {
                Some("object") => true,
                None => schema_properties(schema).is_some(),
                _ => false,
            };
            if !is_obj {
                return;
            }

            let props = schema_properties(schema);
            let additional = schema_additional(schema);

            if matches!(additional, Some(J::Bool(false))) {
                if let Some(p) = props {
                    obj.retain(|k, _| p.contains_key(k));
                } else {
                    obj.clear();
                }
            }

            let add_schema_obj = match additional {
                Some(J::Object(_)) => additional,
                _ => None,
            };

            let keys: Vec<String> = obj.keys().cloned().collect();
            for k in keys {
                let child_schema = if let Some(p) = props.and_then(|m| m.get(&k)) {
                    p
                } else if let Some(s) = add_schema_obj {
                    s
                } else {
                    continue;
                };
                if let Some(v) = obj.get_mut(&k) {
                    filter_json_by_schema(v, child_schema);
                }
            }
        }
        J::Array(arr) => {
            if schema_type(schema) == Some("array") {
                if let Some(it_schema) = schema_items(schema) {
                    for v in arr.iter_mut() {
                        filter_json_by_schema(v, it_schema);
                    }
                }
            }
        }
        _ => {}
    }
}

/* ---------------- write: apply JSON updates (append new keys) ---------------- */

/** Apply JSON updates into a TOML item, appending new keys to the end. */
fn apply_json_updates_append_new(item: &mut Item, j: &J) {
    match j {
        J::Object(obj) => match item {
            Item::Table(t) => {
                for (k, v) in obj {
                    if let Some(child) = t.get_mut(k) {
                        apply_json_updates_append_new(child, v);
                    } else if let Some(new_item) = json_to_item(v) {
                        t.insert(k, new_item); // 追加到末尾
                    }
                }
            }
            other => {
                if let Some(new_item) = json_to_item(j) {
                    *other = new_item;
                }
            }
        },

        J::Array(arr) => match item {
            // ✅ 修正点：ArrayOfTables 不用索引 aot[i]
            Item::ArrayOfTables(aot) => {
                // 先更新已有（按顺序 zip）
                for (t, v) in aot.iter_mut().zip(arr.iter()) {
                    if let J::Object(obj) = v {
                        for (k, vv) in obj {
                            if let Some(child) = t.get_mut(k) {
                                apply_json_updates_append_new(child, vv);
                            } else if let Some(new_item) = json_to_item(vv) {
                                t.insert(k, new_item);
                            }
                        }
                    }
                }

                // 追加多出来的 table
                let existing = aot.len();
                if arr.len() > existing {
                    for v in arr.iter().skip(existing) {
                        if let J::Object(obj) = v {
                            let mut nt = Table::new();
                            for (k, vv) in obj {
                                if let Some(new_item) = json_to_item(vv) {
                                    nt.insert(k, new_item);
                                }
                            }
                            aot.push(nt);
                        }
                    }
                } else if arr.len() < existing {
                    // Trim extra tables when JSON array shrinks (supports deletions).
                    while aot.len() > arr.len() {
                        aot.remove(aot.len() - 1);
                    }
                }
            }

            Item::Value(v) => {
                if let Some(newv) = json_to_toml_value(j) {
                    *v = newv;
                }
            }

            other => {
                if let Some(new_item) = json_to_item(j) {
                    *other = new_item;
                }
            }
        },

        _ => match item {
            Item::Value(v) => {
                if let Some(newv) = json_to_toml_value(j) {
                    *v = newv;
                }
            }
            other => {
                if let Some(new_item) = json_to_item(j) {
                    *other = new_item;
                }
            }
        },
    }
}

/* ---------------- TOML layout normalization ---------------- */

fn normalize_table_implicit(table: &mut Table, depth: usize) {
    let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
    let mut has_table_child = false;
    let mut has_non_table_child = false;

    for key in keys {
        if let Some(child) = table.get_mut(&key) {
            match child {
                Item::Table(child_table) => {
                    has_table_child = true;
                    normalize_table_implicit(child_table, depth + 1);
                }
                Item::ArrayOfTables(aot) => {
                    has_non_table_child = true;
                    for child_table in aot.iter_mut() {
                        normalize_table_implicit(child_table, depth + 1);
                    }
                }
                Item::Value(_) => {
                    has_non_table_child = true;
                }
                _ => {
                    has_non_table_child = true;
                }
            }
        }
    }

    if depth > 0 && has_table_child && !has_non_table_child {
        table.set_implicit(true);
    }
}

fn normalize_toml_layout(item: &mut Item) {
    match item {
        Item::Table(table) => normalize_table_implicit(table, 0),
        Item::ArrayOfTables(aot) => {
            for table in aot.iter_mut() {
                normalize_table_implicit(table, 0);
            }
        }
        _ => {}
    }
}

fn toml_item_to_json(item: &Item) -> J {
    match item {
        Item::Table(t) => toml_table_to_json(t),
        Item::ArrayOfTables(aot) => toml_aot_to_json(aot),
        Item::Value(v) => toml_value_to_json(v),
        _ => J::Null,
    }
}

fn toml_item_key_order(item: &Item) -> Vec<String> {
    match item {
        Item::Table(t) => t.iter().map(|(k, _)| k.to_string()).collect(),
        _ => Vec::new(),
    }
}

fn json_key_order(j: &J) -> Vec<String> {
    match j {
        J::Object(obj) => obj.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

fn toml_table_to_json(table: &Table) -> J {
    let mut map = Map::new();
    for (k, v) in table.iter() {
        map.insert(k.to_string(), toml_item_to_json(v));
    }
    J::Object(map)
}

fn toml_aot_to_json(aot: &ArrayOfTables) -> J {
    let mut arr = Vec::with_capacity(aot.len());
    for t in aot.iter() {
        arr.push(toml_table_to_json(t));
    }
    J::Array(arr)
}

fn toml_value_to_json(v: &Value) -> J {
    match v {
        Value::String(s) => J::String(s.value().to_string()),
        Value::Integer(i) => J::Number(serde_json::Number::from(*i.value())),
        Value::Float(f) => {
            if let Some(n) = serde_json::Number::from_f64(*f.value()) {
                J::Number(n)
            } else {
                J::String(f.value().to_string())
            }
        }
        Value::Boolean(b) => J::Bool(*b.value()),
        Value::Datetime(dt) => J::String(dt.value().to_string()),
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for it in arr.iter() {
                out.push(toml_value_to_json(it));
            }
            J::Array(out)
        }
        Value::InlineTable(inl) => {
            let mut map = Map::new();
            for (k, v) in inl.iter() {
                map.insert(k.to_string(), toml_value_to_json(v));
            }
            J::Object(map)
        }
    }
}

fn json_to_item(j: &J) -> Option<Item> {
    match j {
        J::Null => None,
        J::Object(obj) => {
            let mut t = Table::new();
            for (k, v) in obj {
                if let Some(it) = json_to_item(v) {
                    t.insert(k, it);
                }
            }
            Some(Item::Table(t))
        }
        J::Array(arr) => {
            let all_obj = arr.iter().all(|x| matches!(x, J::Object(_)));
            if all_obj {
                let mut aot = ArrayOfTables::new();
                for x in arr {
                    if let J::Object(obj) = x {
                        let mut t = Table::new();
                        for (k, v) in obj {
                            if let Some(it) = json_to_item(v) {
                                t.insert(k, it);
                            }
                        }
                        aot.push(t);
                    }
                }
                Some(Item::ArrayOfTables(aot))
            } else {
                json_to_toml_value(j).map(Item::Value)
            }
        }
        _ => json_to_toml_value(j).map(Item::Value),
    }
}

fn json_to_toml_value(j: &J) -> Option<Value> {
    match j {
        J::Null => None,
        J::Bool(b) => Some(toml_edit::value(*b).as_value()?.clone()),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(toml_edit::value(i).as_value()?.clone())
            } else if let Some(u) = n.as_u64() {
                if u <= i64::MAX as u64 {
                    Some(toml_edit::value(u as i64).as_value()?.clone())
                } else {
                    Some(toml_edit::value(n.to_string()).as_value()?.clone())
                }
            } else if let Some(f) = n.as_f64() {
                Some(toml_edit::value(f).as_value()?.clone())
            } else {
                None
            }
        }
        J::String(s) => Some(toml_edit::value(s.as_str()).as_value()?.clone()),
        J::Array(arr) => {
            let mut a = Array::new();
            for it in arr {
                if let Some(v) = json_to_toml_value(it) {
                    a.push(v);
                }
            }
            Some(Value::Array(a))
        }
        J::Object(_) => {
            let mut t = toml_edit::InlineTable::new();
            if let J::Object(m) = j {
                for (k, v) in m {
                    if let Some(tv) = json_to_toml_value(v) {
                        t.insert(k, tv);
                    }
                }
            }
            Some(Value::InlineTable(t))
        }
    }
}
