//! Property-list walker.
//!
//! Cite: `objc4/runtime/objc-runtime-new.h:1227-1230` (`property_t`)
//! and `:1496-1502` (`property_list_t` —
//! `entsize_list_tt<property_t, property_list_t, 0>`).
//! `RESEARCH.md` anchors the layout at line 1535.
//!
//! Each property is `(name, attributes)` — two 64-bit pointers — and
//! the attribute string is a comma-separated grammar like
//! `T@"NSString",C,N,V_name`. The grammar is documented in Apple's
//! runtime documentation (not the header itself); each comma-
//! separated item starts with a single-letter key.
//!
//! `darwinscope` exposes both the **raw** attribute string (for
//! tools that prefer their own parser) and a parsed
//! [`ParsedAttributes`] view that splits on commas without
//! interpreting the values.

use crate::{objc::ObjcRuntime, util::read_u32_le_at};

const PROPERTY_ENTSIZE: u32 = 16;

/// One property entry from a `class_ro_t.baseProperties` /
/// `protocol_t.instanceProperties` list (`property_t`).
///
/// Cite: `objc4/runtime/objc-runtime-new.h:1227-1230`. Each entry is
/// just two 64-bit pointers — `name` and `attributes` — both into
/// `__TEXT,__cstring`. The runtime never *uses* properties at
/// dispatch time (Obj-C dispatch is selector-based); they exist
/// purely for KVC / KVO, the runtime introspection API, and Swift's
/// `@objc` bridging.
///
/// The attribute string follows Apple's "Property Attribute String"
/// grammar: comma-separated items, each beginning with a one-letter
/// key, e.g. `T@"NSString",C,N,V_name`. The leading `T` carries the
/// type-encoding; subsequent letters are flags (`C` = copy,
/// `N` = nonatomic, `R` = readonly, `&` = retain, …) and `V` names
/// the backing ivar. Use [`Property::parsed`] for a structured view
/// that splits the items but does not further interpret each value.
#[derive(Debug, Clone)]
pub struct Property<'a> {
    name: &'a str,
    attributes: &'a str,
}

impl<'a> Property<'a> {
    /// Property name (e.g. `"name"`).
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Raw attribute string (e.g. `"T@\"NSString\",C,N,V_name"`).
    pub fn attributes(&self) -> &'a str {
        self.attributes
    }

    /// Parsed attribute view — splits on commas into single-letter
    /// keys and per-key values.
    pub fn parsed(&self) -> ParsedAttributes<'a> {
        parse_attributes(self.attributes)
    }
}

/// Single parsed attribute item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedAttribute<'a> {
    /// Single-letter attribute key (`T`, `R`, `C`, `&`, `N`, `G`,
    /// `S`, `D`, `W`, `V`, `t`, `P`).
    pub key: char,
    /// Body following the key, before the next comma. Empty for
    /// keys that have no payload (`R`, `C`, `&`, `N`, `D`, `W`, `P`).
    pub value: &'a str,
}

/// Parsed attribute string.
#[derive(Debug, Clone)]
pub struct ParsedAttributes<'a> {
    /// Type-encoding from the leading `T<value>` item; empty when
    /// no `T` item is present.
    pub type_encoding: &'a str,
    /// All parsed items in source order, including the type item.
    pub items: Vec<ParsedAttribute<'a>>,
}

/// Iterator over a single `property_list_t`.
pub struct PropertyIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    layout: Option<PropertyListLayout>,
    cursor: u32,
}

#[derive(Debug, Clone, Copy)]
struct PropertyListLayout {
    base_va: u64,
    entsize: u32,
    count: u32,
}

impl<'a, 'p> PropertyIter<'a, 'p> {
    pub(crate) fn empty(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            layout: None,
            cursor: 0,
        }
    }
}

impl<'a, 'p> Iterator for PropertyIter<'a, 'p> {
    type Item = Property<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let layout = self.layout?;
        loop {
            if self.cursor >= layout.count {
                return None;
            }
            let i = self.cursor;
            self.cursor = self.cursor.checked_add(1)?;
            let entry_off = u64::from(i).checked_mul(u64::from(layout.entsize))?;
            let entry_va = layout.base_va.checked_add(entry_off)?;
            if let Some(p) = decode_property(self.rt, entry_va) {
                return Some(p);
            }
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::objc: property row at 0x{:x} (idx={}) skipped — decode failed",
                entry_va,
                i
            );
        }
    }
}

pub(crate) fn property_list_iter<'a, 'p>(
    rt: &'p ObjcRuntime<'a>,
    list_va: u64,
) -> PropertyIter<'a, 'p> {
    if list_va == 0 || (list_va & 0x1) != 0 {
        return PropertyIter::empty(rt);
    }

    let Some(header) = rt.read_bytes(list_va, 8) else {
        return PropertyIter::empty(rt);
    };
    let Some(entsize_and_flags) = read_u32_le_at(header, 0) else {
        return PropertyIter::empty(rt);
    };
    let Some(count) = read_u32_le_at(header, 4) else {
        return PropertyIter::empty(rt);
    };
    // FlagMask = 0; entsize is the full word.
    let entsize = entsize_and_flags;
    if entsize < PROPERTY_ENTSIZE {
        return PropertyIter::empty(rt);
    }

    let base_va = match list_va.checked_add(8) {
        Some(v) => v,
        None => return PropertyIter::empty(rt),
    };

    PropertyIter {
        rt,
        layout: Some(PropertyListLayout {
            base_va,
            entsize,
            count,
        }),
        cursor: 0,
    }
}

fn decode_property<'a>(rt: &ObjcRuntime<'a>, entry_va: u64) -> Option<Property<'a>> {
    rt.read_bytes(entry_va, PROPERTY_ENTSIZE as usize)?;
    let name_va = rt.resolve_pointer(entry_va)?;
    let attrs_va = rt.resolve_pointer(entry_va.checked_add(8)?).unwrap_or(0);

    let name = rt.read_cstr(name_va)?;
    let attributes = rt.read_cstr(attrs_va).unwrap_or("");

    Some(Property { name, attributes })
}

/// Split an ObjC property attribute string on commas.
///
/// Each comma-separated chunk has a single-character key followed
/// by an optional payload. Quoted type strings (`T@"NSString"`) are
/// left intact — the parser does *not* descend into the type
/// grammar; it only segments by top-level commas. Quote-state is
/// tracked so that a comma inside a `"..."` quoted region is not
/// treated as a separator.
fn parse_attributes(s: &str) -> ParsedAttributes<'_> {
    let mut items: Vec<ParsedAttribute<'_>> = Vec::new();
    let mut type_encoding: &str = "";
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Each item begins with a single-byte ASCII key.
        let Some(&key_byte) = bytes.get(i) else { break };
        let key = key_byte as char;
        let value_start = match i.checked_add(1) {
            Some(v) => v,
            None => break,
        };

        // Find the next *unquoted* comma.
        let mut j = value_start;
        let mut in_quotes = false;
        while j < bytes.len() {
            let Some(&c) = bytes.get(j) else { break };
            if c == b'"' {
                in_quotes = !in_quotes;
            } else if c == b',' && !in_quotes {
                break;
            }
            j = match j.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
        // Bytes in `value_start..j` are the value. Slice on byte
        // indices is safe because the string is ASCII through that
        // segment (the only multi-byte content possible is inside
        // quoted type encodings, which always start/end on `"` —
        // ASCII boundaries).
        let value = s.get(value_start..j).unwrap_or("");
        let item = ParsedAttribute { key, value };
        if key == 'T' && type_encoding.is_empty() {
            type_encoding = value;
        }
        items.push(item);

        // Skip the comma if present.
        i = j;
        if bytes.get(i) == Some(&b',') {
            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }
    ParsedAttributes {
        type_encoding,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let p = parse_attributes("T@\"NSString\",C,N,V_name");
        assert_eq!(p.type_encoding, "@\"NSString\"");
        assert_eq!(p.items.len(), 4);
        assert_eq!(p.items[0].key, 'T');
        assert_eq!(p.items[0].value, "@\"NSString\"");
        assert_eq!(p.items[1].key, 'C');
        assert_eq!(p.items[1].value, "");
        assert_eq!(p.items[2].key, 'N');
        assert_eq!(p.items[3].key, 'V');
        assert_eq!(p.items[3].value, "_name");
    }

    #[test]
    fn parse_empty() {
        let p = parse_attributes("");
        assert!(p.items.is_empty());
        assert_eq!(p.type_encoding, "");
    }

    #[test]
    fn parse_handles_quoted_commas() {
        // Type encoding for a property of type `NSDictionary<NSString*, NSNumber*>`
        // (illustrative — real ObjC encodes generics differently, but
        // the parser must not split inside quotes regardless).
        let p = parse_attributes("T@\"NSDictionary<NSString,NSNumber>\",R,V_dict");
        assert_eq!(p.items.len(), 3);
        assert_eq!(p.type_encoding, "@\"NSDictionary<NSString,NSNumber>\"");
        assert_eq!(p.items[1].key, 'R');
        assert_eq!(p.items[2].key, 'V');
        assert_eq!(p.items[2].value, "_dict");
    }
}
