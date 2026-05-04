//! Class ↔ protocol conformance edges.
//!
//! Flattens every class's `class_ro_t.baseProtocols` list into a
//! stream of `(class_address, class_name, protocol_name, is_meta)`
//! rows.

use std::marker::PhantomData;

use crate::objc::{ObjcRuntime, class::ClassIter, protocol::ProtocolNameIter};

/// One conformance edge.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceEdge<'a> {
    /// VM address of the class declaring the conformance.
    pub class_address: u64,
    /// Best-effort class name (`None` when the class's
    /// `class_ro_t.name` fails to resolve).
    pub class_name: Option<&'a str>,
    /// Conformed-to protocol name. Resolved through in-image
    /// protocol descriptors and chained-fixup binds.
    pub protocol_name: &'a str,
    /// Whether the row was emitted from the metaclass twin
    /// (i.e. class-method protocols).
    pub is_meta: bool,
}

/// Iterator over [`ConformanceEdge`] rows for every class in the
/// image.
pub struct ConformanceIter<'a, 'p> {
    classes: ClassIter<'a, 'p>,
    /// Drained on each outer step until empty.
    current: Option<ConformanceEdgeCursor<'a, 'p>>,
    _phantom: PhantomData<&'a ()>,
}

struct ConformanceEdgeCursor<'a, 'p> {
    class_address: u64,
    class_name: Option<&'a str>,
    is_meta: bool,
    protocols: ProtocolNameIter<'a, 'p>,
}

impl<'a, 'p> ConformanceIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            classes: ClassIter::new(rt),
            current: None,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for ConformanceIter<'a, 'p> {
    type Item = ConformanceEdge<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Drain the current class's protocol list first.
            if let Some(cur) = self.current.as_mut() {
                if let Some(name) = cur.protocols.next() {
                    return Some(ConformanceEdge {
                        class_address: cur.class_address,
                        class_name: cur.class_name,
                        protocol_name: name,
                        is_meta: cur.is_meta,
                    });
                }
                self.current = None;
            }

            // Advance to the next class.
            let cls = self.classes.next()?;
            let class_address = cls.address();
            let is_meta = cls.is_meta();
            let (class_name, protocols) = match cls.ro() {
                Some(ro) => (Some(ro.name()), ro.protocols()),
                None => continue,
            };
            self.current = Some(ConformanceEdgeCursor {
                class_address,
                class_name,
                is_meta,
                protocols,
            });
        }
    }
}
