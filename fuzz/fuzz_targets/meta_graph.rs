#![no_main]

//! HEIF / MIAF item-graph fuzzing (ISO/IEC 14496-12 §8.11 + 23008-12
//! §9.3/§9.4) — two arms over one recipe:
//!
//! 1. **Valid-by-construction identity.** The recipe assembles an
//!    item catalogue through this crate's own byte-exact builders —
//!    `iloc` (every v0/v1/v2 field-width selector × construction
//!    method 0/1/2), `pitm`, `iinf` (v2 typed entries), `iref`
//!    reference groups that may form cycles and self-references,
//!    `iprp` (`ipco` property list + `ipma` associations, including
//!    out-of-range property indexes), and an `idat` payload — wraps
//!    them into a `meta` body, and asserts `parse_meta_items`
//!    reproduces every constructed record exactly. Then the item
//!    resolution surface runs over the parsed graph:
//!    `item_byte_ranges` / `item_data_from_idat` /
//!    `properties_for` must resolve or refuse without panicking,
//!    whatever cycles or dangling IDs the recipe wired.
//!
//! 2. **Hostile mutation.** The remaining recipe bytes drive byte
//!    flips + a truncation over the assembled `meta` body; the same
//!    parse + resolution battery runs on the mutant with no identity
//!    asserts (contract: no panic, no unbounded allocation).

use libfuzzer_sys::fuzz_target;
use oxideav_mp4::demux::{
    self, IinfBox, IlocBox, IlocExtent, IlocItem, IrefBox, ItemInfoEntry, ItemProperties,
    ItemProperty, ItemPropertyAssociationEntry, ItemReference, PropertyAssociation,
};
use oxideav_mp4_fuzz::Recipe;

fn wrap(fourcc: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(fourcc);
    out.extend_from_slice(body);
    out
}

/// Minimal §8.4.3 `hdlr` with the given handler type.
fn hdlr(handler: &[u8; 4]) -> Vec<u8> {
    let mut body = vec![0u8; 4]; // version/flags
    body.extend_from_slice(&[0u8; 4]); // pre_defined
    body.extend_from_slice(handler);
    body.extend_from_slice(&[0u8; 12]); // reserved
    body.push(0); // empty NUL-terminated name
    wrap(b"hdlr", &body)
}

fn exercise_meta(body: &[u8]) {
    let meta = demux::parse_meta_items(body);
    let mut ids: Vec<u32> = Vec::new();
    if let Some(iloc) = &meta.iloc {
        ids.extend(iloc.items.iter().map(|it| it.item_id));
    }
    if let Some(pid) = meta.primary_item_id {
        ids.push(pid);
    }
    // A couple of IDs the catalogue never declared, too.
    ids.push(0);
    ids.push(u32::MAX);
    for id in ids {
        let _ = meta.item_byte_ranges(id);
        let _ = meta.item_data_from_idat(id);
        if let Some(iprp) = &meta.iprp {
            let _ = iprp.properties_for(id).len();
            let _ = iprp.property(id as u16);
        }
    }
    if let Some(grpl) = &meta.grpl {
        for g in &grpl.groups {
            let _ = grpl.by_type(g.grouping_type).count();
            let _ = grpl.by_id(g.group_id);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut r = Recipe::new(data);

    let n_items = 1 + (r.u8() % 6) as u32;
    let item_ids: Vec<u32> = (1..=n_items).collect();

    // ── iloc: width selectors × construction methods ────────────────
    let version = r.u8() % 3;
    let pick_size = |b: u8| [4u8, 8][(b % 2) as usize];
    let offset_size = pick_size(r.u8());
    let length_size = pick_size(r.u8());
    let base_offset_size = [0u8, 4, 8][(r.u8() % 3) as usize];
    let index_size = if version == 0 {
        0
    } else {
        [0u8, 4, 8][(r.u8() % 3) as usize]
    };
    let mut iloc_items = Vec::new();
    for &id in &item_ids {
        let construction_method = if version == 0 { 0 } else { r.u8() % 3 };
        let n_ext = 1 + (r.u8() % 3) as usize;
        let mut extents = Vec::with_capacity(n_ext);
        for _ in 0..n_ext {
            extents.push(IlocExtent {
                extent_index: if index_size > 0 { r.u8() as u64 } else { 0 },
                extent_offset: r.u16() as u64,
                extent_length: r.u16() as u64,
            });
        }
        iloc_items.push(IlocItem {
            item_id: id,
            construction_method,
            data_reference_index: (r.u8() % 2) as u16,
            base_offset: if base_offset_size > 0 {
                r.u16() as u64
            } else {
                0
            },
            extents,
        });
    }
    let iloc = IlocBox {
        version,
        offset_size,
        length_size,
        base_offset_size,
        index_size,
        items: iloc_items,
    };

    // ── iinf: v2 typed entries ──────────────────────────────────────
    let types: [[u8; 4]; 5] = [*b"mime", *b"uri ", *b"av01", *b"hvc1", *b"Exif"];
    let mut iinf = IinfBox::default();
    for &id in &item_ids {
        let item_type = types[(r.u8() % 5) as usize];
        iinf.entries.push(ItemInfoEntry {
            item_id: id,
            item_type,
            item_name: String::from_utf8_lossy(&r.take(4)).into_owned(),
            content_type: if &item_type == b"mime" {
                "image/heic".to_string()
            } else {
                String::new()
            },
            version: 2,
            ..ItemInfoEntry::default()
        });
    }

    // ── iref: typed groups, cycles allowed ──────────────────────────
    let ref_types: [[u8; 4]; 4] = [*b"dimg", *b"thmb", *b"cdsc", *b"auxl"];
    let n_refs = (r.u8() % 4) as usize;
    let mut references = Vec::with_capacity(n_refs);
    for _ in 0..n_refs {
        let from = item_ids[(r.u8() as usize) % item_ids.len()];
        let n_to = 1 + (r.u8() % 3) as usize;
        let to: Vec<u32> = (0..n_to)
            .map(|_| item_ids[(r.u8() as usize) % item_ids.len()])
            .collect();
        references.push(ItemReference {
            reference_type: ref_types[(r.u8() % 4) as usize],
            from_item_id: from,
            to_item_ids: to,
        });
    }
    let iref = IrefBox {
        version: 0,
        references,
    };

    // ── iprp: property list + associations ──────────────────────────
    let n_props = 1 + (r.u8() % 4) as usize;
    let mut properties = Vec::with_capacity(n_props);
    for _ in 0..n_props {
        properties.push(match r.u8() % 4 {
            0 => ItemProperty::Ispe {
                image_width: r.u16() as u32,
                image_height: r.u16() as u32,
            },
            1 => ItemProperty::Irot { angle: r.u8() % 4 },
            2 => ItemProperty::Pixi {
                bits_per_channel: r.take(3),
            },
            _ => ItemProperty::Other {
                box_type: *b"zzzz",
                body: r.take(6),
            },
        });
    }
    let mut assoc = Vec::new();
    for &id in &item_ids {
        if r.u8() & 1 == 0 {
            continue;
        }
        let n_a = 1 + (r.u8() % 3) as usize;
        let associations = (0..n_a)
            .map(|_| PropertyAssociation {
                essential: r.u8() & 1 == 1,
                // Deliberately reaches past the ipco list (max index
                // n_props) — out-of-range associations are legal bytes
                // the resolver must skip.
                property_index: (r.u8() % 24) as u16,
            })
            .collect();
        assoc.push(ItemPropertyAssociationEntry {
            item_id: id,
            associations,
        });
    }
    let iprp = ItemProperties {
        properties,
        associations: assoc,
    };

    let idat_len = 1 + (r.u8() % 96) as usize;
    let idat: Vec<u8> = r.take(idat_len);
    let primary = item_ids[(r.u8() as usize) % item_ids.len()];

    // ── Assemble the meta body via the byte-exact builders ──────────
    let mut body = vec![0u8; 4]; // meta FullBox version/flags
    body.extend_from_slice(&hdlr(b"pict"));
    body.extend_from_slice(&demux::build_pitm_box(primary));
    let built_iloc = demux::build_iloc_box(&iloc);
    if let Some(b) = &built_iloc {
        body.extend_from_slice(b);
    }
    let built_iinf = demux::build_iinf_box(&iinf);
    if let Some(b) = &built_iinf {
        body.extend_from_slice(b);
    }
    let built_iref = demux::build_iref_box(&iref);
    if let Some(b) = &built_iref {
        body.extend_from_slice(b);
    }
    let built_iprp = demux::build_iprp_box(&iprp);
    if let Some(b) = &built_iprp {
        body.extend_from_slice(b);
    }
    body.extend_from_slice(&demux::build_idat_box(&idat));

    // ── Arm 1: identity through the full meta walk ──────────────────
    let meta = demux::parse_meta_items(&body);
    assert_eq!(meta.handler_type, *b"pict", "meta hdlr identity");
    assert_eq!(meta.primary_item_id, Some(primary), "pitm identity");
    if built_iloc.is_some() {
        assert_eq!(meta.iloc.as_ref(), Some(&iloc), "iloc identity");
    }
    if built_iinf.is_some() {
        assert_eq!(meta.iinf.as_ref(), Some(&iinf), "iinf identity");
    }
    if built_iref.is_some() {
        assert_eq!(meta.iref.as_ref(), Some(&iref), "iref identity");
    }
    if built_iprp.is_some() && !iprp.is_empty() {
        // build_ipma_box sorts entries by ascending item_ID (§9.3.1);
        // the parsed associations come back in that order.
        let mut expect = iprp.clone();
        expect.associations.sort_by_key(|e| e.item_id);
        assert_eq!(meta.iprp.as_ref(), Some(&expect), "iprp identity");
    }
    assert_eq!(meta.idat, idat, "idat identity");
    exercise_meta(&body);

    // ── Arm 2: hostile mutation of the assembled body ───────────────
    let mut m = body;
    let mut ops = Recipe::new(r.rest());
    let n_ops = 1 + (ops.u8() % 8) as usize;
    for _ in 0..n_ops {
        if m.is_empty() {
            break;
        }
        match ops.u8() % 4 {
            0 | 1 | 3 => {
                let pos = ops.u32() as usize % m.len();
                m[pos] ^= ops.u8().max(1);
            }
            _ => {
                let cut = ops.u32() as usize % (m.len() + 1);
                m.truncate(cut);
                break;
            }
        }
    }
    exercise_meta(&m);
});
