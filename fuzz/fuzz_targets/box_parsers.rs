#![no_main]

//! Hostile bytes through every standalone public box parser — the
//! open fronts a caller can reach *without* a full `open()`: the HEIF
//! item catalogue (`iloc` / `pitm` / `iinf` / `iref` / `ipma` /
//! `ipco` / `iprp` / `grpl` / `mere` / `meco`, plus the assembled
//! `parse_meta_items` walk with byte-range / idat resolution over the
//! parsed graph), edit lists, CENC (`tenc` / `pssh` / `senc` /
//! `seig`) and their PIFF `uuid` predecessors, `emsg`, FD item
//! information, hint sample entries + statistics, sample-group entry
//! blobs, the QuickTime `gmin` / `tcmi` / `tmcd` / `text` / `load`
//! atoms, the aux-info / subsample / random-access records (`saiz` /
//! `saio` / `subs` / `sidx` / `ssix` / `mfra` / `prft` / `pdin` /
//! `pnot` / `leva` / `trep` / `assp` / `stvi` / `csgp`), and the raw
//! §4.2 box-header reader.
//!
//! Two contracts per arm:
//!   1. the parser must return (Ok/Some/Err/None) — never panic,
//!      overflow in a debug build, or allocate beyond what the input
//!      backs;
//!   2. **parse∘build fixed-point** — when the crate exposes the
//!      byte-exact builder dual and it accepts the parsed record,
//!      rebuilding and reparsing MUST reproduce the identical record.
//!      A mismatch means parser and builder disagree about the wire
//!      format, which is a real bug even when no crash is reachable.

use libfuzzer_sys::fuzz_target;
use oxideav_mp4::sample_group_entries as sge;
use oxideav_mp4::{cenc, demux, emsg, fd, hint};
use oxideav_mp4_fuzz::Recipe;

/// Body of a `[size][fourcc]`-wrapped builder output ( `uuid` boxes
/// also carry a 16-byte usertype).
fn body_of(built: &[u8]) -> &[u8] {
    if built.len() >= 8 {
        let declared = u32::from_be_bytes([built[0], built[1], built[2], built[3]]) as usize;
        if declared == built.len() {
            if &built[4..8] == b"uuid" && built.len() >= 24 {
                return &built[24..];
            }
            return &built[8..];
        }
    }
    built
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mut r = Recipe::new(data);
    let sel = r.u8();
    let aux = r.u8();
    let body = r.rest();

    // IV width selector for the senc-family parsers (§7.2.3: the box
    // does not carry its own width; the caller supplies it from tenc).
    let iv_size = [0u8, 8, 16][(aux % 3) as usize];

    match sel % 44 {
        // ── HEIF item catalogue ────────────────────────────────────
        0 => {
            if let Some(rec) = demux::parse_iloc_box(body) {
                if let Some(rebuilt) = demux::build_iloc_box(&rec) {
                    let again =
                        demux::parse_iloc_box(body_of(&rebuilt)).expect("iloc reparse after build");
                    assert_eq!(again, rec, "iloc parse∘build fixed-point");
                }
            }
        }
        1 => {
            if let Some(id) = demux::parse_pitm_box(body) {
                let rebuilt = demux::build_pitm_box(id);
                assert_eq!(
                    demux::parse_pitm_box(body_of(&rebuilt)),
                    Some(id),
                    "pitm parse∘build fixed-point"
                );
            }
        }
        2 => {
            if let Some(rec) = demux::parse_iinf_box(body) {
                if let Some(rebuilt) = demux::build_iinf_box(&rec) {
                    let again =
                        demux::parse_iinf_box(body_of(&rebuilt)).expect("iinf reparse after build");
                    assert_eq!(again, rec, "iinf parse∘build fixed-point");
                }
            }
        }
        3 => {
            if let Some(rec) = demux::parse_iref_box(body) {
                if let Some(rebuilt) = demux::build_iref_box(&rec) {
                    let again =
                        demux::parse_iref_box(body_of(&rebuilt)).expect("iref reparse after build");
                    assert_eq!(again, rec, "iref parse∘build fixed-point");
                }
            }
        }
        4 => {
            // Assembled meta walk + graph resolution over whatever
            // hostile catalogue came out (cycles, overlaps, huge
            // lengths — resolution must bound-check, never panic).
            let meta = demux::parse_meta_items(body);
            let mut ids: Vec<u32> = Vec::new();
            if let Some(iloc) = &meta.iloc {
                ids.extend(iloc.items.iter().map(|it| it.item_id));
            }
            if let Some(pid) = meta.primary_item_id {
                ids.push(pid);
            }
            for id in ids {
                let _ = meta.item_byte_ranges(id);
                let _ = meta.item_data_from_idat(id);
                if let Some(iprp) = &meta.iprp {
                    let _ = iprp.properties_for(id).len();
                }
            }
        }
        5 => {
            let props = demux::parse_ipco_box(body);
            let rebuilt = demux::build_ipco_box(&props);
            assert_eq!(
                demux::parse_ipco_box(body_of(&rebuilt)),
                props,
                "ipco parse∘build fixed-point"
            );
        }
        6 => {
            let entries = demux::parse_ipma_box(body);
            if let Some(rebuilt) = demux::build_ipma_box(&entries) {
                let mut sorted = entries.clone();
                sorted.sort_by_key(|e| e.item_id);
                assert_eq!(
                    demux::parse_ipma_box(body_of(&rebuilt)),
                    sorted,
                    "ipma parse∘build fixed-point (builder sorts by item_ID per §9.3.1)"
                );
            }
        }
        7 => {
            let rec = demux::parse_iprp_box(body);
            if let Some(rebuilt) = demux::build_iprp_box(&rec) {
                assert_eq!(
                    demux::parse_iprp_box(body_of(&rebuilt)),
                    rec,
                    "iprp parse∘build fixed-point"
                );
            }
        }
        8 => {
            let rec = demux::parse_grpl_box(body);
            let rebuilt = demux::build_grpl_box(&rec);
            assert_eq!(
                demux::parse_grpl_box(body_of(&rebuilt)),
                rec,
                "grpl parse∘build fixed-point"
            );
        }
        9 => {
            if let Some(rec) = demux::parse_mere_box(body) {
                let rebuilt = demux::build_mere_box(&rec);
                assert_eq!(
                    demux::parse_mere_box(body_of(&rebuilt)),
                    Some(rec),
                    "mere parse∘build fixed-point"
                );
            }
        }
        10 => {
            let _ = demux::parse_meco_box(body);
        }

        // ── Edit lists ─────────────────────────────────────────────
        11 => {
            if let Ok(entries) = demux::parse_elst_box(body) {
                if let Ok(rebuilt) = demux::build_elst_box(&entries) {
                    let again =
                        demux::parse_elst_box(body_of(&rebuilt)).expect("elst reparse after build");
                    assert_eq!(again, entries, "elst parse∘build fixed-point");
                }
            }
        }

        // ── CENC / PIFF ────────────────────────────────────────────
        12 => {
            if let Ok(rec) = cenc::parse_tenc(body) {
                if let Ok(rebuilt) = cenc::build_tenc_box(&rec) {
                    let again =
                        cenc::parse_tenc(body_of(&rebuilt)).expect("tenc reparse after build");
                    assert_eq!(again, rec, "tenc parse∘build fixed-point");
                }
            }
        }
        13 => {
            if let Ok(rec) = cenc::parse_pssh(body) {
                if let Ok(rebuilt) = cenc::build_pssh_box(&rec) {
                    let again =
                        cenc::parse_pssh(body_of(&rebuilt)).expect("pssh reparse after build");
                    assert_eq!(again, rec, "pssh parse∘build fixed-point");
                }
            }
        }
        14 => {
            if let Ok(rec) = cenc::parse_senc(body, iv_size) {
                if let Ok(rebuilt) = cenc::build_senc_box(&rec) {
                    let again = cenc::parse_senc(body_of(&rebuilt), iv_size)
                        .expect("senc reparse after build");
                    assert_eq!(again, rec, "senc parse∘build fixed-point");
                }
            }
        }
        15 => {
            if let Ok(rec) = cenc::parse_seig(body) {
                if let Ok(rebuilt) = cenc::build_seig_entry(&rec) {
                    let again = cenc::parse_seig(&rebuilt).expect("seig reparse after build");
                    assert_eq!(again, rec, "seig parse∘build fixed-point");
                }
            }
        }
        16 => {
            if let Ok(rec) = cenc::parse_piff_tenc(body) {
                if let Ok(rebuilt) = cenc::build_piff_tenc_box(&rec) {
                    let again = cenc::parse_piff_tenc(body_of(&rebuilt))
                        .expect("piff tenc reparse after build");
                    assert_eq!(again, rec, "piff tenc parse∘build fixed-point");
                }
            }
        }
        17 => {
            if let Ok(rec) = cenc::parse_piff_senc(body, iv_size) {
                if let Ok(rebuilt) = cenc::build_piff_senc_box(&rec) {
                    let again = cenc::parse_piff_senc(body_of(&rebuilt), iv_size)
                        .expect("piff senc reparse after build");
                    assert_eq!(again, rec, "piff senc parse∘build fixed-point");
                }
            }
        }
        18 => {
            if let Ok(rec) = cenc::parse_piff_pssh(body) {
                if let Ok(rebuilt) = cenc::build_piff_pssh_box(&rec) {
                    let again = cenc::parse_piff_pssh(body_of(&rebuilt))
                        .expect("piff pssh reparse after build");
                    assert_eq!(again, rec, "piff pssh parse∘build fixed-point");
                }
            }
        }

        // ── emsg ───────────────────────────────────────────────────
        19 => {
            if let Ok(rec) = emsg::parse_emsg_box(body) {
                if let Ok(rebuilt) = emsg::build_emsg_box(&rec) {
                    let again =
                        emsg::parse_emsg_box(body_of(&rebuilt)).expect("emsg reparse after build");
                    assert_eq!(again, rec, "emsg parse∘build fixed-point");
                }
            }
        }

        // ── FD item information ────────────────────────────────────
        20 => {
            if let Some(rec) = fd::parse_fpar_box(body) {
                let rebuilt = fd::build_fpar_box(&rec);
                assert_eq!(
                    fd::parse_fpar_box(body_of(&rebuilt)),
                    Some(rec),
                    "fpar parse∘build fixed-point"
                );
            }
        }
        21 => {
            if let Some(rec) = fd::parse_reservoir_box(body) {
                let fourcc = if aux & 1 == 0 { *b"fecr" } else { *b"fire" };
                let rebuilt = fd::build_reservoir_box(&fourcc, &rec);
                assert_eq!(
                    fd::parse_reservoir_box(body_of(&rebuilt)),
                    Some(rec),
                    "fecr/fire parse∘build fixed-point"
                );
            }
        }
        22 => {
            let rec = fd::parse_paen_box(body);
            let rebuilt = fd::build_paen_box(&rec);
            assert_eq!(
                fd::parse_paen_box(body_of(&rebuilt)),
                rec,
                "paen parse∘build fixed-point"
            );
        }
        23 => {
            if let Some(rec) = fd::parse_segr_box(body) {
                let rebuilt = fd::build_segr_box(&rec);
                assert_eq!(
                    fd::parse_segr_box(body_of(&rebuilt)),
                    Some(rec),
                    "segr parse∘build fixed-point"
                );
            }
        }
        24 => {
            if let Some(rec) = fd::parse_gitn_box(body) {
                let rebuilt = fd::build_gitn_box(&rec);
                assert_eq!(
                    fd::parse_gitn_box(body_of(&rebuilt)),
                    Some(rec),
                    "gitn parse∘build fixed-point"
                );
            }
        }
        25 => {
            if let Some(rec) = fd::parse_fiin_box(body) {
                let rebuilt = fd::build_fiin_box(&rec);
                assert_eq!(
                    fd::parse_fiin_box(body_of(&rebuilt)),
                    Some(rec),
                    "fiin parse∘build fixed-point"
                );
            }
        }
        26 => {
            if let Some(rec) = fd::parse_feci_box(body) {
                let rebuilt = fd::build_feci_box(&rec);
                assert_eq!(
                    fd::parse_feci_box(body_of(&rebuilt)),
                    Some(rec),
                    "feci parse∘build fixed-point"
                );
            }
        }

        // ── Hint tracks ────────────────────────────────────────────
        27 => {
            if let Some(rec) = hint::parse_srpp_box(body) {
                let rebuilt = hint::build_srpp_box(&rec);
                assert_eq!(
                    hint::parse_srpp_box(body_of(&rebuilt)),
                    Some(rec),
                    "srpp parse∘build fixed-point"
                );
            }
        }
        28 => {
            let format = [*b"rtp ", *b"srtp", *b"rrtp", *b"rtcp"][(aux % 4) as usize];
            let _ = hint::parse_rtp_hint_sample_entry(format, body);
        }
        29 => {
            let format = if aux & 1 == 0 { *b"sm2t" } else { *b"rm2t" };
            let _ = hint::parse_mpeg2ts_hint_sample_entry(format, body);
        }
        30 => {
            let rec = hint::parse_hinf_box(body);
            let rebuilt = hint::build_hinf_box(&rec);
            assert_eq!(
                hint::parse_hinf_box(body_of(&rebuilt)),
                rec,
                "hinf parse∘build fixed-point"
            );
        }

        // ── Sample-group entry blobs ───────────────────────────────
        31 => {
            let gt = [
                *b"roll", *b"prol", *b"rash", *b"alst", *b"rap ", *b"tele", *b"sap ",
            ][(aux % 7) as usize];
            let _ = sge::decode_sample_group_entry(&gt, body);
            if let Ok(rec) = sge::parse_roll(body) {
                let again = sge::parse_roll(&sge::build_roll(&rec));
                assert_eq!(again.ok(), Some(rec), "roll blob fixed-point");
            }
            if let Ok(rec) = sge::parse_rash(body) {
                let again = sge::parse_rash(&sge::build_rash(&rec));
                assert_eq!(again.ok(), Some(rec), "rash blob fixed-point");
            }
            if let Ok(rec) = sge::parse_alst(body) {
                let again = sge::parse_alst(&sge::build_alst(&rec));
                assert_eq!(again.ok(), Some(rec), "alst blob fixed-point");
            }
            if let Ok(rec) = sge::parse_rap(body) {
                let again = sge::parse_rap(&sge::build_rap(&rec));
                assert_eq!(again.ok(), Some(rec), "rap blob fixed-point");
            }
            if let Ok(rec) = sge::parse_tele(body) {
                let again = sge::parse_tele(&sge::build_tele(&rec));
                assert_eq!(again.ok(), Some(rec), "tele blob fixed-point");
            }
            if let Ok(rec) = sge::parse_sap(body) {
                let again = sge::parse_sap(&sge::build_sap(&rec));
                assert_eq!(again.ok(), Some(rec), "sap blob fixed-point");
            }
        }

        // ── QuickTime atoms ────────────────────────────────────────
        32 => {
            if let Ok(rec) = demux::parse_gmin_box(body) {
                let rebuilt = demux::build_gmin_box(&rec);
                let again =
                    demux::parse_gmin_box(body_of(&rebuilt)).expect("gmin reparse after build");
                assert_eq!(again, rec, "gmin parse∘build fixed-point");
            }
        }
        33 => {
            if let Ok(rec) = demux::parse_tcmi_box(body) {
                let rebuilt = demux::build_tcmi_box(&rec);
                let again =
                    demux::parse_tcmi_box(body_of(&rebuilt)).expect("tcmi reparse after build");
                // A font name longer than 255 UTF-8 bytes (lossy
                // expansion of a non-UTF-8 wire name) is not
                // representable in the Pascal length byte — the
                // builder truncates it at a char boundary, so exact
                // fixed-point only applies to representable records.
                if rec.font_name.len() <= 255 {
                    assert_eq!(again, rec, "tcmi parse∘build fixed-point");
                } else {
                    assert!(
                        rec.font_name.starts_with(&again.font_name),
                        "tcmi over-long name must rebuild to a clean prefix"
                    );
                }
            }
        }
        34 => {
            let _ = demux::parse_tmcd_sample_entry_box(body);
            let _ = demux::parse_text_sample_entry_box(body);
        }
        35 => {
            if let Ok(rec) = demux::parse_load_settings_box(body) {
                let rebuilt = demux::build_load_settings_box(&rec);
                let again = demux::parse_load_settings_box(body_of(&rebuilt))
                    .expect("load reparse after build");
                assert_eq!(again, rec, "load parse∘build fixed-point");
            }
        }

        // ── Visual/aux records ─────────────────────────────────────
        36 => {
            if let Ok(rec) = demux::parse_pasp_box(body) {
                let rebuilt = demux::build_pasp_box(&rec);
                assert_eq!(
                    demux::parse_pasp_box(body_of(&rebuilt)).ok(),
                    Some(rec),
                    "pasp parse∘build fixed-point"
                );
            }
            if let Ok(rec) = demux::parse_clap_box(body) {
                let rebuilt = demux::build_clap_box(&rec);
                assert_eq!(
                    demux::parse_clap_box(body_of(&rebuilt)).ok(),
                    Some(rec),
                    "clap parse∘build fixed-point"
                );
            }
            if let Ok(rec) = demux::parse_colr_box(body) {
                let rebuilt = demux::build_colr_box(&rec);
                assert_eq!(
                    demux::parse_colr_box(body_of(&rebuilt)).ok(),
                    Some(rec),
                    "colr parse∘build fixed-point"
                );
            }
            let _ = demux::parse_amve_box(body);
            let _ = demux::parse_btrt_box(body);
        }
        37 => {
            if let Ok(rec) = demux::parse_stvi_box(body) {
                if let Ok(rebuilt) = demux::build_stvi_box(&rec) {
                    assert_eq!(
                        demux::parse_stvi_box(body_of(&rebuilt)).ok(),
                        Some(rec),
                        "stvi parse∘build fixed-point"
                    );
                }
            }
        }

        // ── Aux-info / subsample / random access ───────────────────
        38 => {
            if let Ok(rec) = demux::parse_saiz_box(body) {
                if let Some(rebuilt) = demux::build_saiz_box(&rec) {
                    assert_eq!(
                        demux::parse_saiz_box(body_of(&rebuilt)).ok(),
                        Some(rec),
                        "saiz parse∘build fixed-point"
                    );
                }
            }
            if let Ok(rec) = demux::parse_saio_box(body) {
                if let Some(rebuilt) = demux::build_saio_box(&rec) {
                    assert_eq!(
                        demux::parse_saio_box(body_of(&rebuilt)).ok(),
                        Some(rec),
                        "saio parse∘build fixed-point"
                    );
                }
            }
        }
        39 => {
            if let Ok(rec) = demux::parse_subs_box(body) {
                if let Some(rebuilt) = demux::build_subs_box(&rec) {
                    assert_eq!(
                        demux::parse_subs_box(body_of(&rebuilt)).ok(),
                        Some(rec),
                        "subs parse∘build fixed-point"
                    );
                }
            }
        }
        40 => {
            let end = r.u64();
            let _ = demux::parse_sidx_box(body, end);
            let _ = demux::parse_mfra_box(body);
            let _ = demux::parse_csgp_box(body);
        }
        41 => {
            if let Ok(rec) = demux::parse_ssix_box(body) {
                if let Ok(rebuilt) = demux::build_ssix_box(&rec) {
                    assert_eq!(
                        demux::parse_ssix_box(body_of(&rebuilt)).ok(),
                        Some(rec),
                        "ssix parse∘build fixed-point"
                    );
                }
            }
            if let Ok(Some(rec)) = demux::parse_prft_box(body) {
                if let Some(rebuilt) = demux::build_prft_box(&rec) {
                    assert_eq!(
                        demux::parse_prft_box(body_of(&rebuilt)).ok(),
                        Some(Some(rec)),
                        "prft parse∘build fixed-point"
                    );
                }
            }
        }
        42 => {
            if let Ok(rec) = demux::parse_pdin_box(body) {
                let rebuilt = demux::build_pdin_box(&rec);
                assert_eq!(
                    demux::parse_pdin_box(body_of(&rebuilt)).ok(),
                    Some(rec),
                    "pdin parse∘build fixed-point"
                );
            }
            if let Ok(rec) = demux::parse_pnot_box(body) {
                let rebuilt = demux::build_pnot_box(&rec);
                assert_eq!(
                    demux::parse_pnot_box(body_of(&rebuilt)).ok(),
                    Some(rec),
                    "pnot parse∘build fixed-point"
                );
            }
            if let Ok(rec) = demux::parse_leva_box(body) {
                if let Ok(rebuilt) = demux::build_leva_box(&rec) {
                    assert_eq!(
                        demux::parse_leva_box(body_of(&rebuilt)).ok(),
                        Some(rec),
                        "leva parse∘build fixed-point"
                    );
                }
            }
            if let Ok(rec) = demux::parse_trep_box(body) {
                if let Ok(rebuilt) = demux::build_trep_box(&rec) {
                    // `payload_len` records the *original* wire length
                    // of each child; a typed child whose wire form
                    // carried tolerated trailing bytes rebuilds to the
                    // canonical (shorter) payload, so compare modulo
                    // that bookkeeping field.
                    let mut again =
                        demux::parse_trep_box(body_of(&rebuilt)).expect("trep reparse after build");
                    let mut want = rec;
                    for c in again.children.iter_mut().chain(want.children.iter_mut()) {
                        c.payload_len = 0;
                    }
                    assert_eq!(again, want, "trep parse∘build fixed-point");
                }
            }
            if let Ok(rec) = demux::parse_assp_box(body) {
                if let Ok(rebuilt) = demux::build_assp_box(&rec) {
                    assert_eq!(
                        demux::parse_assp_box(body_of(&rebuilt)).ok(),
                        Some(rec),
                        "assp parse∘build fixed-point"
                    );
                }
            }
        }

        // ── Raw §4.2 box-header walk ───────────────────────────────
        _ => {
            let mut cur = std::io::Cursor::new(body.to_vec());
            for _ in 0..64 {
                match oxideav_mp4::boxes::read_box_header(&mut cur) {
                    Ok(Some(h)) => {
                        if aux & 1 == 0 {
                            if oxideav_mp4::boxes::read_box_body(&mut cur, &h).is_err() {
                                break;
                            }
                        } else if oxideav_mp4::boxes::skip_box_body(&mut cur, &h).is_err() {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
});
