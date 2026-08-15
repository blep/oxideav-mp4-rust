#![no_main]

//! Demux arbitrary fuzz-supplied bytes through the MP4 / ISO Base
//! Media File Format demuxer.
//!
//! The contract under test is purely that the calls *return*: a
//! malformed stream yields `Err(Error::…)`, a well-formed one yields
//! `Ok(_)` packets until `Error::Eof`, and neither path may panic,
//! abort, integer-overflow (in a debug build), index out of bounds,
//! or attempt an attacker-controlled `Vec::with_capacity` /
//! `vec![0; n]` allocation that exceeds what the input could
//! possibly back. Return values are intentionally discarded.
//!
//! The ISO BMFF attack surface this exercises:
//!   * The box-tree walker, which descends `moov > trak > mdia >
//!     minf > stbl > ...` and the parallel `moof > traf > trun`
//!     fragmented-MP4 tree, where every level is a
//!     `size:u32 / type:FourCC [/ largesize:u64]` length-prefixed
//!     container (ISO/IEC 14496-12 §4.2). `size:u32 = 0` ("to EOF")
//!     and `size:u32 = 1` ("largesize follows") are the two box
//!     sentinels that have historically defeated naive parsers.
//!   * Sample-table expansion — `stts`, `stsc`, `stsz`/`stz2`,
//!     `stco`/`co64`, `stss`, `ctts`, `sdtp`, `sbgp`/`sgpd` all
//!     have attacker-controlled entry counts that drive
//!     allocations and per-sample arithmetic.
//!   * Fragmented MP4 — `tfhd` per-track defaults, `tfdt` base
//!     media decode time, `trun` per-sample overrides, all of
//!     which compose into the absolute file-offset arithmetic that
//!     locates each fragment's payload bytes.
//!   * Edit list (`edts/elst`) — signed `media_time` plus
//!     fixed-point `media_rate`, with segment durations in the
//!     (possibly zero) movie timescale.
//!   * Sample-entry inner parsers — `avcC`, `hvcC`, `av1C`, `vpcC`,
//!     `dfLa`, `dOps`, `dac3`, `dec3`, and the BER-encoded `esds`
//!     descriptor chain, all walked under an outer
//!     `data_reference_index` the input chooses.
//!   * Metadata — 3GPP `udta` boxes (`titl`/`auth`/…) and
//!     iTunes-style `meta`/`ilst` (whose `item > data` inner shape
//!     is itself a recursive box tree).
//!   * `seek_to(0, 0)` re-exercises the sample-table walker from a
//!     random offset.
//!
//! Open is the only entry point: a successful open hands back a
//! demuxer whose `next_packet` then walks every sample / fragment.
//! We cap the per-input packet count so a pathological valid stream
//! can't dominate fuzz time.

use libfuzzer_sys::fuzz_target;
use oxideav_mp4_fuzz::exercise_demux;

fuzz_target!(|data: &[u8]| {
    // The shared battery: typed open front, every public accessor
    // (CENC / PIFF / emsg / HEIF item catalogue / edit lists /
    // fragment records / saiz-saio aux-info resolution), a bounded
    // packet drain, and both seek paths. See
    // `oxideav_mp4_fuzz::exercise_demux` for the full walk.
    exercise_demux(data);
});
