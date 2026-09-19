// src/bdb/bdb_writer.cpp
//
// Minimal BDB hash file writer for synthetic test fixtures.
//
// Emits a 2-page BDB hash database that our own Reader can fully
// re-parse. The format is compatible with the BDB 4.x hash file
// layout documented in db_page.h, but only the simplest case:
//
//   Page 0: HASHMETA (page_type=8, magic=0x00061561, version=9,
//                      pagesize=4096, last_pgno=1)
//   Page 1: P_HASH_UNSORTED data page with all the records.
//
// If the records do not fit on a single page, we chain additional
// data pages with prev_pgno / next_pgno links (and update last_pgno
// in the metadata page accordingly).
//
// The historical Bitcoin Core client used a more sophisticated
// multi-bucket hash layout, but our reader walks pages linearly
// and identifies hash data pages by their page_type — so the
// simpler layout we emit here is functionally indistinguishable.
//
#include "btclegacy/bdb/bdb_writer.h"
#include "btclegacy/util/file_util.h"
#include <cstring>
#include <cstdint>
#include <vector>

namespace btclegacy::bdb {

namespace {
inline void put_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(uint8_t(x & 0xff));
    v.push_back(uint8_t((x >> 8) & 0xff));
}
inline void put_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t(x & 0xff));
    v.push_back(uint8_t((x >> 8) & 0xff));
    v.push_back(uint8_t((x >> 16) & 0xff));
    v.push_back(uint8_t((x >> 24) & 0xff));
}
inline void put_u64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v.push_back(uint8_t((x >> (i*8)) & 0xff));
    }
}

// Helper to write a uint16 at a specific offset within a page.
inline void set_u16(std::vector<uint8_t>& page, size_t offset, uint16_t value) {
    page[offset]   = uint8_t(value & 0xff);
    page[offset+1] = uint8_t((value >> 8) & 0xff);
}
inline void set_u32(std::vector<uint8_t>& page, size_t offset, uint32_t value) {
    page[offset]   = uint8_t(value & 0xff);
    page[offset+1] = uint8_t((value >> 8) & 0xff);
    page[offset+2] = uint8_t((value >> 16) & 0xff);
    page[offset+3] = uint8_t((value >> 24) & 0xff);
}

// Layout of a single page's content. Page header is 26 bytes, then
// an `entries*2` byte item-offset table, then items stored from the
// high end of the page backwards (this matches BDB).
//
// Each BKEYDATA item has: type:u16=1, len:u16, then `len` bytes of data.
struct PackedPage {
    uint32_t pgno;
    uint32_t next_pgno = 0;
    uint32_t prev_pgno = 0;
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> pairs;
};

std::vector<uint8_t> emit_page(const PackedPage& pp, uint32_t pagesize) {
    std::vector<uint8_t> page(pagesize, 0);
    // Header at 0..25
    // 0..7: LSN (already zero)
    set_u32(page, 8,  pp.pgno);
    set_u32(page, 12, pp.prev_pgno);
    set_u32(page, 16, pp.next_pgno);
    set_u16(page, 20, uint16_t(pp.pairs.size() * 2));  // entries
    // 22: hf_offset (filled later)
    page[24] = 1;                          // level=1 (leaf)
    page[25] = PAGE_TYPE_HASH_UNSORTED;   // type

    size_t entries = pp.pairs.size() * 2;
    size_t inp_off = 26;
    size_t inp_size = entries * 2;
    if (26 + inp_size > pagesize) {
        return page; // cannot fit even empty items
    }

    size_t high = pagesize;
    size_t idx = 0;
    for (auto& kv : pp.pairs) {
        // Key item
        size_t k_item_size = 4 + kv.first.size();
        size_t k_off = high - k_item_size;
        if (k_off < 26 + inp_size) return page;
        high = k_off;
        set_u16(page, k_off, BKEYDATA_KEYDATA);
        set_u16(page, k_off + 2, uint16_t(kv.first.size()));
        std::memcpy(&page[k_off + 4], kv.first.data(), kv.first.size());
        set_u16(page, inp_off + idx*2, uint16_t(k_off));
        idx++;
        // Value item
        size_t v_item_size = 4 + kv.second.size();
        size_t v_off = high - v_item_size;
        if (v_off < 26 + inp_size) return page;
        high = v_off;
        set_u16(page, v_off, BKEYDATA_KEYDATA);
        set_u16(page, v_off + 2, uint16_t(kv.second.size()));
        std::memcpy(&page[v_off + 4], kv.second.data(), kv.second.size());
        set_u16(page, inp_off + idx*2, uint16_t(v_off));
        idx++;
    }
    set_u16(page, 22, uint16_t(high)); // hf_offset
    return page;
}

} // namespace

bool write_bdb_hash_file(const std::string& path,
                          const std::vector<WriteRecord>& records,
                          uint32_t pagesize,
                          std::string* err) {
    std::vector<uint8_t> meta(pagesize, 0);
    // 0..7: LSN (zero)
    set_u32(meta, 8,  0);                  // pgno
    set_u32(meta, 12, DB_HASHMAGIC);       // magic
    set_u32(meta, 16, 9);                  // version
    set_u32(meta, 20, pagesize);            // pagesize
    meta[24] = 0;                          // encrypt_alg
    meta[25] = PAGE_TYPE_HASHMETA;         // page_type = 8
    meta[26] = 0;                          // metaflags

    // Layout records into pages
    std::vector<PackedPage> pages;
    PackedPage cur;
    cur.pgno = 1;
    auto fits = [&](const WriteRecord& r) -> bool {
        size_t used = 0;
        for (auto& kv : cur.pairs) used += 8 + kv.first.size() + kv.second.size();
        used += 8 + r.key.size() + r.value.size();
        used += (cur.pairs.size() + 1) * 4;
        return used + 26 < pagesize;
    };
    for (auto& r : records) {
        if (!fits(r)) {
            pages.push_back(cur);
            cur = PackedPage{};
            cur.pgno = uint32_t(pages.size() + 2);
        }
        cur.pairs.emplace_back(r.key, r.value);
    }
    if (!cur.pairs.empty()) pages.push_back(cur);
    if (pages.empty()) { PackedPage p; p.pgno = 1; pages.push_back(p); }

    for (size_t i = 0; i < pages.size(); ++i) {
        pages[i].prev_pgno = (i == 0) ? 0 : pages[i-1].pgno;
        pages[i].next_pgno = (i+1 < pages.size()) ? pages[i+1].pgno : 0;
    }
    uint32_t last_pgno = pages.back().pgno;

    set_u32(meta, 61, last_pgno);                       // last_pgno
    set_u32(meta, 69, uint32_t(records.size()));         // keycount
    set_u32(meta, 73, uint32_t(records.size()));         // record_count

    // Hash-specific fields at offset 84+
    set_u32(meta, 84, 0);                               // maxbucket
    set_u32(meta, 88, 0);                               // high_mask
    set_u32(meta, 92, 0);                               // low_mask
    set_u32(meta, 96, 1);                               // ffactor
    set_u32(meta, 100, uint32_t(records.size()));        // nelem
    set_u32(meta, 104, 0);                              // h_charkey

    std::vector<uint8_t> file_data = meta;
    for (auto& p : pages) {
        auto pg = emit_page(p, pagesize);
        file_data.insert(file_data.end(), pg.begin(), pg.end());
    }

    if (!util::write_all(path, file_data)) {
        if (err) *err = "failed to write file";
        return false;
    }
    return true;
}

} // namespace btclegacy::bdb
