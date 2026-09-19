// src/bdb/bdb_reader.cpp
//
// Read-only Berkeley DB "hash" database reader.
//
// The historical Bitcoin Core wallet.dat from 2009-2015 used BDB 4.x
// configured as a DB_HASH database with default parameters. The page
// layout is documented in Berkeley DB 4.x dbinc/db_page.h and
// dbinc/db_am.h.
//
// Layout summary:
//   Page 0: HASHMETA (page_type=8, magic=0x00061561)
//   Pages 1..last_pgno: data pages (P_HASH_UNSORTED=13 or P_LHASH=14)
//                       or overflow pages (P_OVERFLOW=7) for large values
//
// Page header (26 bytes):
//   0  uint64 lsn
//   8  uint32 pgno
//  12  uint32 prev_pgno
//  16  uint32 next_pgno
//  20  uint16 entries        (number of items on page)
//  22  uint16 hf_offset      (high free byte offset)
//  24  uint8  level
//  25  uint8  type
//
// After the header, an array of `entries` uint16_t offsets (the "inp"
// table) points to per-item structures within the page. The item
// structures are BKEYDATA or BOVERFLOW (see bdb_database.h).
//
// For hash pages, items are laid out as (key, value) pairs. For
// P_HASH_UNSORTED pages (the type used by old BDB 1.85 hash format
// and Bitcoin wallets) the entries array goes:
//     inp[0]=key0, inp[1]=val0, inp[2]=key1, inp[3]=val1, ...
//
#include "btclegacy/bdb/bdb_reader.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/util/file_util.h"
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdexcept>

#ifdef _WIN32
#include <io.h>
#define O_RDONLY _O_RDONLY
#else
#include <unistd.h>
#endif

namespace btclegacy::bdb {

namespace {

inline uint16_t rd_u16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
inline uint32_t rd_u32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t rd_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

constexpr uint16_t PAGE_HEADER_SIZE = 26;

} // namespace

Reader::Reader() = default;
Reader::~Reader() { close(); }

bool Reader::open(const std::string& path, std::string& err) {
    close();
#ifdef _WIN32
    int fd = ::_open(path.c_str(), _O_RDONLY | _O_BINARY);
#else
    int fd = ::open(path.c_str(), O_RDONLY);
#endif
    if (fd < 0) {
        err = std::string("cannot open: ") + path;
        return false;
    }
    fd_ = fd;
    path_ = path;
    file_size_ = util::file_size(path);

    // Read metadata page (page 0). We don't yet know pagesize, so
    // fall back to the default if the field is still zero. The
    // historical Bitcoin Core wallet uses pagesize=4096.
    uint32_t guess_pagesize = WALLET_DEFAULT_PAGESIZE;
    if (guess_pagesize > file_size_ && file_size_ > 256) {
        // Use a smaller guess for tiny files
        guess_pagesize = uint32_t(file_size_);
    }
    // Temporarily set pagesize so read_page works.
    meta_.pagesize = guess_pagesize;
    std::vector<uint8_t> meta_page;
    if (!read_page(0, meta_page, err)) {
        close(); return false;
    }
    // Parse the metadata first to get the real pagesize
    if (!parse_meta_page_(meta_page, meta_, err)) {
        close(); return false;
    }
    // Sanity checks
    if (meta_.magic != DB_HASHMAGIC && meta_.magic != DB_BTREEMAGIC &&
        meta_.magic != DB_QAMMAGIC && meta_.magic != DB_RECNO) {
        err = "unrecognised BDB magic";
        close();
        return false;
    }
    if (meta_.magic != DB_HASHMAGIC) {
        err = "not a BDB hash file (magic=" + util::to_hex(reinterpret_cast<const uint8_t*>(&meta_.magic), 4) + ")";
        close();
        return false;
    }
    if (meta_.pagesize == 0 || meta_.pagesize > (1u<<24)) {
        err = "invalid pagesize";
        close();
        return false;
    }
    stats_.metadata_pages = 1;
    stats_.total_pages = uint32_t((file_size_ + meta_.pagesize - 1) / meta_.pagesize);
    return true;
}

void Reader::close() {
    if (fd_ >= 0) {
#ifdef _WIN32
        ::_close(fd_);
#else
        ::close(fd_);
#endif
        fd_ = -1;
    }
    path_.clear();
    file_size_ = 0;
    meta_ = DatabaseMeta{};
    stats_ = ReadStats{};
}

bool Reader::read_page(uint32_t pgno, std::vector<uint8_t>& out, std::string& err) const {
    if (fd_ < 0) { err = "file not open"; return false; }
    if (meta_.pagesize == 0) { err = "metadata not parsed"; return false; }
    uint64_t off = uint64_t(pgno) * meta_.pagesize;
    if (off >= file_size_) {
        err = "page past EOF";
        return false;
    }
    out.resize(meta_.pagesize);
#ifdef _WIN32
    if (::_lseeki64(fd_, __int64(off), SEEK_SET) != __int64(off)) {
        err = "seek failed"; return false;
    }
    auto r = ::_read(fd_, out.data(), meta_.pagesize);
#else
    if (::lseek(fd_, off_t(off), SEEK_SET) != off_t(off)) {
        err = "seek failed"; return false;
    }
    ssize_t r = ::read(fd_, out.data(), meta_.pagesize);
#endif
    if (r < 0) {
        err = "read failed";
        out.clear();
        return false;
    }
    // Short read at EOF: pad to pagesize with zeros, treat as truncated page.
    if (size_t(r) < out.size()) {
        std::memset(out.data() + r, 0, out.size() - r);
        stats_.errors++;
    }
    return true;
}

bool Reader::parse_page_header(const std::vector<uint8_t>& p, PageHeader& hdr, std::string& err) const {
    if (p.size() < PAGE_HEADER_SIZE) {
        err = "page too short for header";
        return false;
    }
    hdr.lsn        = rd_u64(p.data() + 0);
    hdr.pgno       = rd_u32(p.data() + 8);
    hdr.prev_pgno  = rd_u32(p.data() + 12);
    hdr.next_pgno  = rd_u32(p.data() + 16);
    hdr.entries    = rd_u16(p.data() + 20);
    hdr.hf_offset  = rd_u16(p.data() + 22);
    hdr.level      = p[24];
    hdr.type       = p[25];
    return true;
}

bool Reader::parse_meta_page_(const std::vector<uint8_t>& p, DatabaseMeta& m, std::string& err) const {
    if (p.size() < 128) {
        err = "metadata page too short";
        return false;
    }
    m.magic      = rd_u32(p.data() + 12);
    m.version    = rd_u32(p.data() + 16);
    m.pagesize   = rd_u32(p.data() + 20);
    m.encrypt_alg = p[24];
    m.page_type   = p[25];
    m.metaflags   = p[26];
    m.flags       = rd_u32(p.data() + 45);
    m.last_pgno   = rd_u32(p.data() + 61);
    m.keycount    = rd_u32(p.data() + 69);
    m.record_count = rd_u32(p.data() + 73);
    // Hash-specific (best-effort — offsets are valid in BDB 4.x HASHMETA)
    if (p.size() >= 124) {
        m.maxbucket  = rd_u32(p.data() + 84);
        m.high_mask  = rd_u32(p.data() + 88);
        m.low_mask   = rd_u32(p.data() + 92);
        m.ffactor    = rd_u32(p.data() + 96);
        m.nelem      = rd_u32(p.data() + 100);
        m.h_charkey  = rd_u32(p.data() + 104);
    }
    return true;
}

bool Reader::read_overflow_chain_(uint32_t first_pgno, std::vector<uint8_t>& out, std::string& err) const {
    uint32_t pgno = first_pgno;
    out.clear();
    uint32_t safety = 0;
    constexpr uint32_t SAFETY_LIMIT = 1024 * 1024; // 1M pages = absurd cap

    while (pgno != 0 && pgno != 0xffffffffu) {
        if (++safety > SAFETY_LIMIT) {
            err = "overflow chain too long";
            return false;
        }
        std::vector<uint8_t> page;
        if (!read_page(pgno, page, err)) return false;
        PageHeader hdr;
        if (!parse_page_header(page, hdr, err)) return false;
        // Overflow page content starts right after the 26-byte header
        const size_t data_start = PAGE_HEADER_SIZE;
        if (page.size() < data_start) { err = "overflow page too short"; return false; }
        size_t avail = page.size() - data_start;
        // Append available bytes (we will trim later if requested)
        out.insert(out.end(), page.data() + data_start, page.data() + data_start + avail);
        if (hdr.next_pgno == 0 || hdr.next_pgno == pgno) break;
        pgno = hdr.next_pgno;
        stats_.overflow_pages++;
    }
    return true;
}

bool Reader::parse_data_page_(const std::vector<uint8_t>& p,
                              std::vector<Record>& out,
                              std::string& err) const {
    PageHeader hdr;
    if (!parse_page_header(p, hdr, err)) return false;
    // Page type check: accept hash pages and overflow pages
    if (hdr.type != PAGE_TYPE_HASH_UNSORTED &&
        hdr.type != PAGE_TYPE_LHASH) {
        // Not a data page we recognize; silently ignore
        return true;
    }
    if (hdr.entries == 0) return true;
    if (hdr.entries % 2 != 0) {
        // Odd number of items — partial; pair up what we can.
        // (Silently skip the trailing lone item.)
    }
    const size_t hdr_size = PAGE_HEADER_SIZE;
    // inp[] table is at offset hdr_size..hdr_size+entries*2
    if (p.size() < hdr_size + hdr.entries * 2u) {
        err = "item offset table exceeds page bounds";
        return false;
    }
    const size_t pairs = hdr.entries / 2;
    for (size_t i = 0; i < pairs; ++i) {
        size_t key_inx = i * 2;
        size_t val_inx = i * 2 + 1;
        uint16_t key_off = rd_u16(p.data() + hdr_size + key_inx * 2u);
        uint16_t val_off = rd_u16(p.data() + hdr_size + val_inx * 2u);
        if (key_off >= p.size() || val_off >= p.size()) {
            stats_.errors++;
            continue;
        }
        // Each item has a 4-byte header (type:u16 + len:u16), then `len` bytes.
        // For type==B_OVERFLOW, header is 10 bytes (type:u16 + tlen:u32 + pgno:u32)
        auto read_item = [&](uint16_t off,
                             std::vector<uint8_t>& value,
                             bool& is_overflow,
                             uint32_t& overflow_pgno,
                             size_t& consumed) -> bool {
            if (off + 4u > p.size()) return false;
            uint16_t itype = rd_u16(p.data() + off);
            uint16_t ilen  = rd_u16(p.data() + off + 2);
            if (itype == BKEYDATA_KEYDATA) {
                if (off + 4u + ilen > p.size()) return false;
                value.assign(p.data() + off + 4u, p.data() + off + 4u + ilen);
                is_overflow = false;
                consumed = 4u + ilen;
                return true;
            }
            if (itype == BKEYDATA_OVERFLOW) {
                // 2-byte type + 4-byte tlen + 4-byte pgno = 10 bytes
                if (off + 10u > p.size()) return false;
                overflow_pgno = rd_u32(p.data() + off + 6u);
                is_overflow = true;
                consumed = 10u;
                return true;
            }
            // Unsupported type (e.g. B_DUPLICATE) — skip
            return false;
        };

        Record rec;
        rec.page = hdr.pgno;
        rec.slot = uint16_t(i);
        rec.overflow = false;

        bool key_overflow = false;
        uint32_t key_overflow_pgno = 0;
        size_t key_consumed = 0;
        (void)key_consumed;
        bool k_ok = read_item(key_off, rec.key, key_overflow, key_overflow_pgno, key_consumed);

        bool val_overflow = false;
        uint32_t val_overflow_pgno = 0;
        size_t val_consumed = 0;
        (void)val_consumed;
        bool v_ok = read_item(val_off, rec.value, val_overflow, val_overflow_pgno, val_consumed);

        if (!k_ok || !v_ok) {
            stats_.errors++;
            continue;
        }
        if (key_overflow) {
            std::vector<uint8_t> chain;
            if (!read_overflow_chain_(key_overflow_pgno, chain, err)) {
                stats_.errors++; continue;
            }
            rec.key = std::move(chain);
            rec.overflow = true;
        }
        if (val_overflow) {
            std::vector<uint8_t> chain;
            if (!read_overflow_chain_(val_overflow_pgno, chain, err)) {
                stats_.errors++; continue;
            }
            rec.value = std::move(chain);
            rec.overflow = true;
        }
        out.push_back(std::move(rec));
    }
    return true;
}

bool Reader::read_page_records(uint32_t pgno, std::vector<Record>& out, std::string& err) const {
    std::vector<uint8_t> page;
    if (!read_page(pgno, page, err)) return false;
    return parse_data_page_(page, out, err);
}

bool Reader::for_each_record(const std::function<bool(const Record&)>& cb,
                              std::string& err,
                              const std::function<void(int pct)>& progress) {
    if (fd_ < 0) { err = "file not open"; return false; }
    uint32_t total = stats_.total_pages > 0 ? stats_.total_pages - 1 : 0;
    uint32_t processed = 0;
    bool any = false;
    for (uint32_t pgno = 1; pgno <= meta_.last_pgno; ++pgno) {
        ++processed;
        if (progress) progress(int((uint64_t(processed) * 100) / std::max(1u, total)));

        std::vector<uint8_t> page;
        std::string perr;
        if (!read_page(pgno, page, perr)) {
            // Truncated: stop here, but record the error
            stats_.errors++;
            continue;
        }
        // Peek page type
        if (page.size() < PAGE_HEADER_SIZE) { stats_.errors++; continue; }
        uint8_t ptype = page[25];
        if (ptype == PAGE_TYPE_INVALID) { stats_.free_pages++; continue; }
        if (ptype == PAGE_TYPE_HASHMETA || ptype == 9 || ptype == 10) {
            stats_.metadata_pages++; continue;
        }
        if (ptype == PAGE_TYPE_HASH_UNSORTED || ptype == PAGE_TYPE_LHASH) {
            stats_.hash_data_pages++;
            std::vector<Record> recs;
            if (!parse_data_page_(page, recs, perr)) {
                stats_.errors++;
                continue;
            }
            for (auto& r : recs) {
                stats_.records++;
                if (!cb(r)) { any = true; return true; }
                any = true;
            }
        } else {
            stats_.free_pages++;
        }
    }
    return any;
}

bool Reader::load_all(std::vector<Record>& out, std::string& err) {
    out.clear();
    auto cb = [&](const Record& r) { out.push_back(r); return true; };
    return for_each_record(cb, err, {});
}

} // namespace btclegacy::bdb
