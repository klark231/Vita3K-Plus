// Vita3K emulator project
// Copyright (C) 2026 Vita3K team
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include <np/account.h>
#include <np/common.h>

#include <atomic>
#include <chrono>
#include <random>

namespace np::account {

bool is_valid_online_id(std::string_view online_id) {
    if (online_id.size() < SCE_NP_ONLINEID_MIN_LENGTH || online_id.size() > SCE_NP_ONLINEID_MAX_LENGTH)
        return false;
    for (const char c : online_id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

std::string generate_online_id() {
    std::random_device rd;
    std::uniform_int_distribution<int> digit(0, 9);
    std::string id = "Vita3K_";
    for (int i = 0; i < 6; i++)
        id += static_cast<char>('0' + digit(rd));
    return id;
}

uint64_t generate_user_id() {
    std::random_device rd;
    std::mt19937_64 gen((static_cast<uint64_t>(rd()) << 32) ^ rd());
    uint64_t id = 0;
    while (id == 0)
        id = gen();
    return id;
}

Account resolve_account(const std::string &cfg_online_id, uint64_t cfg_user_id, const std::string &cfg_region, const std::string &fallback_name) {
    Account acc;
    acc.online_id = cfg_online_id.empty() ? fallback_name : cfg_online_id;
    acc.region = (cfg_region.size() == 2) ? cfg_region : "us";
    acc.user_id = cfg_user_id;
    if (acc.user_id == 0) {
        // FNV-1a over the online ID, so the same name always maps to the same account ID
        uint64_t h = 0xcbf29ce484222325ULL;
        for (const char c : acc.online_id) {
            h ^= static_cast<uint8_t>(c);
            h *= 0x100000001b3ULL;
        }
        acc.user_id = h ? h : 1;
    }
    return acc;
}

namespace {

// Ticket TLV container, ported from RPCN's src/server/client/ticket.rs
struct Field {
    enum class Type : uint16_t {
        Empty = 0,
        U32 = 1,
        U64 = 2,
        BString = 4,
        Time = 7,
        Binary = 8,
        Blob = 0x3000,
    };

    Type type = Type::Empty;
    uint8_t blob_id = 0;
    uint64_t number = 0;
    std::vector<uint8_t> bytes;
    std::vector<Field> children;

    static Field empty() { return {}; }
    static Field u32(uint32_t v) {
        Field f;
        f.type = Type::U32;
        f.number = v;
        return f;
    }
    static Field u64(uint64_t v) {
        Field f;
        f.type = Type::U64;
        f.number = v;
        return f;
    }
    static Field time(uint64_t v) {
        Field f;
        f.type = Type::Time;
        f.number = v;
        return f;
    }
    static Field binary(std::vector<uint8_t> v) {
        Field f;
        f.type = Type::Binary;
        f.bytes = std::move(v);
        return f;
    }
    static Field bstring(std::vector<uint8_t> v) {
        Field f;
        f.type = Type::BString;
        f.bytes = std::move(v);
        return f;
    }
    static Field blob(uint8_t id, std::vector<Field> children) {
        Field f;
        f.type = Type::Blob;
        f.blob_id = id;
        f.children = std::move(children);
        return f;
    }

    uint16_t id() const {
        if (type == Type::Blob)
            return static_cast<uint16_t>(0x3000 | blob_id);
        return static_cast<uint16_t>(type);
    }

    uint16_t length() const {
        switch (type) {
        case Type::Empty: return 0;
        case Type::U32: return 4;
        case Type::U64:
        case Type::Time: return 8;
        case Type::BString:
        case Type::Binary: return static_cast<uint16_t>(bytes.size());
        case Type::Blob: {
            uint16_t total = 0;
            for (const auto &c : children)
                total += c.length() + 4;
            return total;
        }
        }
        return 0;
    }

    void write(std::vector<uint8_t> &out) const {
        put_be(out, id(), 2);
        put_be(out, length(), 2);
        switch (type) {
        case Type::Empty: break;
        case Type::U32: put_be(out, number, 4); break;
        case Type::U64:
        case Type::Time: put_be(out, number, 8); break;
        case Type::BString:
        case Type::Binary: out.insert(out.end(), bytes.begin(), bytes.end()); break;
        case Type::Blob:
            for (const auto &c : children)
                c.write(out);
            break;
        }
    }

    static void put_be(std::vector<uint8_t> &out, uint64_t value, int size) {
        for (int i = size - 1; i >= 0; i--)
            out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
};

std::vector<uint8_t> padded(std::string_view s, size_t size) {
    std::vector<uint8_t> v(s.begin(), s.end());
    v.resize(size, 0);
    return v;
}

} // namespace

std::vector<uint8_t> build_ticket(const Account &account, std::string_view service_id, const uint8_t *cookie, size_t cookie_size) {
    static std::atomic<uint64_t> ticket_counter{ 1 };

    const uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::system_clock::now().time_since_epoch())
                                                      .count());
    const uint64_t issued = now_ms - 60 * 1000; // issued a minute ago, like RPCN
    const uint64_t expires = issued + 15 * 60 * 1000; // valid 15 minutes

    std::vector<uint8_t> region(account.region.begin(), account.region.end());
    region.resize(4, 0);

    std::vector<Field> user = {
        Field::binary(padded(std::to_string(ticket_counter.fetch_add(1)), 0x14)), // serial
        Field::u32(0x100), // issuer id (0x100 = release network)
        Field::time(issued),
        Field::time(expires),
        Field::u64(account.user_id),
        Field::bstring(padded(account.online_id, 0x20)),
        Field::binary(region),
        Field::bstring({ 'u', 'n', 0, 0 }), // domain
        Field::binary(padded(service_id, 0x18)),
        Field::u32(0), // status
    };
    if (cookie && cookie_size > 0)
        user.push_back(Field::binary(std::vector<uint8_t>(cookie, cookie + cookie_size)));
    user.push_back(Field::empty());
    user.push_back(Field::empty());

    const std::vector<Field> fields = {
        Field::blob(0, std::move(user)),
        // unsigned: 4 zero bytes + 56 zero bytes, same as RPCN with SignTickets=false
        Field::blob(2, { Field::binary({ 0, 0, 0, 0 }), Field::binary(std::vector<uint8_t>(56, 0)) }),
    };

    uint32_t size = 0;
    for (const auto &f : fields)
        size += f.length() + 4;

    std::vector<uint8_t> ticket;
    Field::put_be(ticket, 0x21010000, 4); // ticket version 2.1
    Field::put_be(ticket, size, 4);
    for (const auto &f : fields)
        f.write(ticket);
    return ticket;
}

} // namespace np::account
