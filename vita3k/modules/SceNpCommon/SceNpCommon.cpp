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

#include <module/module.h>

#include <io/state.h>
#include <kernel/state.h>
#include <np/account.h>
#include <np/common.h>
#include <util/fs.h>
#include <util/hash.h>

#include <util/tracy.h>
TRACY_MODULE_NAME(SceNpCommon);

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
#include <vector>

enum SceNpUtilErrorCode {
    SCE_NP_UTIL_Ok = 0x0,
    SCE_NP_UTIL_ERROR_INVALID_ARGUMENT = 0x80550601,
    SCE_NP_UTIL_ERROR_INVALID_NP_ID = 0x80550605,
    SCE_NP_UTIL_ERROR_NOT_MATCH = 0x80550609,
};

EXPORT(int, sceNpAuthAbortRequest) {
    TRACY_FUNC(sceNpAuthAbortRequest);
    return UNIMPLEMENTED();
}

struct SceNpAuthRequestParameter {
    SceSize size;
    uint32_t version;
    Ptr<const char> serviceId;
    Ptr<const void> cookie;
    SceSize cookieSize;
    Ptr<const char> entitlementId;
    SceUInt32 consumedCount;
    Ptr<void> ticketCb; // int (*ticketCb)(SceNpAuthRequestId, int, void *);
    Ptr<void> cbArg;
};

constexpr size_t NP_TICKET_SIZE = 256;
static std::string np_auth_service_id;

static std::string np_online_id(EmuEnvState &emuenv) {
    static std::mutex mutex;
    const std::lock_guard<std::mutex> lock(mutex);
    const fs::path user_path = emuenv.vita_fs_path / "ux0/user" / emuenv.io.user_id;
    const fs::path secret_path = user_path / "np_secret.bin";
    std::vector<uint8_t> secret;
    if (!fs_utils::read_data(secret_path, secret) || secret.size() != 16) {
        std::random_device rd;
        secret.resize(16);
        for (auto &b : secret)
            b = static_cast<uint8_t>(rd());
        boost::system::error_code ec;
        fs::create_directories(user_path, ec);
        fs::ofstream file(secret_path, fs::ofstream::binary);
        file.write(reinterpret_cast<const char *>(secret.data()), static_cast<std::streamsize>(secret.size()));
        if (file.good())
            LOG_INFO("Created the NP ticket secret {}", fs_utils::path_to_utf8(secret_path));
        else
            LOG_ERROR("Could not save the NP ticket secret {}, the online ID will change next session", fs_utils::path_to_utf8(secret_path));
    }
    const Sha256Hash hash = sha256(secret.data(), secret.size());
    std::string id = "v3k";
    for (size_t i = 0; i < 13; i++)
        id += "0123456789abcdefghjkmnpqrstvwxyz"[hash[i] & 31];
    const fs::path id_path = user_path / "np_online_id.txt";
    const std::string id_line = id + "\n";
    fs_utils::dump_data(id_path, id_line.data(), id_line.size());
    LOG_INFO("NP ticket online ID for user {} is in {}", emuenv.io.user_name, fs_utils::path_to_utf8(id_path));
    return id;
}

static std::vector<uint8_t> make_np_ticket(const std::string &online_id, const std::string &service_id, uint64_t cfg_user_id = 0, const std::string &region = "us") {
    std::vector<uint8_t> t(NP_TICKET_SIZE, 0);
    size_t pos = 0;
    const auto u16 = [&](uint16_t v) {
        t[pos++] = static_cast<uint8_t>(v >> 8);
        t[pos++] = static_cast<uint8_t>(v);
    };
    const auto u32 = [&](uint32_t v) {
        u16(static_cast<uint16_t>(v >> 16));
        u16(static_cast<uint16_t>(v));
    };
    const auto u64 = [&](uint64_t v) {
        u32(static_cast<uint32_t>(v >> 32));
        u32(static_cast<uint32_t>(v));
    };
    const auto str = [&](const std::string &s, size_t n) {
        for (size_t i = 0; i < n; i++)
            t[pos++] = i < s.size() ? static_cast<uint8_t>(s[i]) : 0;
    };
    uint64_t user_id = 0xCBF29CE484222325ull;
    for (const char c : online_id)
        user_id = (user_id ^ static_cast<uint8_t>(c)) * 0x100000001B3ull;
    if (cfg_user_id)
        user_id = cfg_user_id;
    const uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    t[pos++] = 0x31;
    t[pos++] = 0x00;
    u16(0);
    u32(NP_TICKET_SIZE - 8);
    u16(0x3000);
    u16(156);
    u16(0x0008);
    u16(20);
    u64(user_id);
    pos += 12;
    u16(0x0001);
    u16(4);
    u32(0x100);
    u16(0x0007);
    u16(8);
    u64(now);
    u16(0x0007);
    u16(8);
    u64(now + 60 * 60 * 1000);
    u16(0x0002);
    u16(8);
    u64(user_id);
    u16(0x0004);
    u16(32);
    str(online_id, 32);
    u16(0x0008);
    u16(4);
    str(region, 4);
    u16(0x0004);
    u16(4);
    str("un", 4);
    u16(0x0008);
    u16(24);
    str(service_id, 24);
    u16(0x0001);
    u16(4);
    u32(0);
    u16(0x3002);
    u16(static_cast<uint16_t>(NP_TICKET_SIZE - pos - 2));
    u16(0x0008);
    u16(4);
    u32(0);
    u16(0x0008);
    u16(static_cast<uint16_t>(NP_TICKET_SIZE - pos - 2));
    return t;
}

static std::vector<uint8_t> np_ticket_for(EmuEnvState &emuenv) {
    if (!emuenv.cfg.np_online_id.empty()) {
        const auto acc = np::account::resolve_account(emuenv.cfg.np_online_id, emuenv.cfg.np_user_id, emuenv.cfg.np_region, "");
        return make_np_ticket(acc.online_id, np_auth_service_id, acc.user_id, acc.region);
    }
    return make_np_ticket(np_online_id(emuenv), np_auth_service_id);
}

EXPORT(int, sceNpAuthCreateStartRequest, const SceNpAuthRequestParameter *param) {
    TRACY_FUNC(sceNpAuthCreateStartRequest, param);
    const ThreadStatePtr thread = emuenv.kernel.get_thread(thread_id);
    // todo: this callback function should be called from sceNpCheckCallback
    STUBBED("Immediately call ticket callback");
    np_auth_service_id = param->serviceId ? param->serviceId.get(emuenv.mem) : "";
    thread->run_callback(param->ticketCb.address(), { 1, static_cast<uint32_t>(NP_TICKET_SIZE), param->cbArg.address() });
    return 1;
}

EXPORT(int, sceNpAuthDestroyRequest) {
    TRACY_FUNC(sceNpAuthDestroyRequest);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpAuthGetEntitlementById) {
    TRACY_FUNC(sceNpAuthGetEntitlementById);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpAuthGetEntitlementByIdPrefix) {
    TRACY_FUNC(sceNpAuthGetEntitlementByIdPrefix);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpAuthGetEntitlementIdList) {
    TRACY_FUNC(sceNpAuthGetEntitlementIdList);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpAuthGetTicket, int id, void *buf, SceSize len) {
    TRACY_FUNC(sceNpAuthGetTicket, id, buf, len);
    const std::vector<uint8_t> ticket = np_ticket_for(emuenv);
    if (buf)
        memcpy(buf, ticket.data(), std::min<size_t>(len, ticket.size()));
    return static_cast<int>(ticket.size());
}

EXPORT(int, sceNpAuthGetTicketParam) {
    TRACY_FUNC(sceNpAuthGetTicketParam);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpAuthInit) {
    TRACY_FUNC(sceNpAuthInit);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpAuthTerm) {
    TRACY_FUNC(sceNpAuthTerm);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpCmpNpId, np::SceNpId *npid1, np::SceNpId *npid2) {
    TRACY_FUNC(sceNpCmpNpId, npid1, npid2);

    if (npid1 == nullptr || npid2 == nullptr)
        return SCE_NP_UTIL_ERROR_INVALID_ARGUMENT;
    if (!npid1->isIdValid || !npid2->isIdValid)
        return SCE_NP_UTIL_ERROR_INVALID_NP_ID;
    if (std::strncmp(npid1->handle.data, npid2->handle.data, SCE_NP_ONLINEID_MAX_LENGTH) != 0)
        return SCE_NP_UTIL_ERROR_NOT_MATCH;

    if (std::memcmp(npid1->opt.unknown, npid2->opt.unknown, 4) != 0)
        return SCE_NP_UTIL_ERROR_NOT_MATCH;

    if (npid1->opt.platformType[0] == 0 && npid2->opt.platformType[0] == 0)
        return SCE_NP_UTIL_Ok;
    if (std::memcmp(&npid1->opt.platformType, &npid2->opt.platformType, 4) != 0)
        return SCE_NP_UTIL_ERROR_NOT_MATCH;

    return SCE_NP_UTIL_Ok;
}

EXPORT(int, sceNpCmpNpIdInOrder) {
    TRACY_FUNC(sceNpCmpNpIdInOrder);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpCmpOnlineId) {
    TRACY_FUNC(sceNpCmpOnlineId);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpCommonBase64Encode) {
    TRACY_FUNC(sceNpCommonBase64Encode);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpCommonFreeNpServerName) {
    TRACY_FUNC(sceNpCommonFreeNpServerName);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpCommonGetNpEnviroment) {
    TRACY_FUNC(sceNpCommonGetNpEnviroment);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpCommonGetSystemSwVersion) {
    TRACY_FUNC(sceNpCommonGetSystemSwVersion);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpCommonMallocNpServerName) {
    TRACY_FUNC(sceNpCommonMallocNpServerName);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpGetPlatformType) {
    TRACY_FUNC(sceNpGetPlatformType);
    return UNIMPLEMENTED();
}

EXPORT(int, sceNpSetPlatformType) {
    TRACY_FUNC(sceNpSetPlatformType);
    return UNIMPLEMENTED();
}
