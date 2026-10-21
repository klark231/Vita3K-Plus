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

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Local, offline "fake PSN account" support, modelled on what RPCN hands out to RPCS3.
// No Sony server is involved: the emulator invents an online ID + numeric account ID and
// signs nothing (the signature blob is zero-filled, like RPCN with SignTickets=false).
namespace np::account {

struct Account {
    std::string online_id;
    uint64_t user_id = 0;
    std::string region = "us"; // 2 letters
};

// Same rule RPCN uses for usernames: 3-16 chars, [A-Za-z0-9_-]
bool is_valid_online_id(std::string_view online_id);

// Random, valid online ID such as "Vita3K_483920"
std::string generate_online_id();

// Random non-zero 64-bit account ID
uint64_t generate_user_id();

// Builds the account used by the NP modules from the config values.
// Falls back to fallback_name if no online ID is configured, and derives a stable user ID if none is stored.
Account resolve_account(const std::string &cfg_online_id, uint64_t cfg_user_id, const std::string &cfg_region, const std::string &fallback_name);

// Builds an unsigned PSN-style ticket blob (same layout RPCN uses, version 2.1).
std::vector<uint8_t> build_ticket(const Account &account, std::string_view service_id, const uint8_t *cookie, size_t cookie_size);

} // namespace np::account
