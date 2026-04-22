-- =============================================================================
-- Guardian.Integrity [SERVER]
-- Challenge issuance, response validation, report processing, and
-- cross-player correlation.  Pairs with cl_integrity.lua.
-- =============================================================================

if CLIENT then return end

Guardian           = Guardian           or {}
Guardian.Integrity = Guardian.Integrity or {}

-- =============================================================================
-- Net strings
-- =============================================================================

util.AddNetworkString("Guardian.Net.Integrity.Challenge")
util.AddNetworkString("Guardian.Net.Integrity.Response")
util.AddNetworkString("Guardian.Net.Integrity.Ping")
util.AddNetworkString("Guardian.Net.Integrity.Pong")
util.AddNetworkString("Guardian.Net.Integrity.Report")

-- =============================================================================
-- Configuration
-- =============================================================================

local CFG =
{
    -- Challenge schedule
    challenge_interval   = 30,    -- seconds between challenges per player
    challenge_timeout    = 12,    -- seconds to receive a valid response
    miss_limit           = 2,     -- consecutive misses before flag

    -- Report processing
    report_rate_max      = 20,    -- max reports processed per player per window
    report_rate_window   = 60,    -- seconds
    report_flood_limit   = 50,    -- reports/window indicating a flood attack

    -- Corroboration: MEDIUM reports require this many distinct signals in
    -- the correlation window before Guardian.FlagPlayer is called.
    corroboration_window = 120,   -- seconds
    corroborate_at       = 2,     -- distinct medium signals needed

    -- Severity thresholds
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4,

    -- Minimum time post-auth before we start trusting reports
    auth_grace_sec = 5,
}

-- =============================================================================
-- Per-player state
-- =============================================================================

-- Returns an initialised state table for a player; creates one if absent.
local player_state = {}

local function get_player_state(ply)
    local sid = ply:SteamID()
    if not player_state[sid] then
        player_state[sid] =
        {
            -- Challenge
            pending_nonce      = nil,
            pending_timestamp  = nil,
            challenge_sent_at  = nil,
            consecutive_misses = 0,
            last_challenge_at  = 0,

            -- Reporting
            report_timestamps  = {},   -- dispatch times within current window
            report_count_total = 0,
            last_seq           = -1,   -- monotonic sequence tracking

            -- Corroboration store: list of { category, time }
            signals            = {},

            -- Auth tracking
            authed_at          = nil,
            flagged            = {},   -- set of flag identifiers already raised
        }
    end
    return player_state[sid]
end

local function clear_player_state(ply)
    player_state[ply:SteamID()] = nil
end

-- =============================================================================
-- Utility
-- =============================================================================

local function format_severity(sev)
    return ({ "LOW", "MEDIUM", "HIGH", "CRITICAL" })[sev] or "UNKNOWN"
end

-- Compute the expected challenge response for a given player + nonce + timestamp.
-- Must match the client-side derivation in cl_integrity.lua exactly.
local function compute_expected_response(ply, nonce, timestamp)
    local steam64 = ply:SteamID64()
    local input   = tostring(nonce) .. steam64 .. tostring(timestamp)
    return util.SHA256(input):sub(1, 16)
end

-- Raise a Guardian flag with deduplication per player per identifier.
local function raise_flag(ply, identifier, reason)
    local ps = get_player_state(ply)
    if ps.flagged[identifier] then return end   -- already raised this flag
    ps.flagged[identifier] = true
    Guardian.FlagPlayer(ply, reason)
end

-- =============================================================================
-- Report rate limiting and sequence checking
-- =============================================================================

-- Returns true if the report should be processed; false if it should be
-- discarded (rate exceeded, replay, flood).
local function should_process_report(ply, seq_num)
    local ps  = get_player_state(ply)
    local now = CurTime()

    -- Discard reports arriving before the auth grace period
    if ps.authed_at and (now - ps.authed_at) < CFG.auth_grace_sec then
        return false
    end

    -- Purge old report timestamps outside the rate window
    local cutoff = now - CFG.report_rate_window
    while ps.report_timestamps[1] and ps.report_timestamps[1] < cutoff do
        table.remove(ps.report_timestamps, 1)
    end

    local count = #ps.report_timestamps

    -- Flood detection: this many reports in the window is itself a flag
    if count >= CFG.report_flood_limit then
        raise_flag(ply, "REPORT_FLOOD",
            string.format("Report flood: %d reports in %ds", count, CFG.report_rate_window))
        return false
    end

    if count >= CFG.report_rate_max then
        return false   -- silently discard; flood not yet reached
    end

    -- Sequence number replay / disorder detection
    -- seq_num is a wrapping uint16; allow small backward movement for wrap-around.
    local last_seq = ps.last_seq
    if last_seq >= 0 then
        local delta = (seq_num - last_seq + 65536) % 65536
        if delta == 0 then return false end   -- exact replay
        if delta > 32768 then
            -- Sequence went backward by more than half the range — suspicious,
            -- but allow it once (could be legitimate module reload).
            Guardian.Print(string.format(
                "[Integrity] Suspicious sequence from %s: last=%d curr=%d",
                ply:SteamID(), last_seq, seq_num))
        end
    end

    ps.last_seq = seq_num
    table.insert(ps.report_timestamps, now)
    return true
end

-- =============================================================================
-- Corroboration
-- =============================================================================

-- Adds a signal and returns the count of distinct categories in the window.
local function record_signal(ply, category)
    local ps      = get_player_state(ply)
    local now     = CurTime()
    local cutoff  = now - CFG.corroboration_window

    -- Evict expired signals
    local fresh = {}
    for _, sig in ipairs(ps.signals) do
        if sig.time >= cutoff then
            fresh[#fresh + 1] = sig
        end
    end
    ps.signals = fresh

    -- Add new signal
    ps.signals[#ps.signals + 1] = { category = category, time = now }

    -- Count distinct categories
    local seen = {}
    for _, sig in ipairs(ps.signals) do
        seen[sig.category] = true
    end
    return table.Count(seen)
end

-- =============================================================================
-- Report processing
-- =============================================================================

net.Receive("Guardian.Net.Integrity.Report", function(len, ply)
    if not IsValid(ply) or ply:IsBot() then return end

    local category = net.ReadString()
    local detail   = net.ReadString()
    local severity = net.ReadUInt(4)
    local seq_num  = net.ReadUInt(16)

    -- Sanitise inputs
    if #category > 64 or #detail > 256 then return end
    if severity < 1 or severity > 4    then return end

    if not should_process_report(ply, seq_num) then return end

    Guardian.Print(string.format(
        "[Integrity] %s reported %s | %s | sev=%s",
        ply:SteamID(), category, detail, format_severity(severity)))

    local distinct_signals = record_signal(ply, category)

    -- CRITICAL and HIGH act immediately
    if severity >= CFG.SEV_HIGH then
        raise_flag(ply,
            "INTEGRITY_" .. category,
            string.format("Integrity: %s — %s", category, detail))
        return
    end

    -- MEDIUM requires corroboration by a second distinct signal
    if severity == CFG.SEV_MEDIUM
    and distinct_signals >= CFG.corroborate_at
    then
        raise_flag(ply,
            "INTEGRITY_CORROBORATED",
            string.format(
                "Integrity corroborated (%d signals): latest=%s — %s",
                distinct_signals, category, detail))
    end
end)

-- =============================================================================
-- Challenge issuance
-- =============================================================================

local function issue_challenge(ply)
    if not IsValid(ply) or ply:IsBot() then return end

    local ps        = get_player_state(ply)
    local nonce     = math.random(0, 0x7FFFFFFF)
    local timestamp = os.time()

    ps.pending_nonce     = nonce
    ps.pending_timestamp = timestamp
    ps.challenge_sent_at = CurTime()
    ps.last_challenge_at = CurTime()

    net.Start("Guardian.Net.Integrity.Challenge")
    net.WriteUInt(nonce, 32)
    net.WriteUInt(timestamp % 0xFFFFFFFF, 32)
    net.Send(ply)
end

local function check_challenge_timeout(ply)
    if not IsValid(ply) then return end

    local ps = get_player_state(ply)
    if not ps.challenge_sent_at then return end

    local elapsed = CurTime() - ps.challenge_sent_at

    if elapsed > CFG.challenge_timeout then
        -- Response not received in time — count as a miss
        ps.pending_nonce     = nil
        ps.pending_timestamp = nil
        ps.challenge_sent_at = nil
        ps.consecutive_misses = ps.consecutive_misses + 1

        Guardian.Print(string.format(
            "[Integrity] %s missed challenge (miss #%d).",
            ply:SteamID(), ps.consecutive_misses))

        if ps.consecutive_misses >= CFG.miss_limit then
            raise_flag(ply,
                "INTEGRITY_MISSED_CHALLENGE",
                string.format(
                    "Integrity: %d consecutive challenge misses",
                    ps.consecutive_misses))
        end
    end
end

-- =============================================================================
-- Challenge response processing
-- =============================================================================

net.Receive("Guardian.Net.Integrity.Response", function(len, ply)
    if not IsValid(ply) or ply:IsBot() then return end

    local nonce_echo = net.ReadUInt(32)
    local response   = net.ReadString()

    if #response ~= 16 then return end   -- malformed

    local ps = get_player_state(ply)

    -- No pending challenge for this player (unsolicited response)
    if not ps.pending_nonce then
        Guardian.Print(string.format(
            "[Integrity] %s sent unsolicited challenge response.", ply:SteamID()))
        return
    end

    -- Nonce must match what we issued
    if nonce_echo ~= ps.pending_nonce then
        raise_flag(ply,
            "INTEGRITY_NONCE_MISMATCH",
            string.format(
                "Challenge nonce mismatch: sent=%d echoed=%d",
                ps.pending_nonce, nonce_echo))
        ps.pending_nonce = nil
        return
    end

    -- Verify response hash
    local expected = compute_expected_response(
        ply, ps.pending_nonce, ps.pending_timestamp)

    if response ~= expected then
        ps.consecutive_misses = ps.consecutive_misses + 1
        Guardian.Print(string.format(
            "[Integrity] %s failed challenge hash (miss #%d).",
            ply:SteamID(), ps.consecutive_misses))

        if ps.consecutive_misses >= CFG.miss_limit then
            raise_flag(ply,
                "INTEGRITY_CHALLENGE_FAILED",
                string.format(
                    "Challenge hash mismatch (%d consecutive failures)",
                    ps.consecutive_misses))
        end
    else
        -- Valid response — reset miss counter
        ps.consecutive_misses = 0
    end

    ps.pending_nonce     = nil
    ps.pending_timestamp = nil
    ps.challenge_sent_at = nil
end)

-- =============================================================================
-- Ping / pong liveness check (lightweight between full challenges)
-- =============================================================================

net.Receive("Guardian.Net.Integrity.Pong", function(len, ply)
    -- Receipt of pong is sufficient; we simply note the player is reachable.
    if not IsValid(ply) then return end
    local ps           = get_player_state(ply)
    ps.last_pong_at    = CurTime()
end)

local function send_ping(ply)
    if not IsValid(ply) or ply:IsBot() then return end
    net.Start("Guardian.Net.Integrity.Ping")
    net.Send(ply)
end

-- =============================================================================
-- Lifecycle hooks
-- =============================================================================

hook.Add("PlayerAuthed", "Guardian.Integrity.Authed", function(ply)
    local ps = get_player_state(ply)
    ps.authed_at = CurTime()
end)

hook.Add("PlayerSpawn", "Guardian.Integrity.Spawn", function(ply)
    if ply:IsBot() then return end

    -- Issue first challenge after a short delay to let the client settle.
    timer.Simple(CFG.auth_grace_sec + 2, function()
        if not IsValid(ply) then return end
        issue_challenge(ply)
    end)
end)

hook.Add("PlayerDisconnected", "Guardian.Integrity.Disconnect", function(ply)
    clear_player_state(ply)
end)

-- =============================================================================
-- Scheduler — periodic challenges and timeout checks for all players
-- =============================================================================

timer.Create("Guardian.Integrity.Scheduler", 5, 0, function()
    for _, ply in ipairs(player.GetHumans()) do
        if not IsValid(ply) then continue end

        local ps  = get_player_state(ply)
        local now = CurTime()

        -- Check for outstanding challenge that has timed out
        if ps.challenge_sent_at then
            check_challenge_timeout(ply)
        end

        -- Issue a new challenge if enough time has passed since the last one
        -- and there is no outstanding challenge pending
        if not ps.challenge_sent_at
        and (now - ps.last_challenge_at) >= CFG.challenge_interval
        then
            issue_challenge(ply)
        end

        -- Send a mid-interval ping to verify net connectivity is intact
        local mid_point = ps.last_challenge_at + CFG.challenge_interval / 2
        if not ps.last_pong_at or ps.last_pong_at < mid_point then
            if now >= mid_point and now < mid_point + 5 then
                send_ping(ply)
            end
        end
    end
end)

Guardian.Print("[Guardian.Integrity] Server module loaded.")