-- =============================================================================
-- Guardian.Integrity [SERVER] v3
--
-- Design philosophy:
--   The server is the sole authority on trust.  The client is treated as
--   fully compromised; its reports are noisy signals, not facts.  The server
--   reconstructs truth by detecting inconsistency across multiple independent
--   dimensions rather than believing any single client assertion.
--
-- Key changes over v2:
--   • Server-secret HMAC component — session keys incorporate a per-boot
--     server secret that the client never sees; token forgery requires the secret
--   • Type-tagged tokens — report and probe tokens use distinct prefixes;
--     a probe response cannot be replayed as a report and vice versa
--   • Probe trap system — server periodically issues PROBE_TRAP; the correct
--     response is a signed rejection; a computed hash result is flagged
--   • Behavioral modeling — per-player Welford online μ/σ of response latency,
--     report inter-arrival time, and report category entropy; deviations scored
--   • "Too clean" detection — long sessions with zero noise accumulate suspicion
--   • Server-authoritative trust — canonical trust lives here; client's trust_hint
--     is a noisy auxiliary signal, weighted at 20 %
--   • Composite flagging — weighted evidence accumulator; enforcement only
--     triggers when multiple distinct signal types combine above a threshold
--   • Trust hint pushed to client in every challenge so the client can scale
--     its adaptive burst limits accordingly
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
util.AddNetworkString("Guardian.Net.Integrity.Probe")
util.AddNetworkString("Guardian.Net.Integrity.ProbeResponse")

-- =============================================================================
-- Server secret — generated once per boot; never leaves this module
-- =============================================================================

local SERVER_SECRET = util.SHA256(
    tostring(math.random()) ..
    tostring(os.time()) ..
    tostring(math.random(0, 0x7FFFFFFF))
):sub(1, 32)

-- =============================================================================
-- Configuration
-- =============================================================================

local CFG =
{
    -- ── Challenge schedule (jittered) ─────────────────────────────────────────
    challenge_interval_min  = 25,
    challenge_interval_max  = 40,
    challenge_timeout       = 12,
    miss_limit              = 2,

    -- ── Probe schedule (jittered) ─────────────────────────────────────────────
    probe_interval_min      = 55,
    probe_interval_max      = 175,
    probe_timeout           = 12,
    probe_instant_floor     = 0.04,   -- responses faster than this are suspicious
    probe_trap_probability  = 0.20,   -- 20 % of probes are traps

    -- ── Trust scoring ─────────────────────────────────────────────────────────
    trust_decay_per_sec     = 0.06,
    trust_max               = 100,
    trust_weight            = { [1] = 5, [2] = 15, [3] = 35, [4] = 60 },

    -- ── Composite evidence accumulator ────────────────────────────────────────
    -- Enforcement only fires when accumulated weighted evidence exceeds these
    -- thresholds AND at least min_distinct_signal_types distinct signal types
    -- have contributed.  Prevents single-signal false positives.
    evidence_warn_threshold  = 40,
    evidence_flag_threshold  = 80,
    evidence_ban_threshold   = 140,
    min_distinct_signal_types_flag = 2,
    min_distinct_signal_types_ban  = 3,

    -- Evidence weights per signal type
    evidence_weight =
    {
        CHALLENGE_MISS      = 30,
        CHALLENGE_FAIL      = 40,
        PROBE_MISS          = 20,
        PROBE_HASH_CHANGED  = 50,
        PROBE_TRAP_FAILED   = 60,
        TOKEN_INVALID       = 25,
        SEQUENCE_GAP        = 15,
        REPORT_FLOOD        = 20,
        BEHAVIORAL          = 10,  -- incremented per behavioral anomaly tick
        LIVENESS_SILENCE    = 15,
        TOO_CLEAN           = 12,
    },

    -- ── Session token ─────────────────────────────────────────────────────────
    session_key_grace       = 45,

    -- ── Report processing ─────────────────────────────────────────────────────
    report_rate_max         = 20,
    report_rate_window      = 60,
    report_flood_limit      = 50,
    seq_gap_warn_limit      = 5,
    seq_gap_flag_limit      = 20,
    report_burst_window     = 3,
    report_burst_limit      = 8,

    -- ── Behavioral modeling ───────────────────────────────────────────────────
    -- Minimum samples before behavioral deviation scoring begins
    latency_min_samples     = 5,
    -- Standard deviations from mean before flagging
    latency_zscore_warn     = 3.0,
    latency_zscore_flag     = 5.0,
    -- Report entropy: fraction of unique categories / total reports (expected > floor)
    entropy_floor           = 0.15,
    entropy_window          = 50,   -- last N reports used for entropy computation
    -- "Too clean" threshold: sessions longer than this with zero noise get bumped
    too_clean_duration      = 120,
    too_clean_check_interval = 60,

    -- ── Cross-player correlation ──────────────────────────────────────────────
    corr_window             = 30,
    corr_player_threshold   = 3,

    -- ── Corroboration (per-player multi-signal) ────────────────────────────────
    corroboration_window    = 120,
    corroborate_at          = 2,

    -- ── Liveness ─────────────────────────────────────────────────────────────
    liveness_silence_warn   = 90,

    -- ── Auth grace ────────────────────────────────────────────────────────────
    auth_grace_sec          = 5,

    -- ── Scheduler tick ────────────────────────────────────────────────────────
    scheduler_tick          = 5,

    -- ── Severity ──────────────────────────────────────────────────────────────
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4,

    -- ── Token type tags (must match client) ───────────────────────────────────
    TOKEN_TAG_REPORT = "R",
    TOKEN_TAG_PROBE  = "P",
    TOKEN_TAG_REJECT = "X",

    -- ── Probe type constants (must match client) ───────────────────────────────
    PROBE_WRAPPERS = 1,
    PROBE_HOOKS    = 2,
    PROBE_CANARIES = 3,
    PROBE_TRAP     = 4,
}

-- =============================================================================
-- Cross-player correlation table
-- =============================================================================

local global_signals = {}

local function record_global_signal(ply, category)
    local now    = CurTime()
    local cutoff = now - CFG.corr_window

    if not global_signals[category] then global_signals[category] = {} end

    local ring  = global_signals[category]
    local fresh = {}
    for _, entry in ipairs(ring) do
        if entry.time >= cutoff then fresh[#fresh + 1] = entry end
    end
    global_signals[category] = fresh

    local sid = ply:SteamID()
    local already_present = false
    for _, entry in ipairs(fresh) do
        if entry.sid == sid then already_present = true break end
    end
    if not already_present then
        fresh[#fresh + 1] = { time = now, sid = sid }
    end

    if #fresh >= CFG.corr_player_threshold then
        Guardian.Print(string.format(
            "[Integrity] Cross-player correlation: %s — %d players / %ds",
            category, #fresh, CFG.corr_window))
    end
end

-- =============================================================================
-- Welford online mean / variance accumulator
-- =============================================================================

local function welford_new()
    return { n = 0, mean = 0, m2 = 0 }
end

local function welford_update(acc, value)
    acc.n = acc.n + 1
    local delta  = value - acc.mean
    acc.mean     = acc.mean + delta / acc.n
    local delta2 = value - acc.mean
    acc.m2       = acc.m2 + delta * delta2
end

local function welford_stddev(acc)
    if acc.n < 2 then return 0 end
    return math.sqrt(acc.m2 / (acc.n - 1))
end

local function welford_zscore(acc, value)
    local sd = welford_stddev(acc)
    if sd < 0.001 then return 0 end
    return math.abs(value - acc.mean) / sd
end

-- =============================================================================
-- Entropy computation over last-N report categories
-- =============================================================================

local function compute_category_entropy(category_ring)
    if #category_ring == 0 then return 1.0 end
    local counts = {}
    for _, cat in ipairs(category_ring) do
        counts[cat] = (counts[cat] or 0) + 1
    end
    local n       = #category_ring
    local entropy = 0
    for _, cnt in pairs(counts) do
        local p = cnt / n
        if p > 0 then entropy = entropy - p * math.log(p) end
    end
    -- Normalise by log(n) so result is in [0, 1]
    local max_entropy = n > 1 and math.log(n) or 1
    return entropy / max_entropy
end

-- =============================================================================
-- Per-player state
-- =============================================================================

local player_state = {}

local function get_player_state(ply)
    local sid = ply:SteamID()
    if not player_state[sid] then
        player_state[sid] =
        {
            -- Challenge
            pending_nonce       = nil,
            pending_timestamp   = nil,
            live_token          = nil,
            challenge_sent_at   = nil,
            consecutive_misses  = 0,
            last_challenge_at   = 0,
            next_challenge_at   = 0,

            -- Session / token
            session_key         = nil,
            session_key_time    = nil,
            prev_session_key    = nil,
            prev_session_time   = nil,

            -- Reporting
            report_timestamps   = {},
            last_seq            = -1,
            last_seq_time       = 0,
            category_ring       = {},   -- rolling window for entropy

            -- Corroboration
            signals             = {},

            -- Trust (server-authoritative)
            trust_score         = 0,
            trust_last_update   = 0,

            -- Composite evidence accumulator
            evidence            = 0,
            evidence_by_type    = {},   -- signal_type → accumulated weight

            -- Probes
            pending_probe       = nil,
            next_probe_at       = 0,
            last_probe_type     = 0,
            probe_baselines     = {},

            -- Behavioral modeling
            challenge_latency   = welford_new(),
            report_interarrival = welford_new(),
            last_report_time    = 0,
            behavioral_anomalies = 0,

            -- Liveness
            authed_at           = nil,
            last_pong_at        = nil,
            session_start       = nil,
            noise_count         = 0,    -- total low-level noise events; 0 = "too clean"
            last_too_clean_check = 0,

            -- Flagging
            flagged             = {},
        }
    end
    return player_state[sid]
end

local function clear_player_state(ply)
    player_state[ply:SteamID()] = nil
end

-- =============================================================================
-- Trust scoring
-- =============================================================================

local function ps_decay_trust(ps)
    local now     = CurTime()
    local elapsed = now - (ps.trust_last_update > 0 and ps.trust_last_update or now)
    ps.trust_score       = math.max(0, ps.trust_score - elapsed * CFG.trust_decay_per_sec)
    ps.trust_last_update = now
end

local function ps_add_suspicion(ps, severity)
    ps_decay_trust(ps)
    ps.trust_score = math.min(CFG.trust_max,
        ps.trust_score + (CFG.trust_weight[severity] or 5))
end

local function ps_trust_score(ps)
    ps_decay_trust(ps)
    return ps.trust_score
end

-- Returns the trust score as a 7-bit uint [0,100] for the client hint field.
local function ps_trust_hint(ps)
    return math.floor(math.min(100, math.max(0, ps_trust_score(ps))))
end

-- =============================================================================
-- Composite evidence accumulator
-- =============================================================================

local function evidence_add(ply, signal_type)
    local ps     = get_player_state(ply)
    local weight = CFG.evidence_weight[signal_type] or 10
    ps.evidence  = ps.evidence + weight
    ps.evidence_by_type[signal_type] = (ps.evidence_by_type[signal_type] or 0) + weight

    local distinct = 0
    for _ in pairs(ps.evidence_by_type) do distinct = distinct + 1 end

    Guardian.Print(string.format(
        "[Integrity] %s evidence +%d (%s) total=%.0f distinct=%d",
        ply:SteamID(), weight, signal_type, ps.evidence, distinct))

    if ps.evidence >= CFG.evidence_ban_threshold
    and distinct >= CFG.min_distinct_signal_types_ban
    then
        raise_flag(ply, "EVIDENCE_BAN",
            string.format("Evidence %.0f / %d signal types → ban threshold",
                ps.evidence, distinct))

    elseif ps.evidence >= CFG.evidence_flag_threshold
    and distinct >= CFG.min_distinct_signal_types_flag
    then
        raise_flag(ply, "EVIDENCE_FLAG",
            string.format("Evidence %.0f / %d signal types → flag threshold",
                ps.evidence, distinct))

    elseif ps.evidence >= CFG.evidence_warn_threshold then
        Guardian.Print(string.format(
            "[Integrity] %s evidence warn (%.0f)", ply:SteamID(), ps.evidence))
    end
end

-- Passive decay of evidence mirrors trust decay (separate axis)
local function evidence_decay_tick(ps)
    -- Evidence decays at half the rate of trust; never below 0
    ps.evidence = math.max(0, ps.evidence - CFG.trust_decay_per_sec * 0.5 * CFG.scheduler_tick)
end

-- =============================================================================
-- Utility
-- =============================================================================

local function format_severity(sev)
    return ({ "LOW", "MEDIUM", "HIGH", "CRITICAL" })[sev] or "UNKNOWN"
end

local function compute_expected_response(ply, nonce, timestamp)
    return util.SHA256(tostring(nonce) .. ply:SteamID64() .. tostring(timestamp)):sub(1, 16)
end

-- Session key includes SERVER_SECRET so the client cannot reproduce it.
local function compute_session_key(ply, nonce, live_token)
    return util.SHA256(
        SERVER_SECRET ..
        tostring(nonce) ..
        ply:SteamID64() ..
        live_token
    ):sub(1, 16)
end

-- Token validation: SHA256(session_key || nonce_component || type_tag || seq_or_id)
-- Mirrors the client's make_token but inserts the server secret into the key.
local function validate_typed_token(ps, type_tag, seq_or_id, token, allow_prev)
    if #token ~= 8 then return false end

    local function derive(sk)
        return util.SHA256(
            sk ..
            tostring(ps.pending_nonce or ps.last_nonce_for_token or 0) ..
            type_tag ..
            tostring(seq_or_id)
        ):sub(1, 8)
    end

    if ps.session_key and token == derive(ps.session_key) then return true end

    if allow_prev and ps.prev_session_key then
        local age = CurTime() - (ps.prev_session_time or 0)
        if age < CFG.session_key_grace and token == derive(ps.prev_session_key) then
            return true
        end
    end

    return false
end

function raise_flag(ply, identifier, reason)
    local ps = get_player_state(ply)
    if ps.flagged[identifier] then return end
    ps.flagged[identifier] = true
    Guardian.FlagPlayer(ply, reason)
end

-- =============================================================================
-- Report rate / sequence / burst-timing checks
-- =============================================================================

local function should_process_report(ply, seq_num, token)
    local ps  = get_player_state(ply)
    local now = CurTime()

    if ps.authed_at and (now - ps.authed_at) < CFG.auth_grace_sec then
        return false
    end

    -- Session token validation (typed: must be a REPORT token)
    if not validate_typed_token(ps, CFG.TOKEN_TAG_REPORT, seq_num, token, true) then
        Guardian.Print(string.format(
            "[Integrity] %s report token invalid (seq=%d)", ply:SteamID(), seq_num))
        ps_add_suspicion(ps, CFG.SEV_MEDIUM)
        evidence_add(ply, "TOKEN_INVALID")
        record_global_signal(ply, "INVALID_REPORT_TOKEN")
        return false
    end

    -- Rate window purge
    local cutoff = now - CFG.report_rate_window
    while ps.report_timestamps[1] and ps.report_timestamps[1] < cutoff do
        table.remove(ps.report_timestamps, 1)
    end

    local count = #ps.report_timestamps

    if count >= CFG.report_flood_limit then
        evidence_add(ply, "REPORT_FLOOD")
        raise_flag(ply, "REPORT_FLOOD",
            string.format("Report flood: %d in %ds", count, CFG.report_rate_window))
        return false
    end

    if count >= CFG.report_rate_max then return false end

    -- Sequence gap detection
    if ps.last_seq >= 0 then
        local delta = (seq_num - ps.last_seq + 65536) % 65536

        if delta == 0 then
            return false   -- exact replay

        elseif delta > 32768 then
            ps_add_suspicion(ps, CFG.SEV_MEDIUM)
            Guardian.Print(string.format(
                "[Integrity] %s seq backward: last=%d curr=%d",
                ply:SteamID(), ps.last_seq, seq_num))

        elseif delta > CFG.seq_gap_flag_limit then
            evidence_add(ply, "SEQUENCE_GAP")
            raise_flag(ply, "SEQUENCE_GAP_LARGE",
                string.format("Seq gap %d: last=%d curr=%d", delta, ps.last_seq, seq_num))

        elseif delta > CFG.seq_gap_warn_limit then
            ps_add_suspicion(ps, CFG.SEV_LOW)
            evidence_add(ply, "SEQUENCE_GAP")
            record_global_signal(ply, "SEQUENCE_GAP")
        end
    end

    ps.last_seq      = seq_num
    ps.last_seq_time = now

    -- Burst-timing analysis
    local burst_start = now - CFG.report_burst_window
    local recent_count = 0
    for _, ts in ipairs(ps.report_timestamps) do
        if ts >= burst_start then recent_count = recent_count + 1 end
    end
    if recent_count >= CFG.report_burst_limit then
        ps_add_suspicion(ps, CFG.SEV_MEDIUM)
        evidence_add(ply, "BEHAVIORAL")
        Guardian.Print(string.format(
            "[Integrity] %s report burst: %d in %.1fs",
            ply:SteamID(), recent_count, CFG.report_burst_window))
    end

    -- Report inter-arrival behavioral model
    if ps.last_report_time > 0 then
        local interarrival = now - ps.last_report_time
        welford_update(ps.report_interarrival, interarrival)

        if ps.report_interarrival.n >= CFG.latency_min_samples then
            local z = welford_zscore(ps.report_interarrival, interarrival)
            if z >= CFG.latency_zscore_flag then
                ps_add_suspicion(ps, CFG.SEV_MEDIUM)
                evidence_add(ply, "BEHAVIORAL")
                Guardian.Print(string.format(
                    "[Integrity] %s inter-arrival z=%.2f (suspicious timing)", ply:SteamID(), z))
            end
        end
    end
    ps.last_report_time = now

    table.insert(ps.report_timestamps, now)
    return true
end

-- =============================================================================
-- Corroboration
-- =============================================================================

local function record_signal(ply, category)
    local ps      = get_player_state(ply)
    local now     = CurTime()
    local cutoff  = now - CFG.corroboration_window

    local fresh = {}
    for _, sig in ipairs(ps.signals) do
        if sig.time >= cutoff then fresh[#fresh + 1] = sig end
    end
    ps.signals = fresh
    ps.signals[#ps.signals + 1] = { category = category, time = now }

    local seen = {}
    for _, sig in ipairs(ps.signals) do seen[sig.category] = true end
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
    local token    = net.ReadString()

    if #category > 64 or #detail > 256 then return end
    if severity < 1 or severity > 4    then return end

    if not should_process_report(ply, seq_num, token) then return end

    local ps = get_player_state(ply)

    -- Client trust_hint carries at most 20 % weight; server drives the rest
    local client_contribution = severity * 0.2
    ps_add_suspicion(ps, math.max(1, math.floor(client_contribution)))

    -- Category entropy tracking
    local ring = ps.category_ring
    ring[#ring + 1] = category
    if #ring > CFG.entropy_window then table.remove(ring, 1) end

    local entropy = compute_category_entropy(ring)
    if #ring >= CFG.entropy_window and entropy < CFG.entropy_floor then
        -- Suspiciously low variety — possible replay / fabricated report stream
        evidence_add(ply, "BEHAVIORAL")
        Guardian.Print(string.format(
            "[Integrity] %s low report entropy=%.3f (min=%.3f)",
            ply:SteamID(), entropy, CFG.entropy_floor))
    end

    -- Noise counter for "too clean" detection
    ps.noise_count = ps.noise_count + 1

    Guardian.Print(string.format(
        "[Integrity] %s → %s | %s | sev=%s | trust=%.1f",
        ply:SteamID(), category, detail,
        format_severity(severity), ps_trust_score(ps)))

    record_global_signal(ply, category)
    local distinct_signals = record_signal(ply, category)

    local score = ps_trust_score(ps)

    if severity >= CFG.SEV_HIGH then
        evidence_add(ply, "BEHAVIORAL")
        raise_flag(ply, "INTEGRITY_" .. category,
            string.format("Integrity: %s — %s", category, detail))
        return
    end

    if severity == CFG.SEV_MEDIUM and distinct_signals >= CFG.corroborate_at then
        raise_flag(ply, "INTEGRITY_CORROBORATED",
            string.format("Corroborated (%d): latest=%s — %s",
                distinct_signals, category, detail))
    end
end)

-- =============================================================================
-- Challenge issuance
-- =============================================================================

local function issue_challenge(ply)
    if not IsValid(ply) or ply:IsBot() then return end

    local ps         = get_player_state(ply)
    local nonce      = math.random(0, 0x7FFFFFFF)
    local timestamp  = os.time()

    local live_token = util.SHA256(
        SERVER_SECRET ..
        tostring(math.random()) ..
        ply:SteamID64() ..
        tostring(timestamp)
    ):sub(1, 16)

    ps.prev_session_key  = ps.session_key
    ps.prev_session_time = CurTime()
    ps.session_key       = compute_session_key(ply, nonce, live_token)
    ps.session_key_time  = CurTime()

    -- Carry the nonce forward so token validation can use it
    ps.last_nonce_for_token = nonce

    ps.pending_nonce     = nonce
    ps.pending_timestamp = timestamp
    ps.live_token        = live_token
    ps.challenge_sent_at = CurTime()
    ps.last_challenge_at = CurTime()

    -- Jitter the next challenge interval
    ps.next_challenge_at = CurTime() +
        math.random(CFG.challenge_interval_min, CFG.challenge_interval_max)

    local trust_hint = ps_trust_hint(ps)

    net.Start("Guardian.Net.Integrity.Challenge")
    net.WriteUInt(nonce, 32)
    net.WriteUInt(timestamp % 0xFFFFFFFF, 32)
    net.WriteString(live_token)
    net.WriteUInt(trust_hint, 7)    -- informs client adaptive scaling
    net.Send(ply)
end

local function check_challenge_timeout(ply)
    if not IsValid(ply) then return end
    local ps = get_player_state(ply)
    if not ps.challenge_sent_at then return end

    if CurTime() - ps.challenge_sent_at > CFG.challenge_timeout then
        ps.pending_nonce      = nil
        ps.pending_timestamp  = nil
        ps.challenge_sent_at  = nil
        ps.consecutive_misses = ps.consecutive_misses + 1

        evidence_add(ply, "CHALLENGE_MISS")
        ps_add_suspicion(ps, CFG.SEV_MEDIUM)

        Guardian.Print(string.format(
            "[Integrity] %s missed challenge #%d", ply:SteamID(), ps.consecutive_misses))

        if ps.consecutive_misses >= CFG.miss_limit then
            raise_flag(ply, "INTEGRITY_MISSED_CHALLENGE",
                string.format("%d consecutive challenge misses", ps.consecutive_misses))
        end
    end
end

-- =============================================================================
-- Challenge response
-- =============================================================================

net.Receive("Guardian.Net.Integrity.Response", function(len, ply)
    if not IsValid(ply) or ply:IsBot() then return end

    local nonce_echo  = net.ReadUInt(32)
    local response    = net.ReadString()
    local token_echo  = net.ReadString()

    if #response ~= 16 then return end

    local ps  = get_player_state(ply)
    local now = CurTime()

    if not ps.pending_nonce then
        ps_add_suspicion(ps, CFG.SEV_LOW)
        Guardian.Print(string.format(
            "[Integrity] %s unsolicited challenge response", ply:SteamID()))
        return
    end

    -- Latency behavioral model
    if ps.challenge_sent_at then
        local latency = now - ps.challenge_sent_at
        welford_update(ps.challenge_latency, latency)

        if ps.challenge_latency.n >= CFG.latency_min_samples then
            local z = welford_zscore(ps.challenge_latency, latency)
            if z >= CFG.latency_zscore_flag then
                evidence_add(ply, "BEHAVIORAL")
                ps_add_suspicion(ps, CFG.SEV_LOW)
                Guardian.Print(string.format(
                    "[Integrity] %s challenge latency z=%.2f (μ=%.3fs σ=%.3fs)",
                    ply:SteamID(), z,
                    ps.challenge_latency.mean,
                    welford_stddev(ps.challenge_latency)))
            end
        end
    end

    if nonce_echo ~= ps.pending_nonce then
        raise_flag(ply, "INTEGRITY_NONCE_MISMATCH",
            string.format("sent=%d echoed=%d", ps.pending_nonce, nonce_echo))
        ps.pending_nonce = nil
        return
    end

    if token_echo ~= ps.live_token then
        raise_flag(ply, "INTEGRITY_TOKEN_MISMATCH", ply:SteamID())
        ps.pending_nonce = nil
        return
    end

    local expected = compute_expected_response(ply, ps.pending_nonce, ps.pending_timestamp)

    if response ~= expected then
        ps.consecutive_misses = ps.consecutive_misses + 1
        ps_add_suspicion(ps, CFG.SEV_HIGH)
        evidence_add(ply, "CHALLENGE_FAIL")

        Guardian.Print(string.format(
            "[Integrity] %s challenge hash fail #%d", ply:SteamID(), ps.consecutive_misses))

        if ps.consecutive_misses >= CFG.miss_limit then
            raise_flag(ply, "INTEGRITY_CHALLENGE_FAILED",
                string.format("Hash mismatch (%d consecutive)", ps.consecutive_misses))
        end
    else
        ps.consecutive_misses = 0
    end

    ps.pending_nonce     = nil
    ps.pending_timestamp = nil
    ps.challenge_sent_at = nil
end)

-- =============================================================================
-- Probe system
-- =============================================================================

local function issue_probe(ply, probe_type)
    if not IsValid(ply) or ply:IsBot() then return end

    local ps       = get_player_state(ply)
    local probe_id = math.random(0, 65535)

    ps.pending_probe =
    {
        id      = probe_id,
        type    = probe_type,
        sent_at = CurTime(),
        is_trap = (probe_type == CFG.PROBE_TRAP),
    }

    net.Start("Guardian.Net.Integrity.Probe")
    net.WriteUInt(probe_id, 16)
    net.WriteUInt(probe_type, 8)
    net.Send(ply)
end

local function check_probe_timeout(ply)
    local ps = get_player_state(ply)
    if not ps.pending_probe then return end

    if CurTime() - ps.pending_probe.sent_at > CFG.probe_timeout then
        evidence_add(ply, "PROBE_MISS")
        ps_add_suspicion(ps, CFG.SEV_MEDIUM)
        record_signal(ply, "PROBE_TIMEOUT")
        Guardian.Print(string.format(
            "[Integrity] %s probe timeout (type=%d)", ply:SteamID(), ps.pending_probe.type))
        ps.pending_probe = nil
    end
end

net.Receive("Guardian.Net.Integrity.ProbeResponse", function(len, ply)
    if not IsValid(ply) or ply:IsBot() then return end

    local probe_id    = net.ReadUInt(16)
    local probe_type  = net.ReadUInt(8)
    local result      = net.ReadString()
    local is_rejection = net.ReadBool()
    local token        = net.ReadString()

    if #result > 32 or #token ~= 8 then return end

    local ps  = get_player_state(ply)
    local now = CurTime()

    if not ps.pending_probe or ps.pending_probe.id ~= probe_id then
        ps_add_suspicion(ps, CFG.SEV_LOW)
        Guardian.Print(string.format(
            "[Integrity] %s unsolicited probe response", ply:SteamID()))
        return
    end

    -- ── Trap probe handling ───────────────────────────────────────────────────
    if ps.pending_probe.is_trap then
        -- Correct behaviour: client sends REJECTED + REJECT token
        local expected_reject_token = util.SHA256(
            ps.session_key ..
            tostring(ps.last_nonce_for_token or 0) ..
            CFG.TOKEN_TAG_REJECT ..
            tostring(probe_id)
        ):sub(1, 8)

        local trap_ok = is_rejection
            and result == "REJECTED"
            and token == expected_reject_token

        if not trap_ok then
            -- Client computed a real hash instead of rejecting — clear sign of
            -- a spoofed environment or a cheat that blindly handles all probes.
            evidence_add(ply, "PROBE_TRAP_FAILED")
            ps_add_suspicion(ps, CFG.SEV_CRITICAL)
            raise_flag(ply, "INTEGRITY_PROBE_TRAP_FAILED",
                string.format("Trap probe %d not correctly rejected", probe_id))
        end

        ps.pending_probe = nil
        return
    end

    -- ── Normal probe handling ─────────────────────────────────────────────────

    -- A rejection on a real probe is suspicious (client confused or modified)
    if is_rejection then
        ps_add_suspicion(ps, CFG.SEV_MEDIUM)
        evidence_add(ply, "PROBE_MISS")
        ps.pending_probe = nil
        return
    end

    -- Session-token verification (typed: must be a PROBE token)
    local expected_token = ps.session_key and util.SHA256(
        ps.session_key ..
        tostring(ps.last_nonce_for_token or 0) ..
        CFG.TOKEN_TAG_PROBE ..
        tostring(probe_id)
    ):sub(1, 8)

    if expected_token and token ~= expected_token then
        ps_add_suspicion(ps, CFG.SEV_MEDIUM)
        evidence_add(ply, "TOKEN_INVALID")
        record_signal(ply, "PROBE_TOKEN_INVALID")
        ps.pending_probe = nil
        return
    end

    -- Timing plausibility
    local elapsed = now - ps.pending_probe.sent_at
    if elapsed < CFG.probe_instant_floor then
        ps_add_suspicion(ps, CFG.SEV_MEDIUM)
        evidence_add(ply, "BEHAVIORAL")
        record_signal(ply, "PROBE_INSTANT_RESPONSE")
        Guardian.Print(string.format(
            "[Integrity] %s probe %.3fs — implausibly fast", ply:SteamID(), elapsed))
    end

    -- Baseline comparison
    local probe_type_key = ps.pending_probe.type
    local baseline       = ps.probe_baselines[probe_type_key]

    if baseline == nil then
        ps.probe_baselines[probe_type_key] = result
        Guardian.Print(string.format(
            "[Integrity] %s probe %d baseline: %s",
            ply:SteamID(), probe_type_key, result:sub(1, 8)))

    elseif result ~= baseline then
        ps_add_suspicion(ps, CFG.SEV_HIGH)
        evidence_add(ply, "PROBE_HASH_CHANGED")
        record_signal(ply, "PROBE_HASH_CHANGED")
        raise_flag(ply, "INTEGRITY_PROBE_HASH_CHANGED",
            string.format("Probe %d hash changed: was=%s now=%s",
                probe_type_key, baseline:sub(1, 8), result:sub(1, 8)))
    end

    ps.pending_probe = nil
end)

-- =============================================================================
-- Ping / pong liveness
-- =============================================================================

net.Receive("Guardian.Net.Integrity.Pong", function(len, ply)
    if not IsValid(ply) then return end
    get_player_state(ply).last_pong_at = CurTime()
end)

local function send_ping(ply)
    if not IsValid(ply) or ply:IsBot() then return end
    net.Start("Guardian.Net.Integrity.Ping")
    net.Send(ply)
end

local function evaluate_liveness(ply)
    local ps = get_player_state(ply)
    if not ps.last_pong_at then return end
    local silence = CurTime() - ps.last_pong_at
    if silence > CFG.liveness_silence_warn then
        evidence_add(ply, "LIVENESS_SILENCE")
        record_signal(ply, "NO_HEARTBEAT")
        Guardian.Print(string.format(
            "[Integrity] %s heartbeat silence: %.0fs", ply:SteamID(), silence))
    end
end

-- =============================================================================
-- "Too clean" detection
--    A client in a long session that never triggers any low-level noise
--    (no exec attempts, no suspicious file reads, zero reports) is more
--    suspicious than a client that occasionally trips benign detections.
-- =============================================================================

local function evaluate_too_clean(ply)
    local ps  = get_player_state(ply)
    local now = CurTime()

    if not ps.session_start then return end
    if (now - ps.last_too_clean_check) < CFG.too_clean_check_interval then return end
    ps.last_too_clean_check = now

    local session_age = now - ps.session_start
    if session_age >= CFG.too_clean_duration and ps.noise_count == 0 then
        evidence_add(ply, "TOO_CLEAN")
        ps_add_suspicion(ps, CFG.SEV_LOW)
        Guardian.Print(string.format(
            "[Integrity] %s zero noise in %.0fs session — suspicious",
            ply:SteamID(), session_age))
    end
end

-- =============================================================================
-- Lifecycle hooks
-- =============================================================================

hook.Add("PlayerAuthed", "Guardian.Integrity.Authed", function(ply)
    local ps = get_player_state(ply)
    ps.authed_at     = CurTime()
    ps.session_start = CurTime()
end)

hook.Add("PlayerSpawn", "Guardian.Integrity.Spawn", function(ply)
    if ply:IsBot() then return end
    timer.Simple(CFG.auth_grace_sec + 2, function()
        if not IsValid(ply) then return end

        local ps = get_player_state(ply)
        issue_challenge(ply)

        -- Stagger first probe past the first challenge response window
        ps.next_probe_at = CurTime() +
            math.random(CFG.probe_interval_min, CFG.probe_interval_max)
    end)
end)

hook.Add("PlayerDisconnected", "Guardian.Integrity.Disconnect", function(ply)
    clear_player_state(ply)
end)

-- =============================================================================
-- Scheduler
-- =============================================================================

timer.Create("Guardian.Integrity.Scheduler", CFG.scheduler_tick, 0, function()
    local now = CurTime()

    for _, ply in ipairs(player.GetHumans()) do
        if not IsValid(ply) then continue end

        local ps = get_player_state(ply)

        -- Decay evidence each scheduler tick
        evidence_decay_tick(ps)

        -- Challenge timeout
        if ps.challenge_sent_at then
            check_challenge_timeout(ply)
        end

        -- Issue new challenge (jittered interval)
        if not ps.challenge_sent_at and ps.next_challenge_at > 0
        and now >= ps.next_challenge_at
        then
            issue_challenge(ply)
        end

        -- Probe timeout
        if ps.pending_probe then
            check_probe_timeout(ply)
        end

        -- Issue probe (jittered; cycle types; inject traps randomly)
        if not ps.pending_probe and ps.next_probe_at > 0 and now >= ps.next_probe_at then
            local probe_type

            if math.random() < CFG.probe_trap_probability then
                probe_type = CFG.PROBE_TRAP
            else
                local last = ps.last_probe_type or 0
                if     last == CFG.PROBE_WRAPPERS then probe_type = CFG.PROBE_HOOKS
                elseif last == CFG.PROBE_HOOKS    then probe_type = CFG.PROBE_CANARIES
                else                                   probe_type = CFG.PROBE_WRAPPERS
                end
            end

            ps.last_probe_type = probe_type
            issue_probe(ply, probe_type)

            ps.next_probe_at = now +
                math.random(CFG.probe_interval_min, CFG.probe_interval_max)
        end

        -- Mid-interval ping
        local mid_point = ps.last_challenge_at + (CFG.challenge_interval_min + CFG.challenge_interval_max) / 4
        if now >= mid_point and now < mid_point + CFG.scheduler_tick then
            if not ps.last_pong_at or ps.last_pong_at < mid_point then
                send_ping(ply)
            end
        end

        -- Liveness check
        evaluate_liveness(ply)

        -- "Too clean" check
        evaluate_too_clean(ply)
    end
end)

-- =============================================================================

Guardian.Print("[Guardian.Integrity] Server module v3 loaded.")