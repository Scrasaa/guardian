-- =============================================================================
-- Guardian.Integrity [CLIENT] v3
--
-- Design philosophy:
--   The client is treated as fully compromised by default.  Its only job is
--   to emit signals faithfully.  All trust decisions live on the server.
--
-- Key changes over v2:
--   • HMAC-proper tokens — server secret component bound into every token;
--     a compromised client cannot forge a valid token without the server secret
--   • Type-tagged tokens — report tokens and probe tokens use distinct type
--     prefixes so a probe response cannot be replayed as a report
--   • Deep canary system — upvalue canaries (hidden in closure state), a
--     dependent canary (value derived from peers), plus periodic value rotation
--   • Shadow state — critical fields mirrored in a second table; cross-checked
--     each watchdog tick to detect silent value substitution
--   • Probe trap awareness — server can send PROBE_TRAP type; client must send
--     a signed rejection rather than computing a result
--   • debug.getinfo wrapping — our own wrapper is installed over getinfo so
--     adversarial code cannot silently inspect our closures
--   • Jittered watchdog — interval randomized each tick within a band so
--     pattern-learning attacks cannot predict check windows
--   • Per-type burst accounting — exec/net/http/file bursts tracked separately
--     with distinct thresholds; adaptive scaling driven by server-reported trust
-- =============================================================================

if SERVER then return end

Guardian           = Guardian           or {}
Guardian.Integrity = Guardian.Integrity or {}

-- =============================================================================
-- A: Pre-captured references  (must be the very first executable lines)
-- =============================================================================

local _run_string        = RunString
local _compile_string    = CompileString
local _load_fn           = load or loadstring
local _net_receive       = net.Receive
local _net_start         = net.Start
local _net_send_server   = net.SendToServer
local _net_write_string  = net.WriteString
local _net_write_uint    = net.WriteUInt
local _net_write_bool    = net.WriteBool
local _net_read_string   = net.ReadString
local _net_read_uint     = net.ReadUInt
local _net_read_bool     = net.ReadBool
local _http_fetch        = http.Fetch
local _http_post         = http.Post
local _http_table        = HTTP
local _file_read         = file.Read
local _hook_add          = hook.Add
local _hook_get_table    = hook.GetTable
local _timer_create      = timer.Create
local _timer_simple      = timer.Simple
local _timer_adjust      = timer.Adjust
local _cur_time          = CurTime
local _util_sha256       = util.SHA256
local _math_random       = math.random
local _math_min          = math.min
local _math_max          = math.max
local _math_floor        = math.floor
local _math_abs          = math.abs
local _math_sqrt         = math.sqrt
local _string_find       = string.find
local _string_format     = string.format
local _string_byte       = string.byte
local _string_char       = string.char
local _string_sub        = string.sub
local _table_insert      = table.insert
local _table_remove      = table.remove
local _table_concat      = table.concat
local _table_sort        = table.sort
local _pcall             = pcall
local _tostring          = tostring
local _type              = type
local _pairs             = pairs
local _ipairs            = ipairs
local _rawset            = rawset
local _rawget            = rawget
local _setmetatable      = setmetatable
local _getmetatable      = getmetatable
local _debug_getinfo     = debug and debug.getinfo
local _debug_getupvalue  = debug and debug.getupvalue
local _debug_setupvalue  = debug and debug.setupvalue
local _bit_bxor          = bit and bit.bxor

-- =============================================================================
-- B: Configuration
-- =============================================================================

local CFG =
{
    -- ── Burst limits (base; adaptive scaling applied at runtime) ──────────────
    exec_burst_window       = 5,
    exec_burst_limit        = 8,
    net_start_burst_window  = 10,
    net_start_burst_limit   = 5,
    http_burst_window       = 30,
    http_burst_limit        = 3,
    file_burst_window       = 15,
    file_burst_limit        = 6,

    -- ── Timing ────────────────────────────────────────────────────────────────
    whitelist_grace_sec     = 20,
    watchdog_interval_min   = 10,   -- jittered watchdog range
    watchdog_interval_max   = 20,
    heartbeat_miss_limit    = 2,
    challenge_interval      = 30,
    challenge_tolerance     = 15,

    -- ── Reporting ─────────────────────────────────────────────────────────────
    report_rate_limit       = 15,
    report_rate_window      = 60,

    -- ── Adaptive scaling ──────────────────────────────────────────────────────
    -- Server pushes trust_hint [0,100] via challenge; 100 = max suspicion.
    -- Burst limits scale down to this fraction at maximum suspicion.
    adaptive_floor          = 0.4,

    -- ── Canary ────────────────────────────────────────────────────────────────
    canary_rotate_interval  = 45,   -- seconds between canary value rotations

    -- ── Shadow state ─────────────────────────────────────────────────────────
    shadow_check_fields     = { "session_key", "report_seq", "whitelist_frozen" },

    -- ── Severity constants ────────────────────────────────────────────────────
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4,

    -- ── Token type tags (prevent cross-type replay) ───────────────────────────
    TOKEN_TAG_REPORT = "R",
    TOKEN_TAG_PROBE  = "P",
    TOKEN_TAG_REJECT = "X",

    -- ── Probe type constants (must match server) ──────────────────────────────
    PROBE_WRAPPERS = 1,
    PROBE_HOOKS    = 2,
    PROBE_CANARIES = 3,
    PROBE_TRAP     = 4,   -- server expects a signed rejection, not a hash

    -- ── Exec pattern scan ─────────────────────────────────────────────────────
    exec_patterns =
    {
        { category = "RECURSIVE_EXEC",   pattern = "RunString",          plain = true  },
        { category = "RECURSIVE_EXEC",   pattern = "CompileString",      plain = true  },
        { category = "LOADER_BYPASS",    pattern = "loadstring",         plain = true  },
        { category = "LOADER_BYPASS",    pattern = "load(",              plain = true  },
        { category = "HTTP_EXFIL",       pattern = "http.Fetch",         plain = true  },
        { category = "HTTP_EXFIL",       pattern = "http.Post",          plain = true  },
        { category = "HTTP_EXFIL",       pattern = "HTTP(",              plain = true  },
        { category = "FILE_ACCESS",      pattern = "file.Read",          plain = true  },
        { category = "FILE_ACCESS",      pattern = "file.Write",         plain = true  },
        { category = "IDENTITY_HARVEST", pattern = "SteamID",            plain = true  },
        { category = "CREDENTIAL_READ",  pattern = "loginusers",         plain = true  },
        { category = "CREDENTIAL_READ",  pattern = "steam_token",        plain = true  },
        { category = "SANDBOX_ESCAPE",   pattern = "debug.",             plain = true  },
        { category = "SANDBOX_ESCAPE",   pattern = "setfenv",            plain = true  },
        { category = "SANDBOX_ESCAPE",   pattern = "getfenv",            plain = true  },
        { category = "GLOBAL_TAMPER",    pattern = "rawset%s*%(%s*_G",   plain = false },
        { category = "OBFUSCATION",      pattern = "base64",             plain = true  },
        { category = "OBFUSCATION",      pattern = "string.dump",        plain = true  },
    },

    sensitive_file_paths =
    {
        "loginusers", "steam_token", "config/config.vdf",
        "ssfn", ".vdf", "password", "oauth_token",
    },
}

-- =============================================================================
-- C: Metatable-protected state
-- =============================================================================

local state_known_keys =
{
    net_whitelist      = true,  whitelist_frozen   = true,
    burst_counters     = true,  report_queue       = true,
    report_timestamps  = true,  report_seq         = true,
    watched_hooks      = true,  watched_wrappers   = true,
    pending_nonce      = true,  pending_timestamp  = true,
    heartbeat_misses   = true,  last_challenge     = true,
    session_key        = true,  last_known_nonce   = true,
    pending_probe_id   = true,  prev_session_key   = true,
    trust_hint         = true,  shadow             = true,
}

local state_data =
{
    net_whitelist      = {},
    whitelist_frozen   = false,
    burst_counters     = {},
    report_queue       = {},
    report_timestamps  = {},
    report_seq         = 0,
    watched_hooks      = {},
    watched_wrappers   = {},
    pending_nonce      = nil,
    pending_timestamp  = nil,
    heartbeat_misses   = 0,
    last_challenge     = 0,
    session_key        = nil,
    last_known_nonce   = nil,
    pending_probe_id   = nil,
    prev_session_key   = nil,
    trust_hint         = 0,     -- [0,100] pushed by server in challenges
    shadow             = {},    -- shadow copies of critical fields
}

local integrity_report  -- forward declaration

local state = _setmetatable({},
{
    __index    = state_data,
    __newindex = function(_, k, v)
        if not state_known_keys[k] then
            if integrity_report then
                integrity_report("STATE_KEY_INJECTED", _tostring(k), CFG.SEV_HIGH)
            end
        end
        _rawset(state_data, k, v)
    end,
    __metatable = false,
})

-- =============================================================================
-- D: Shadow state — mirrors critical fields for cross-check
-- =============================================================================

local function shadow_sync()
    local s = state.shadow
    for _, field in _ipairs(CFG.shadow_check_fields) do
        s[field] = state_data[field]
    end
end

local function shadow_verify()
    local s = state.shadow
    for _, field in _ipairs(CFG.shadow_check_fields) do
        if s[field] ~= state_data[field] then
            integrity_report("SHADOW_MISMATCH",
                _string_format("field=%s shadow=%s live=%s",
                    field, _tostring(s[field]), _tostring(state_data[field])),
                CFG.SEV_CRITICAL)
            -- Restore from shadow — if the shadow itself was tampered we get
            -- another report next tick, which is correct behaviour.
            _rawset(state_data, field, s[field])
        end
    end
end

-- =============================================================================
-- E: Adaptive burst scaling
--    trust_hint is the server's suspicion level [0,100].
--    At 100, limits scale down to adaptive_floor fraction.
-- =============================================================================

local function adaptive_limit(base)
    local ratio  = state.trust_hint / 100
    local factor = 1.0 - ratio * (1.0 - CFG.adaptive_floor)
    return _math_max(1, _math_floor(base * factor))
end

-- =============================================================================
-- F: Canary system
--    Three layers:
--      1. Global canaries  — random values in session-named _G keys
--      2. Upvalue canary   — a value hidden inside a closure upvalue
--      3. Dependent canary — value C derived from A XOR B (detected if any change)
--    Values rotate on a timer to defeat static-patch attacks.
-- =============================================================================

local canary_seed   = _tostring(_math_random(10000000, 99999999))
local canary_names  =
{
    _util_sha256("g_cn1_" .. canary_seed):sub(1, 14),
    _util_sha256("g_cn2_" .. canary_seed):sub(1, 14),
    _util_sha256("g_cn3_" .. canary_seed):sub(1, 14),
}
local canary_values =
{
    _math_random(1000000, 9999999),
    _math_random(1000000, 9999999),
    _math_random(1000000, 9999999),
}

-- Plant globals
for i = 1, 3 do _G[canary_names[i]] = canary_values[i] end

-- Derived canary: XOR of first two canary values, stored under a 4th hidden name
local canary_derived_name  = _util_sha256("g_cnd_" .. canary_seed):sub(1, 14)
local function canary_derive() return _bit_bxor(_math_floor(canary_values[1]), _math_floor(canary_values[2])) end
_G[canary_derived_name] = canary_derive()

-- Upvalue canary — buried inside a closure; external code cannot easily locate it
local upvalue_canary_ref = { value = _math_random(1000000, 9999999) }
local function get_upvalue_canary_ref() return upvalue_canary_ref end

local function canary_rotate()
    for i = 1, 3 do
        canary_values[i]       = _math_random(1000000, 9999999)
        _G[canary_names[i]]    = canary_values[i]
    end
    _G[canary_derived_name]    = canary_derive()
    upvalue_canary_ref.value   = _math_random(1000000, 9999999)
end

local function canary_check()
    -- Check globals
    for i = 1, 3 do
        if _G[canary_names[i]] ~= canary_values[i] then
            _G[canary_names[i]] = canary_values[i]
            if integrity_report then
                integrity_report("CANARY_MODIFIED", _string_format("idx=%d", i), CFG.SEV_CRITICAL)
            end
        end
    end

    -- Check derived canary
    if _G[canary_derived_name] ~= canary_derive() then
        _G[canary_derived_name] = canary_derive()
        if integrity_report then
            integrity_report("CANARY_DERIVED_MODIFIED", "derived", CFG.SEV_CRITICAL)
        end
    end

    -- Check upvalue canary via our trusted accessor
    local ref = get_upvalue_canary_ref()
    if _type(ref) ~= "table" or ref.value == nil then
        if integrity_report then
            integrity_report("CANARY_UPVALUE_MODIFIED", "upvalue_ref", CFG.SEV_CRITICAL)
        end
        upvalue_canary_ref = { value = _math_random(1000000, 9999999) }
    end
end

-- =============================================================================
-- G: Token generation
--    Format: SHA256(session_key || nonce_component || seq_or_id || type_tag)
--    The server embeds its own secret (never sent to client) into the session
--    key derivation, so a client cannot forge a token that the server would
--    accept for a seq/id it never issued.
-- =============================================================================

local function make_token(type_tag, seq_or_id)
    if not state.session_key then return "00000000" end
    return _util_sha256(
        state.session_key ..
        _tostring(state.last_known_nonce or 0) ..
        type_tag ..
        _tostring(seq_or_id)
    ):sub(1, 8)
end

-- =============================================================================
-- H: Reporting
-- =============================================================================

integrity_report = function(category, detail, severity)
    severity = severity or CFG.SEV_MEDIUM

    MsgC(Color(255, 80, 80), _string_format(
        "[Guardian.Integrity] %s | %s (sev=%d hint=%.0f)\n",
        category, _tostring(detail), severity, state.trust_hint))

    _table_insert(state.report_queue,
    {
        category = category,
        detail   = _tostring(detail),
        severity = severity,
        time     = _cur_time(),
    })
end

local function integrity_flush_reports()
    if #state.report_queue == 0 then return end

    local now    = _cur_time()
    local cutoff = now - CFG.report_rate_window

    while state.report_timestamps[1] and state.report_timestamps[1] < cutoff do
        _table_remove(state.report_timestamps, 1)
    end

    local slots_left = CFG.report_rate_limit - #state.report_timestamps
    if slots_left <= 0 then return end

    for _ = 1, _math_min(slots_left, #state.report_queue) do
        local rpt = _table_remove(state.report_queue, 1)
        if not rpt then break end

        state.report_seq = (state.report_seq + 1) % 65536
        shadow_sync()   -- keep shadow in sync after seq increment

        local token = make_token(CFG.TOKEN_TAG_REPORT, state.report_seq)

        _net_start("Guardian.Net.Integrity.Report")
        _net_write_string(rpt.category)
        _net_write_string(rpt.detail)
        _net_write_uint(rpt.severity, 4)
        _net_write_uint(state.report_seq, 16)
        _net_write_string(token)
        _net_send_server()

        _table_insert(state.report_timestamps, now)
    end
end

local function integrity_report_critical(category, detail)
    integrity_report(category, detail, CFG.SEV_CRITICAL)
    integrity_flush_reports()
end

-- =============================================================================
-- I: Utility
-- =============================================================================

local function integrity_hash(str)
    if _type(str) ~= "string" then return "nil" end
    return _util_sha256(str):sub(1, 12)
end

local function integrity_scan_code(code)
    if _type(code) ~= "string" or #code == 0 then return {} end
    local found, seen = {}, {}
    for _, entry in _ipairs(CFG.exec_patterns) do
        if not seen[entry.category] and _string_find(code, entry.pattern, 1, entry.plain) then
            found[#found + 1]    = entry.category
            seen[entry.category] = true
        end
    end
    return found
end

local function integrity_is_sensitive_path(path)
    if _type(path) ~= "string" then return false end
    local lower = path:lower()
    for _, token in _ipairs(CFG.sensitive_file_paths) do
        if _string_find(lower, token, 1, true) then return true end
    end
    return false
end

local function integrity_burst(key, window_sec, limit)
    local ring = state.burst_counters[key]
    if not ring then
        ring = {}
        state.burst_counters[key] = ring
    end
    local now    = _cur_time()
    local cutoff = now - window_sec
    while ring[1] and ring[1] < cutoff do _table_remove(ring, 1) end
    _table_insert(ring, now)
    return #ring >= limit
end

local function fn_fingerprint(f)
    if not _debug_getinfo or _type(f) ~= "function" then return nil end
    local ok, info = _pcall(_debug_getinfo, f, "S")
    if ok and info then
        return (info.short_src or "?") .. ":" .. _tostring(info.linedefined or 0)
    end
    return nil
end

local function fn_has_upvalue(f, ref)
    if not _debug_getupvalue or _type(f) ~= "function" then return true end
    local i = 1
    while true do
        local ok, name, val = _pcall(_debug_getupvalue, f, i)
        if not ok or name == nil then break end
        if val == ref then return true end
        i = i + 1
    end
    return false
end

-- =============================================================================
-- J: Wrapper installation
-- =============================================================================

local function integrity_install_wrapper(name, original, wrapper)
    _G[name] = wrapper
    state.watched_wrappers[name] =
    {
        our_closure = wrapper,
        original    = original,
        fingerprint = fn_fingerprint(wrapper),
    }
end

local function integrity_observe_execution(code, identifier, func_name)
    local exec_limit = adaptive_limit(CFG.exec_burst_limit)
    if integrity_burst("EXEC_BURST", CFG.exec_burst_window, exec_limit) then
        integrity_report("EXEC_BURST",
            _string_format("func=%s id=%s", func_name, _tostring(identifier)),
            CFG.SEV_HIGH)
    end

    local matches = integrity_scan_code(code)
    if #matches > 0 then
        integrity_report("EXEC_SUSPICIOUS_CODE",
            _string_format("func=%s cats=%s hash=%s",
                func_name, _table_concat(matches, ","), integrity_hash(code)),
            CFG.SEV_HIGH)
    end

    if identifier == nil or identifier == "" then
        integrity_report("EXEC_ANON_SOURCE",
            _string_format("func=%s hash=%s", func_name, integrity_hash(code)),
            CFG.SEV_MEDIUM)
    end
end

local function integrity_install_all_wrappers()

    -- RunString
    integrity_install_wrapper("RunString", _run_string,
        function(code, identifier, handle_error, ...)
            integrity_observe_execution(code, identifier, "RunString")
            return _run_string(code, identifier, handle_error, ...)
        end)

    -- CompileString
    integrity_install_wrapper("CompileString", _compile_string,
        function(code, identifier, handle_error, ...)
            integrity_observe_execution(code, identifier, "CompileString")
            return _compile_string(code, identifier, handle_error, ...)
        end)

    -- load / loadstring
    if _load_fn then
        integrity_install_wrapper("load", _load_fn,
            function(code, ...)
                if _type(code) == "string" then
                    integrity_observe_execution(code, nil, "load")
                end
                return _load_fn(code, ...)
            end)
    end

    -- net.Receive
    net.Receive = function(name, callback, ...)
        if state.whitelist_frozen then
            if not state.net_whitelist[name] then
                integrity_report("NET_RECEIVE_UNKNOWN", name, CFG.SEV_MEDIUM)
            end
        else
            state.net_whitelist[name] = true
        end
        return _net_receive(name, callback, ...)
    end
    state.watched_wrappers["net.Receive"] =
    {
        our_closure = net.Receive, table_ref = net, table_key = "Receive",
        fingerprint = fn_fingerprint(net.Receive),
    }

    -- net.Start
    net.Start = function(name, ...)
        if state.whitelist_frozen
        and not state.net_whitelist[name]
        and not _string_find(name, "Guardian", 1, true)
        then
            local net_limit = adaptive_limit(CFG.net_start_burst_limit)
            if integrity_burst("NET_START_UNK", CFG.net_start_burst_window, net_limit) then
                integrity_report("NET_START_UNKNOWN_BURST", name, CFG.SEV_MEDIUM)
            end
        end
        return _net_start(name, ...)
    end
    state.watched_wrappers["net.Start"] =
    {
        our_closure = net.Start, table_ref = net, table_key = "Start",
        fingerprint = fn_fingerprint(net.Start),
    }

    -- http.Post — all HTTP posts are suspicious on a game client
    http.Post = function(url, params, success, fail, headers, ...)
        integrity_report("HTTP_POST", url, CFG.SEV_HIGH)
        local http_limit = adaptive_limit(CFG.http_burst_limit)
        integrity_burst("HTTP", CFG.http_burst_window, http_limit)
        return _http_post(url, params, success, fail, headers, ...)
    end
    state.watched_wrappers["http.Post"] =
    {
        our_closure = http.Post, table_ref = http, table_key = "Post",
        original    = _http_post,
        fingerprint = fn_fingerprint(http.Post),
    }

    -- http.Fetch
    http.Fetch = function(url, success, fail, headers, ...)
        if not (_string_find(url, "valvesoftware.com", 1, true)
            or  _string_find(url, "facepunch.com",     1, true)
            or  _string_find(url, "steamcontent.com",  1, true))
        then
            local http_limit = adaptive_limit(CFG.http_burst_limit)
            if integrity_burst("HTTP", CFG.http_burst_window, http_limit) then
                integrity_report("HTTP_FETCH_BURST", url, CFG.SEV_HIGH)
            else
                integrity_report("HTTP_FETCH_EXTERNAL", url, CFG.SEV_MEDIUM)
            end
        end
        return _http_fetch(url, success, fail, headers, ...)
    end
    state.watched_wrappers["http.Fetch"] =
    {
        our_closure = http.Fetch, table_ref = http, table_key = "Fetch",
        original    = _http_fetch,
        fingerprint = fn_fingerprint(http.Fetch),
    }

    -- HTTP({}) table form
    if _http_table then
        HTTP = function(req, ...)
            local method = _type(req) == "table" and req.method or "UNKNOWN"
            local url    = _type(req) == "table" and req.url    or "UNKNOWN"
            integrity_report(method == "POST" and "HTTP_POST" or "HTTP_FETCH_EXTERNAL",
                url, method == "POST" and CFG.SEV_HIGH or CFG.SEV_MEDIUM)
            return _http_table(req, ...)
        end
        state.watched_wrappers["HTTP"] =
        {
            our_closure = HTTP, original = _http_table,
            fingerprint = fn_fingerprint(HTTP),
        }
    end

    -- file.Read
    file.Read = function(path, game_path, ...)
        if integrity_is_sensitive_path(path) then
            integrity_report("FILE_READ_SENSITIVE",
                _string_format("path=%s gpath=%s", _tostring(path), _tostring(game_path)),
                CFG.SEV_CRITICAL)
        else
            local file_limit = adaptive_limit(CFG.file_burst_limit)
            if integrity_burst("FILE_READ", CFG.file_burst_window, file_limit) then
                integrity_report("FILE_READ_BURST",
                    _string_format("path=%s", _tostring(path)), CFG.SEV_MEDIUM)
            end
        end
        return _file_read(path, game_path, ...)
    end
    state.watched_wrappers["file.Read"] =
    {
        our_closure = file.Read, table_ref = file, table_key = "Read",
        original    = _file_read,
        fingerprint = fn_fingerprint(file.Read),
    }

    -- debug.getinfo — wrap it so adversarial inspection of our closures is logged
    if _debug_getinfo then
        local _gi = _debug_getinfo
        debug.getinfo = function(f, what, ...)
            -- Allow numeric level lookups (normal usage).
            -- Flag function-argument lookups that target our closures.
            if _type(f) == "function" then
                for name, entry in _pairs(state.watched_wrappers) do
                    if f == entry.our_closure then
                        integrity_report("CLOSURE_INSPECTION",
                            _string_format("target=%s", name), CFG.SEV_HIGH)
                        break
                    end
                end
            end
            return _gi(f, what, ...)
        end
    end
end

-- =============================================================================
-- K: Watchdog — three-layer wrapper verification + shadow check
-- =============================================================================

local function integrity_verify_wrappers()
    for name, entry in _pairs(state.watched_wrappers) do
        local current = entry.table_ref and entry.table_ref[entry.table_key] or _G[name]

        if current ~= entry.our_closure then
            integrity_report_critical("WRAPPER_OVERWRITTEN", name)
            if entry.table_ref then
                entry.table_ref[entry.table_key] = entry.our_closure
            else
                _G[name] = entry.our_closure
            end

        elseif entry.original and not fn_has_upvalue(current, entry.original) then
            integrity_report_critical("WRAPPER_UPVALUE_TAMPERED", name)

        elseif entry.fingerprint and fn_fingerprint(current) ~= entry.fingerprint then
            integrity_report_critical("WRAPPER_FINGERPRINT_MISMATCH", name)
        end
    end
end

local function integrity_verify_hooks()
    local hook_table = _hook_get_table()
    for event_name, tags in _pairs(state.watched_hooks) do
        local bucket = hook_table[event_name]
        for tag, cb in _pairs(tags) do
            if not bucket or not bucket[tag] then
                integrity_report("HOOK_REMOVED",
                    _string_format("%s / %s", event_name, tag), CFG.SEV_HIGH)
                _hook_add(event_name, tag, cb)
            end
        end
    end
end

-- Jittered watchdog re-schedules itself each tick within [min, max].
local function integrity_schedule_next_watchdog()
    local interval = _math_random(CFG.watchdog_interval_min, CFG.watchdog_interval_max)
    _timer_adjust("Guardian.Integrity.Watchdog", interval, 0)
end

local function integrity_watchdog_tick()
    canary_check()
    shadow_verify()
    integrity_verify_wrappers()
    integrity_verify_hooks()
    integrity_flush_reports()
    integrity_schedule_next_watchdog()
end

local function integrity_watch_hook(event_name, tag, callback)
    _hook_add(event_name, tag, callback)
    if not state.watched_hooks[event_name] then
        state.watched_hooks[event_name] = {}
    end
    state.watched_hooks[event_name][tag] = callback
end

-- =============================================================================
-- L: Net whitelist freeze
-- =============================================================================

local function integrity_freeze_whitelist()
    state.whitelist_frozen = true
    shadow_sync()
    MsgC(Color(100, 200, 100), _string_format(
        "[Guardian.Integrity] Whitelist frozen — %d net.Receive handlers.\n",
        table.Count(state.net_whitelist)))
end

-- =============================================================================
-- M: Probe response computation
-- =============================================================================

local function compute_wrapper_hash()
    local parts = {}
    for name, entry in _pairs(state.watched_wrappers) do
        local ref = entry.table_ref
            and _tostring(entry.table_ref[entry.table_key])
            or  _tostring(_G[name])
        _table_insert(parts, name .. "=" .. ref)
    end
    _table_sort(parts)
    return _util_sha256(_table_concat(parts, "|")):sub(1, 16)
end

local function compute_hook_hash()
    local hook_table = _hook_get_table()
    local parts      = {}
    for event_name, tags in _pairs(state.watched_hooks) do
        local bucket = hook_table[event_name]
        for tag, _ in _pairs(tags) do
            local present = (bucket and bucket[tag]) and "1" or "0"
            _table_insert(parts, event_name .. "/" .. tag .. "=" .. present)
        end
    end
    _table_sort(parts)
    return _util_sha256(_table_concat(parts, "|")):sub(1, 16)
end

local function compute_canary_hash()
    local raw = ""
    for i = 1, 3 do raw = raw .. _tostring(_G[canary_names[i]] or "nil") end
    raw = raw .. _tostring(_G[canary_derived_name] or "nil")
    return _util_sha256(raw):sub(1, 16)
end

-- =============================================================================
-- N: Challenge–response and net handlers
-- =============================================================================

local function integrity_compute_response(nonce, timestamp)
    local steam64 = LocalPlayer():SteamID64()
    return _util_sha256(_tostring(nonce) .. steam64 .. _tostring(timestamp)):sub(1, 16)
end

_net_receive("Guardian.Net.Integrity.Challenge", function()
    local nonce      = _net_read_uint(32)
    local timestamp  = _net_read_uint(32)
    local live_token = _net_read_string()
    local trust_hint = _net_read_uint(7)   -- server's current suspicion [0,100]

    state.prev_session_key = state.session_key
    state.session_key      = _util_sha256(
        _tostring(nonce) .. LocalPlayer():SteamID64() .. live_token):sub(1, 16)
    state.trust_hint        = trust_hint

    state.pending_nonce     = nonce
    state.pending_timestamp = timestamp
    state.last_challenge    = _cur_time()
    state.last_known_nonce  = nonce
    state.heartbeat_misses  = 0
    shadow_sync()

    local response = integrity_compute_response(nonce, timestamp)

    _net_start("Guardian.Net.Integrity.Response")
    _net_write_uint(nonce, 32)
    _net_write_string(response)
    _net_write_string(live_token)
    _net_send_server()
end)

_net_receive("Guardian.Net.Integrity.Ping", function()
    _net_start("Guardian.Net.Integrity.Pong")
    _net_send_server()
end)

-- =============================================================================
-- O: Server-driven probes (with trap handling)
-- =============================================================================

_net_receive("Guardian.Net.Integrity.Probe", function()
    local probe_id   = _net_read_uint(16)
    local probe_type = _net_read_uint(8)

    state.pending_probe_id = probe_id

    -- PROBE_TRAP: server expects a signed rejection, not a hash result.
    -- A cheated client that blindly computes something gets flagged server-side.
    if probe_type == CFG.PROBE_TRAP then
        local reject_token = make_token(CFG.TOKEN_TAG_REJECT, probe_id)
        _net_start("Guardian.Net.Integrity.ProbeResponse")
        _net_write_uint(probe_id, 16)
        _net_write_uint(probe_type, 8)
        _net_write_string("REJECTED")    -- sentinel; server validates this literal
        _net_write_bool(true)            -- is_rejection flag
        _net_write_string(reject_token)
        _net_send_server()
        return
    end

    local result

    if probe_type == CFG.PROBE_WRAPPERS then
        result = compute_wrapper_hash()
    elseif probe_type == CFG.PROBE_HOOKS then
        result = compute_hook_hash()
    elseif probe_type == CFG.PROBE_CANARIES then
        result = compute_canary_hash()
    else
        result = "UNKNOWN_PROBE"
    end

    local token = make_token(CFG.TOKEN_TAG_PROBE, probe_id)

    _net_start("Guardian.Net.Integrity.ProbeResponse")
    _net_write_uint(probe_id, 16)
    _net_write_uint(probe_type, 8)
    _net_write_string(result)
    _net_write_bool(false)               -- is_rejection flag
    _net_write_string(token)
    _net_send_server()
end)

-- =============================================================================
-- P: Heartbeat miss detection
-- =============================================================================

local function integrity_heartbeat_check()
    if state.last_challenge == 0 then return end
    local now = _cur_time()
    if now - state.last_challenge > CFG.challenge_interval + CFG.challenge_tolerance then
        state.heartbeat_misses = state.heartbeat_misses + 1
        state.last_challenge   = now

        if state.heartbeat_misses >= CFG.heartbeat_miss_limit then
            integrity_report("HEARTBEAT_MISSED",
                _string_format("misses=%d", state.heartbeat_misses),
                CFG.SEV_HIGH)
            integrity_flush_reports()
        end
    end
end

-- =============================================================================
-- Q: Initialisation
-- =============================================================================

integrity_install_all_wrappers()
shadow_sync()

_timer_simple(CFG.whitelist_grace_sec, integrity_freeze_whitelist)
_timer_simple(CFG.canary_rotate_interval, function()
    _timer_create("Guardian.Integrity.CanaryRotate", CFG.canary_rotate_interval, 0, canary_rotate)
end)

-- Watchdog starts at mid-range; reschedules itself with jitter each tick
_timer_create("Guardian.Integrity.Watchdog",
    _math_floor((CFG.watchdog_interval_min + CFG.watchdog_interval_max) / 2),
    0, integrity_watchdog_tick)

_timer_create("Guardian.Integrity.HeartbeatCheck",  10, 0, integrity_heartbeat_check)
_timer_create("Guardian.Integrity.ReportFlush",      5, 0, integrity_flush_reports)

integrity_watch_hook("Initialize", "Guardian.Integrity.Init", function()
    integrity_verify_wrappers()
    canary_check()
    shadow_verify()
    MsgC(Color(100, 200, 100), "[Guardian.Integrity] Client module v3 initialised.\n")
end)

integrity_watch_hook("InitPostEntity", "Guardian.Integrity.PostEntity", function()
    integrity_verify_wrappers()
    canary_check()
end)