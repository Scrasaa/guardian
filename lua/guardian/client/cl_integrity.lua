-- =============================================================================
-- Guardian.Integrity [CLIENT]
-- Unauthorised execution, hook tampering, net abuse, and data exfiltration
-- detection.  Pairs with sv_integrity.lua for challenge-response and server-
-- side report processing.
-- =============================================================================

if SERVER then return end

Guardian          = Guardian          or {}
Guardian.Integrity = Guardian.Integrity or {}

-- =============================================================================
-- Configuration
-- =============================================================================

local CFG =
{
    -- RunString / CompileString burst detection
    exec_burst_window   = 5,     -- seconds in sliding window
    exec_burst_limit    = 8,     -- calls before burst flag fires

    -- net.Receive whitelist: registrations after this many seconds post-load
    -- are treated as unknown injected handlers.
    whitelist_grace_sec = 20,

    -- net.Start unknown-name burst
    net_start_burst_window = 10,
    net_start_burst_limit  = 5,

    -- Watchdog: how often hook + wrapper integrity is verified (seconds)
    watchdog_interval = 15,

    -- Heartbeat: tolerated consecutive missed challenges before flag
    heartbeat_miss_limit = 2,

    -- Reporting: max reports dispatched to the server per window
    report_rate_limit  = 15,
    report_rate_window = 60,

    -- Severity constants (used in reports)
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4,

    -- Patterns scanned inside dynamic code strings.
    -- Only category names are reported; raw code is never transmitted.
    exec_patterns =
    {
        { category = "RECURSIVE_EXEC",   pattern = "RunString",      plain = true  },
        { category = "RECURSIVE_EXEC",   pattern = "CompileString",  plain = true  },
        { category = "HTTP_EXFIL",       pattern = "http.Fetch",     plain = true  },
        { category = "HTTP_EXFIL",       pattern = "http.Post",      plain = true  },
        { category = "HTTP_EXFIL",       pattern = "HTTP(",          plain = true  },
        { category = "FILE_ACCESS",      pattern = "file.Read",      plain = true  },
        { category = "FILE_ACCESS",      pattern = "file.Write",     plain = true  },
        { category = "IDENTITY_HARVEST", pattern = "SteamID",        plain = true  },
        { category = "CREDENTIAL_READ",  pattern = "loginusers",     plain = true  },
        { category = "CREDENTIAL_READ",  pattern = "steam_token",    plain = true  },
        { category = "SANDBOX_ESCAPE",   pattern = "debug.",         plain = true  },
        { category = "SANDBOX_ESCAPE",   pattern = "setfenv",        plain = true  },
        { category = "SANDBOX_ESCAPE",   pattern = "getfenv",        plain = true  },
        { category = "GLOBAL_TAMPER",    pattern = "rawset%s*%(%s*_G", plain = false },
        { category = "OBFUSCATION",      pattern = "base64",         plain = true  },
        { category = "OBFUSCATION",      pattern = "string.dump",    plain = true  },
    },

    -- file.Read paths that should never be read by arbitrary code
    sensitive_file_paths =
    {
        "loginusers",
        "steam_token",
        "config/config.vdf",
        "ssfn",
        ".vdf",
        "password",
        "oauth_token",
    },
}

-- =============================================================================
-- Pre-wrap references  —  captured before any other code can replace them.
-- Using local upvalues means our originals survive even if _G is later patched.
-- =============================================================================

local _run_string       = RunString
local _compile_string   = CompileString
local _net_receive      = net.Receive
local _net_start        = net.Start
local _net_send_server  = net.SendToServer
local _net_write_string = net.WriteString
local _net_write_uint   = net.WriteUInt
local _net_read_string  = net.ReadString
local _net_read_uint    = net.ReadUInt
local _http_fetch       = http.Fetch
local _http_post        = http.Post
local _http_table       = HTTP          -- newer GMod HTTP({}) form
local _file_read        = file.Read
local _hook_add         = hook.Add
local _hook_remove      = hook.Remove
local _hook_get_table   = hook.GetTable
local _timer_create     = timer.Create
local _timer_simple     = timer.Simple
local _cur_time         = CurTime
local _util_sha256      = util.SHA256
local _math_random      = math.random
local _string_find      = string.find
local _string_format    = string.format
local _table_insert     = table.insert
local _table_remove     = table.remove

-- =============================================================================
-- Internal state
-- =============================================================================

local state =
{
    -- net.Receive whitelist
    net_whitelist   = {},
    whitelist_frozen = false,

    -- Burst tracking: maps category → { timestamps ring }
    burst_counters = {},

    -- Report queue
    report_queue       = {},
    report_timestamps  = {},   -- timestamps of dispatched reports this window
    report_seq         = 0,    -- monotonic sequence number (wraps at 65535)

    -- Hook watchdog: maps hook_event → { tag → callback }
    watched_hooks = {},

    -- Wrapper table: maps name → { current_global_key, our_closure }
    watched_wrappers = {},

    -- Challenge state
    pending_nonce     = nil,
    pending_timestamp = nil,
    heartbeat_misses  = 0,
    last_challenge    = 0,
}

-- =============================================================================
-- Utility
-- =============================================================================

-- Short non-reversible fingerprint of a string — used so we can compare
-- code blobs for repeat detection without storing or transmitting raw code.
local function integrity_hash(str)
    if type(str) ~= "string" then return "nil" end
    -- SHA256 is available in GMod; we take only the first 12 chars.
    return _util_sha256(str):sub(1, 12)
end

-- Scan dynamic code for suspicious token categories.
-- Returns a table of unique category strings matched, or an empty table.
local function integrity_scan_code(code)
    if type(code) ~= "string" or #code == 0 then return {} end

    local found    = {}
    local seen_cat = {}

    for _, entry in ipairs(CFG.exec_patterns) do
        if not seen_cat[entry.category] then
            if _string_find(code, entry.pattern, 1, entry.plain) then
                found[#found + 1]        = entry.category
                seen_cat[entry.category] = true
            end
        end
    end

    return found
end

-- Check whether a file path touches a known-sensitive location.
local function integrity_is_sensitive_path(path)
    if type(path) ~= "string" then return false end
    local lower = path:lower()
    for _, token in ipairs(CFG.sensitive_file_paths) do
        if _string_find(lower, token, 1, true) then return true end
    end
    return false
end

-- Sliding-window burst detector.
-- Returns true if the number of events for `key` within the configured
-- window exceeds the configured limit.
local function integrity_burst(key, window_sec, limit)
    local ring = state.burst_counters[key]
    if not ring then
        ring = {}
        state.burst_counters[key] = ring
    end

    local now    = _cur_time()
    local cutoff = now - window_sec

    -- Evict stale entries from the front
    while ring[1] and ring[1] < cutoff do
        _table_remove(ring, 1)
    end

    _table_insert(ring, now)

    return #ring >= limit
end

-- =============================================================================
-- Reporting
-- =============================================================================

-- Queue a report.  category is a short string identifier; detail is any
-- additional context (never raw code); severity is one of CFG.SEV_*.
local function integrity_report(category, detail, severity)
    severity = severity or CFG.SEV_MEDIUM

    -- Always print locally so server admins with file access can audit logs.
    MsgC(Color(255, 80, 80), _string_format(
        "[Guardian.Integrity] %s | %s (sev=%d)\n",
        category, tostring(detail), severity))

    state.report_queue[#state.report_queue + 1] =
    {
        category = category,
        detail   = tostring(detail),
        severity = severity,
        time     = _cur_time(),
    }
end

-- Flush queued reports to the server, honouring the rate limit.
-- Called by a timer; also callable directly for CRITICAL events.
local function integrity_flush_reports()
    if #state.report_queue == 0 then return end

    -- Purge old dispatch timestamps outside the rate window
    local now    = _cur_time()
    local cutoff = now - CFG.report_rate_window
    while state.report_timestamps[1] and state.report_timestamps[1] < cutoff do
        _table_remove(state.report_timestamps, 1)
    end

    -- Respect per-window cap
    local slots_left = CFG.report_rate_limit - #state.report_timestamps
    if slots_left <= 0 then return end

    local to_send = math.min(slots_left, #state.report_queue)

    for i = 1, to_send do
        local rpt = _table_remove(state.report_queue, 1)
        if not rpt then break end

        state.report_seq = (state.report_seq + 1) % 65536

        _net_start("Guardian.Net.Integrity.Report")
        _net_write_string(rpt.category)
        _net_write_string(rpt.detail)
        _net_write_uint(rpt.severity, 4)
        _net_write_uint(state.report_seq, 16)
        _net_send_server()

        _table_insert(state.report_timestamps, now)
    end
end

-- Direct flush bypass for CRITICAL reports — uses cached net references so
-- a cheat that patched public net.Start/SendToServer cannot suppress it.
local function integrity_report_critical(category, detail)
    integrity_report(category, detail, CFG.SEV_CRITICAL)
    integrity_flush_reports()
end

-- =============================================================================
-- Function wrappers
-- =============================================================================

-- Wraps a global function in-place and registers it with the watchdog.
-- `name` is the _G key (e.g. "RunString"), `original` is the pre-wrapped
-- reference, `wrapper` is the closure we install.
local function integrity_install_wrapper(name, original, wrapper)
    _G[name] = wrapper
    state.watched_wrappers[name] =
    {
        our_closure = wrapper,
        original    = original,
    }
end

-- Called during execution observation for RunString/CompileString.
local function integrity_observe_execution(code, identifier, func_name)
    -- Burst check: too many dynamic executions in a short window
    if integrity_burst("EXEC_BURST", CFG.exec_burst_window, CFG.exec_burst_limit) then
        integrity_report("EXEC_BURST",
            _string_format("func=%s id=%s", func_name, tostring(identifier)),
            CFG.SEV_HIGH)
    end

    -- Pattern scan: check code for suspicious API usage
    local matches = integrity_scan_code(code)
    if #matches > 0 then
        local category_str = table.concat(matches, ",")
        integrity_report("EXEC_SUSPICIOUS_CODE",
            _string_format("func=%s cats=%s hash=%s",
                func_name, category_str, integrity_hash(code)),
            CFG.SEV_HIGH)
    end

    -- Unknown source identifier (blank, or one we've never seen legitimately)
    -- is a medium signal on its own.
    if identifier == nil or identifier == "" then
        integrity_report("EXEC_ANON_SOURCE",
            _string_format("func=%s hash=%s", func_name, integrity_hash(code)),
            CFG.SEV_MEDIUM)
    end
end

local function integrity_install_all_wrappers()

    -- RunString
    integrity_install_wrapper("RunString",
        _run_string,
        function(code, identifier, handle_error, ...)
            integrity_observe_execution(code, identifier, "RunString")
            return _run_string(code, identifier, handle_error, ...)
        end)

    -- CompileString
    integrity_install_wrapper("CompileString",
        _compile_string,
        function(code, identifier, handle_error, ...)
            integrity_observe_execution(code, identifier, "CompileString")
            return _compile_string(code, identifier, handle_error, ...)
        end)

    -- net.Receive — whitelist building + post-freeze enforcement
    net.Receive = function(name, callback, ...)
        if state.whitelist_frozen then
            if not state.net_whitelist[name] then
                integrity_report("NET_RECEIVE_UNKNOWN",
                    name, CFG.SEV_MEDIUM)
            end
        else
            state.net_whitelist[name] = true
        end
        return _net_receive(name, callback, ...)
    end
    state.watched_wrappers["net.Receive"] =
    {
        our_closure = net.Receive,
        table_ref   = net,
        table_key   = "Receive",
    }

    -- net.Start — monitor outbound message names for burst / unknown targets
    net.Start = function(name, ...)
        if state.whitelist_frozen
        and not state.net_whitelist[name]
        and not _string_find(name, "Guardian", 1, true)
        then
            if integrity_burst("NET_START_UNK", CFG.net_start_burst_window, CFG.net_start_burst_limit) then
                integrity_report("NET_START_UNKNOWN_BURST",
                    name, CFG.SEV_MEDIUM)
            end
        end
        return _net_start(name, ...)
    end
    state.watched_wrappers["net.Start"] =
    {
        our_closure = net.Start,
        table_ref   = net,
        table_key   = "Start",
    }

    -- http.Post — any POST is high-severity; URL logged, body never transmitted
    http.Post = function(url, params, success, fail, headers, ...)
        integrity_report("HTTP_POST", url, CFG.SEV_HIGH)
        return _http_post(url, params, success, fail, headers, ...)
    end
    state.watched_wrappers["http.Post"] =
    {
        our_closure = http.Post,
        table_ref   = http,
        table_key   = "Post",
    }

    -- http.Fetch — medium severity; external unknown domains flagged
    http.Fetch = function(url, success, fail, headers, ...)
        -- Allow Valve/Facepunch CDNs silently
        if not (_string_find(url, "valvesoftware.com", 1, true)
            or  _string_find(url, "facepunch.com",     1, true)
            or  _string_find(url, "steamcontent.com",  1, true))
        then
            integrity_report("HTTP_FETCH_EXTERNAL", url, CFG.SEV_MEDIUM)
        end
        return _http_fetch(url, success, fail, headers, ...)
    end
    state.watched_wrappers["http.Fetch"] =
    {
        our_closure = http.Fetch,
        table_ref   = http,
        table_key   = "Fetch",
    }

    -- HTTP({}) table-form — same policy as Fetch/Post
    if _http_table then
        HTTP = function(req, ...)
            local method = type(req) == "table" and req.method or "UNKNOWN"
            local url    = type(req) == "table" and req.url    or "UNKNOWN"

            if method == "POST" then
                integrity_report("HTTP_POST", url, CFG.SEV_HIGH)
            else
                integrity_report("HTTP_FETCH_EXTERNAL", url, CFG.SEV_MEDIUM)
            end
            return _http_table(req, ...)
        end
        state.watched_wrappers["HTTP"] =
        {
            our_closure = HTTP,
            original    = _http_table,
        }
    end

    -- file.Read — flag sensitive paths; never log the file contents
    file.Read = function(path, game_path, ...)
        if integrity_is_sensitive_path(path) then
            integrity_report("FILE_READ_SENSITIVE",
                _string_format("path=%s game_path=%s", tostring(path), tostring(game_path)),
                CFG.SEV_CRITICAL)
        end
        return _file_read(path, game_path, ...)
    end
    state.watched_wrappers["file.Read"] =
    {
        our_closure = file.Read,
        table_ref   = file,
        table_key   = "Read",
    }
end

-- =============================================================================
-- Watchdog — hook + wrapper integrity verification
-- =============================================================================

local function integrity_verify_wrappers()
    for name, entry in pairs(state.watched_wrappers) do
        -- Table-keyed wrappers (net, http, file sub-tables)
        if entry.table_ref then
            if entry.table_ref[entry.table_key] ~= entry.our_closure then
                integrity_report_critical("WRAPPER_OVERWRITTEN", name)
                -- Reinstall using cached original
                entry.table_ref[entry.table_key] = entry.our_closure
            end
        else
            -- _G-level wrappers
            if _G[name] ~= entry.our_closure then
                integrity_report_critical("WRAPPER_OVERWRITTEN", name)
                _G[name] = entry.our_closure
            end
        end
    end
end

local function integrity_verify_hooks()
    local hook_table = _hook_get_table()

    for event_name, tags in pairs(state.watched_hooks) do
        local bucket = hook_table[event_name]
        for tag, cb in pairs(tags) do
            if not bucket or not bucket[tag] then
                integrity_report("HOOK_REMOVED",
                    _string_format("%s / %s", event_name, tag),
                    CFG.SEV_HIGH)
                -- Silently re-register using cached hook.Add reference
                _hook_add(event_name, tag, cb)
            end
        end
    end
end

local function integrity_watchdog_tick()
    integrity_verify_wrappers()
    integrity_verify_hooks()
    integrity_flush_reports()
end

-- Wrapper around hook.Add that also registers the hook for watchdog monitoring.
local function integrity_watch_hook(event_name, tag, callback)
    _hook_add(event_name, tag, callback)
    if not state.watched_hooks[event_name] then
        state.watched_hooks[event_name] = {}
    end
    state.watched_hooks[event_name][tag] = callback
end

-- =============================================================================
-- Net whitelist freeze
-- =============================================================================

local function integrity_freeze_whitelist()
    state.whitelist_frozen = true
    MsgC(Color(100, 200, 100), _string_format(
        "[Guardian.Integrity] Whitelist frozen — %d net.Receive handlers known.\n",
        table.Count(state.net_whitelist)))
end

-- =============================================================================
-- Challenge–response
-- =============================================================================

-- The server sends a nonce (UInt32) and a Unix timestamp (UInt32).
-- We respond with the first 16 characters of SHA256(nonce..SteamID64..timestamp).
-- Only the truncated hash travels over the wire; neither nonce nor SteamID
-- are transmitted in plain form.

local function integrity_compute_response(nonce, timestamp)
    local steam64 = LocalPlayer():SteamID64()
    local input   = tostring(nonce) .. steam64 .. tostring(timestamp)
    return _util_sha256(input):sub(1, 16)
end

_net_receive("Guardian.Net.Integrity.Challenge", function()
    local nonce     = _net_read_uint(32)
    local timestamp = _net_read_uint(32)

    state.pending_nonce     = nonce
    state.pending_timestamp = timestamp
    state.last_challenge    = _cur_time()
    state.heartbeat_misses  = 0   -- receiving a challenge resets the miss counter

    local response = integrity_compute_response(nonce, timestamp)

    _net_start("Guardian.Net.Integrity.Response")
    _net_write_uint(nonce, 32)
    _net_write_string(response)
    _net_send_server()
end)

-- The server can also send a lightweight ping to verify the client's net
-- receiver is alive without issuing a full challenge.
_net_receive("Guardian.Net.Integrity.Ping", function()
    _net_start("Guardian.Net.Integrity.Pong")
    _net_send_server()
end)

-- =============================================================================
-- Heartbeat miss detection (client-side)
-- =============================================================================
-- If the server stops sending challenges the client detects it here.
-- This fires even if a cheat suppresses the incoming challenge net message.

local function integrity_heartbeat_check()
    local now               = _cur_time()
    local challenge_interval = 30   -- expected seconds between challenges
    local tolerance          = 15   -- grace period

    if state.last_challenge == 0 then
        -- Haven't received first challenge yet; give server time to send it.
        return
    end

    if now - state.last_challenge > challenge_interval + tolerance then
        state.heartbeat_misses = state.heartbeat_misses + 1
        state.last_challenge   = now   -- reset to avoid repeated flags per tick

        if state.heartbeat_misses >= CFG.heartbeat_miss_limit then
            integrity_report("HEARTBEAT_MISSED",
                _string_format("misses=%d", state.heartbeat_misses),
                CFG.SEV_HIGH)
            integrity_flush_reports()
        end
    end
end

-- =============================================================================
-- Initialisation
-- =============================================================================

integrity_watch_hook("Initialize", "Guardian.Integrity.Init", function()
    integrity_install_all_wrappers()

    -- Freeze the whitelist after the grace period
    _timer_simple(CFG.whitelist_grace_sec, integrity_freeze_whitelist)

    -- Periodic watchdog: verify hooks + wrappers + flush reports
    _timer_create("Guardian.Integrity.Watchdog",
        CFG.watchdog_interval, 0, integrity_watchdog_tick)

    -- Heartbeat miss check runs more frequently than the challenge interval
    _timer_create("Guardian.Integrity.HeartbeatCheck",
        10, 0, integrity_heartbeat_check)

    -- Report flush ticker (catches any reports that didn't trigger a direct flush)
    _timer_create("Guardian.Integrity.ReportFlush",
        5, 0, integrity_flush_reports)

    MsgC(Color(100, 200, 100), "[Guardian.Integrity] Client module initialised.\n")
end)

-- Re-verify on every LocalPlayer spawn in case a cheat re-injects post-death.
integrity_watch_hook("InitPostEntity", "Guardian.Integrity.PostEntity", function()
    integrity_verify_wrappers()
end)