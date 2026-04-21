-- =============================================================================
-- Guardian — Anti-Cheat
-- Detections:
--   1a. Aimbot / statistical angle analysis
--       (hard snap, soft run, spin-bot, smooth aimbot, snap-return)
--   1b. Aimbot / input-contradiction analysis  (ported from Nova Defender)
--       (silent aim, slow tracking with no mouse, mouse direction contradiction)
--   2.  Bullet accuracy
--   3.  Bhop
--   4.  Noclip attempt
--   5.  Suspicious convars
--   6.  Network DoS — processing-time based  (ported from Nova Defender)
--   7.  Network spam — netmessage flood counter  (ported from Nova Defender)
--   8.  Decompress zipbomb protection  (ported from Nova Defender)
--
-- Detection layers 1a and 1b are independent and complementary:
--   Layer 1a measures *output*  — what angles the client produces each tick.
--   Layer 1b measures *input*   — whether mouse movement matches angle change.
--   A silent aimbot that moves smoothly may evade 1a but always fails 1b.
--   A spinbot evades 1b (mouse matches its own output) but always fails 1a.
-- =============================================================================

if SERVER then
    Guardian.Print("Guardian anti-cheat system loaded.")
end

Guardian = Guardian or {}

-- =============================================================================
-- [1a] Aimbot — Statistical Angle Analysis
-- =============================================================================
-- Detection vectors:
--   Hard snap       — physically impossible angular acceleration (>150°/tick)
--   Soft snap run   — N consecutive ticks above a softer threshold
--   Spin-bot        — statistically perfect yaw delta (stddev < 1.2° over 66 ticks)
--   Smooth aimbot   — coefficient of variation below human jitter floor
--   Snap-return     — lock-on signature: large snap followed by counter-snap
--
-- Suspicion score with exponential decay. No single tick produces a flag alone.
-- Per-flag cooldowns prevent alert spam. Context-suppressed during damage/spawn.
-- Welford online statistics — O(1) per tick, no GC pressure from table copies.
-- =============================================================================

local ANGLE_CFG =
{
    -- Suspicion scoring
    flag_threshold          = 130,   -- points required to trigger a flag
    decay_per_clean_tick    = 2.0,
    max_suspicion           = 300,

    -- 1. Hard/soft snap thresholds
    -- Research basis: fastest measured human flick peaks ~80-100°/tick at 66 Hz.
    -- 150° is a 3-sigma outlier floor.
    snap_hard_deg           = 150,  -- °/tick → +80 suspicion
    snap_soft_deg           = 95,   -- °/tick → +25 suspicion per occurrence
    snap_soft_run           = 4,    -- N consecutive soft snaps → +40 bonus

    -- 2. Spin-bot fingerprint
    spin_window             = 66,   -- ticks (~1s at 66 Hz)
    spin_min_samples        = 40,
    spin_min_mean_deg       = 8,    -- ignore near-stationary players
    spin_max_stddev_deg     = 1.2,  -- humans always produce >3° stddev at speed

    -- 3. Smooth aimbot (CV threshold)
    smooth_window           = 24,   -- ticks
    smooth_min_mean_deg     = 4,
    smooth_max_cv           = 0.08, -- stddev/mean: below this is robotic

    -- 4. Snap-return lock-on pattern
    snapreturn_window_ticks = 5,
    snapreturn_min_deg      = 80,

    -- Context suppression (seconds)
    suppress_after_damage   = 1.5,
    suppress_after_spawn    = 4.0,

    -- Flag cooldowns (seconds)
    cooldown_hard_snap      = 3.0,
    cooldown_spinbot        = 5.0,
    cooldown_smooth         = 8.0,
    cooldown_snapreturn     = 4.0,
    cooldown_accumulation   = 6.0,
}

local angle_state = {}

local function get_angle_state(ply)
    local idx = ply:EntIndex()
    if not angle_state[idx] then
        angle_state[idx] =
        {
            last_yaw        = 0,
            initialized     = false,
            deltas          = {},
            delta_count     = 0,
            wf_n            = 0,
            wf_mean         = 0,
            wf_M2           = 0,
            last_large_snap = nil,
            suspicion       = 0,
            soft_run        = 0,
            cd_hard         = -math.huge,
            cd_spin         = -math.huge,
            cd_smooth       = -math.huge,
            cd_snapreturn   = -math.huge,
            cd_accum        = -math.huge,
            t_spawn         = CurTime(),
            t_last_damage   = -math.huge,
        }
    end
    return angle_state[idx]
end

local function reset_angle_state(s)
    s.t_spawn         = CurTime()
    s.suspicion       = 0
    s.soft_run        = 0
    s.wf_n            = 0
    s.wf_mean         = 0
    s.wf_M2           = 0
    s.deltas          = {}
    s.delta_count     = 0
    s.last_large_snap = nil
    s.initialized     = false
end

-- Shortest yaw arc in [0, 180]
local function yaw_delta(a, b)
    local d = math.abs(a - b) % 360
    return d > 180 and (360 - d) or d
end

local function welford_update(n, mean, M2, value)
    n = n + 1
    local delta = value - mean
    mean = mean + delta / n
    M2   = M2 + delta * (value - mean)
    return n, mean, M2
end

local function welford_remove(n, mean, M2, value)
    if n <= 1 then return 0, 0, 0 end
    n = n - 1
    local delta = value - mean
    mean = mean - delta / n
    M2   = M2 - delta * (value - mean)
    if M2 < 0 then M2 = 0 end
    return n, mean, M2
end

local function welford_stddev(n, M2)
    if n < 2 then return 0 end
    return math.sqrt(M2 / (n - 1))
end

local function try_angle_flag(ply, s, cd_field, cooldown, reason)
    local now = CurTime()
    if now - s[cd_field] < cooldown then return end
    s[cd_field] = now
    Guardian.FlagPlayer(ply, reason)
end

hook.Add("PlayerSpawn", "Guardian.AntiCheat.Angles.Spawn", function(ply)
    reset_angle_state(get_angle_state(ply))
end)

hook.Add("EntityTakeDamage", "Guardian.AntiCheat.Angles.Damage", function(ent, dmg)
    if not ent:IsPlayer() then return end
    get_angle_state(ent).t_last_damage = CurTime()
end)

hook.Add("StartCommand", "Guardian.AntiCheat.Angles", function(ply, cmd)
    if ply:IsBot()       then return end
    if not ply:Alive()   then return end
    if ply:InVehicle()   then return end
    if ply:GetMoveType() == MOVETYPE_NOCLIP then return end

    local now = CurTime()
    local s   = get_angle_state(ply)
    local yaw = cmd:GetViewAngles().y

    if not s.initialized then
        s.last_yaw    = yaw
        s.initialized = true
        return
    end

    local suppressed = (now - s.t_spawn      < ANGLE_CFG.suppress_after_spawn)
                    or (now - s.t_last_damage < ANGLE_CFG.suppress_after_damage)

    local delta    = yaw_delta(yaw, s.last_yaw)
    local prev_yaw = s.last_yaw
    s.last_yaw     = yaw

    if suppressed then
        s.suspicion = math.max(0, s.suspicion - ANGLE_CFG.decay_per_clean_tick)
        return
    end

    -- 1. Hard snap
    if delta >= ANGLE_CFG.snap_hard_deg then
        s.suspicion = math.min(ANGLE_CFG.max_suspicion, s.suspicion + 80)
        s.soft_run  = 0
        try_angle_flag(ply, s, "cd_hard", ANGLE_CFG.cooldown_hard_snap,
            string.format("Hard angle snap: %.1f°/tick | suspicion: %d", delta, s.suspicion))

    -- 2. Soft snap / flick run
    elseif delta >= ANGLE_CFG.snap_soft_deg then
        s.suspicion = math.min(ANGLE_CFG.max_suspicion, s.suspicion + 25)
        s.soft_run  = s.soft_run + 1

        if s.soft_run >= ANGLE_CFG.snap_soft_run then
            s.suspicion = math.min(ANGLE_CFG.max_suspicion, s.suspicion + 40)
            try_angle_flag(ply, s, "cd_hard", ANGLE_CFG.cooldown_hard_snap,
                string.format("Soft snap run: %d ticks ≥ %.0f° | last=%.1f° | suspicion: %d",
                    s.soft_run, ANGLE_CFG.snap_soft_deg, delta, s.suspicion))
        end
    else
        s.soft_run  = 0
        s.suspicion = math.max(0, s.suspicion - ANGLE_CFG.decay_per_clean_tick)
    end

    -- 3. Update ring-buffer and Welford accumulators
    local buf = s.deltas
    local win = ANGLE_CFG.spin_window
    local dc  = s.delta_count + 1
    s.delta_count = dc

    local slot = ((dc - 1) % win) + 1
    if dc > win then
        s.wf_n, s.wf_mean, s.wf_M2 =
            welford_remove(s.wf_n, s.wf_mean, s.wf_M2, buf[slot] or 0)
    end
    buf[slot] = delta
    s.wf_n, s.wf_mean, s.wf_M2 =
        welford_update(s.wf_n, s.wf_mean, s.wf_M2, delta)

    local sample_count = math.min(dc, win)

    -- 4. Spin-bot: statistically perfect rotation
    if sample_count >= ANGLE_CFG.spin_min_samples
    and s.wf_mean  >= ANGLE_CFG.spin_min_mean_deg then
        local stddev = welford_stddev(s.wf_n, s.wf_M2)
        if stddev <= ANGLE_CFG.spin_max_stddev_deg then
            s.suspicion = math.min(ANGLE_CFG.max_suspicion, s.suspicion + 55)
            try_angle_flag(ply, s, "cd_spin", ANGLE_CFG.cooldown_spinbot,
                string.format("Spin-bot: mean=%.2f° stddev=%.3f° n=%d | suspicion: %d",
                    s.wf_mean, stddev, sample_count, s.suspicion))
        end
    end

    -- 5. Smooth aimbot: robotically low coefficient of variation
    local sw = ANGLE_CFG.smooth_window
    if sample_count >= sw then
        local scratch = {}
        for i = 0, sw - 1 do
            scratch[i + 1] = buf[((dc - sw + i) % win) + 1] or 0
        end

        local n2, mean2, M2_2 = 0, 0, 0
        for _, v in ipairs(scratch) do
            n2, mean2, M2_2 = welford_update(n2, mean2, M2_2, v)
        end
        if mean2 >= ANGLE_CFG.smooth_min_mean_deg and mean2 > 0 then
            local cv = welford_stddev(n2, M2_2) / mean2
            if cv <= ANGLE_CFG.smooth_max_cv then
                s.suspicion = math.min(ANGLE_CFG.max_suspicion, s.suspicion + 30)
                try_angle_flag(ply, s, "cd_smooth", ANGLE_CFG.cooldown_smooth,
                    string.format("Smooth aimbot: CV=%.4f mean=%.2f° n=%d | suspicion: %d",
                        cv, mean2, sw, s.suspicion))
            end
        end
    end

    -- 6. Snap-return: aimbot lock-on signature
    if delta >= ANGLE_CFG.snapreturn_min_deg then
        local lsnap = s.last_large_snap
        if lsnap and (now - lsnap.time) <= (ANGLE_CFG.snapreturn_window_ticks / 66.0) then
            local dir_now  = yaw - prev_yaw
            local dir_prev = lsnap.dir
            if dir_now * dir_prev < 0 then
                s.suspicion = math.min(ANGLE_CFG.max_suspicion, s.suspicion + 50)
                try_angle_flag(ply, s, "cd_snapreturn", ANGLE_CFG.cooldown_snapreturn,
                    string.format("Snap-return: %.1f° → %.1f° (%.1f ms) | suspicion: %d",
                        lsnap.delta, delta, (now - lsnap.time) * 1000, s.suspicion))
                s.last_large_snap = nil
            end
        end
        s.last_large_snap = { time = now, delta = delta, dir = yaw - prev_yaw }
    end

    -- 7. Suspicion accumulation flag
    if s.suspicion >= ANGLE_CFG.flag_threshold then
        try_angle_flag(ply, s, "cd_accum", ANGLE_CFG.cooldown_accumulation,
            string.format("Suspicion threshold: %d pts | multi-vector anomaly", s.suspicion))
        s.suspicion = math.max(0, s.suspicion - ANGLE_CFG.flag_threshold * 0.6)
    end
end)

-- =============================================================================
-- [1b] Aimbot — Input Contradiction Analysis  (ported from Nova Defender)
-- =============================================================================
-- Compares raw mouse input against actual angle change each tick.
-- Legitimate play always has a coherent relationship between mouse movement
-- and view angle change. Silent aimbots externally write angles without touching
-- the mouse, producing a persistent contradiction that accumulates quickly.
--
-- Three sub-detections (each individually togglable via Guardian.AimbotCFG):
--
--   snap   — View changed > SNAP_MIN_DEG in one tick with zero mouse input on
--            both this tick and the previous tick. Classic snap-to-target.
--
--   move   — View drifted > MOVE_ANGLE_DEG total over MOVE_TICKS consecutive
--            ticks, all with zero mouse input. Catches smooth silent trackers
--            that stay below the per-tick snap threshold.
--
--   contr  — Mouse direction contradicts the angle change direction more than
--            CONTR_MAX times in a sliding window. Catches aimbots that add
--            slight mouse perturbation as cover but still disagree with the
--            actual angle produced.
--
-- False-positive suppression:
--   • Server-forced angle changes (SetAngles / SetEyeAngles) suppress all
--     checks for that tick via entityMeta / playerMeta overrides.
--   • IN_LEFT / IN_RIGHT produce legitimate mouseless yaw — excluded.
--   • Movetype changes (ladder, vehicle, noclip) reset accumulators.
--   • Players inactive for >8 s (AFK) are suppressed.
--   • Per-detection re-flag timeout of 120 s prevents repeat-flooding.
--   • Weapon blacklist excludes tools that cannot hurt other players.
--   • Slow precompute timer (0.3 s) keeps the per-tick hook cost near zero.
-- =============================================================================

Guardian.AimbotCFG =
{
    enabled = true,

    -- snap: one-tick silent lock-on
    check_snap      = true,
    snap_min_deg    = 25,   -- minimum angle change (°) with zero mouse input to flag

    -- move: slow silent tracking
    check_move      = true,
    move_ticks      = 53,   -- ~0.8 s at 66 Hz — zero-mouse ticks before flagging
    move_angle_deg  = 15,   -- total accumulated drift (°) required alongside move_ticks

    -- contr: mouse/angle direction contradiction accumulation
    check_contr     = true,
    contr_max       = 13,   -- contradiction ticks before flagging (~0.2 s at 66 Hz)

    -- per-detection re-flag timeout (seconds)
    flag_timeout    = 120,

    -- slow precompute timer interval (seconds)
    slow_interval   = 0.3,

    -- weapons that cannot hurt players — excluded from all checks
    blacklist_weapons =
    {
        ["gmod_camera"]       = true,
        ["gmod_tool"]         = true,
        ["weapon_crowbar"]    = true,
        ["weapon_physcannon"] = true,
        ["weapon_physgun"]    = true,
    },
}

-- Movetypes where input-contradiction analysis is valid
local INPUT_VALID_MOVETYPES =
{
    [MOVETYPE_NONE]     = true,
    [MOVETYPE_WALK]     = true,
    [MOVETYPE_VPHYSICS] = true,
}

-- Override SetAngles / SetEyeAngles to mark server-forced angle changes so we
-- don't false-positive on teleports, knockback, etc.
local ent_meta = FindMetaTable("Entity")
local ply_meta = FindMetaTable("Player")
local orig_set_angles     = ent_meta.SetAngles
local orig_set_eye_angles = ply_meta.SetEyeAngles

function ent_meta:SetAngles(ang)
    if not IsValid(self) or not self:IsPlayer() then
        orig_set_angles(self, ang)
        return
    end
    local stats = input_cmd_stats[self:SteamID()]
    if stats then stats.server_changed = true end
    orig_set_angles(self, ang)
end

function ply_meta:SetEyeAngles(ang)
    local stats = input_cmd_stats[self:SteamID()]
    if stats then stats.server_changed = true end
    orig_set_eye_angles(self, ang)
end

-- Per-player precomputed status (refreshed by slow timer, read in StartCommand)
local input_player_status = {}

-- Per-player per-tick command stats (written and read in StartCommand)
local input_cmd_stats = {}

-- Per-player per-detection-type timeout timestamps
local input_flag_timeouts = {}

-- Slow timer: precompute weapon/observer/AFK context so StartCommand stays cheap
timer.Create("Guardian.AntiCheat.AimbotInput.Slow", Guardian.AimbotCFG.slow_interval, 0, function()
    for _, ply in ipairs(player.GetHumans()) do
        if not IsValid(ply) or not ply:Alive() then continue end

        local sid    = ply:SteamID()
        local status = input_player_status[sid] or {}

        -- AFK detection: track whether position/angle changed since last slow tick
        local pos = ply:GetPos()
        local ang = ply:EyeAngles()
        if status.pos and status.ang then
            if status.pos == pos and status.ang.p == ang.p and status.ang.y == ang.y then
                status.no_move_time = (status.no_move_time or 0) + Guardian.AimbotCFG.slow_interval
            else
                status.no_move_time = 0
            end
        end
        status.pos = pos
        status.ang = ang

        -- Weapon context
        local wep   = ply:GetActiveWeapon()
        local class = IsValid(wep) and wep:GetClass() or nil
        status.weapon_class = (class and not Guardian.AimbotCFG.blacklist_weapons[class]) and class or nil

        -- Misc suppressors
        local movetype      = ply:GetMoveType()
        status.observer     = ply:GetObserverMode() ~= OBS_MODE_NONE
        status.frozen       = ply:IsFrozen()
        status.in_vehicle   = ply:InVehicle()

        -- Aggregate: is this player in a state where aimbot use is plausible?
        status.can_shoot =
            status.weapon_class ~= nil  and
            not status.frozen           and
            not status.observer         and
            not status.in_vehicle       and
            movetype ~= MOVETYPE_NOCLIP

        input_player_status[sid] = status

        -- Gently decay the contradiction counter between slow ticks so a single
        -- burst doesn't linger indefinitely
        local cmd = input_cmd_stats[sid]
        if cmd then
            cmd.total_contradictions = math.max(0,
                cmd.total_contradictions - Guardian.AimbotCFG.slow_interval * 66 * 0.1)
        end
    end
end)

local function input_check_timeout(sid, identifier)
    if not input_flag_timeouts[sid] then
        input_flag_timeouts[sid] = {}
    end
    local now     = CurTime()
    local expires = input_flag_timeouts[sid][identifier]
    if expires and expires > now then return false end
    input_flag_timeouts[sid][identifier] = now + Guardian.AimbotCFG.flag_timeout
    return true
end

hook.Add("StartCommand", "Guardian.AntiCheat.AimbotInput", function(ply, cmd)
    if not Guardian.AimbotCFG.enabled then return end
    if ply:IsBot()     then return end
    if not ply:Alive() then return end

    local sid    = ply:SteamID()
    local status = input_player_status[sid]
    if not status then return end

    local ang_p, ang_y, ang_r = cmd:GetViewAngles():Unpack()
    local mouse_x, mouse_y    = cmd:GetMouseX(), cmd:GetMouseY()
    local server_ang_y        = ply:GetAngles().y
    local movetype            = ply:GetMoveType()
    local buttons             = cmd:GetButtons()

    -- Initialise command stats on first tick
    local stats = input_cmd_stats[sid]
    if not stats then
        input_cmd_stats[sid] =
        {
            last_x               = mouse_x,
            last_y               = mouse_y,
            last_ang_p           = ang_p,
            last_ang_y           = ang_y,
            last_server_ang_y    = server_ang_y,
            last_movetype        = movetype,
            last_contr           = false,
            server_changed       = false,
            mouse_null_count     = 0,
            total_angle_drift    = 0,
            total_contradictions = 0,
        }
        return
    end

    -- Snapshot previous values
    local last_x        = stats.last_x
    local last_y        = stats.last_y
    local last_ang_p    = stats.last_ang_p
    local last_ang_y    = stats.last_ang_y
    local last_server_y = stats.last_server_ang_y
    local last_movetype = stats.last_movetype
    local last_contr    = stats.last_contr

    -- Detect any server-side angle override this tick
    local server_changed = stats.server_changed or (last_server_y ~= server_ang_y)

    -- Delta computation
    local pitch_diff = last_ang_p - ang_p
    local yaw_diff   = ((last_ang_y - ang_y + 180) % 360) - 180
    local angle_diff = math.abs(pitch_diff) + math.abs(yaw_diff)
    local mouse_null  = (mouse_x == 0 and mouse_y == 0)
    local last_null   = (last_x  == 0 and last_y  == 0)
    local mouse_moved = (mouse_x ~= last_x or mouse_y ~= last_y)

    -- IN_LEFT / IN_RIGHT create legitimate mouseless yaw — suppress all checks
    local axis_only = bit.band(buttons, IN_LEFT + IN_RIGHT) ~= 0

    -- Advance persistent state for next tick
    stats.last_x            = mouse_x
    stats.last_y            = mouse_y
    stats.last_ang_p        = ang_p
    stats.last_ang_y        = ang_y
    stats.last_server_ang_y = server_ang_y
    stats.last_movetype     = movetype
    stats.last_contr        = false
    stats.server_changed    = false

    -- Skip if player is not in a shooting context
    if not status.can_shoot then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    -- Skip on movetype transitions (ladder mount, vehicle entry, etc.)
    if movetype ~= last_movetype then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    -- Skip if valid movetype
    if not INPUT_VALID_MOVETYPES[movetype] then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    -- Skip if server forced the angle change this tick
    if server_changed then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    if axis_only                          then return end
    if not mouse_moved and angle_diff == 0 then return end
    if (status.no_move_time or 0) > 8    then return end  -- AFK suppression
    if ang_r ~= 0                         then return end  -- view roll artefact
    if cmd:IsForced()                     then return end  -- server-scripted move

    -- =========================================================================
    -- Contradiction check
    -- Mouse X positive  → yaw increases   (player turns right)
    -- Mouse Y positive  → pitch increases  (player looks down)
    -- A contradiction is when the mouse axis reports movement in one direction
    -- but the resulting angle went the opposite way — impossible with real input.
    -- We require two consecutive ticks before accumulating to absorb rounding.
    -- =========================================================================
    local contradictions = 0
    if mouse_x ~= 0 and math.abs(yaw_diff)   ~= 0 and mouse_x * yaw_diff   < 0 then
        contradictions = contradictions + 1
    end
    if mouse_y ~= 0 and math.abs(pitch_diff) ~= 0 and mouse_y * pitch_diff >= 0 then
        contradictions = contradictions + 1
    end

    if contradictions ~= 0 then
        if last_contr then
            stats.total_contradictions = stats.total_contradictions + contradictions
        else
            stats.last_contr = true
        end
    else
        stats.total_contradictions = math.max(0, stats.total_contradictions - 1)
    end

    -- =========================================================================
    -- Accumulate mouse-null angle drift
    -- View is changing but the mouse reports zero input on both this and the
    -- previous tick — the external aimbot is writing angles directly.
    -- =========================================================================
    if mouse_null and angle_diff > 0 then
        stats.total_angle_drift = stats.total_angle_drift + angle_diff
        stats.mouse_null_count  = stats.mouse_null_count  + 1
    else
        stats.total_angle_drift = 0
        stats.mouse_null_count  = 0
    end

    -- =========================================================================
    -- [snap] One-tick silent lock-on
    -- =========================================================================
    if  Guardian.AimbotCFG.check_snap
    and stats.mouse_null_count ~= 0
    and angle_diff             >  Guardian.AimbotCFG.snap_min_deg
    and last_null
    and input_check_timeout(sid, "snap")
    then
        Guardian.FlagPlayer(ply,
            string.format("Silent aimbot snap: %.0f° in 1 tick with zero mouse input", angle_diff))
        
    end

    -- =========================================================================
    -- [move] Slow silent tracking
    -- =========================================================================
    if  Guardian.AimbotCFG.check_move
    and stats.total_angle_drift > Guardian.AimbotCFG.move_angle_deg
    and stats.mouse_null_count  > Guardian.AimbotCFG.move_ticks
    and input_check_timeout(sid, "move")
    then
        Guardian.FlagPlayer(ply,
            string.format("Silent aimbot tracking: %.0f° drift over %d ticks with zero mouse input",
                stats.total_angle_drift, stats.mouse_null_count))
    end

    -- =========================================================================
    -- [contr] Mouse/angle direction contradiction accumulation
    -- =========================================================================
    if  Guardian.AimbotCFG.check_contr
    and stats.total_contradictions > Guardian.AimbotCFG.contr_max
    and input_check_timeout(sid, "contr")
    then
        Guardian.FlagPlayer(ply,
            string.format("Silent aimbot contradiction: mouse opposed angle change %d times",
                math.floor(stats.total_contradictions)))
    end
end)

hook.Add("PlayerSpawn", "Guardian.AntiCheat.AimbotInput.Spawn", function(ply)
    local sid = ply:SteamID()
    input_player_status[sid] = {}
    input_cmd_stats[sid]     = nil
end)

hook.Add("PlayerDisconnected", "Guardian.AntiCheat.AimbotInput.Disconnect", function(ply)
    local sid = ply:SteamID()
    input_player_status[sid] = nil
    input_cmd_stats[sid]     = nil
    input_flag_timeouts[sid] = nil
end)

-- =============================================================================
-- [2] Bullet Accuracy
-- Counts trigger-pull events, not pellets — shotguns counted correctly.
-- Only player-on-player hits measured. Staggered reset prevents re-flag loops.
-- =============================================================================

local ACCURACY_SAMPLE    = 30  -- trigger-pull events before evaluation
local ACCURACY_THRESHOLD = 0.7  -- 70% player hit-rate triggers flag

local ac_shot_stats = {}

local function get_shot_stats(ply)
    if not IsValid(ply) then return nil end
    if not ac_shot_stats[ply] then
        ac_shot_stats[ply] = { events = 0, player_hits = 0 }
    end
    return ac_shot_stats[ply]
end

hook.Add("EntityFireBullets", "Guardian.AntiCheat.BulletFire", function(ent, _)
    if not IsValid(ent) or not ent:IsPlayer() then return end
    local stats = get_shot_stats(ent)
    if stats then stats.events = stats.events + 1 end
end)

hook.Add("EntityTakeDamage", "Guardian.AntiCheat.BulletHits", function(target, dmginfo)
    local attacker = dmginfo:GetAttacker()
    if not IsValid(attacker) or not attacker:IsPlayer() then return end
    if not dmginfo:IsBulletDamage() then return end
    if not IsValid(target) or not target:IsPlayer() then return end

    local stats = get_shot_stats(attacker)
    if not stats then return end
    stats.player_hits = stats.player_hits + 1

    if stats.events >= ACCURACY_SAMPLE then
        local ratio = stats.player_hits / stats.events
        if ratio >= ACCURACY_THRESHOLD then
            Guardian.FlagPlayer(attacker,
                string.format("Suspicious accuracy: %d%% over %d shots",
                    math.Round(ratio * 100), stats.events))
        end
        -- Stagger reset: keep half the window to avoid a fresh zero-sample loop
        stats.events      = math.floor(stats.events      / 2)
        stats.player_hits = math.floor(stats.player_hits / 2)
    end
end)
-- =============================================================================
-- [3] Noclip
-- =============================================================================

hook.Add("PlayerNoClip", "Guardian.AntiCheat.Noclip", function(ply, desired)
    if desired and not ply:IsAdmin() then
        Guardian.FlagPlayer(ply, "Attempted noclip")
        return false
    end
end)

-- =============================================================================
-- [4] Suspicious Convars
-- Checked 10s after spawn to allow client convar reporting to settle.
-- =============================================================================

local SUSPICIOUS_CONVARS =
{
    { name = "sv_cheats",         type = "bool", flag_if = "1"  },
    { name = "cl_yawspeed",       type = "num",  max = 360      }, -- default 210; >360 = spin-only
    { name = "cl_interp_ratio",   type = "num",  min = 0.5      }, -- 0 exploits lag compensation
    { name = "r_drawothermodels", type = "num",  max = 1        }, -- 2 = wireframe wallhack
    { name = "cl_cmdrate",        type = "num",  max = 128      },
    { name = "cl_updaterate",     type = "num",  max = 128      },
}

hook.Add("PlayerInitialSpawn", "Guardian.AntiCheat.Convars", function(ply)
    timer.Simple(10, function()
        if not IsValid(ply) then return end
        for _, check in ipairs(SUSPICIOUS_CONVARS) do
            if check.type == "num" then
                local val = ply:GetInfoNum(check.name, 0)
                if check.max and val > check.max then
                    Guardian.FlagPlayer(ply, "Suspicious convar: " .. check.name .. " = " .. val)
                elseif check.min and val < check.min then
                    Guardian.FlagPlayer(ply, "Suspicious convar: " .. check.name .. " = " .. val)
                end
            elseif check.type == "bool" then
                if ply:GetInfo(check.name) == check.flag_if then
                    Guardian.FlagPlayer(ply, "Suspicious convar: " .. check.name .. " = " .. check.flag_if)
                end
            end
        end
    end)
end)

-- =============================================================================
-- [5] Network DoS — Processing Time  (ported from Nova Defender)
-- Measures server-side CPU time consumed processing each player's netmessages.
-- Computes a 95th-percentile server baseline across all players; flags players
-- whose total processing time deviates beyond the sensitivity multiplier.
--
-- Requires your net hook layer to fire:
--   hook.Run("Guardian.Net.Incoming",     client, steamID, strName, len)
--   hook.Run("Guardian.Net.IncomingPost", client, strName, deltaTime)
-- =============================================================================

local DOS_CFG =
{
    check_interval = 5,     -- seconds between evaluations
    percentile     = 0.95,  -- server-wide baseline percentile
    min_time       = 1,     -- seconds; below this is always ignored
    sensitivity    = 4,     -- deviation multiplier threshold (medium)

    -- Prefixes known to be legitimately expensive — skip these
    blacklist =
    {
        ["FProfile_"] = true,
    },
}

local dos_process_collector = {}  -- [steamID] = { total, count, max, messages }
local dos_global_percentile = 0
local dos_next_check        = 0

local function format_time(t)
    return t >= 0.1 and string.format("%.1fs", t) or string.format("%.1fms", t * 1000)
end

local function is_dos_time_too_long(time)
    if time < DOS_CFG.min_time then return false end
    if time > DOS_CFG.check_interval * 0.9 then return true end
    if dos_global_percentile == 0 then return false end
    local deviation = time / dos_global_percentile
    return deviation > DOS_CFG.sensitivity
end

local function dos_check_collector()
    local time_values = {}

    for steamID, v in pairs(dos_process_collector) do
        if v.total == 0 then continue end

        if not is_dos_time_too_long(v.total) then
            table.insert(time_values, v.max)
            if v.total > v.max then v.max = v.total end
        else
            Guardian.Print(string.format(
                "[DOS] %s caused server lag — processing time: %s in %ds.",
                steamID, format_time(v.total), DOS_CFG.check_interval))

            local flagging_ply = player.GetBySteamID and player.GetBySteamID(steamID) or NULL
            if IsValid(flagging_ply) then
                Guardian.FlagPlayer(flagging_ply,
                    string.format("Network DoS: %s processing time in %ds",
                        format_time(v.total), DOS_CFG.check_interval))
            end
        end

        v.total    = 0
        v.count    = 0
        v.messages = {}
    end

    if #time_values == 0 then return end
    table.sort(time_values)
    dos_global_percentile = time_values[math.max(1, math.Round(#time_values * DOS_CFG.percentile))]
end

local dos_last_client  = nil
local dos_last_message = nil

hook.Add("Guardian.Net.Incoming", "Guardian.AntiCheat.DoS.Pre", function(client, steamID, strName, len)
    dos_last_client  = steamID
    dos_last_message = strName
end)

hook.Add("Guardian.Net.IncomingPost", "Guardian.AntiCheat.DoS.Post", function(client, strName, deltaTime)
    local steamID    = client:SteamID()
    dos_last_client  = nil
    dos_last_message = nil

    for prefix, _ in pairs(DOS_CFG.blacklist) do
        if string.StartWith(strName, prefix) then return end
    end

    if not dos_process_collector[steamID] then
        dos_process_collector[steamID] = { total = 0, count = 0, max = 0, messages = {} }
    end

    local entry = dos_process_collector[steamID]
    entry.total = entry.total + deltaTime
    entry.count = entry.count + 1
    entry.messages[strName] = (entry.messages[strName] or 0) + deltaTime

    if deltaTime > 0.5 then
        Guardian.Print(string.format("[DOS] %q from %s took %s to process.",
            strName, steamID, format_time(deltaTime)))
    end

    local now = CurTime()
    if now > dos_next_check then
        dos_next_check = now + DOS_CFG.check_interval
        timer.Simple(0, dos_check_collector)
    end
end)

hook.Add("PlayerDisconnected", "Guardian.AntiCheat.DoS.Cleanup", function(ply)
    dos_process_collector[ply:SteamID()] = nil
end)

-- =============================================================================
-- [6] Network Spam — Netmessage Flood Counter  (ported from Nova Defender)
-- Counts netmessages per player per interval. Drops messages past the drop
-- threshold and flags players who exceed the action threshold.
-- =============================================================================

local SPAM_CFG =
{
    check_interval = 3,    -- seconds per counting window
    action_at      = 500,  -- flag at this many messages per window
    drop_at        = 100,  -- drop messages beyond this (must be ≤ action_at)

    -- These send many messages by design — excluded from the total count
    false_positives =
    {
        ["mCasino_interface"]                = true,
        ["Photon2:SetControllerChannelState"] = true,
    },
}

local spam_active_counter = {}  -- [steamID] = { [msgName] = count, ___total = n }
local spam_old_messages   = {}  -- history preserved for post-disconnect inspection
local spam_next_check     = 0

local function spam_move_old_messages()
    for steamID, data in pairs(spam_active_counter) do
        spam_old_messages[steamID] = spam_old_messages[steamID] or {}

        for name, count in pairs(data) do
            if name ~= "___total" then
                spam_old_messages[steamID][name] = (spam_old_messages[steamID][name] or 0) + count
            end
        end

        local total = data.___total or 0
        if total > SPAM_CFG.action_at then
            Guardian.Print(string.format(
                "[SPAM] %s exceeded threshold: %d/%d in %ds.",
                steamID, total, SPAM_CFG.action_at, SPAM_CFG.check_interval))

            local flagging_ply = player.GetBySteamID and player.GetBySteamID(steamID) or NULL
            if IsValid(flagging_ply) then
                Guardian.FlagPlayer(flagging_ply,
                    string.format("Net spam: %d messages in %ds (%d allowed)",
                        total, SPAM_CFG.check_interval, SPAM_CFG.action_at))
            end
        end

        spam_active_counter[steamID] = { ___total = 0 }
    end
end

hook.Add("Guardian.Net.Incoming", "Guardian.AntiCheat.Spam", function(client, steamID, strName, len)
    if not spam_active_counter[steamID] then
        spam_active_counter[steamID] = { ___total = 0 }
    end

    spam_active_counter[steamID][strName] = (spam_active_counter[steamID][strName] or 0) + 1

    if not SPAM_CFG.false_positives[strName] then
        spam_active_counter[steamID].___total = spam_active_counter[steamID].___total + 1
    end

    local now = CurTime()
    if now > spam_next_check then
        spam_next_check = now + SPAM_CFG.check_interval
        timer.Simple(0, spam_move_old_messages)
    end

    local drop_at = math.min(SPAM_CFG.drop_at, SPAM_CFG.action_at)
    local total   = spam_active_counter[steamID].___total

    if total > drop_at then
        if total - 1 == drop_at then
            Guardian.Print(string.format(
                "[SPAM] Dropping messages from %s — exceeded %d in %.0fs.",
                steamID, drop_at, SPAM_CFG.check_interval))
        end
        return false  -- drop the netmessage
    end
end)

hook.Add("PlayerDisconnected", "Guardian.AntiCheat.Spam.Cleanup", function(ply)
    local sid = ply:SteamID()
    spam_active_counter[sid] = nil
    spam_old_messages[sid]   = nil
end)

-- Expose message history for external inspection (e.g. admin panel)
function Guardian.GetPlayerNetmessages(ply)
    local sid = type(ply) == "string" and ply or ply:SteamID()
    return table.Copy(spam_old_messages[sid] or {})
end

-- =============================================================================
-- [7 ] Decompress Zipbomb Protection  (ported from Nova Defender)
-- Overrides util.Decompress to cap decompressed output size.
-- Only activates when the call originates from a tracked netmessage context,
-- so server-internal decompression is never affected.
-- =============================================================================

local DECOMPRESS_CFG =
{
    enabled           = true,
    max_size_mb       = 400,               -- hard cap on decompressed output
    max_ratio         = 100,               -- flag if decompressed/compressed > this
    min_size_to_check = 10 * 1000 * 1000,  -- 10 MB minimum before ratio check
    whitelist         = {},                -- [msgName] = true to exempt
}

local decompress_original = util.Decompress

local function decompress_is_exempt(msg_name)
    return msg_name == nil or DECOMPRESS_CFG.whitelist[msg_name] == true
end

local function install_decompress_override()
    if util.Decompress ~= decompress_original then return end

    util.Decompress = function(compressed, limit, ...)
        local compressed_size = #compressed
        local max_bytes       = DECOMPRESS_CFG.max_size_mb * 1000000

        -- Pass through if: explicit limit already set, no tracked context, exempt
        if (limit and limit > 0) or compressed_size == 0 or decompress_is_exempt(dos_last_message) then
            return decompress_original(compressed, limit, ...)
        end

        local start_time   = SysTime()
        local decompressed = decompress_original(compressed, max_bytes, ...)
        local delta_time   = SysTime() - start_time

        if decompressed == nil then
            -- Hit the cap — this is a zipbomb
            ErrorNoHalt("[Guardian] util.Decompress blocked — zipbomb from " .. tostring(dos_last_client) .. "\n")
            local flagging_ply = dos_last_client and
                (player.GetBySteamID and player.GetBySteamID(dos_last_client) or NULL) or NULL
            if IsValid(flagging_ply) then
                local est_ratio = math.Round(max_bytes / math.max(1, compressed_size))
                Guardian.FlagPlayer(flagging_ply,
                    string.format("Zipbomb: msg=%s compressed=%dB decompressed=>%dMB ratio=>%d:1 took=%s",
                        tostring(dos_last_message), compressed_size,
                        DECOMPRESS_CFG.max_size_mb, est_ratio, format_time(delta_time)))
            end
            return nil
        end

        local decompressed_size = #decompressed
        local ratio             = math.Round(decompressed_size / math.max(1, compressed_size), 2)

        Guardian.Print(string.format(
            "[DECOMPRESS] %s | compressed: %dB  decompressed: %dB  ratio: %.1f:1  took: %s",
            tostring(dos_last_client), compressed_size, decompressed_size, ratio, format_time(delta_time)))

        if decompressed_size > DECOMPRESS_CFG.min_size_to_check and ratio > DECOMPRESS_CFG.max_ratio then
            local flagging_ply = dos_last_client and
                (player.GetBySteamID and player.GetBySteamID(dos_last_client) or NULL) or NULL
            if IsValid(flagging_ply) then
                Guardian.FlagPlayer(flagging_ply,
                    string.format("Suspicious decompress: msg=%s compressed=%dB decompressed=%dB ratio=%.1f:1",
                        tostring(dos_last_message), compressed_size, decompressed_size, ratio))
            end
        end

        return decompressed
    end
end

local function remove_decompress_override()
    if util.Decompress ~= decompress_original then
        util.Decompress = decompress_original
    end
end

if DECOMPRESS_CFG.enabled then
    install_decompress_override()
end

concommand.Add("guardian_decompress_protection", function(ply, cmd, args)
    if IsValid(ply) and not ply:IsAdmin() then return end
    if args[1] == "1" then
        install_decompress_override()
        print("[Guardian] Decompress protection enabled.")
    else
        remove_decompress_override()
        print("[Guardian] Decompress protection disabled.")
    end
end)

-- =============================================================================
-- Shared Cleanup
-- =============================================================================

hook.Add("PlayerDisconnected", "Guardian.AntiCheat.SharedCleanup", function(ply)
    angle_state[ply:EntIndex()] = nil
    ac_shot_stats[ply]          = nil
    ac_bhop[ply]                = nil
end)

local BHOP_WINDOW = 5     -- seconds
local BHOP_LIMIT  = 5     -- only trigger after 5 bhops

local bhop_tracker = {}

local function ShouldClampBhop(ply, cmd)
    local state = bhop_tracker[ply]
    if not state then
        state = { timestamps = {} }
        bhop_tracker[ply] = state
    end

    local on_ground    = ply:IsOnGround()
    local jump_pressed = bit.band(cmd:GetButtons(), IN_JUMP) ~= 0

    if jump_pressed and not on_ground then
        local now    = CurTime()
        local cutoff = now - BHOP_WINDOW

        table.insert(state.timestamps, now)

        -- remove old entries
        while state.timestamps[1] and state.timestamps[1] < cutoff do
            table.remove(state.timestamps, 1)
        end

        return #state.timestamps >= BHOP_LIMIT
    end

    return false
end

local function PreventBhop(ply)
    local vel = ply:GetVelocity()
    local speed = vel:Length()
    local maxSpeed = ply:GetMaxSpeed()

    if speed > maxSpeed then
        vel:Normalize()
        local maxVel = vel * maxSpeed
        local newVel = maxVel - ply:GetVelocity()
        newVel.z = 0
        ply:SetVelocity(newVel)
    end
end

hook.Add("Move", "GuardianAC_PreventBhop", function(ply, mv)
    if ShouldClampBhop(ply, mv) then
        PreventBhop(ply)
    end
end)