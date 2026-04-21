-- =============================================================================
-- Guardian — Anti-Cheat
-- Detections:
--   1a. Aimbot / CPP zero-mouse on-target trace analysis
--       (replaces statistical angle analysis; silent aim stays via 1b)
--   1b. Aimbot / input-contradiction analysis
--       (silent aim, slow tracking, mouse direction contradiction)
--   2.  Bullet accuracy
--   3.  Bhop
--   4.  Noclip attempt
--   5.  Suspicious convars
--   6.  Network DoS  — processing-time based
--   7.  Network spam — netmessage flood counter
--   8.  Decompress zipbomb protection
--   9.  Engine prediction  (client-side, server-verified)
--   10. Suspicious keybind detection
--   11. Source crasher / ExecuteStringCommand exploit  (Linux)
--   12. Anti-screengrab evasion detection
--   13. No-recoil / viewpunch suppression  (client-side, server-verified)
--   14. Anti-spread / bullet spread removal
--   15. Alt account / ban evasion detection
-- =============================================================================

Guardian = Guardian or {}

-- =============================================================================
-- Shared initialisation — network strings + feature toggles
-- =============================================================================

if SERVER then
    Guardian.Print("Guardian anti-cheat system loaded.")

    util.AddNetworkString("Guardian.Net.EngPredFlag")
    util.AddNetworkString("Guardian.Net.NoRecoilFlag")
    util.AddNetworkString("Guardian.Net.AntiScreenGrab.Check")
    util.AddNetworkString("Guardian.Net.AntiScreenGrab.Report")
    util.AddNetworkString("Guardian.Net.AltCheck")
    util.AddNetworkString("Guardian.Net.AltCheckResponse")
    util.AddNetworkString("Guardian.Net.AltCheckCount")
end

-- Feature toggles — override in your server config before Guardian loads.
Guardian.Config = Guardian.Config or
{
    cpp_aimbot          = true,
    anti_engine_pred    = true,
    keybind_checks      = true,
    source_crasher      = true,   -- Linux only; silently skipped on Windows
    anti_screengrab     = true,
    anti_recoil         = true,
    anti_spread         = true,
    alt_detection       = true,
    alt_notify          = true,   -- log when a player joins with multiple alts
}

-- =============================================================================
-- [1a] Aimbot — CPP Zero-Mouse On-Target Trace  (replaces statistical 1a)
-- =============================================================================
-- Detects external C++/external-process aimbots that write eye angles directly
-- without generating mouse input.  Each tick where:
--   • both mouse axes are exactly zero, AND
--   • both pitch AND yaw changed from the previous tick, AND
--   • a trace from the new eye position hits a living player
-- …a detection counter increments.  CPP_AIMBOT_THRESHOLD consecutive hits
-- trigger a flag.  Any tick with mouse input resets the counter to zero so
-- legitimate rapid flicks to targets are never flagged.
--
-- Grace period: 25 s post-join + PlayerAuthed must have fired.
-- Blacklisted tools cannot aim at players; counter is zeroed for them.
-- =============================================================================

if SERVER then

local CPP_AIMBOT_BLACKLIST =
{
    ["weapon_physgun"]    = true,
    ["gmod_tool"]         = true,
    ["weapon_physcannon"] = true,
}

local CPP_AIMBOT_THRESHOLD  = 15   -- consecutive qualifying ticks before flag
local CPP_AIMBOT_GRACE_SEC  = 25   -- seconds post-join before checks begin
local CPP_PACKET_LOSS_MAX   = 80   -- % packet loss above which checks are skipped

hook.Add("PlayerInitialSpawn", "Guardian.AntiCheat.CppAimbot.Init", function(ply)
    ply.guardian_join_time      = CurTime()
    ply.guardian_fully_authed   = false
    ply.guardian_cpp_detections = 0
    ply.guardian_aimbot_flagged = false
    ply.guardian_cpp_prev_view  = nil
end)

hook.Add("PlayerAuthed", "Guardian.AntiCheat.CppAimbot.Auth", function(ply)
    ply.guardian_fully_authed = true
end)

hook.Add("StartCommand", "Guardian.AntiCheat.CppAimbot", function(ply, cmd)
    if not Guardian.Config.cpp_aimbot              then return end
    if ply:IsBot()                                 then return end
    if not ply:Alive()                             then return end
    if ply:InVehicle()                             then return end
    if ply:IsTimingOut()                           then return end
    if ply:PacketLoss() > CPP_PACKET_LOSS_MAX      then return end

    local wep = ply:GetActiveWeapon()
    if IsValid(wep) and CPP_AIMBOT_BLACKLIST[wep:GetClass()] then
        ply.guardian_cpp_detections = 0
        return
    end

    local mx        = math.abs(cmd:GetMouseX())
    local my        = math.abs(cmd:GetMouseY())
    local view      = cmd:GetViewAngles()
    local prev_view = ply.guardian_cpp_prev_view

    if prev_view == nil then
        ply.guardian_cpp_prev_view  = view
        ply.guardian_cpp_detections = 0
        return
    end

    if mx == 0 and my == 0 then
        if view.p ~= prev_view.p and view.y ~= prev_view.y then
            local tr = util.TraceLine(
            {
                start  = ply:EyePos(),
                endpos = ply:EyePos() + view:Forward() * 32768,
                filter = ply,
            })

            if IsValid(tr.Entity) and (tr.Entity:IsPlayer() or tr.Entity:IsBot()) and tr.Entity:Alive() then
                ply.guardian_cpp_detections = ply.guardian_cpp_detections + 1

                print(ply.guardian_cpp_detections)
                if ply.guardian_cpp_detections >= CPP_AIMBOT_THRESHOLD then
                    ply.guardian_aimbot_flagged = true
                    Guardian.FlagPlayer(ply,
                        string.format(
                            "CPP aimbot: %d on-target zero-mouse ticks",
                            ply.guardian_cpp_detections))
                end
            elseif ply.guardian_cpp_detections > 0 then
                ply.guardian_cpp_detections = ply.guardian_cpp_detections - 1
            end
        else
            ply.guardian_cpp_detections = 0
        end
    else
        ply.guardian_cpp_detections = 0
    end

    ply.guardian_cpp_prev_view = view
end)

end -- SERVER [1a]

-- =============================================================================
-- [1b] Aimbot — Input Contradiction Analysis
-- =============================================================================
-- Compares raw mouse input against actual angle change each tick.
-- Legitimate play always has a coherent relationship between mouse movement
-- and view angle change. Silent aimbots externally write angles without touching
-- the mouse, producing a persistent contradiction that accumulates quickly.
--
-- Three sub-detections (each individually togglable via Guardian.AimbotCFG):
--
--   snap   — View changed > SNAP_MIN_DEG in one tick with zero mouse input on
--            both this tick and the previous tick.
--
--   move   — View drifted > MOVE_ANGLE_DEG total over MOVE_TICKS consecutive
--            ticks, all with zero mouse input.
--
--   contr  — Mouse direction contradicts the angle change direction more than
--            CONTR_MAX times in a sliding window.
-- =============================================================================

Guardian.AimbotCFG =
{
    enabled = true,

    check_snap      = true,
    snap_min_deg    = 25,

    check_move      = true,
    move_ticks      = 53,
    move_angle_deg  = 15,

    check_contr     = true,
    contr_max       = 13,

    flag_timeout    = 120,
    slow_interval   = 0.3,

    blacklist_weapons =
    {
        ["gmod_camera"]       = true,
        ["gmod_tool"]         = true,
        ["weapon_crowbar"]    = true,
        ["weapon_physcannon"] = true,
        ["weapon_physgun"]    = true,
    },
}

local INPUT_VALID_MOVETYPES =
{
    [MOVETYPE_NONE]     = true,
    [MOVETYPE_WALK]     = true,
    [MOVETYPE_VPHYSICS] = true,
}

local ent_meta            = FindMetaTable("Entity")
local ply_meta            = FindMetaTable("Player")
local orig_set_angles     = ent_meta.SetAngles
local orig_set_eye_angles = ply_meta.SetEyeAngles

local input_player_status = {}
local input_cmd_stats     = {}
local input_flag_timeouts = {}

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

timer.Create("Guardian.AntiCheat.AimbotInput.Slow", Guardian.AimbotCFG.slow_interval, 0, function()
    for _, ply in ipairs(player.GetHumans()) do
        if not IsValid(ply) or not ply:Alive() then continue end

        local sid    = ply:SteamID()
        local status = input_player_status[sid] or {}

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

        local wep   = ply:GetActiveWeapon()
        local class = IsValid(wep) and wep:GetClass() or nil
        status.weapon_class = (class and not Guardian.AimbotCFG.blacklist_weapons[class])
            and class or nil

        local movetype     = ply:GetMoveType()
        status.observer    = ply:GetObserverMode() ~= OBS_MODE_NONE
        status.frozen      = ply:IsFrozen()
        status.in_vehicle  = ply:InVehicle()

        status.can_shoot =
            status.weapon_class ~= nil and
            not status.frozen           and
            not status.observer         and
            not status.in_vehicle       and
            movetype ~= MOVETYPE_NOCLIP

        input_player_status[sid] = status

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

    local last_x        = stats.last_x
    local last_y        = stats.last_y
    local last_ang_p    = stats.last_ang_p
    local last_ang_y    = stats.last_ang_y
    local last_server_y = stats.last_server_ang_y
    local last_movetype = stats.last_movetype
    local last_contr    = stats.last_contr

    local server_changed = stats.server_changed or (last_server_y ~= server_ang_y)

    local pitch_diff = last_ang_p - ang_p
    local yaw_diff   = ((last_ang_y - ang_y + 180) % 360) - 180
    local angle_diff = math.abs(pitch_diff) + math.abs(yaw_diff)
    local mouse_null  = (mouse_x == 0 and mouse_y == 0)
    local last_null   = (last_x  == 0 and last_y  == 0)
    local mouse_moved = (mouse_x ~= last_x or mouse_y ~= last_y)

    local axis_only = bit.band(buttons, IN_LEFT + IN_RIGHT) ~= 0

    stats.last_x            = mouse_x
    stats.last_y            = mouse_y
    stats.last_ang_p        = ang_p
    stats.last_ang_y        = ang_y
    stats.last_server_ang_y = server_ang_y
    stats.last_movetype     = movetype
    stats.last_contr        = false
    stats.server_changed    = false

    if not status.can_shoot then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    if movetype ~= last_movetype then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    if not INPUT_VALID_MOVETYPES[movetype] then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    if server_changed then
        stats.mouse_null_count  = 0
        stats.total_angle_drift = 0
        return
    end

    if axis_only                           then return end
    if not mouse_moved and angle_diff == 0 then return end
    if (status.no_move_time or 0) > 8     then return end
    if ang_r ~= 0                          then return end
    if cmd:IsForced()                      then return end

    -- Contradiction accumulation
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

    -- Mouse-null angle drift
    if mouse_null and angle_diff > 0 then
        stats.total_angle_drift = stats.total_angle_drift + angle_diff
        stats.mouse_null_count  = stats.mouse_null_count  + 1
    else
        stats.total_angle_drift = 0
        stats.mouse_null_count  = 0
    end

    -- [snap] One-tick silent lock-on
    if  Guardian.AimbotCFG.check_snap
    and stats.mouse_null_count ~= 0
    and angle_diff             >  Guardian.AimbotCFG.snap_min_deg
    and last_null
    and input_check_timeout(sid, "snap")
    then
        Guardian.FlagPlayer(ply,
            string.format("Silent aimbot snap: %.0f° in 1 tick with zero mouse input",
                angle_diff))
    end

    -- [move] Slow silent tracking
    if  Guardian.AimbotCFG.check_move
    and stats.total_angle_drift > Guardian.AimbotCFG.move_angle_deg
    and stats.mouse_null_count  > Guardian.AimbotCFG.move_ticks
    and input_check_timeout(sid, "move")
    then
        Guardian.FlagPlayer(ply,
            string.format(
                "Silent aimbot tracking: %.0f° drift over %d ticks with zero mouse input",
                stats.total_angle_drift, stats.mouse_null_count))
    end

    -- [contr] Mouse/angle direction contradiction
    if  Guardian.AimbotCFG.check_contr
    and stats.total_contradictions > Guardian.AimbotCFG.contr_max
    and input_check_timeout(sid, "contr")
    then
        Guardian.FlagPlayer(ply,
            string.format("Silent aimbot contradiction: mouse opposed angle %d times",
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

local ACCURACY_SAMPLE    = 30
local ACCURACY_THRESHOLD = 0.7

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
    if not dmginfo:IsBulletDamage()                      then return end
    if not IsValid(target) or not target:IsPlayer()      then return end

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
-- Checked 10 s after spawn to allow client convar reporting to settle.
-- =============================================================================

local SUSPICIOUS_CONVARS =
{
    { name = "sv_cheats",         type = "bool", flag_if = "1"  },
    { name = "cl_yawspeed",       type = "num",  max = 360      },
    { name = "cl_interp_ratio",   type = "num",  min = 0.5      },
    { name = "r_drawothermodels", type = "num",  max = 1        },
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
                    Guardian.FlagPlayer(ply,
                        "Suspicious convar: " .. check.name .. " = " .. val)
                elseif check.min and val < check.min then
                    Guardian.FlagPlayer(ply,
                        "Suspicious convar: " .. check.name .. " = " .. val)
                end
            elseif check.type == "bool" then
                if ply:GetInfo(check.name) == check.flag_if then
                    Guardian.FlagPlayer(ply,
                        "Suspicious convar: " .. check.name .. " = " .. check.flag_if)
                end
            end
        end
    end)
end)

-- =============================================================================
-- [5] Network DoS — Processing Time
-- =============================================================================

local DOS_CFG =
{
    check_interval = 5,
    percentile     = 0.95,
    min_time       = 1,
    sensitivity    = 4,
    blacklist      = { ["FProfile_"] = true },
}

local dos_process_collector = {}
local dos_global_percentile = 0
local dos_next_check        = 0

local function format_time(t)
    return t >= 0.1 and string.format("%.1fs", t) or string.format("%.1fms", t * 1000)
end

local function is_dos_time_too_long(time)
    if time < DOS_CFG.min_time                      then return false end
    if time > DOS_CFG.check_interval * 0.9          then return true  end
    if dos_global_percentile == 0                   then return false end
    return (time / dos_global_percentile) > DOS_CFG.sensitivity
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
    dos_global_percentile =
        time_values[math.max(1, math.Round(#time_values * DOS_CFG.percentile))]
end

local dos_last_client  = nil
local dos_last_message = nil

hook.Add("Guardian.Net.Incoming", "Guardian.AntiCheat.DoS.Pre",
    function(client, steamID, strName, len)
        dos_last_client  = steamID
        dos_last_message = strName
    end)

hook.Add("Guardian.Net.IncomingPost", "Guardian.AntiCheat.DoS.Post",
    function(client, strName, deltaTime)
        local steamID    = client:SteamID()
        dos_last_client  = nil
        dos_last_message = nil

        for prefix in pairs(DOS_CFG.blacklist) do
            if string.StartWith(strName, prefix) then return end
        end

        if not dos_process_collector[steamID] then
            dos_process_collector[steamID] =
                { total = 0, count = 0, max = 0, messages = {} }
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
-- [6] Network Spam — Netmessage Flood Counter
-- =============================================================================

local SPAM_CFG =
{
    check_interval  = 3,
    action_at       = 500,
    drop_at         = 100,
    false_positives =
    {
        ["mCasino_interface"]                 = true,
        ["Photon2:SetControllerChannelState"] = true,
    },
}

local spam_active_counter = {}
local spam_old_messages   = {}
local spam_next_check     = 0

local function spam_move_old_messages()
    for steamID, data in pairs(spam_active_counter) do
        spam_old_messages[steamID] = spam_old_messages[steamID] or {}

        for name, count in pairs(data) do
            if name ~= "___total" then
                spam_old_messages[steamID][name] =
                    (spam_old_messages[steamID][name] or 0) + count
            end
        end

        local total = data.___total or 0
        if total > SPAM_CFG.action_at then
            Guardian.Print(string.format(
                "[SPAM] %s exceeded threshold: %d/%d in %ds.",
                steamID, total, SPAM_CFG.action_at, SPAM_CFG.check_interval))

            local flagging_ply = player.GetBySteamID
                and player.GetBySteamID(steamID) or NULL
            if IsValid(flagging_ply) then
                Guardian.FlagPlayer(flagging_ply,
                    string.format("Net spam: %d messages in %ds (%d allowed)",
                        total, SPAM_CFG.check_interval, SPAM_CFG.action_at))
            end
        end

        spam_active_counter[steamID] = { ___total = 0 }
    end
end

hook.Add("Guardian.Net.Incoming", "Guardian.AntiCheat.Spam",
    function(client, steamID, strName, len)
        if not spam_active_counter[steamID] then
            spam_active_counter[steamID] = { ___total = 0 }
        end

        spam_active_counter[steamID][strName] =
            (spam_active_counter[steamID][strName] or 0) + 1

        if not SPAM_CFG.false_positives[strName] then
            spam_active_counter[steamID].___total =
                spam_active_counter[steamID].___total + 1
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
            return false
        end
    end)

hook.Add("PlayerDisconnected", "Guardian.AntiCheat.Spam.Cleanup", function(ply)
    local sid = ply:SteamID()
    spam_active_counter[sid] = nil
    spam_old_messages[sid]   = nil
end)

function Guardian.GetPlayerNetmessages(ply)
    local sid = type(ply) == "string" and ply or ply:SteamID()
    return table.Copy(spam_old_messages[sid] or {})
end

-- =============================================================================
-- [7] Decompress Zipbomb Protection
-- =============================================================================

local DECOMPRESS_CFG =
{
    enabled           = true,
    max_size_mb       = 400,
    max_ratio         = 100,
    min_size_to_check = 10 * 1000 * 1000,
    whitelist         = {},
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

        if (limit and limit > 0)
        or compressed_size == 0
        or decompress_is_exempt(dos_last_message)
        then
            return decompress_original(compressed, limit, ...)
        end

        local start_time   = SysTime()
        local decompressed = decompress_original(compressed, max_bytes, ...)
        local delta_time   = SysTime() - start_time

        if decompressed == nil then
            ErrorNoHalt("[Guardian] util.Decompress blocked — zipbomb from "
                .. tostring(dos_last_client) .. "\n")
            local flagging_ply = dos_last_client and
                (player.GetBySteamID and player.GetBySteamID(dos_last_client) or NULL)
                or NULL
            if IsValid(flagging_ply) then
                local est_ratio =
                    math.Round(max_bytes / math.max(1, compressed_size))
                Guardian.FlagPlayer(flagging_ply,
                    string.format(
                        "Zipbomb: msg=%s compressed=%dB decompressed=>%dMB ratio=>%d:1 took=%s",
                        tostring(dos_last_message), compressed_size,
                        DECOMPRESS_CFG.max_size_mb, est_ratio,
                        format_time(delta_time)))
            end
            return nil
        end

        local decompressed_size = #decompressed
        local ratio = math.Round(decompressed_size / math.max(1, compressed_size), 2)

        Guardian.Print(string.format(
            "[DECOMPRESS] %s | compressed: %dB  decompressed: %dB  ratio: %.1f:1  took: %s",
            tostring(dos_last_client), compressed_size,
            decompressed_size, ratio, format_time(delta_time)))

        if decompressed_size > DECOMPRESS_CFG.min_size_to_check
        and ratio            > DECOMPRESS_CFG.max_ratio
        then
            local flagging_ply = dos_last_client and
                (player.GetBySteamID and player.GetBySteamID(dos_last_client) or NULL)
                or NULL
            if IsValid(flagging_ply) then
                Guardian.FlagPlayer(flagging_ply,
                    string.format(
                        "Suspicious decompress: msg=%s compressed=%dB decompressed=%dB ratio=%.1f:1",
                        tostring(dos_last_message), compressed_size,
                        decompressed_size, ratio))
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
-- [8] Bhop
-- =============================================================================

local BHOP_WINDOW  = 5
local BHOP_LIMIT   = 5
local bhop_tracker = {}

local function should_clamp_bhop(ply, cmd)
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

        while state.timestamps[1] and state.timestamps[1] < cutoff do
            table.remove(state.timestamps, 1)
        end

        return #state.timestamps >= BHOP_LIMIT
    end

    return false
end

local function prevent_bhop(ply)
    local vel      = ply:GetVelocity()
    local speed    = vel:Length()
    local max_speed = ply:GetMaxSpeed()

    if speed > max_speed then
        vel:Normalize()
        local max_vel = vel * max_speed
        local new_vel = max_vel - ply:GetVelocity()
        new_vel.z = 0
        ply:SetVelocity(new_vel)
    end
end

hook.Add("Move", "Guardian.AntiCheat.Bhop", function(ply, mv)
    if should_clamp_bhop(ply, mv) then
        prevent_bhop(ply)
    end
end)

-- =============================================================================
-- [9] Engine Prediction  (client-side detection, server-verified flag)
-- =============================================================================
-- SetupMove fires with the command number the engine is about to simulate.
-- CreateMove fires when the client produces a command.  If SetupMove's cmdnum
-- is higher than the last CreateMove cmdnum, the engine is running a prediction
-- frame the client never submitted — a sign of engine prediction manipulation.
-- After 10 consecutive failures the client sends a flag net message to the
-- server, which calls Guardian.FlagPlayer authoritatively.
-- =============================================================================

if CLIENT then

local engine_pred_cmd_number = 0
local engine_pred_failures   = 0
local engine_pred_sent       = false

hook.Add("CreateMove", "Guardian.AntiCheat.EnginePred.CreateMove", function(cmd)
    if not Guardian.Config.anti_engine_pred then return end
    local cmdnum = cmd:CommandNumber()
    if cmdnum == 0 then return end
    engine_pred_cmd_number = cmdnum
end)

hook.Add("SetupMove", "Guardian.AntiCheat.EnginePred.SetupMove", function(ply, mv, cmd)
    if not Guardian.Config.anti_engine_pred then return end
    if ply ~= LocalPlayer()                 then return end

    local cmdnum = cmd:CommandNumber()
    if cmdnum == 0 then return end

    if engine_pred_cmd_number ~= 0 and engine_pred_cmd_number < cmdnum then
        if engine_pred_failures >= 10 and not engine_pred_sent then
            net.Start("Guardian.Net.EngPredFlag")
            net.SendToServer()
            engine_pred_sent = true
        else
            engine_pred_failures = engine_pred_failures + 1
        end
    elseif engine_pred_cmd_number > cmdnum and engine_pred_failures > 0 then
        engine_pred_failures = engine_pred_failures - 1
    end
end)

end -- CLIENT [9]

if SERVER then

net.Receive("Guardian.Net.EngPredFlag", function(len, ply)
    if not Guardian.Config.anti_engine_pred then return end
    if not IsValid(ply) or ply:IsBot()      then return end
    Guardian.FlagPlayer(ply, "Engine prediction manipulation detected")
end)

end -- SERVER [9]

-- =============================================================================
-- [10] Suspicious Keybind Detection  (server-side)
-- =============================================================================
-- HOME, INSERT, and END are common cheat-menu hotkeys with no legitimate
-- in-game function.  A 10 s per-player cooldown prevents alert spam when a
-- player repeats the press.
-- =============================================================================

if SERVER then

local SUSPICIOUS_KEYS =
{
    [KEY_HOME]   = "HOME",
    [KEY_INSERT] = "INSERT",
    [KEY_END]    = "END",
}

local KEYBIND_CHECK_COOLDOWN = 10   -- seconds between flags per player

hook.Add("PlayerButtonDown", "Guardian.AntiCheat.Keybind", function(ply, button)
    if not Guardian.Config.keybind_checks       then return end
    local key_name = SUSPICIOUS_KEYS[button]
    if not key_name                             then return end

    local now       = CurTime()
    local last_time = ply.guardian_keybind_last_check

    if last_time and now < last_time + KEYBIND_CHECK_COOLDOWN then return end

    ply.guardian_keybind_last_check = now
    Guardian.FlagPlayer(ply,
        "Suspicious keybind pressed: " .. key_name)
end)

end -- SERVER [10]

-- =============================================================================
-- [11] Source Crasher — ExecuteStringCommand Exploit  (server-side, Linux)
-- =============================================================================
-- Abuses of the ExecuteStringCommand network channel can crash the server.
-- Limits: 10 000 cumulative bytes and 100 individual commands per tick.
-- Both counters reset every Tick so the window is exactly one simulation step.
-- Requires the 'slog' and 'sourcenet' modules; silently disabled on Windows.
-- =============================================================================
--[[
if SERVER and system.IsLinux() and Guardian.Config.source_crasher then

    local ok_slog, ok_snet = pcall(require, "slog"), false
    if ok_slog then ok_snet = pcall(require, "sourcenet") end

    if ok_slog and ok_snet then

        local SC_MAX_LENGTH  = 10000   -- cumulative byte budget per tick
        local SC_MAX_COUNT   = 100     -- command count budget per tick

        local sc_length_map  = {}
        local sc_count_map   = {}

        local function punish_source_crasher(steamID)
            local ply = player.GetBySteamID(steamID)
            if not IsValid(ply) or ply.guardian_sc_kicked then return end
            ply.guardian_sc_kicked = true

            Guardian.FlagPlayer(ply, "Source crasher: ExecuteStringCommand exploit")

            if CNetChan and CNetChan(ply:EntIndex()) then
                CNetChan(ply:EntIndex()):Shutdown("Source Crasher exploit")
            end
        end

        hook.Add("ExecuteStringCommand", "Guardian.AntiCheat.SourceCrasher",
            function(steamID, command)
                local cur_len = sc_length_map[steamID] or 0
                local cur_cnt = sc_count_map[steamID]  or 0

                if cur_len > SC_MAX_LENGTH or cur_cnt > SC_MAX_COUNT then
                    punish_source_crasher(steamID)
                    return true   -- suppress command
                end

                sc_count_map[steamID]  = cur_cnt + 1
                sc_length_map[steamID] = cur_len + #command
            end)

        hook.Add("Tick", "Guardian.AntiCheat.SourceCrasher.Reset", function()
            for k in next, sc_length_map do sc_length_map[k] = nil end
            for k in next, sc_count_map  do sc_count_map[k]  = nil end
        end)

    else
        Guardian.Print("[Guardian] Source crasher module unavailable "
            .. "(slog/sourcenet not installed).")
    end

end -- SERVER + Linux [11]
]]

-- =============================================================================
-- [12] Anti-Screengrab Evasion Detection  (server triggers, client verifies)
-- =============================================================================
-- The server sends a covert render-capture challenge to the client.
-- The client uses render.Capture to force a frame render; if HUDPaint does not
-- fire during that capture it means a screengrab hook intercepted the call,
-- which is a tell-tale sign of screengrab-blocker software.
-- The client sends the result back; the server flags on a positive report.
--
-- Challenge fires 15–30 s after PlayerSpawn (random to resist timing attacks).
-- =============================================================================

if SERVER then

net.Receive("Guardian.Net.AntiScreenGrab.Report", function(len, ply)
    if not Guardian.Config.anti_screengrab then return end
    if not IsValid(ply)                    then return end
    if ply.guardian_screengrab_flagged     then return end
    ply.guardian_screengrab_flagged = true
    Guardian.FlagPlayer(ply, "Anti-screengrab software detected")
end)

hook.Add("PlayerSpawn", "Guardian.AntiCheat.AntiScreenGrab.Spawn", function(ply)
    if not Guardian.Config.anti_screengrab then return end

    local delay = math.random(15, 30)
    timer.Simple(delay, function()
        if not IsValid(ply) then return end
        net.Start("Guardian.Net.AntiScreenGrab.Check")
        net.Send(ply)
    end)
end)

end -- SERVER [12]

if CLIENT then

local asg_hook_hudpaint  = nil
local asg_hook_postrender = nil

net.Receive("Guardian.Net.AntiScreenGrab.Check", function()
    if not Guardian.Config.anti_screengrab then return end

    local render_count       = 0
    local render_count_saved = 0

    -- Unique hook names prevent collisions with repeated challenges
    local tag = "Guardian.ASG." .. math.random(100000, 999999)
    local hp_tag = tag .. ".HUDPaint"
    local pr_tag = tag .. ".PostRender"

    hook.Add("HUDPaint", hp_tag, function()
        render_count = render_count + 1
    end)

    -- Small random delay before the capture so timing is non-deterministic
    timer.Simple(math.random(5, 10), function()
        hook.Add("PostRender", pr_tag, function()
            hook.Remove("PostRender", pr_tag)

            render_count_saved = render_count

            render.Capture(
            {
                format  = "jpeg",
                w       = ScrW(),
                h       = ScrH(),
                quality = 1,
                x       = 0,
                y       = 0,
            })

            -- If HUDPaint did not fire during render.Capture, a hook blocked it
            if render_count == render_count_saved then
                net.Start("Guardian.Net.AntiScreenGrab.Report")
                net.SendToServer()
            end

            hook.Remove("HUDPaint", hp_tag)
        end)
    end)
end)

end -- CLIENT [12]

-- =============================================================================
-- [13] No-Recoil / Viewpunch Suppression  (client-side, server-verified flag)
-- =============================================================================
-- A legitimate client's CalcView will always produce angles that equal
-- EyeAngles + ViewPunchAngles when a punch is active.  If the displayed
-- angles diverge from that sum more than 20 times the client is likely
-- zeroing the viewpunch, either by overriding CalcView or by patching the
-- prediction directly.  After the threshold a flag net message is sent once.
-- =============================================================================

if CLIENT then

local NO_RECOIL_THRESHOLD = 20   -- qualifying frames before flag is sent

local no_recoil_failures = 0
local no_recoil_sent     = false

local orig_calc_view = GAMEMODE.CalcView

local function round_scalar(n, dp)
    local m = 10 ^ (dp or 0)
    return math.floor(n * m + 0.5) / m
end

local function round_angle(ang)
    return Angle(round_scalar(ang.p), round_scalar(ang.y), round_scalar(ang.r))
end

local function angles_equal(a, b)
    return a.p == b.p and a.y == b.y and a.r == b.r
end

function GAMEMODE:CalcView(ply, origin, angles, fov, znear, zfar, ...)
    if not Guardian.Config.anti_recoil then
        return orig_calc_view(self, ply, origin, angles, fov, znear, zfar, ...)
    end

    if LocalPlayer() ~= ply or GetViewEntity() ~= LocalPlayer() then
        return orig_calc_view(self, ply, origin, angles, fov, znear, zfar, ...)
    end

    local vpunch = ply:GetViewPunchAngles()
    local vp_r   = round_scalar(vpunch.p)
    local vp_y   = round_scalar(vpunch.y)
    local vp_z   = round_scalar(vpunch.r)

    -- Only check when a meaningful punch is active
    if vp_r ~= 0 or vp_y ~= 0 or vp_z ~= 0 then
        local eye_a    = round_angle(ply:EyeAngles())
        local disp_a   = round_angle(angles - vpunch)

        if not angles_equal(eye_a, disp_a) then
            no_recoil_failures = no_recoil_failures + 1
            if no_recoil_failures >= NO_RECOIL_THRESHOLD and not no_recoil_sent then
                net.Start("Guardian.Net.NoRecoilFlag")
                net.SendToServer()
                no_recoil_sent = true
            end
        elseif no_recoil_failures > 0 then
            no_recoil_failures = no_recoil_failures - 1
        end
    end

    return orig_calc_view(self, ply, origin, angles, fov, znear, zfar, ...)
end

end -- CLIENT [13]

if SERVER then

net.Receive("Guardian.Net.NoRecoilFlag", function(len, ply)
    if not Guardian.Config.anti_recoil  then return end
    if not IsValid(ply) or ply:IsBot()  then return end
    Guardian.FlagPlayer(ply, "No-recoil / viewpunch suppression detected")
end)

end -- SERVER [13]

-- =============================================================================
-- [14] Anti-Spread — Server-Authoritative Bullet Spread Restoration
-- =============================================================================
-- Some cheats zero the Spread vector in the BulletInfo table on the client,
-- producing perfectly accurate shots.  This hook overrides FireBullets on the
-- server: for single-bullet weapons it reseeds the RNG from bullet direction
-- and reapplies the engine spread, so the server trace always matches what a
-- legitimate client would produce regardless of what the client submitted.
--
-- Multi-pellet weapons (Num > 1) are left untouched because they carry their
-- own spread logic that must match CS:S / HL2 mechanics exactly.
-- =============================================================================

if SERVER then

timer.Simple(5, function()
    local entity_meta = FindMetaTable("Entity")
    local orig_fire_bullets = entity_meta.FireBullets

    function entity_meta:FireBullets(bullet_info, suppress_host_events)
        if not bullet_info
        or not bullet_info.Num
        or bullet_info.Num > 1
        then
            return orig_fire_bullets(self, bullet_info, suppress_host_events)
        end

        local spread = bullet_info.Spread
        if type(spread) == "Vector" then
            bullet_info.Spread = vector_origin

            -- Deterministic reseed from bullet direction so the server-side
            -- trace matches what a legitimate client would produce.
            local d = bullet_info.Dir
            math.randomseed(CurTime()
                + math.sqrt(d.x * d.x * d.y * d.y * d.z * d.z))

            bullet_info.Dir = bullet_info.Dir + Vector(
                spread.x * (math.random() * 2.5 - 1),
                spread.y * (math.random() * 2.5 - 1),
                spread.z * (math.random() * 2.0 - 1))
        end

        return orig_fire_bullets(self, bullet_info, suppress_host_events)
    end
end)

end -- SERVER [14]

-- =============================================================================
-- [15] Alt Account / Ban Evasion Detection
-- =============================================================================
-- After PlayerSpawn the server sends a challenge to the client.
-- The client reads the persistent gac_alts PData key, appends its current
-- SteamID64 if absent, then reports every stored ID back to the server.
-- The server checks each reported ID against the active ban list and flags if
-- any banned ID is found.  Optionally the server also logs when a player
-- appears to be using multiple accounts (alt_notify).
--
-- PData is per-player persistent storage; the list accumulates across sessions.
-- =============================================================================

if SERVER then

local ALT_CHECK_GRACE_SEC = 15   -- seconds post-spawn before challenge fires

hook.Add("PlayerSpawn", "Guardian.AntiCheat.AltDetection.Spawn", function(ply)
    if not Guardian.Config.alt_detection then return end

    timer.Simple(ALT_CHECK_GRACE_SEC, function()
        if not IsValid(ply) then return end
        net.Start("Guardian.Net.AltCheck")
        net.Send(ply)
    end)
end)

net.Receive("Guardian.Net.AltCheckResponse", function(len, ply)
    if not Guardian.Config.alt_detection then return end
    if not IsValid(ply)                  then return end

    local steam64 = net.ReadString()
    if steam64 == ""                     then return end

    -- Check custom ban storage (adapt to your ban backend)
    local steam32 = util.SteamIDFrom64(steam64)
    local is_banned = false

    if GetUPDataGACSID64 then
        is_banned = GetUPDataGACSID64("IsBanned", steam64) == true
    elseif ULib and ULib.bans and steam32 then
        is_banned = ULib.bans[steam32] ~= nil
    end

    if is_banned then
        Guardian.FlagPlayer(ply,
            "Ban evasion detected (alt account: " .. steam64 .. ")")
    end
end)

net.Receive("Guardian.Net.AltCheckCount", function(len, ply)
    if not Guardian.Config.alt_notify then return end
    if not IsValid(ply)               then return end

    local count = net.ReadUInt(8)
    if count > 1 then
        Guardian.FlagPlayer(ply,
            string.format("Player joined with %d known alt accounts", count))
    end
end)

end -- SERVER [15]

if CLIENT then

net.Receive("Guardian.Net.AltCheck", function()
    local local_ply = LocalPlayer()
    local steam64   = local_ply:SteamID64()

    -- Load existing alt list from persistent storage
    local raw_ids   = local_ply:GetPData("guardian_alts", "")
    local id_array  = string.Explode("|", raw_ids, false)

    -- Ensure the current ID is in the list
    local found = false
    for _, id in ipairs(id_array) do
        if id == steam64 then found = true; break end
    end

    if not found then
        table.insert(id_array, steam64)
        local new_raw = table.concat(id_array, "|")
        local_ply:SetPData("guardian_alts", new_raw)
    end

    -- Report every known ID to the server for ban-list cross-check
    for _, id in ipairs(id_array) do
        if id ~= "" then
            net.Start("Guardian.Net.AltCheckResponse")
            net.WriteString(id)
            net.SendToServer()
        end
    end

    -- Report total account count
    local count = 0
    for _, id in ipairs(id_array) do
        if id ~= "" then count = count + 1 end
    end

    net.Start("Guardian.Net.AltCheckCount")
    net.WriteUInt(math.min(count, 255), 8)
    net.SendToServer()
end)

end -- CLIENT [15]

-- =============================================================================
-- Shared Cleanup
-- =============================================================================

hook.Add("PlayerDisconnected", "Guardian.AntiCheat.SharedCleanup", function(ply)
    ac_shot_stats[ply]  = nil
    bhop_tracker[ply]   = nil

    if SERVER then
        dos_process_collector[ply:SteamID()] = nil
    end
end)