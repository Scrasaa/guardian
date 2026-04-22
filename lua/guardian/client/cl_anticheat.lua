-- =============================================================================
-- Guardian — Anti-Cheat  [CLIENT]
-- Detections handled client-side (server-verified where noted):
--   9.  Engine prediction manipulation
--   12. Anti-screengrab evasion
--   13. No-recoil / viewpunch suppression
--   15. Alt account / ban evasion (client half)
-- =============================================================================

Guardian = Guardian or {}

-- Mirror of the server config — client only reads these flags, never writes them.
Guardian.Config = Guardian.Config or
{
    anti_engine_pred = true,
    anti_screengrab  = true,
    anti_recoil      = true,
    alt_detection    = true,
}

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

-- =============================================================================
-- [12] Anti-Screengrab Evasion Detection  (client half)
-- =============================================================================
-- The server sends a covert render-capture challenge to the client.
-- The client uses render.Capture to force a frame render; if HUDPaint does not
-- fire during that capture it means a screengrab hook intercepted the call,
-- which is a tell-tale sign of screengrab-blocker software.
-- The client sends the result back; the server flags on a positive report.
-- =============================================================================

net.Receive("Guardian.Net.AntiScreenGrab.Check", function()
    if not Guardian.Config.anti_screengrab then return end

    local render_count       = 0
    local render_count_saved = 0

    -- Unique hook names prevent collisions with repeated challenges.
    local tag    = "Guardian.ASG." .. math.random(100000, 999999)
    local hp_tag = tag .. ".HUDPaint"
    local pr_tag = tag .. ".PostRender"

    hook.Add("HUDPaint", hp_tag, function()
        render_count = render_count + 1
    end)

    -- Small random delay before the capture so timing is non-deterministic.
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

            -- If HUDPaint did not fire during render.Capture, a hook blocked it.
            if render_count == render_count_saved then
                net.Start("Guardian.Net.AntiScreenGrab.Report")
                net.SendToServer()
            end

            hook.Remove("HUDPaint", hp_tag)
        end)
    end)
end)

-- =============================================================================
-- [13] No-Recoil / Viewpunch Suppression  (client-side, server-verified flag)
-- =============================================================================
-- A legitimate client's CalcView will always produce angles that equal
-- EyeAngles + ViewPunchAngles when a punch is active.  If the displayed
-- angles diverge from that sum more than 20 times the client is likely
-- zeroing the viewpunch, either by overriding CalcView or by patching the
-- prediction directly.  After the threshold a flag net message is sent once.
-- =============================================================================

local NO_RECOIL_THRESHOLD = 20   -- qualifying frames before flag is sent

local no_recoil_failures = 0
local no_recoil_sent     = false

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

hook.Add("CalcView", "Guardian_NoRecoilCheck", function(ply, origin, angles, fov, znear, zfar)
    if not Guardian.Config.anti_recoil then return end

    if LocalPlayer() ~= ply or GetViewEntity() ~= LocalPlayer() then return end

    local vpunch = ply:GetViewPunchAngles()

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

    local vp_r = round_scalar(vpunch.p)
    local vp_y = round_scalar(vpunch.y)
    local vp_z = round_scalar(vpunch.r)

    if vp_r ~= 0 or vp_y ~= 0 or vp_z ~= 0 then
        local eye_a  = round_angle(ply:EyeAngles())
        local disp_a = round_angle(angles - vpunch)

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
end)

-- =============================================================================
-- [15] Alt Account / Ban Evasion Detection  (client half)
-- =============================================================================
-- On challenge receipt the client reads the persistent guardian_alts PData key,
-- appends its current SteamID64 if absent, then reports every stored ID back to
-- the server for ban-list cross-checking.  Also reports the total account count.
-- =============================================================================

net.Receive("Guardian.Net.AltCheck", function()
    local local_ply = LocalPlayer()
    local steam64   = local_ply:SteamID64()

    -- Load existing alt list from persistent storage.
    local raw_ids  = local_ply:GetPData("guardian_alts", "")
    local id_array = string.Explode("|", raw_ids, false)

    -- Ensure the current ID is in the list.
    local found = false
    for _, id in ipairs(id_array) do
        if id == steam64 then found = true; break end
    end

    if not found then
        table.insert(id_array, steam64)
        local_ply:SetPData("guardian_alts", table.concat(id_array, "|"))
    end

    -- Report every known ID to the server for ban-list cross-check.
    for _, id in ipairs(id_array) do
        if id ~= "" then
            net.Start("Guardian.Net.AltCheckResponse")
            net.WriteString(id)
            net.SendToServer()
        end
    end

    -- Report total account count.
    local count = 0
    for _, id in ipairs(id_array) do
        if id ~= "" then count = count + 1 end
    end

    net.Start("Guardian.Net.AltCheckCount")
    net.WriteUInt(math.min(count, 255), 8)
    net.SendToServer()
end)