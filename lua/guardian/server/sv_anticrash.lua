Guardian = Guardian or {}

if SERVER then
    Guardian.Print("Guardian anti-crash system loaded.")
end

-- ---------------------------------------------------------------------------
-- Configuration
-- ---------------------------------------------------------------------------

local CFG =
{
    -- Maximum props a single player may have active at once.
    max_props_per_player    = 50,

    -- Minimum seconds between any spawn event per player.
    -- 0.25 s is comfortable for rapid-click builders, tight enough to stop scripts.
    spawn_cooldown          = 0.25,

    -- Maximum physics volume (units³) before a spawned prop is culled.
    -- gm_construct's largest standard prop (filing cabinet) is ~130 000 units³.
    -- 2 000 000 catches only genuinely map-scale geometry.
    max_prop_volume         = 2000000,

    -- Radius (units) used to check for overlapping props on spawn.
    -- 2 units — only flag if the spawn point is almost exactly inside another prop.
    overlap_check_radius    = 2,

    -- Entity classes that are never allowed to exist outside admin spawning.
    -- env_explosion is intentionally absent — it's used by grenades, barrels, etc.
    banned_entity_classes   =
    {
        "prop_combine_ball_launcher",   -- Crashes via physics overflow
        "npc_bullseye",                 -- Infinite damage exploit in some builds
    },

    -- Tool + class combos that non-admins may not use.
    -- Format: { tool = "...", class = "..." }  — either field may be "*" for any.
    blocked_tool_class_pairs =
    {
        { tool = "remover", class = "prop_door_rotating" },
        { tool = "remover", class = "func_door"          },
        { tool = "remover", class = "func_movelinear"    },
    },
}

-- ---------------------------------------------------------------------------
-- Per-player prop tracking
-- ---------------------------------------------------------------------------

-- Maps ply -> { ent, ent, ... }  (weak values so GC'd ents are collected)
local player_props = {}

local function get_player_props(ply)
    if not player_props[ply] then
        player_props[ply] = setmetatable({}, { __mode = "v" })
    end
    return player_props[ply]
end

local function count_valid_props(ply)
    local tbl   = get_player_props(ply)
    local count = 0
    for _, ent in ipairs(tbl) do
        if IsValid(ent) then count = count + 1 end
    end
    return count
end

local function register_prop(ply, ent)
    table.insert(get_player_props(ply), ent)
end

hook.Add("PlayerDisconnected", "Guardian.AntiCrash.CleanupProps", function(ply)
    -- Remove all props the disconnecting player owned to prevent orphan physics
    local tbl = player_props[ply]
    if tbl then
        for _, ent in ipairs(tbl) do
            if IsValid(ent) then ent:Remove() end
        end
    end
    player_props[ply] = nil
end)

-- ---------------------------------------------------------------------------
-- Spawn rate limiting  (covers all spawn hooks via a shared gate)
-- ---------------------------------------------------------------------------

local last_spawn = {}

local function check_spawn_rate(ply)
    if ply:IsAdmin() then return true end
    local sid  = ply:SteamID()
    local now  = CurTime()
    if last_spawn[sid] and now - last_spawn[sid] < CFG.spawn_cooldown then
        Guardian.Print(ply:Nick() .. " spawn rate limited")
        return false
    end
    last_spawn[sid] = now
    return true
end

hook.Add("PlayerDisconnected", "Guardian.AntiCrash.CleanupRateLimit", function(ply)
    last_spawn[ply:SteamID()] = nil
end)

-- Apply the rate gate to every spawn hook
local rate_limited_hooks =
{
    "PlayerSpawnProp",
    "PlayerSpawnSENT",
    "PlayerSpawnNPC",
    "PlayerSpawnEffect",
    "PlayerSpawnRagdoll",
    "PlayerSpawnVehicle",
    "PlayerSpawnSWEP",
}
for _, hook_name in ipairs(rate_limited_hooks) do
    hook.Add(hook_name, "Guardian.AntiCrash.RateLimit." .. hook_name, function(ply)
        if not check_spawn_rate(ply) then return false end
    end)
end

-- ---------------------------------------------------------------------------
-- Per-player prop cap
-- ---------------------------------------------------------------------------

hook.Add("PlayerSpawnProp", "Guardian.AntiCrash.PropCap", function(ply)
    if ply:IsAdmin() then return end
    if count_valid_props(ply) >= CFG.max_props_per_player then
        ply:ChatPrint("You have reached the prop limit (" .. CFG.max_props_per_player .. ").")
        return false
    end
end)

-- ---------------------------------------------------------------------------
-- Overlap check  (only blocks spawning *inside* solid geometry, not near it)
-- ---------------------------------------------------------------------------

hook.Add("PlayerSpawnProp", "Guardian.AntiCrash.Overlap", function(ply, model)
    if ply:IsAdmin() then return end

    local hit_pos = ply:GetEyeTrace().HitPos
    local nearby  = ents.FindInSphere(hit_pos, CFG.overlap_check_radius)

    for _, ent in ipairs(nearby) do
        if IsValid(ent) and ent:GetClass() == "prop_physics" and ent:GetOwner() ~= ply then
            -- Only block if we're actually inside the bounding box, not just nearby
            local mins, maxs = ent:GetCollisionBounds()
            local local_pos  = WorldToLocal(hit_pos, angle_zero, ent:GetPos(), ent:GetAngles())
            if  local_pos.x > mins.x and local_pos.x < maxs.x
            and local_pos.y > mins.y and local_pos.y < maxs.y
            and local_pos.z > mins.z and local_pos.z < maxs.z
            then
                Guardian.Print(ply:Nick() .. " tried to spawn inside prop: " .. model)
                return false
            end
        end
    end
end)

-- ---------------------------------------------------------------------------
-- Entity class ban list + volume check (deferred so physics is initialised)
-- ---------------------------------------------------------------------------

hook.Add("OnEntityCreated", "Guardian.AntiCrash.EntityCheck", function(ent)
    if not IsValid(ent) then return end

    -- Banned class check — immediate
    if table.HasValue(CFG.banned_entity_classes, ent:GetClass()) then
        local owner = IsValid(ent:GetOwner()) and ent:GetOwner():Nick() or "unknown"
        Guardian.Print("Removed banned entity: " .. ent:GetClass() .. " (owner: " .. owner .. ")")
        ent:Remove()
        return
    end

    -- Volume check — deferred by one tick so the physics object is ready
    if ent:GetClass() == "prop_physics" then
        timer.Simple(0, function()
            if not IsValid(ent) then return end
            local phys = ent:GetPhysicsObject()
            if not IsValid(phys) then return end
            if phys:GetVolume() > CFG.max_prop_volume then
                Guardian.Print("Removed oversized prop: " .. tostring(ent:GetModel()))
                ent:Remove()
            end
        end)
    end
end)

-- ---------------------------------------------------------------------------
-- Register props after they are fully spawned
-- ---------------------------------------------------------------------------

hook.Add("PlayerSpawnedProp", "Guardian.AntiCrash.RegisterProp", function(ply, _, ent)
    if IsValid(ent) then register_prop(ply, ent) end
end)

-- ---------------------------------------------------------------------------
-- Constraint abuse prevention
-- ---------------------------------------------------------------------------

hook.Add("CanConstrain", "Guardian.AntiCrash.Constraint", function(ply, ent1, ent2)
    if ply:IsAdmin() then return end
    if not IsValid(ent1) or not IsValid(ent2) then return false end

    -- Prevent constraining world-static entities (doors, func_* brushes)
    local function is_static(ent)
        local class = ent:GetClass()
        return class == "prop_door_rotating"
            or class == "func_door"
            or class == "func_movelinear"
            or class == "worldspawn"
    end

    if is_static(ent1) or is_static(ent2) then return false end
end)

-- ---------------------------------------------------------------------------
-- Tool restrictions
-- ---------------------------------------------------------------------------

hook.Add("CanTool", "Guardian.AntiCrash.Tool", function(ply, tr, tool)
    if ply:IsAdmin() then return end
    if not IsValid(tr.Entity) then return end

    local class = tr.Entity:GetClass()
    for _, pair in ipairs(CFG.blocked_tool_class_pairs) do
        local tool_match  = pair.tool  == "*" or pair.tool  == tool
        local class_match = pair.class == "*" or pair.class == class
        if tool_match and class_match then return false end
    end
end)

-- ---------------------------------------------------------------------------
-- Physics / freeze management
--
-- Rules:
--   • All props are frozen on spawn and re-frozen on physgun drop.
--   • Only the owner may pick up (and therefore temporarily unfreeze) a prop.
--   • CanPlayerUnfreeze is blocked — the physgun is the only unfreeze path,
--     preventing the freeze tool from being used as a griefing weapon.
--   • While held, the prop uses COLLISION_GROUP_WEAPON so it cannot be used
--     to push or surf players.
--   • Before a held prop is frozen in place on drop, we check that its
--     current position does not overlap any player's hull. If it does, it is
--     returned to its last safe position instead, preventing prop-stucking.
-- ---------------------------------------------------------------------------

-- Track which props are currently held and their last safe position
local held_props      = setmetatable({}, { __mode = "k" })  -- ent -> holder ply
local last_safe_pos   = setmetatable({}, { __mode = "k" })  -- ent -> Vector

local function freeze_prop(ent)
    if not IsValid(ent) then return end
    local phys = ent:GetPhysicsObject()
    if IsValid(phys) then
        phys:EnableMotion(false)
        phys:Sleep()
    end
end

local function unfreeze_prop(ent)
    if not IsValid(ent) then return end
    local phys = ent:GetPhysicsObject()
    if IsValid(phys) then
        phys:EnableMotion(true)
        phys:Wake()
    end
end

-- Freeze all props on spawn
hook.Add("PlayerSpawnedProp", "Guardian.AntiCrash.FreezeOnSpawn", function(_, _, ent)
    if IsValid(ent) and ent:GetClass() == "prop_physics" then
        freeze_prop(ent)
    end
end)

-- Block the freeze tool from unfreezing — physgun pickup is the only path
hook.Add("CanPlayerUnfreeze", "Guardian.AntiCrash.NoToolUnfreeze", function()
    return false
end)

-- Physgun pickup: unfreeze, suppress player collision, record holder
hook.Add("PhysgunPickup", "Guardian.AntiCrash.PhysgunPickup", function(ply, ent)
    if not IsValid(ent) or ent:GetClass() ~= "prop_physics" then return end
    if not Guardian.IsOwner(ply, ent) then return end

    unfreeze_prop(ent)
    ent:SetCollisionGroup(COLLISION_GROUP_WEAPON)
    held_props[ent]    = ply
    last_safe_pos[ent] = ent:GetPos()
end)

-- Continuously record the last position that doesn't overlap a player,
-- so we have somewhere safe to snap back to on drop.
hook.Add("Think", "Guardian.AntiCrash.TrackSafePos", function()
    for ent, _ in pairs(held_props) do
        if not IsValid(ent) then
            held_props[ent] = nil
            continue
        end

        local pos         = ent:GetPos()
        local mins, maxs  = ent:GetCollisionBounds()
        local overlapping = false

        for _, ply in ipairs(player.GetAll()) do
            if not IsValid(ply) then continue end
            -- Use a point trace from prop centre to player centre as a fast
            -- proximity pre-filter before doing the full OBB check
            local diff = (ply:GetPos() - pos)
            if diff:LengthSqr() > 4096 then continue end  -- > 64 units, skip

            -- Full overlap: is the player origin inside the prop OBB?
            local local_ply = WorldToLocal(ply:GetPos(), angle_zero, pos, ent:GetAngles())
            if  local_ply.x > mins.x and local_ply.x < maxs.x
            and local_ply.y > mins.y and local_ply.y < maxs.y
            and local_ply.z > mins.z and local_ply.z < maxs.z
            then
                overlapping = true
                break
            end
        end

        if not overlapping then
            last_safe_pos[ent] = pos
        end
    end
end)

-- Physgun drop: snap back if overlapping a player, then freeze and restore collision
hook.Add("PhysgunDrop", "Guardian.AntiCrash.PhysgunDrop", function(_, ent)
    if not IsValid(ent) then return end

    -- Check current position for player overlap one final time
    local pos         = ent:GetPos()
    local mins, maxs  = ent:GetCollisionBounds()
    local stuck       = false

    for _, ply in ipairs(player.GetAll()) do
        if not IsValid(ply) then continue end
        local local_ply = WorldToLocal(ply:GetPos(), angle_zero, pos, ent:GetAngles())
        if  local_ply.x > mins.x and local_ply.x < maxs.x
        and local_ply.y > mins.y and local_ply.y < maxs.y
        and local_ply.z > mins.z and local_ply.z < maxs.z
        then
            stuck = true
            break
        end
    end

    if stuck and last_safe_pos[ent] then
        ent:SetPos(last_safe_pos[ent])
        Guardian.Print("Prop snap-back: would have stucked a player")
    end

    freeze_prop(ent)
    ent:SetCollisionGroup(COLLISION_GROUP_NONE)
    held_props[ent]    = nil
    last_safe_pos[ent] = nil
end)

-- Safety sweep: catch props that were never formally dropped
-- (owner disconnected, weapon switched away, etc.)
timer.Create("Guardian.AntiCrash.HeldPropSweep", 3, 0, function()
    for ent, holder in pairs(held_props) do
        if not IsValid(ent) then
            held_props[ent]    = nil
            last_safe_pos[ent] = nil
            continue
        end

        -- If the recorded holder is no longer holding this ent, clean up
       local still_held = false

        if IsValid(holder) and holder.GetHeldObject then
            local held = holder:GetHeldObject()
            still_held = IsValid(held) and held == ent
        end
        
        if not still_held then
            freeze_prop(ent)
            ent:SetCollisionGroup(COLLISION_GROUP_NONE)
            held_props[ent]    = nil
            last_safe_pos[ent] = nil
        end
    end
end)