-- =============================================================================
-- Guardian — Restrictions
-- Handles: prop/tool/physgun ownership, spawn blocking, player model lock,
--          spawn protection, friend system, playtime/ticks, spawn-area cleanup.
-- =============================================================================

if SERVER then
    Guardian.Print("Guardian Restrictions system loaded.")
end

Guardian = Guardian or {}

-- ---------------------------------------------------------------------------
-- Database init
-- ---------------------------------------------------------------------------

hook.Add("Initialize", "Guardian.InitDB", function()
    sql.Query([[CREATE TABLE IF NOT EXISTS guardian_cheaters (
        steamid   TEXT,
        name      TEXT,
        reason    TEXT,
        timestamp INTEGER
    )]])
    sql.Query([[CREATE TABLE IF NOT EXISTS guardian_players (
        steamid  TEXT PRIMARY KEY,
        name     TEXT,
        ticks    INTEGER DEFAULT 0,
        playtime INTEGER DEFAULT 0
    )]])
    sql.Query([[CREATE TABLE IF NOT EXISTS guardian_friends (
        owner  TEXT,
        friend TEXT,
        UNIQUE(owner, friend)
    )]])
    Guardian.Print("Databases initialised")
end)

-- ---------------------------------------------------------------------------
-- Flag helper (rate-limited per player per reason)
-- ---------------------------------------------------------------------------

local flag_cooldowns = {}
local FLAG_COOLDOWN  = 60 -- seconds

function Guardian.FlagPlayer(ply, reason)
    if not IsValid(ply) then return end

    local sid = ply:SteamID()
    flag_cooldowns[sid] = flag_cooldowns[sid] or {}

    local now = CurTime()
    if flag_cooldowns[sid][reason] and now - flag_cooldowns[sid][reason] < FLAG_COOLDOWN then
        return -- duplicate suppressed
    end
    flag_cooldowns[sid][reason] = now

    sql.Query(
        "INSERT INTO guardian_cheaters (steamid, name, reason, timestamp) VALUES ("
        .. sql.SQLStr(sid) .. ","
        .. sql.SQLStr(ply:Nick()) .. ","
        .. sql.SQLStr(reason) .. ","
        .. os.time() .. ")"
    )
    Guardian.Print("Flagged " .. ply:Nick() .. " for: " .. reason)
end

-- ---------------------------------------------------------------------------
-- Ownership helpers
-- ---------------------------------------------------------------------------

local function is_owner(ply, ent)
    return Guardian.IsOwner(ply, ent)
end

-- ---------------------------------------------------------------------------
-- Tool / prop restrictions
-- ---------------------------------------------------------------------------

hook.Add("PhysgunPickup",     "Guardian.Restrictions.Physgun",   function(ply, ent)    if not is_owner(ply, ent) then return false end end)
hook.Add("CanProperty",       "Guardian.Restrictions.Property",  function(ply, _, ent) if not is_owner(ply, ent) then return false end end)
hook.Add("CanDrive",          "Guardian.Restrictions.Drive",     function(ply, ent)    if not is_owner(ply, ent) then return false end end)
hook.Add("PlayerUse",         "Guardian.Restrictions.Use",       function(ply, ent)    if not is_owner(ply, ent) then return false end end)
hook.Add("CanPlayerUnfreeze", "Guardian.Restrictions.Unfreeze",  function(ply, ent)    if not is_owner(ply, ent) then return false end end)

hook.Add("CanTool", "Guardian.Restrictions.Toolgun", function(ply, tr, tool)
    if IsValid(tr.Entity) and not is_owner(ply, tr.Entity) then return false end
    if Guardian.BlockedTools[tool] and not ply:IsAdmin() then return false end
end)

hook.Add("EntityTakeDamage", "Guardian.Restrictions.Damage", function(target, dmginfo)
    local attacker = dmginfo:GetAttacker()
    if IsValid(attacker) and attacker:IsPlayer() and not is_owner(attacker, target) then
        dmginfo:ScaleDamage(0)
        return true
    end
end)

-- ---------------------------------------------------------------------------
-- Spawn restrictions
-- ---------------------------------------------------------------------------

local function check_spawn(ply, model, pos)
    if Guardian.BlockedModels[model] and not ply:IsAdmin() then
        Guardian.Print(ply:Nick() .. " tried to spawn blocked model: " .. model)
        return false
    end
    if pos and Guardian.IsInSpawnArea(pos) and not ply:IsAdmin() then
        Guardian.Print(ply:Nick() .. " tried to spawn in spawn area")
        return false
    end
end

local spawn_hooks =
{
    { "PlayerSpawnProp",    "Guardian.Block.SpawnProp"    },
    { "PlayerSpawnEffect",  "Guardian.Block.SpawnEffect"  },
    { "PlayerSpawnRagdoll", "Guardian.Block.SpawnRagdoll" },
    { "PlayerSpawnNPC",     "Guardian.Block.SpawnNPC"     },
    { "PlayerSpawnSENT",    "Guardian.Block.SpawnSENT"    },
    { "PlayerSpawnVehicle", "Guardian.Block.SpawnVehicle" },
    { "PlayerSpawnSWEP",    "Guardian.Block.SpawnSWEP"    },
}
for _, pair in ipairs(spawn_hooks) do
    hook.Add(pair[1], pair[2], function(ply, model)
        return check_spawn(ply, model, ply:GetEyeTrace().HitPos)
    end)
end

-- ---------------------------------------------------------------------------
-- Player model lock
-- ---------------------------------------------------------------------------

local player_models = {}

hook.Add("PlayerInitialSpawn", "Guardian.Restrictions.InitModel", function(ply)
    player_models[ply] = ply:GetModel()

    local data = sql.Query("SELECT * FROM guardian_players WHERE steamid = " .. sql.SQLStr(ply:SteamID()))
    if data and data[1] then
        ply:SetNWInt("GuardianTicks",    tonumber(data[1].ticks)    or 0)
        ply:SetNWInt("GuardianPlaytime", tonumber(data[1].playtime) or 0)
    else
        sql.Query(
            "INSERT INTO guardian_players (steamid, name, ticks, playtime) VALUES ("
            .. sql.SQLStr(ply:SteamID()) .. ","
            .. sql.SQLStr(ply:Nick()) .. ", 0, 0)"
        )
        ply:SetNWInt("GuardianTicks",    0)
        ply:SetNWInt("GuardianPlaytime", 0)
    end
end)

hook.Add("PlayerSetModel", "Guardian.Restrictions.ModelChange", function(ply, model)
    if not ply:IsAdmin() and Guardian.BlockedPlayerModels[model] then
        timer.Simple(0, function()
            if IsValid(ply) then
                ply:SetModel(player_models[ply] or "models/player/kleiner.mdl")
            end
        end)
        return
    end
    player_models[ply] = model
end)

hook.Add("PlayerDisconnected", "Guardian.Restrictions.CleanupModel", function(ply)
    local sid      = ply:SteamID()
    local ticks    = ply:GetNWInt("GuardianTicks",    0)
    local playtime = ply:GetNWInt("GuardianPlaytime", 0)
    sql.Query(
        "UPDATE guardian_players SET ticks = " .. ticks
        .. ", playtime = " .. playtime
        .. ", name = "     .. sql.SQLStr(ply:Nick())
        .. " WHERE steamid = " .. sql.SQLStr(sid)
    )
    player_models[ply]  = nil
    flag_cooldowns[sid] = nil
end)

-- ---------------------------------------------------------------------------
-- Spawn protection
-- ---------------------------------------------------------------------------

Guardian.ProtectedPlayers = {}

hook.Add("PlayerSpawn", "Guardian.SpawnProtection", function(ply)
    Guardian.ProtectedPlayers[ply] = true
end)

hook.Add("PlayerShouldTakeDamage", "Guardian.SpawnProtection", function(ply)
    if Guardian.ProtectedPlayers[ply] then return false end
end)

hook.Add("PlayerButtonDown", "Guardian.RemoveProtection", function(ply)
    Guardian.ProtectedPlayers[ply] = nil
end)

hook.Add("StartCommand", "Guardian.RemoveProtectionMove", function(ply, cmd)
    if not Guardian.ProtectedPlayers[ply] then return end
    if  cmd:GetForwardMove() ~= 0
     or cmd:GetSideMove()   ~= 0
     or cmd:GetUpMove()     ~= 0
     or cmd:GetMouseX()     ~= 0
     or cmd:GetMouseY()     ~= 0
    then
        Guardian.ProtectedPlayers[ply] = nil
    end
end)

hook.Add("PlayerDisconnected", "Guardian.CleanupProtection", function(ply)
    Guardian.ProtectedPlayers[ply] = nil
end)

-- ---------------------------------------------------------------------------
-- Friend system
-- ---------------------------------------------------------------------------

local function send_friend_data(ply)
    if not IsValid(ply) then return end
    local rows = sql.Query("SELECT friend FROM guardian_friends WHERE owner = " .. sql.SQLStr(ply:SteamID())) or {}
    local data = {}
    for _, row in ipairs(rows) do
        local friend_ply  = player.GetBySteamID(row.friend)
        local friend_name = IsValid(friend_ply) and friend_ply:Nick() or "Unknown"
        table.insert(data, { steamid = row.friend, name = friend_name })
    end
    net.Start("Guardian.FriendData")
    net.WriteTable(data)
    net.Send(ply)
end

local function resolve_friend_target(ply, identifier)
    if not identifier or identifier == "" then return nil end
    identifier = string.Trim(identifier)

    if string.find(identifier, "STEAM_", 1, true) then
        for _, p in ipairs(player.GetAll()) do
            if p:SteamID() == identifier then return p end
        end
        return nil
    end

    local lower = string.lower(identifier)
    for _, p in ipairs(player.GetAll()) do
        if string.find(string.lower(p:Nick()), lower, 1, true) then return p end
    end
    return nil
end

net.Receive("Guardian.RequestFriendData", function(_, ply) send_friend_data(ply) end)

net.Receive("Guardian.AddFriend", function(_, ply)
    local target = resolve_friend_target(ply, net.ReadString())
    if not IsValid(target) or target == ply then
        ply:ChatPrint("Friend not found or invalid.")
        return
    end
    sql.Query(
        "INSERT OR IGNORE INTO guardian_friends (owner, friend) VALUES ("
        .. sql.SQLStr(ply:SteamID()) .. "," .. sql.SQLStr(target:SteamID()) .. ")"
    )
    ply:ChatPrint("Added " .. target:Nick() .. " as friend.")
    send_friend_data(ply)
end)

net.Receive("Guardian.RemoveFriend", function(_, ply)
    local steamid = net.ReadString()
    if not steamid or steamid == "" then return end
    sql.Query(
        "DELETE FROM guardian_friends WHERE owner = " .. sql.SQLStr(ply:SteamID())
        .. " AND friend = " .. sql.SQLStr(steamid)
    )
    ply:ChatPrint("Removed friend: " .. steamid)
    send_friend_data(ply)
end)

-- ---------------------------------------------------------------------------
-- Playtime / Ticks
-- ---------------------------------------------------------------------------

timer.Create("Guardian.Playtime", 60, 0, function()
    for _, ply in ipairs(player.GetAll()) do
        if not IsValid(ply) then continue end
        local playtime = ply:GetNWInt("GuardianPlaytime", 0) + 60
        ply:SetNWInt("GuardianPlaytime", playtime)
        local query

        if playtime % 900 == 0 then
            local ticks = ply:GetNWInt("GuardianTicks", 0) + 1
            ply:SetNWInt("GuardianTicks", ticks)
            ply:ChatPrint("You earned 1 Tick for 15 minutes of playtime!")
            ply:EmitSound("garrysmod/balloon_pop_cute.wav")
            query = "UPDATE guardian_players SET ticks = " .. ticks
                 .. ", playtime = " .. playtime
                 .. " WHERE steamid = " .. sql.SQLStr(ply:SteamID())
        else
            query = "UPDATE guardian_players SET playtime = " .. playtime
                 .. " WHERE steamid = " .. sql.SQLStr(ply:SteamID())
        end
        sql.Query(query)
    end
end)

-- ---------------------------------------------------------------------------
-- Spawn-area prop cleanup
-- ---------------------------------------------------------------------------

hook.Add("PhysgunDrop", "Guardian.SpawnArea", function(ply, ent)
    if IsValid(ent) and Guardian.IsInSpawnArea(ent:GetPos()) then
        ent:Remove()
        Guardian.Print(ply:Nick() .. " dropped prop into spawn area — removed")
    end
end)

hook.Add("GravGunOnDropped", "Guardian.SpawnArea", function(ply, ent)
    if IsValid(ent) and Guardian.IsInSpawnArea(ent:GetPos()) then
        ent:Remove()
        Guardian.Print(ply:Nick() .. " dropped prop into spawn area — removed")
    end
end)

local spawn_area_classes = { "prop_physics", "prop_ragdoll", "prop_effect" }
timer.Create("Guardian.SpawnAreaCleanup", 2, 0, function()
    for _, class in ipairs(spawn_area_classes) do
        for _, ent in ipairs(ents.FindByClass(class)) do
            if IsValid(ent) and Guardian.IsInSpawnArea(ent:GetPos()) then
                ent:Remove()
            end
        end
    end
end)

-- ---------------------------------------------------------------------------
-- Admin commands
-- ---------------------------------------------------------------------------

local admin_commands =
{
    ["!check"] = function(ply)
        local data = sql.Query("SELECT * FROM guardian_cheaters") or {}
        net.Start("Guardian.CheckMenu")
        net.WriteTable(data)
        net.Send(ply)
    end,

    ["!countflags"] = function(ply)
        local result = sql.Query("SELECT COUNT(*) as count FROM guardian_cheaters")
        ply:ChatPrint("Total flags: " .. (result and result[1].count or 0))
    end,

    ["!clearflags"] = function(ply)
        sql.Query("DELETE FROM guardian_cheaters")
        ply:ChatPrint("Cleared all flags.")
    end,

    ["!resetdb"] = function(ply)
        sql.Query("DROP TABLE IF EXISTS guardian_cheaters")
        sql.Query([[CREATE TABLE guardian_cheaters (
            steamid TEXT, name TEXT, reason TEXT, timestamp INTEGER
        )]])
        ply:ChatPrint("Reset anticheat database.")
    end,
}

hook.Add("PlayerSay", "Guardian.AdminCommands", function(ply, text)
    if not ply:IsAdmin() then return end

    local handler = admin_commands[text]
    if handler then
        handler(ply)
        return ""
    end

    if string.StartWith(text, "!giveticks ") then
        local args   = string.Explode(" ", text)
        local amount = tonumber(args[3])
        if #args < 3 or not amount or amount <= 0 then
            ply:ChatPrint("Usage: !giveticks <player> <amount>")
            return ""
        end

        local target_name = string.lower(args[2])
        local target
        for _, p in ipairs(player.GetAll()) do
            if string.find(string.lower(p:Nick()), target_name, 1, true) then
                target = p
                break
            end
        end

        if not IsValid(target) then
            ply:ChatPrint("Player not found.")
            return ""
        end

        local new_ticks = target:GetNWInt("GuardianTicks", 0) + amount
        target:SetNWInt("GuardianTicks", new_ticks)
        sql.Query(
            "UPDATE guardian_players SET ticks = " .. new_ticks
            .. " WHERE steamid = " .. sql.SQLStr(target:SteamID())
        )
        ply:ChatPrint("Gave " .. amount .. " Ticks to " .. target:Nick() .. ".")
        target:ChatPrint("You received " .. amount .. " Ticks from " .. ply:Nick() .. "!")
        return ""
    end
end)