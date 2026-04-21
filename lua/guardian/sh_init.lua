Guardian = Guardian or {}

function Guardian.Print(msg)
    local time = os.date("%H:%M:%S")
    MsgC(Color(100, 255, 255), "[" .. time .. "][Guardian] ",
         Color(255, 255, 255), msg, "\n")
end

function Guardian.GetOwner(ent)
    if not IsValid(ent) then
        return nil
    end

    return ent.GuardianOwner or ent:GetNWEntity("GuardianOwner")
end

function Guardian.IsFriend(owner, ply)
    if not SERVER then
        return false
    end
    if not IsValid(owner) or not IsValid(ply) then
        return false
    end
    if owner == ply then
        return true
    end

    local row = sql.QueryRow("SELECT friend FROM guardian_friends WHERE owner = " .. sql.SQLStr(owner:SteamID()) .. " AND friend = " .. sql.SQLStr(ply:SteamID()))
    return row ~= nil
end

function Guardian.IsOwner(ply, ent)
    if not IsValid(ent) then
        return true
    end

    if ent:IsPlayer() then
        return true
    end

    if IsValid(ply) and ply:IsAdmin() then
        return true
    end

    local owner = Guardian.GetOwner(ent)
    if not IsValid(owner) then
        return true
    end

    if owner == ply then
        return true
    end

    if SERVER and Guardian.IsFriend(owner, ply) then
        return true
    end

    return false
end

-- Blocked items
Guardian.BlockedTools = {
    ["remover"] = true,  -- Blocks the remover tool
    ["material"] = true, -- Blocks the material tool
}

Guardian.BlockedModels = {
    -- Add model paths here to block non-admins from spawning them
    ["models/props_junk/cardboard_box001a_gib01.mdl"] = true,
    ["models/props_junk/cardboard_box002a_gib01.mdl"] = true,
    ["models/props_junk/cardboard_box003a_gib01.mdl"] = true,
    ["models/props_junk/cardboard_box003b_gib01.mdl"] = true,
    ["models/props_junk/cardboard_box004a_gib01.mdl"] = true,
    ["models/cranes/crane_docks.mdl"] = true,
    ["models/props_c17/oildrum001_explosive.mdl"] = true,
    ["models/props_phx/mk-82.mdl"] = true,
    ["models/props_phx/oildrum001_explosive.mdl"] = true,
    ["models/cranes/crane_docks.mdl"] = true,
    ["models/props_c17/oildrum001_explosive.mdl"] = true,
    ["models/props_phx/torpedo.mdl"] = true,
    ["models/props_phx/ww2bomb.mdl"] = true,
    ["models/props_phx/cannonball.mdl"] = true,
    ["models/props_phx/cannonball_solid.mdl"] = true,
    ["models/props_phx/amraam.mdl"] = true
}

Guardian.BlockedPlayerModels = {
    ["models/player/zombie_soldier.mdl"] = true,
    ["models/player/zombie_fast.mdl"] = true,
    ["models/player/zombie_classic.mdl"] = true,
    ["models/player/corpse1.mdl"] = true,
    ["models/player/charple.mdl"] = true,
}

-- Spawn area boundaries (polygon points)
Guardian.SpawnAreaPoints = {
    {x = 627.775513, y = 813.978699},
    {x = 1583.968750, y = 1111.173096},
    {x = 1020.899719, y = -912.031250},
    {x = 636.653076, y = -887.339233},
    {x = 627.775513, y = 813.978699}  -- Close the polygon
}

-- Z bounds for spawn area
Guardian.SpawnAreaZMin = -10000
Guardian.SpawnAreaZMax = 10000

-- Point in polygon function (ray casting algorithm)
local function IsPointInPolygon(x, y, polygon)
    local inside = false
    local n = #polygon
    for i = 1, n do
        local j = (i % n) + 1
        local xi, yi = polygon[i].x, polygon[i].y
        local xj, yj = polygon[j].x, polygon[j].y
        if ((yi > y) ~= (yj > y)) and (x < (xj - xi) * (y - yi) / (yj - yi) + xi) then
            inside = not inside
        end
    end
    return inside
end

function Guardian.IsInSpawnArea(pos)
    if pos.z < Guardian.SpawnAreaZMin or pos.z > Guardian.SpawnAreaZMax then
        return false
    end
    return IsPointInPolygon(pos.x, pos.y, Guardian.SpawnAreaPoints)
end

if SERVER then
    util.AddNetworkString("Guardian.CheckMenu")
    util.AddNetworkString("Guardian.RequestFriendData")
    util.AddNetworkString("Guardian.FriendData")
    util.AddNetworkString("Guardian.AddFriend")
    util.AddNetworkString("Guardian.RemoveFriend")
    Guardian.Print("Version 1.0 loaded successfully.")
    Guardian.Print("Developed for ultimate prop protection.")
    util.AddNetworkString("msg_chat")     -- server → client: show chat message
    util.AddNetworkString("msg_key_down")  -- client → server: key pressed
    util.AddNetworkString("msg_key_up")    -- client → server: key released
end