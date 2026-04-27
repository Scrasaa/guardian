-- ============================================================
--  guardian_ranks_sv.lua  –  Guardian Ranks  (server)
--  SQL persistence · playtime tracking · NW sync
-- ============================================================

if CLIENT then return end

Guardian = Guardian or {}

-- ============================================================
--  SQL
-- ============================================================
sql.Query([[
    CREATE TABLE IF NOT EXISTS guardian_playtime (
        steamid  TEXT    PRIMARY KEY,
        seconds  INTEGER NOT NULL DEFAULT 0
    )
]])

-- ============================================================
--  Helpers
-- ============================================================
local function load_playtime(ply)
    local res = sql.Query(
        "SELECT seconds FROM guardian_playtime WHERE steamid = " ..
        sql.SQLStr(ply:SteamID())
    )
    local seconds = (res and res[1]) and tonumber(res[1].seconds) or 0
    ply:SetNWInt("G_Playtime", seconds)
    local rank = Guardian.GetRank(seconds)
    ply:SetNWString("G_RankID",    rank.id)
    ply:SetNWString("G_RankLabel", rank.label)
    ply:SetNWString("G_RankCR",
        rank.color.r .. "," .. rank.color.g .. "," .. rank.color.b)
end

local function save_playtime(ply)
    if not IsValid(ply) then return end
    local seconds = ply:GetNWInt("G_Playtime", 0)
    sql.Query(string.format(
        "INSERT OR REPLACE INTO guardian_playtime (steamid, seconds) VALUES (%s, %d)",
        sql.SQLStr(ply:SteamID()), seconds
    ))
end

local function add_second(ply)
    if not IsValid(ply) then return end
    local seconds = ply:GetNWInt("G_Playtime", 0) + 1
    ply:SetNWInt("G_Playtime", seconds)

    -- Update rank NW vars only when the rank actually changes.
    local new_rank = Guardian.GetRank(seconds)
    if ply:GetNWString("G_RankID", "") ~= new_rank.id then
        ply:SetNWString("G_RankID",    new_rank.id)
        ply:SetNWString("G_RankLabel", new_rank.label)
        ply:SetNWString("G_RankCR",
            new_rank.color.r .. "," .. new_rank.color.g .. "," .. new_rank.color.b)
    end
end

-- ============================================================
--  Global accessor (other server files may call this)
-- ============================================================
function Guardian.GetPlaytime(ply)
    if not IsValid(ply) then return 0 end
    return ply:GetNWInt("G_Playtime", 0)
end

-- ============================================================
--  Per-second timer – ticks for every connected player
-- ============================================================
timer.Create("Guardian.Playtime", 1, 0, function()
    for _, ply in ipairs(player.GetAll()) do
        if IsValid(ply) and ply:IsConnected() then
            add_second(ply)
        end
    end
end)

-- Save to DB every 60 seconds to reduce write pressure.
timer.Create("Guardian.Playtime.Save", 60, 0, function()
    for _, ply in ipairs(player.GetAll()) do
        save_playtime(ply)
    end
end)

-- ============================================================
--  Hooks
-- ============================================================
hook.Add("PlayerInitialSpawn", "Guardian.Ranks.Load", function(ply)
    timer.Simple(1, function()
        if not IsValid(ply) then return end
        load_playtime(ply)
    end)
end)

hook.Add("PlayerDisconnected", "Guardian.Ranks.Save", function(ply)
    save_playtime(ply)
end)