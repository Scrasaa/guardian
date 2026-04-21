-- ============================================================
--  guardian_shop_sv.lua  –  Guardian Shop  (server)
--  SQL persistence · purchase validation · cosmetic application
--  Requires guardian_shop_sh.lua to be loaded first.
-- ============================================================

if CLIENT then return end

Guardian = Guardian or {}

-- ============================================================
--  SQL initialisation
-- ============================================================
sql.Query([[
    CREATE TABLE IF NOT EXISTS guardian_ticks (
        steamid TEXT PRIMARY KEY,
        ticks   INTEGER NOT NULL DEFAULT 0
    )
]])

sql.Query([[
    CREATE TABLE IF NOT EXISTS guardian_owned_items (
        steamid TEXT    NOT NULL,
        item_id TEXT    NOT NULL,
        PRIMARY KEY (steamid, item_id)
    )
]])

sql.Query([[
    CREATE TABLE IF NOT EXISTS guardian_equipped (
        steamid  TEXT NOT NULL,
        category TEXT NOT NULL,
        item_id  TEXT NOT NULL,
        PRIMARY KEY (steamid, category)
    )
]])

-- ============================================================
--  DB sanitisation
--  Runs once at startup. Removes any equipped rows whose item_id
--  no longer exists in the catalogue or whose category has drifted
--  out of sync – the root cause of the stale-state bug.
-- ============================================================
local function sanitize_equipped_db()
    local rows = sql.Query("SELECT steamid, category, item_id FROM guardian_equipped")
    if not rows then return end

    local removed = 0
    for _, row in ipairs(rows) do
        local item  = Guardian.FindItem(row.item_id)
        -- For skin items the stored category is "skins:<weapon_class>", not plain "skins".
        local valid = item and (equip_key(item) == row.category)

        if not valid then
            sql.Query(string.format(
                "DELETE FROM guardian_equipped WHERE steamid = %s AND category = %s",
                sql.SQLStr(row.steamid), sql.SQLStr(row.category)
            ))
            removed = removed + 1
        end
    end

    if removed > 0 then
        MsgN("[Guardian] Sanitised " .. removed .. " stale equipped row(s) from the database.")
    end
end

-- Also prune owned items that no longer exist in the catalogue.
local function sanitize_owned_db()
    local rows = sql.Query("SELECT steamid, item_id FROM guardian_owned_items")
    if not rows then return end

    local removed = 0
    for _, row in ipairs(rows) do
        if not Guardian.FindItem(row.item_id) then
            sql.Query(string.format(
                "DELETE FROM guardian_owned_items WHERE steamid = %s AND item_id = %s",
                sql.SQLStr(row.steamid), sql.SQLStr(row.item_id)
            ))
            removed = removed + 1
        end
    end

    if removed > 0 then
        MsgN("[Guardian] Pruned " .. removed .. " orphaned owned_item row(s) from the database.")
    end
end

-- Defer until after all shared files have registered their items.
timer.Simple(0, function()
    sanitize_equipped_db()
    sanitize_owned_db()
end)

-- ============================================================
--  Tick helpers
-- ============================================================
function Guardian.GetTicks(ply)
    if not IsValid(ply) then return 0 end
    return ply:GetNWInt("GuardianTicks", 0)
end

function Guardian.SetTicks(ply, amount)
    if not IsValid(ply) then return end
    amount = math.max(0, math.floor(amount))
    ply:SetNWInt("GuardianTicks", amount)
    sql.Query(string.format(
        "INSERT OR REPLACE INTO guardian_ticks (steamid, ticks) VALUES (%s, %d)",
        sql.SQLStr(ply:SteamID()), amount
    ))
end

function Guardian.AddTicks(ply, amount)
    Guardian.SetTicks(ply, Guardian.GetTicks(ply) + amount)
end

local function load_ticks(ply)
    local res = sql.Query(
        "SELECT ticks FROM guardian_ticks WHERE steamid = " .. sql.SQLStr(ply:SteamID())
    )
    ply:SetNWInt("GuardianTicks", (res and res[1]) and tonumber(res[1].ticks) or 0)
end

-- ============================================================
--  Ownership helpers
-- ============================================================
function Guardian.IsOwned(ply, item_id)
    local res = sql.Query(string.format(
        "SELECT 1 FROM guardian_owned_items WHERE steamid = %s AND item_id = %s",
        sql.SQLStr(ply:SteamID()), sql.SQLStr(item_id)
    ))
    return res ~= nil and #res > 0
end

function Guardian.GetOwned(ply)
    local res = sql.Query(
        "SELECT item_id FROM guardian_owned_items WHERE steamid = " .. sql.SQLStr(ply:SteamID())
    )
    local owned = {}
    if res then
        for _, row in ipairs(res) do
            owned[row.item_id] = true
        end
    end
    return owned
end

function Guardian.GiveItem(ply, item_id)
    sql.Query(string.format(
        "INSERT OR IGNORE INTO guardian_owned_items (steamid, item_id) VALUES (%s, %s)",
        sql.SQLStr(ply:SteamID()), sql.SQLStr(item_id)
    ))
end

-- ============================================================
--  Equip key helper
--  Skins get a per-weapon-class DB slot ("skins:weapon_pistol")
--  so each weapon carries an independent skin simultaneously.
--  Every other category keeps its plain id as the slot key.
-- ============================================================
local function equip_key(item)
    if item.category == "skins" and item.data and item.data.weapon then
        return "skins:" .. item.data.weapon
    end
    return item.category
end

-- ============================================================
--  Equip helpers
-- ============================================================
function Guardian.GetEquipped(ply)
    local res = sql.Query(
        "SELECT category, item_id FROM guardian_equipped WHERE steamid = " .. sql.SQLStr(ply:SteamID())
    )
    local equipped = {}
    if res then
        for _, row in ipairs(res) do
            local item = Guardian.FindItem(row.item_id)
            -- Accept rows only where the stored key matches equip_key(item).
            -- This correctly handles plain categories and "skins:<weapon_class>".
            if item and equip_key(item) == row.category then
                equipped[row.category] = row.item_id
            end
        end
    end
    return equipped
end

function Guardian.SetEquipped(ply, category, item_id)
    local sid = sql.SQLStr(ply:SteamID())
    local cat = sql.SQLStr(category)
    if item_id == nil or item_id == "" then
        sql.Query("DELETE FROM guardian_equipped WHERE steamid = " .. sid .. " AND category = " .. cat)
    else
        sql.Query(string.format(
            "INSERT OR REPLACE INTO guardian_equipped (steamid, category, item_id) VALUES (%s, %s, %s)",
            sid, cat, sql.SQLStr(item_id)
        ))
    end
end

-- ============================================================
--  Cosmetic application
-- ============================================================
local function make_cr(r, g, b)
    return tostring(r) .. "," .. tostring(g) .. "," .. tostring(b)
end

function Guardian.ApplyCosmetics(ply)
    if not IsValid(ply) then return end
    local equipped = Guardian.GetEquipped(ply)
    local owned    = Guardian.GetOwned(ply)

    -- ── Chat tag ────────────────────────────────────────────
    local tag_item = equipped["tags"] and Guardian.FindItem(equipped["tags"])
    if tag_item then
        ply:SetNWString("G_Tag",   tag_item.data.text)
        ply:SetNWString("G_TagCR", make_cr(tag_item.data.r, tag_item.data.g, tag_item.data.b))
    else
        ply:SetNWString("G_Tag",   "")
        ply:SetNWString("G_TagCR", "")
    end

    -- ── Name color ──────────────────────────────────────────
    local col_item = equipped["colors"] and Guardian.FindItem(equipped["colors"])
    ply:SetNWString("G_NameCR", col_item
        and make_cr(col_item.data.r, col_item.data.g, col_item.data.b)
        or  "")

    -- ── Emoji ───────────────────────────────────────────────
    local emo_item = equipped["emojis"] and Guardian.FindItem(equipped["emojis"])
    ply:SetNWString("G_Emoji", emo_item and emo_item.data.text or "")

    -- ── Player model ────────────────────────────────────────
    local mdl_item = equipped["models"] and Guardian.FindItem(equipped["models"])
    if mdl_item then
        ply:SetModel(mdl_item.data.model)
    end

    -- ── Prop bonus ──────────────────────────────────────────
    local prop_bonus = 0
    for item_id in pairs(owned) do
        local it = Guardian.FindItem(item_id)
        if it and it.category == "props" and it.data and it.data.bonus then
            prop_bonus = prop_bonus + it.data.bonus
        end
    end
    ply:SetNWInt("G_PropBonus", prop_bonus)

    -- ── Unlocked tools ──────────────────────────────────────
    local tool_list = {}
    for item_id in pairs(owned) do
        local it = Guardian.FindItem(item_id)
        if it and it.category == "tools" and it.data and it.data.tool then
            table.insert(tool_list, it.data.tool)
        end
    end
    ply:SetNWString("G_Tools", table.concat(tool_list, ","))
end

-- ============================================================
--  Net: shop data request
-- ============================================================
net.Receive("Guardian.OpenShop", function(_, ply)
    local owned    = Guardian.GetOwned(ply)
    local equipped = Guardian.GetEquipped(ply)
    net.Start("Guardian.ShopData")
        net.WriteTable(owned)
        net.WriteTable(equipped)
        net.WriteInt(Guardian.GetTicks(ply), 32)
    net.Send(ply)
end)

-- ============================================================
--  Net: buy item
-- ============================================================
net.Receive("Guardian.BuyItem", function(_, ply)
    local item_id = net.ReadString()
    local item    = Guardian.FindItem(item_id)

    local function fail(reason)
        net.Start("Guardian.BuyResult")
            net.WriteBool(false)
            net.WriteString(reason)
        net.Send(ply)
    end

    if not item                          then return fail("Unknown item.")            end
    if Guardian.IsOwned(ply, item_id)   then return fail("You already own this.")    end

    local ticks = Guardian.GetTicks(ply)
    if ticks < item.price then
        return fail("Need " .. item.price .. " ticks; you have " .. ticks .. ".")
    end

    Guardian.SetTicks(ply, ticks - item.price)
    Guardian.GiveItem(ply, item_id)
    Guardian.ApplyCosmetics(ply)

    net.Start("Guardian.BuyResult")
        net.WriteBool(true)
        net.WriteString(item.name)
    net.Send(ply)

    -- Push refreshed shop data so the client grid updates immediately.
    local owned    = Guardian.GetOwned(ply)
    local equipped = Guardian.GetEquipped(ply)
    net.Start("Guardian.ShopData")
        net.WriteTable(owned)
        net.WriteTable(equipped)
        net.WriteInt(Guardian.GetTicks(ply), 32)
    net.Send(ply)
end)

-- ============================================================
--  Net: equip / unequip item
--  The client sends the full slot key (equip_key result), not just
--  the category string, so skin slots like "skins:weapon_pistol"
--  are independent from one another in the DB.
-- ============================================================
net.Receive("Guardian.EquipItem", function(_, ply)
    local item_id = net.ReadString()
    local key     = net.ReadString()   -- e.g. "tags", "skins:weapon_pistol"

    if item_id == "" then
        -- Unequip: key pinpoints exactly which slot to clear.
        Guardian.SetEquipped(ply, key, nil)
    else
        local item = Guardian.FindItem(item_id)
        if not item                           then return end
        -- Validate the key matches the canonical slot for this item.
        if equip_key(item) ~= key             then return end
        if not Guardian.IsOwned(ply, item_id) then return end
        Guardian.SetEquipped(ply, key, item_id)
    end

    Guardian.ApplyCosmetics(ply)

    net.Start("Guardian.EquipResult")
        net.WriteBool(true)
        net.WriteString(item_id)
        net.WriteString(key)
    net.Send(ply)
end)

-- ============================================================
--  Hooks
-- ============================================================

hook.Add("PlayerInitialSpawn", "Guardian.Shop.Init", function(ply)
    timer.Simple(1, function()
        if not IsValid(ply) then return end
        load_ticks(ply)
        timer.Simple(0.5, function()
            if not IsValid(ply) then return end
            Guardian.ApplyCosmetics(ply)
        end)
    end)
end)

hook.Add("PlayerInitialSpawn", "Guardian.Shop.JoinMsg", function(ply)
    timer.Simple(3, function()
        if not IsValid(ply) then return end
        local equipped = Guardian.GetEquipped(ply)
        local msg_item = equipped["joinmsg"] and Guardian.FindItem(equipped["joinmsg"])
        if not msg_item then return end
        local text = msg_item.data.msg:gsub("{name}", ply:Nick())
        PrintMessage(HUD_PRINTTALK, "[*] " .. text)
    end)
end)

hook.Add("PlayerSpawn", "Guardian.Shop.ModelRestore", function(ply)
    timer.Simple(0, function()
        if not IsValid(ply) then return end
        local equipped = Guardian.GetEquipped(ply)
        local mdl_item = equipped["models"] and Guardian.FindItem(equipped["models"])
        if mdl_item then ply:SetModel(mdl_item.data.model) end
    end)
end)

-- ── Coloured chat with tag + emoji + name color ──────────────
hook.Add("PlayerSay", "Guardian.Shop.ChatTag", function(ply, text)
    -- Let command-prefixed messages fall through untouched so that
    -- client-side hooks like OnPlayerChat(!shop) still receive them.
    if text:sub(1, 1) == "!" or text:sub(1, 1) == "/" then return end

    local tag = ply:GetNWString("G_Tag",    "")
    local tcr = ply:GetNWString("G_TagCR",  "")
    local emo = ply:GetNWString("G_Emoji",  "")
    local ncr = ply:GetNWString("G_NameCR", "")

    if tag == "" and emo == "" and ncr == "" then return end

    local function parse(s, dr, dg, db)
        local r, g, b = s:match("(%d+),(%d+),(%d+)")
        return Color(tonumber(r) or dr, tonumber(g) or dg, tonumber(b) or db)
    end

    local parts = {}
    if tag ~= "" then
        local tc = parse(tcr, 255, 255, 255)
        table.insert(parts, { r = tc.r, g = tc.g, b = tc.b })
        table.insert(parts, tag .. " ")
    end
    if emo ~= "" then
        table.insert(parts, { r = 255, g = 255, b = 255 })
        table.insert(parts, emo .. " ")
    end
    local nc = (ncr ~= "") and parse(ncr, 220, 220, 232) or Color(220, 220, 232)
    table.insert(parts, { r = nc.r, g = nc.g, b = nc.b })
    table.insert(parts, ply:Nick())
    table.insert(parts, { r = 220, g = 220, b = 232 })
    table.insert(parts, ": " .. text)

    net.Start("Guardian.ChatMsg")
        net.WriteEntity(ply)
        net.WriteTable(parts)
    net.Broadcast()

    return ""
end)

-- ── Prop limit enforcement ───────────────────────────────────
hook.Add("PlayerSpawnedProp", "Guardian.Shop.PropLimit", function(ply, _, ent)
    local base  = GetConVarNumber("sbox_maxprops")
    local bonus = ply:GetNWInt("G_PropBonus", 0)
    local limit = base + bonus

    local count = 0
    for _, e in ipairs(ents.GetAll()) do
        if IsValid(e) and e:GetOwner() == ply then
            count = count + 1
        end
    end

    if count > limit then
        if IsValid(ent) then ent:Remove() end
        ply:PrintMessage(HUD_PRINTTALK,
            "[Guardian] Prop limit reached (" .. limit .. " max, " .. bonus .. " bonus).")
    end
end)

-- ── Weapon skin: apply on weapon give / spawn ────────────────
--  Standard HL2 weapon models have only skin group 0, so SetSkin()
--  has no visual effect on them. The system instead replaces the
--  weapon's world model and, when the weapon is active, the view
--  model entity. Supply custom model paths in the skin item data.
--
--  data fields used:
--    weapon      (string) – entity class to match, e.g. "weapon_pistol"
--    world_model (string) – replacement world model path
--    view_model  (string) – replacement view model path
--    label       (string) – display name shown in the shop card
local function apply_weapon_skin(ply, wep)
    if not IsValid(ply) or not IsValid(wep) then return end
    local equipped = Guardian.GetEquipped(ply)
    local key      = "skins:" .. wep:GetClass()
    local item_id  = equipped[key]
    if not item_id then return end
    local it = Guardian.FindItem(item_id)
    if not it or it.category ~= "skins" then return end

    timer.Simple(0, function()
        if not IsValid(wep) then return end

        -- World model (visible to other players).
        local wm = it.data.world_model
        if wm and wm ~= "" then
            wep:SetModel(wm)
        end

        -- View model (first-person, only for the owning player).
        local vm_path = it.data.view_model
        if vm_path and vm_path ~= "" and IsValid(ply) then
            local vm = ply:GetViewModel()
            if IsValid(vm) and ply:GetActiveWeapon() == wep then
                vm:SetModel(vm_path)
            end
        end
    end)
end

-- PlayerSpawnedSWEP: (Player ply, string classname, Weapon wep)
hook.Add("PlayerSpawnedSWEP", "Guardian.Shop.SkinSpawn", function(ply, _, wep)
    apply_weapon_skin(ply, wep)
end)

-- PlayerGivenWeapon: (Player ply, Weapon wep)
hook.Add("PlayerGivenWeapon", "Guardian.Shop.SkinPickup", function(ply, wep)
    apply_weapon_skin(ply, wep)
end)

-- Re-apply view model when the player switches to a skinned weapon.
hook.Add("WeaponEquipped", "Guardian.Shop.SkinViewmodel", function(wep, ply)
    if not IsValid(ply) or not IsValid(wep) then return end
    local equipped = Guardian.GetEquipped(ply)
    local key      = "skins:" .. wep:GetClass()
    local item_id  = equipped[key]
    if not item_id then return end
    local it = Guardian.FindItem(item_id)
    if not it or not it.data.view_model or it.data.view_model == "" then return end

    timer.Simple(0.05, function()   -- small delay lets the engine set up the VM first
        if not IsValid(ply) or not IsValid(wep) then return end
        if ply:GetActiveWeapon() ~= wep then return end
        local vm = ply:GetViewModel()
        if IsValid(vm) then vm:SetModel(it.data.view_model) end
    end)
end)

-- ── Tool permission gate ──────────────────────────────────────
local BASE_TOOLS = {
    physgun = true, physcannon = true, paint = true,
    remover = true, camera = true, colour = true,
    material = true, faceposer = true, resizer = true,
}

hook.Add("CanTool", "Guardian.Shop.ToolGate", function(ply, _, tool_mode)
    if ply:IsAdmin() then return end
    if BASE_TOOLS[tool_mode] then return end

    local tools_str = ply:GetNWString("G_Tools", "")
    for _, t in ipairs(string.Explode(",", tools_str)) do
        if t == tool_mode then return end
    end

    return false
end)