-- ============================================================
--  guardian_cl_ui.lua  –  Guardian client-side UI
--  Scoreboard · Friend List · Check Menu · HUD
-- ============================================================

Guardian = Guardian or {}

-- ============================================================
--  Fonts
-- ============================================================
surface.CreateFont("G.Sm",    { font = "Tahoma", size = 13, weight = 500 })
surface.CreateFont("G.Body",  { font = "Tahoma", size = 15, weight = 400 })
surface.CreateFont("G.Bold",  { font = "Tahoma", size = 15, weight = 700 })
surface.CreateFont("G.Title", { font = "Tahoma", size = 19, weight = 700 })
surface.CreateFont("G.Num",   { font = "Tahoma", size = 34, weight = 700 })
surface.CreateFont("G.NumSm", { font = "Tahoma", size = 22, weight = 700 })

-- ============================================================
--  Palette
-- ============================================================
local C = {
    bg       = Color(14,  14,  18),
    surface  = Color(24,  24,  30),
    elevated = Color(32,  32,  40),
    border   = Color(46,  46,  60),
    accent   = Color(80,  160, 255),
    gold     = Color(255, 195, 50),
    fg       = Color(220, 220, 232),   -- was 210/210/220 – brighter
    sub      = Color(155, 155, 178),   -- was 110/110/135 – much brighter, readable
    ok       = Color(65,  195, 100),
    warn      = Color(255, 185, 35),
    err      = Color(240, 70,  70),
    self_hl  = Color(80,  160, 255, 20),
}

local function A(col, alpha)
    return Color(col.r, col.g, col.b, alpha)
end

-- ============================================================
--  Draw helpers
-- ============================================================
local function Rect(x, y, w, h, col)
    surface.SetDrawColor(col)
    surface.DrawRect(x, y, w, h)
end

local function Box(r, x, y, w, h, col)
    draw.RoundedBox(r, x, y, w, h, col)
end

local function Txt(str, font, x, y, col, ax, ay)
    draw.SimpleText(str, font, x, y, col,
        ax or TEXT_ALIGN_LEFT,
        ay or TEXT_ALIGN_TOP)
end

-- Draws a progress bar with a rounded bg track and filled portion
local function Bar(x, y, w, h, frac, fill, bg)
    local r  = math.floor(h / 2)
    Box(r, x, y, w, h, bg)
    local fw = math.floor(math.Clamp(frac, 0, 1) * w)
    if fw >= 2 then
        Box(r, x, y, fw, h, fill)
    end
end

-- Draws a stat card (health / armor / etc.)
local function StatCard(x, y, w, h, value, label, frac, col)
    Box(6, x, y, w, h, A(C.bg, 210))
    Rect(x, y, 2, h, A(col, 180))
    Txt(tostring(value), "G.Num",  x + 12, y + 6,      col)
    Txt(label,           "G.Sm",   x + 14, y + h - 24, C.sub)
    Bar(x + 12, y + h - 13, w - 24, 5, frac, col, A(C.border, 140))
end

-- ============================================================
--  Forward declarations
-- ============================================================
local OpenFriendMenu
local OpenScoreboard

-- ============================================================
--  Per-player voice volume  (userid → 0-100)
--  Scroll wheel on a hovered player row adjusts that player only.
-- ============================================================
Guardian.PlayerVolume = Guardian.PlayerVolume or {}

local function get_player_volume(ply)
    if not IsValid(ply) then return 100 end
    local uid = ply:UserID()
    if Guardian.PlayerVolume[uid] == nil then
        Guardian.PlayerVolume[uid] = 100
    end
    return Guardian.PlayerVolume[uid]
end

local function set_player_volume(ply, pct)
    if not IsValid(ply) then return end
    local uid = ply:UserID()
    Guardian.PlayerVolume[uid] = math.Clamp(pct, 0, 100)
    -- SetVoiceVolumeScale is the correct per-player GMod API (0.0 – 1.0)
    ply:SetVoiceVolumeScale(Guardian.PlayerVolume[uid] / 100)
end

-- ============================================================
--  Column layout constants (scoreboard)
--  Right-to-left: VOL-SLIDER | PING | TICKS | DEATHS | KILLS
-- ============================================================
local COL = {
    edge_pad = 12,   -- right margin before vol slider
    vol_w    = 108,  -- voice volume slider column width
    ping_w   = 52,
    ticks_w  = 64,
    deaths_w = 60,
    kills_w  = 52,
    col_gap  = 24,   -- gap between every pair of stat columns
}

-- Returns the left edge x of the voice slider area
local function vol_left(w)
    return w - COL.edge_pad - COL.vol_w
end

-- Pre-compute right-edge x positions (from panel right, TEXT_ALIGN_RIGHT)
local function col_x(w, col_name)
    local rx = w - COL.edge_pad - COL.vol_w - COL.col_gap
    if col_name == "ping"   then return rx end
    rx = rx - COL.ping_w - COL.col_gap
    if col_name == "ticks"  then return rx end
    rx = rx - COL.ticks_w - COL.col_gap
    if col_name == "deaths" then return rx end
    rx = rx - COL.deaths_w - COL.col_gap
    if col_name == "kills"  then return rx end
    return rx
end

-- ============================================================
--  GuardianPlayerPanel
-- ============================================================
local PLAYERPANEL = {}

function PLAYERPANEL:Init()
    self:SetTall(52)
end

function PLAYERPANEL:SetPlayer(ply)
    self.ply = ply

    self.avatar = vgui.Create("AvatarImage", self)
    self.avatar:SetSize(36, 36)
    self.avatar:SetPos(8, 8)
    self.avatar:SetPlayer(ply, 64)
end

-- No separate mute button – volume slider in the row replaces it.
-- Scroll wheel on the row adjusts this player's volume by ±10.
function PLAYERPANEL:OnMouseWheeled(delta)
    local ply = self.ply
    if not IsValid(ply) or ply == LocalPlayer() then return end
    set_player_volume(ply, get_player_volume(ply) + delta * 10)
    return true
end

function PLAYERPANEL:PerformLayout(w, h) end   -- nothing to lay out

function PLAYERPANEL:Paint(w, h)
    local ply     = self.ply
    local is_self = IsValid(ply) and ply == LocalPlayer()

    -- Row background
    Box(4, 0, 0, w, h, is_self and C.self_hl or C.elevated)
    if is_self then Rect(0, 0, 3, h, C.accent) end
    -- Bottom separator
    Rect(0, h - 1, w, 1, C.border)

    if not IsValid(ply) then return end

    -- Name (vertically centred)
    Txt(ply:Nick(), "G.Bold", 52, math.floor((h - 15) * 0.5), C.fg)

    -- ── Kills (centred in slot) ──
    local kx = col_x(w, "kills") - math.floor(COL.kills_w * 0.5)
    Txt(tostring(ply:Frags()),  "G.Bold", kx, math.floor((h - 15) * 0.5), C.fg, TEXT_ALIGN_CENTER)

    -- ── Deaths (centred in slot) ──
    local dx = col_x(w, "deaths") - math.floor(COL.deaths_w * 0.5)
    Txt(tostring(ply:Deaths()), "G.Bold", dx, math.floor((h - 15) * 0.5), C.fg, TEXT_ALIGN_CENTER)

    -- ── Ticks ──
    local ticks = ply:GetNWInt("GuardianTicks", 0)
    local tx    = col_x(w, "ticks")
    Txt(tostring(ticks), "G.Bold", tx, 13, C.gold,         TEXT_ALIGN_RIGHT)
    Txt("TICKS",         "G.Sm",   tx, 31, A(C.gold, 180), TEXT_ALIGN_RIGHT)

    -- ── Ping ──
    local ping     = ply:Ping()
    local ping_col = ping < 80 and C.ok or (ping < 150 and C.warn or C.err)
    local px       = col_x(w, "ping")
    Txt(ping .. " ms", "G.Bold", px, 13, ping_col, TEXT_ALIGN_RIGHT)
    Txt("PING",        "G.Sm",   px, 31, C.sub,    TEXT_ALIGN_RIGHT)

    -- ── Voice volume slider ──────────────────────────────────
    local vx   = vol_left(w)
    local vy   = math.floor((h - 20) * 0.5)   -- vertically centred in row
    local vw   = COL.vol_w
    local vh   = 20

    local vol  = get_player_volume(ply)
    local frac = vol / 100
    local is_local = ply == LocalPlayer()

    -- Colour: green > 50%, yellow 20-50%, red < 20%, grey for self
    local vol_col = is_local and C.sub
                 or (vol == 0   and C.err
                 or (vol < 20   and C.err
                 or (vol < 50   and C.warn or C.ok)))

    -- Track background
    Box(3, vx, vy + 7, vw, 6, A(C.border, 160))
    -- Filled portion
    local fill_w = math.max(math.floor(frac * vw), vol > 0 and 4 or 0)
    if fill_w > 0 then
        Box(3, vx, vy + 7, fill_w, 6, A(vol_col, 200))
    end
    -- Thumb knob (hidden for local player – can't adjust self)
    if not is_local then
        local knob_x = vx + fill_w - 4
        Box(4, knob_x, vy + 4, 8, 12, vol_col)
    end

    -- Percentage label right of track
    Txt(tostring(vol) .. "%", "G.Sm",
        vx + vw + 6, vy + 3, is_local and C.sub or vol_col)
end

vgui.Register("GuardianPlayerPanel", PLAYERPANEL, "DPanel")

-- ============================================================
--  GuardianScoreboard
-- ============================================================
local SCOREBOARD = {}

function SCOREBOARD:Init()
    local w = math.min(860, ScrW() * 0.84)
    local h = math.min(660, ScrH() * 0.84)
    self:SetSize(w, h)
    self:Center()
    self:SetDraggable(false)
    self:ShowCloseButton(false)
    self:SetBackgroundBlur(true)
    self:MakePopup()
    self:SetTitle("")

    -- ── Suppress keyboard so typing still works while tab is held ──
    -- We steal focus only for the frame, but pass keyboard input through
    self:SetKeyBoardInputEnabled(false)

    -- Column header row
    self.cols = vgui.Create("DPanel", self)
    self.cols:SetTall(24)
    self.cols:Dock(TOP)
    self.cols:DockMargin(12, 50, 12, 0)
    self.cols.Paint = function(s, cw, ch)
        Rect(0, ch - 1, cw, 1, C.border)
        Txt("PLAYER",  "G.Sm", 52,                                                        5, C.sub)
        Txt("KILLS",   "G.Sm", col_x(cw, "kills")  - math.floor(COL.kills_w  * 0.5),     5, C.sub, TEXT_ALIGN_CENTER)
        Txt("DEATHS",  "G.Sm", col_x(cw, "deaths") - math.floor(COL.deaths_w * 0.5),     5, C.sub, TEXT_ALIGN_CENTER)
        Txt("TICKS",   "G.Sm", col_x(cw, "ticks"),                                        5, C.sub, TEXT_ALIGN_RIGHT)
        Txt("PING",    "G.Sm", col_x(cw, "ping"),                                         5, C.sub, TEXT_ALIGN_RIGHT)
        Txt("VOICE",   "G.Sm", vol_left(cw) + math.floor(COL.vol_w * 0.5),                5, C.sub, TEXT_ALIGN_CENTER)
    end

    -- Scroll panel
    self.scroll = vgui.Create("DScrollPanel", self)
    self.scroll:Dock(FILL)
    self.scroll:DockMargin(12, 4, 12, 8)

    -- Minimal scrollbar
    local sbar = self.scroll:GetVBar()
    sbar:SetWide(3)
    sbar.Paint         = function(s, sw, sh) Box(2, 0, 0, sw, sh, C.surface) end
    sbar.btnUp.Paint   = function() end
    sbar.btnDown.Paint = function() end
    sbar.btnGrip.Paint = function(s, sw, sh) Box(2, 0, 0, sw, sh, C.accent) end

    -- Friends button
    self.friendBtn = vgui.Create("DButton", self)
    self.friendBtn:SetFont("G.Body")
    self.friendBtn:SetTextColor(C.fg)
    self.friendBtn:SetText("Friends")
    self.friendBtn.Paint = function(s, bw, bh)
        Box(4, 0, 0, bw, bh, s:IsHovered() and C.accent or C.surface)
    end
    self.friendBtn.DoClick = function() OpenFriendMenu() end

    self:Refresh()
end

function SCOREBOARD:Paint(w, h)
    Box(8, 0, 0, w, h, C.bg)
    Box(8, 0, 0, w, 46, C.surface)
    Rect(0, 36, w, 10, C.surface)
    Rect(0, 46, w, 1, C.border)
    Txt("GUARDIAN", "G.Title", 14, 12, C.fg)
    local n = #player.GetAll()
    Txt(n .. (n == 1 and " player" or " players"), "G.Sm", 14, 31, C.sub)
end

function SCOREBOARD:PerformLayout(w, h)
    if IsValid(self.friendBtn) then
        self.friendBtn:SetPos(w - 108, 8)
        self.friendBtn:SetSize(96, 30)
    end
end

function SCOREBOARD:Refresh()
    self.scroll:Clear()

    local plys = player.GetAll()
    table.sort(plys, function(a, b) return a:Frags() > b:Frags() end)

    for _, ply in ipairs(plys) do
        local p = vgui.Create("GuardianPlayerPanel", self.scroll)
        p:SetPlayer(ply)
        p:Dock(TOP)
        p:DockMargin(0, 0, 0, 2)
    end
end

vgui.Register("GuardianScoreboard", SCOREBOARD, "DFrame")

-- ============================================================
--  GuardianCheckMenu
-- ============================================================
local CHECKMENU = {}

function CHECKMENU:Init()
    self:SetSize(760, 520)
    self:SetTitle("")
    self:Center()
    self:MakePopup()
    self:ShowCloseButton(false)

    self.close = vgui.Create("DButton", self)
    self.close:SetText("X")
    self.close:SetSize(32, 32)
    self.close:SetPos(self:GetWide() - 36, 6)

    self.close.DoClick = function()
        self:Close()
    end

    -- ── Search bar ──────────────────────────────────────────
    self.search = vgui.Create("DTextEntry", self)
    self.search:SetFont("G.Body")
    self.search:SetPlaceholderText("Search by name or SteamID…")
    self.search:SetUpdateOnType(true)
    self.search.OnChange = function()
        self:ApplyFilter(self.search:GetValue())
    end

    -- ── List ────────────────────────────────────────────────
    self.list = vgui.Create("DListView", self)
    self.list:AddColumn("SteamID"):SetFixedWidth(145)
    self.list:AddColumn("Name"):SetFixedWidth(160)
    self.list:AddColumn("Reason")
    self.list:AddColumn("Date"):SetFixedWidth(145)

    self.raw_data = {}
end

function CHECKMENU:PerformLayout(w, h)
    -- Guard: PerformLayout fires via Center() before Init() finishes
    if not IsValid(self.search) or not IsValid(self.list) then return end

    local header_h = 44
    local search_h = 30
    local pad      = 8

    self.search:SetPos(pad, header_h + pad)
    self.search:SetSize(w - pad * 2, search_h)

    self.list:SetPos(pad, header_h + pad + search_h + pad)
    self.list:SetSize(w - pad * 2, h - header_h - search_h - pad * 3)
end

function CHECKMENU:Paint(w, h)
    Box(8, 0, 0, w, h, C.bg)
    Box(8, 0, 0, w, 44, C.surface)
    Rect(0, 36, w, 8, C.surface)
    Rect(0, 44, w, 1, C.border)
    Txt("CHEATER CHECK", "G.Title", 14, 12, C.fg)
end

function CHECKMENU:SetData(data)
    self.raw_data = data
    self:ApplyFilter(IsValid(self.search) and self.search:GetValue() or "")
end

function CHECKMENU:ApplyFilter(query)
    self.list:Clear()
    query = query:lower()
    for _, row in ipairs(self.raw_data) do
        local name_match    = row.name:lower():find(query, 1, true)
        local steamid_match = row.steamid:lower():find(query, 1, true)
        if query == "" or name_match or steamid_match then
            self.list:AddLine(
                row.steamid,
                row.name,
                row.reason,
                os.date("%Y-%m-%d %H:%M", row.timestamp)
            )
        end
    end
end

vgui.Register("GuardianCheckMenu", CHECKMENU, "DFrame")

-- ============================================================
--  GuardianFriendMenu  (standalone popup, not parented to scoreboard)
-- ============================================================
local FRIENDMENU = {}

local function MakeButton(parent, text, col_hover, callback)
    local btn = vgui.Create("DButton", parent)
    btn:SetFont("G.Sm")
    btn:SetTextColor(C.fg)
    btn:SetText(text)
    btn.Paint = function(s, w, h)
        Box(4, 0, 0, w, h, s:IsHovered() and col_hover or C.surface)
    end
    btn.DoClick = callback
    return btn
end

function FRIENDMENU:Init()
    self:SetSize(460, 420)
    self:SetTitle("")
    self:Center()
    -- True standalone popup – does NOT steal focus from the scoreboard,
    -- allowing both windows to coexist cleanly.
    self:MakePopup()
    self:SetKeyBoardInputEnabled(true)  -- needs keyboard for the entry field

    self.list = vgui.Create("DListView", self)
    self.list:Dock(FILL)
    self.list:DockMargin(8, 50, 8, 54)
    self.list:AddColumn("SteamID"):SetFixedWidth(150)
    self.list:AddColumn("Name")

    -- Footer
    local footer = vgui.Create("DPanel", self)
    footer:Dock(BOTTOM)
    footer:SetTall(46)
    footer:DockMargin(8, 0, 8, 6)
    footer.Paint = function() end

    self.entry = vgui.Create("DTextEntry", footer)
    self.entry:Dock(FILL)
    self.entry:DockMargin(0, 0, 4, 0)
    self.entry:SetFont("G.Body")
    self.entry:SetPlaceholderText("SteamID or player name…")

    local remove_btn = MakeButton(footer, "Remove", A(C.err, 80), function()
        local line = self.list:GetSelectedLine()
        if not line then return end
        local row = self.list:GetLine(line)
        if not row then return end
        net.Start("Guardian.RemoveFriend")
            net.WriteString(row:GetValue(1))
        net.SendToServer()
    end)
    remove_btn:Dock(RIGHT)
    remove_btn:SetWide(80)
    remove_btn:DockMargin(0, 0, 4, 0)

    local add_btn = MakeButton(footer, "Add", C.accent, function()
        local text = self.entry:GetValue()
        if text == "" then return end
        net.Start("Guardian.AddFriend")
            net.WriteString(text)
        net.SendToServer()
        self.entry:SetText("")
    end)
    add_btn:Dock(RIGHT)
    add_btn:SetWide(70)
    add_btn:DockMargin(0, 0, 4, 0)
end

function FRIENDMENU:Paint(w, h)
    Box(8, 0, 0, w, h, C.bg)
    Box(8, 0, 0, w, 44, C.surface)
    Rect(0, 36, w, 8,  C.surface)
    Rect(0, 44, w, 1,  C.border)
    Txt("FRIENDS", "G.Title", 14, 12, C.fg)
end

function FRIENDMENU:SetData(data)
    self.list:Clear()
    for _, row in ipairs(data) do
        self.list:AddLine(row.steamid, row.name)
    end
end

vgui.Register("GuardianFriendMenu", FRIENDMENU, "DFrame")

-- ============================================================
--  Open helpers  (resolves forward declarations)
-- ============================================================
OpenFriendMenu = function()
    if IsValid(Guardian.FriendMenu) then
        Guardian.FriendMenu:Remove()
    end
    Guardian.FriendMenu = vgui.Create("GuardianFriendMenu")
    net.Start("Guardian.RequestFriendData")
    net.SendToServer()
end

OpenScoreboard = function()
    if IsValid(Guardian.Scoreboard) then Guardian.Scoreboard:Remove() end
    Guardian.Scoreboard = vgui.Create("GuardianScoreboard")
end

-- ============================================================
--  HUD – suppress default elements
-- ============================================================
local SUPPRESS = {
    CHudHealth        = true,
    CHudBattery       = true,
    CHudAmmo          = true,
    CHudSecondaryAmmo = true,
}

hook.Add("HUDShouldDraw", "Guardian.HUDSuppress", function(name)
    if SUPPRESS[name] then return false end
end)

-- ============================================================
--  HUD – custom paint
-- ============================================================
hook.Add("HUDPaint", "Guardian.HUD", function()
    local ply = LocalPlayer()
    if not IsValid(ply) or not ply:Alive() then return end

    local sw, sh   = ScrW(), ScrH()
    local card_w   = 190
    local card_h   = 68
    local pad_x    = 18
    local pad_y    = 16
    local card_gap = 8

    -- ── Health  (bottom-left, primary) ──────────────────────
    local hp     = ply:Health()
    local hp_max = math.max(ply:GetMaxHealth(), 1)
    local hp_f   = hp / hp_max
    local hp_col = hp_f > 0.5 and C.ok or (hp_f > 0.25 and C.warn or C.err)

    local hp_y = sh - pad_y - card_h
    StatCard(pad_x, hp_y, card_w, card_h, hp, "HEALTH", hp_f, hp_col)

    -- ── Armor  (stacked above health, only when > 0) ────────
    local armor = ply:Armor()
    if armor > 0 then
        local ar_y = hp_y - card_gap - card_h
        StatCard(pad_x, ar_y, card_w, card_h, armor, "ARMOR", armor / 100, C.accent)
    end

    -- ── Ammo  (bottom-right) ────────────────────────────────
    local wep = ply:GetActiveWeapon()
    if IsValid(wep) then
        local clip    = wep:Clip1()
        local reserve = ply:GetAmmoCount(wep:GetPrimaryAmmoType())

        if clip >= 0 then
            local am_w = 170
            local am_h = card_h
            local am_x = sw - pad_x - am_w
            local am_y = sh - pad_y - am_h

            Box(6, am_x, am_y, am_w, am_h, A(C.bg, 210))
            Rect(am_x + am_w - 2, am_y, 2, am_h, A(C.accent, 160))

            Txt(tostring(clip), "G.Num",
                am_x + am_w - 12, am_y + 6, C.fg, TEXT_ALIGN_RIGHT)
            Txt("/ " .. reserve, "G.Sm",
                am_x + am_w - 12, am_y + am_h - 24, C.sub, TEXT_ALIGN_RIGHT)
            Txt("AMMO", "G.Sm",
                am_x + 14, am_y + am_h - 24, C.sub)
        end
    end

end)

-- ============================================================
--  HUD – entity owner tooltip (centred at crosshair)
-- ============================================================
hook.Add("HUDPaint", "Guardian.OwnerLabel", function()
    local ply = LocalPlayer()
    local tr  = ply:GetEyeTrace()
    local ent = tr.Entity

    if not IsValid(ent) or ent:IsPlayer() or ent:IsWorld() then return end
    if ply:GetPos():DistToSqr(tr.HitPos) > 160000 then return end

    local owner = Guardian.GetOwner and Guardian.GetOwner(ent)
    if not (IsValid(owner) and owner:IsPlayer()) then return end

    local label = "Owner: " .. owner:Nick()
    local cx    = ScrW() * 0.5
    local cy    = ScrH() * 0.5 + 34

    surface.SetFont("G.Bold")
    local tw = surface.GetTextSize(label)

    Box(4, cx - tw * 0.5 - 10, cy - 5, tw + 20, 24, A(C.bg, 220))
    Txt(label, "G.Bold", cx, cy + 7, C.fg, TEXT_ALIGN_CENTER, TEXT_ALIGN_CENTER)
end)

-- ============================================================
--  Net receivers
-- ============================================================
net.Receive("Guardian.CheckMenu", function()
    local frame = vgui.Create("GuardianCheckMenu")
    frame:SetData(net.ReadTable())
end)

net.Receive("Guardian.FriendData", function()
    local data = net.ReadTable()
    if IsValid(Guardian.FriendMenu) then
        Guardian.FriendMenu:SetData(data)
    end
end)

-- ============================================================
--  Scoreboard hooks
-- ============================================================
hook.Add("ScoreboardShow", "Guardian.ScoreboardShow", function()
    OpenScoreboard()
    return false
end)

hook.Add("ScoreboardHide", "Guardian.ScoreboardHide", function()
    if IsValid(Guardian.Scoreboard) then Guardian.Scoreboard:Remove() end
    -- Friend menu stays open intentionally – player may have opened it
    -- independently. Close it too if you prefer:
    -- if IsValid(Guardian.FriendMenu) then Guardian.FriendMenu:Remove() end
    return false
end)