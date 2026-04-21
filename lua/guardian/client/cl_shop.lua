-- ============================================================
--  guardian_shop_cl.lua  –  Guardian Shop  (client)
--  Shop VGUI · coloured chat · scoreboard patch notes
--  Requires guardian_shop_sh.lua and guardian_cl_ui.lua first.
-- ============================================================

if SERVER then return end

Guardian = Guardian or {}

-- ============================================================
--  Palette  (mirrors guardian_cl_ui.lua)
-- ============================================================
local C = {
    bg       = Color(14,  14,  18),
    surface  = Color(24,  24,  30),
    elevated = Color(32,  32,  40),
    border   = Color(46,  46,  60),
    accent   = Color(80,  160, 255),
    gold     = Color(255, 195, 50),
    fg       = Color(220, 220, 232),
    sub      = Color(155, 155, 178),
    ok       = Color(65,  195, 100),
    warn     = Color(255, 185, 35),
    err      = Color(240, 70,  70),
}

local function A(col, alpha)
    return Color(col.r, col.g, col.b, alpha)
end
local function Box(r, x, y, w, h, col)
    draw.RoundedBox(r, x, y, w, h, col)
end
local function Rect(x, y, w, h, col)
    surface.SetDrawColor(col)
    surface.DrawRect(x, y, w, h)
end
local function Txt(str, font, x, y, col, ax, ay)
    draw.SimpleText(str, font, x, y, col,
        ax or TEXT_ALIGN_LEFT,
        ay or TEXT_ALIGN_TOP)
end

-- ============================================================
--  Category accent colours
-- ============================================================
local CAT_COLOR = {
    tags    = Color(220, 60,  60),
    colors  = Color(80,  160, 255),
    emojis  = Color(255, 195, 50),
    tools   = Color(65,  195, 100),
    props   = Color(160, 80,  240),
    models  = Color(255, 140, 40),
    skins   = Color(50,  210, 220),
    joinmsg = Color(255, 80,  180),
}

-- ============================================================
--  Local shop state  (synced from server on open)
-- ============================================================
local sh_owned    = {}
local sh_equipped = {}
local sh_ticks    = 0

local active_cat  = "tags"

-- ============================================================
--  NWString colour parser  "r,g,b" → Color
-- ============================================================
local function parse_cr(s, dr, dg, db)
    if not s or s == "" then return Color(dr or 220, dg or 220, db or 232) end
    local r, g, b = s:match("(%d+),(%d+),(%d+)")
    return Color(tonumber(r) or dr, tonumber(g) or dg, tonumber(b) or db)
end

-- ============================================================
--  Equip key helper  (mirrors guardian_shop_sv.lua)
--  Returns the sh_equipped table key for a given item.
-- ============================================================
local function equip_key(item)
    if item.category == "skins" and item.data and item.data.weapon then
        return "skins:" .. item.data.weapon
    end
    return item.category
end

-- ============================================================
--  Header layout constants
--  Defined once so Init, Paint, and PerformLayout stay in sync.
-- ============================================================
local HDR_CLOSE_W  = 34
local HDR_CLOSE_X  = -42   -- offset from right edge  (negative = from right)
local HDR_INV_W    = 94
local HDR_INV_X    = -144  -- leaves a 6px gap from the close button's left edge
-- Ticks label: right-aligned so it never collides with the inv button.
-- The right edge of the ticks text sits 10px left of the inv button's left edge.
local HDR_TICKS_RX = -154  -- right-align anchor, offset from right edge

-- ============================================================
--  GuardianShop VGUI frame
-- ============================================================
local SHOP = {}

-- ── Init ─────────────────────────────────────────────────────
function SHOP:Init()
    local W = math.min(900, ScrW() * 0.88)
    local H = math.min(590, ScrH() * 0.86)
    self:SetSize(W, H)
    self:Center()
    self:SetTitle("")
    self:SetDraggable(false)
    self:ShowCloseButton(false)
    self:SetBackgroundBlur(true)
    self:MakePopup()
    self:SetKeyBoardInputEnabled(false)

    self.sel_item = nil
    self.inv_mode = false

    -- ── Header ──────────────────────────────────────────────
    local hdr = vgui.Create("DPanel", self)
    hdr:SetTall(50)
    hdr:Dock(TOP)
    hdr.Paint = function(_, hw, hh)
        Box(0, 0, 0, hw, hh, C.surface)
        Rect(0, hh - 1, hw, 1, C.border)
        Txt("GUARDIAN SHOP", "G.Title", 14, 14, C.fg)

        -- FIX: right-align ticks so it can never collide with the inv button
        -- regardless of tick digit count or panel width.
        Txt(tostring(sh_ticks) .. "  TICKS", "G.Bold",
            hw + HDR_TICKS_RX, 17, C.gold,
            TEXT_ALIGN_RIGHT, TEXT_ALIGN_TOP)
    end
    self.hdr = hdr

    -- Close button
    local close = vgui.Create("DButton", hdr)
    close:SetText("X")
    close:SetFont("G.Bold")
    close:SetTextColor(C.sub)
    close:SetSize(HDR_CLOSE_W, 34)
    close:SetPos(W + HDR_CLOSE_X, 8)
    close.Paint = function(s, bw, bh)
        Box(4, 0, 0, bw, bh, s:IsHovered() and A(C.err, 80) or Color(0, 0, 0, 0))
    end
    close.DoClick = function() self:Remove() end
    self.close_btn = close

    -- Inventory toggle
    local inv = vgui.Create("DButton", hdr)
    inv:SetFont("G.Sm")
    inv:SetText("MY ITEMS")
    inv:SetTextColor(C.fg)
    inv:SetSize(HDR_INV_W, 28)
    inv:SetPos(W + HDR_INV_X, 11)
    inv.Paint = function(s, bw, bh)
        Box(4, 0, 0, bw, bh,
            self.inv_mode and C.accent
            or (s:IsHovered() and C.elevated or C.surface))
    end
    inv.DoClick = function()
        self.inv_mode = not self.inv_mode
        self.sel_item = nil
        self:Rebuild()
        self:RefreshDetail()
    end
    self.inv_btn = inv

    -- ── Body (sidebar + content) ─────────────────────────────
    local body = vgui.Create("DPanel", self)
    body:Dock(FILL)
    body.Paint = function() end

    -- ── Sidebar ─────────────────────────────────────────────
    local sidebar = vgui.Create("DPanel", body)
    sidebar:SetWide(158)
    sidebar:Dock(LEFT)
    sidebar.Paint = function(_, sw, sh)
        Rect(0, 0, sw, sh, C.surface)
        Rect(sw - 1, 0, 1, sh, C.border)
    end

    for _, cat in ipairs(Guardian.ShopCategories) do
        local cid = cat.id
        local btn = vgui.Create("DButton", sidebar)
        btn:SetText("")
        btn:SetTall(38)
        btn:Dock(TOP)
        btn.Paint = function(s, bw, bh)
            local act  = active_cat == cid
            local aclr = CAT_COLOR[cid] or C.accent
            if act   then Box(0, 0, 0, bw, bh, A(aclr, 22)) end
            if s:IsHovered() and not act then
                Box(0, 0, 0, bw, bh, A(C.elevated, 160))
            end
            if act then Rect(0, 0, 3, bh, aclr) end
            Txt(cat.label, "G.Body", 14, math.floor((bh - 15) * 0.5),
                act and C.fg or C.sub)

            local n = 0
            for _, it in ipairs(Guardian.ShopItems) do
                if it.category == cid and sh_owned[it.id] then n = n + 1 end
            end
            if n > 0 then
                local badge = tostring(n)
                surface.SetFont("G.Sm")
                local bw2 = surface.GetTextSize(badge) + 10
                Box(8, bw - bw2 - 6, math.floor((bh - 16) * 0.5), bw2, 16, A(C.ok, 120))
                Txt(badge, "G.Sm",
                    bw - 6 - math.floor(bw2 * 0.5), math.floor((bh - 16) * 0.5) + 2,
                    C.fg, TEXT_ALIGN_CENTER)
            end
        end
        btn.DoClick = function()
            active_cat    = cid
            self.sel_item = nil
            self:Rebuild()
            self:RefreshDetail()
        end
    end

    -- ── Content area ─────────────────────────────────────────
    local content = vgui.Create("DPanel", body)
    content:Dock(FILL)
    content.Paint = function() end
    self.content  = content

    local det = vgui.Create("DPanel", content)
    det:SetTall(114)
    det:Dock(BOTTOM)
    det:DockMargin(8, 0, 8, 8)
    det.Paint = function(_, dw, dh)
        Box(6, 0, 0, dw, dh, C.surface)
        Rect(0, 0, dw, 1, C.border)
        self:PaintDetail(dw, dh)
    end
    self.det = det

    local scroll = vgui.Create("DScrollPanel", content)
    scroll:Dock(FILL)
    scroll:DockMargin(8, 8, 8, 4)
    scroll.Paint = function() end
    local sb = scroll:GetVBar()
    sb:SetWide(3)
    sb.Paint         = function(_, sw, sh) Box(2, 0, 0, sw, sh, C.surface) end
    sb.btnUp.Paint   = function() end
    sb.btnDown.Paint = function() end
    sb.btnGrip.Paint = function(_, sw, sh) Box(2, 0, 0, sw, sh, C.accent) end
    self.scroll      = scroll

    self.cards = {}
    self.inner = nil

    self:Rebuild()
    self:RefreshDetail()
end

-- ── Rebuild – repopulate item grid ────────────────────────────
function SHOP:Rebuild()
    self.scroll:Clear()
    self.cards = {}
    self.inner = nil

    local items = {}
    for _, item in ipairs(Guardian.ShopItems) do
        if item.category == active_cat then
            if not self.inv_mode or sh_owned[item.id] then
                table.insert(items, item)
            end
        end
    end

    if #items == 0 then
        local empty = vgui.Create("DPanel", self.scroll)
        empty:Dock(TOP)
        empty:SetTall(80)
        empty.Paint = function(_, ew, eh)
            Txt(
                self.inv_mode
                    and "You do not own anything in this category yet."
                    or  "No items in this category.",
                "G.Body", ew * 0.5, eh * 0.5, C.sub,
                TEXT_ALIGN_CENTER, TEXT_ALIGN_CENTER
            )
        end
        return
    end

    local COLS   = 3
    local GAP    = 8
    local CARD_H = 94
    local rows   = math.ceil(#items / COLS)

    local inner = vgui.Create("DPanel", self.scroll)
    inner:Dock(TOP)
    inner:SetTall(rows * (CARD_H + GAP) + GAP)
    inner.Paint = function() end
    self.inner  = inner

    for i, item in ipairs(items) do
        local card  = vgui.Create("DPanel", inner)
        card.item   = item
        card.Paint  = function(s, cw, ch) self:PaintCard(s, cw, ch, item) end
        card.OnMousePressed = function(_, btn)
            if btn == MOUSE_LEFT then
                self.sel_item = item
                self:RefreshDetail()
            end
        end
        card:SetCursor("hand")
        self.cards[i] = { panel = card, item = item }
    end

    self:LayoutCards()
end

-- ── LayoutCards – grid positioning ───────────────────────────
function SHOP:LayoutCards()
    if not self.inner or not self.cards or #self.cards == 0 then return end

    local COLS   = 3
    local GAP    = 8
    local CARD_H = 94

    local iw = self.inner:GetWide()
    if iw <= 10 then iw = self.scroll:GetWide() end
    if iw <= 10 then iw = self:GetWide() - 160  end
    iw = math.max(iw, 300)

    local card_w = math.Clamp(
        math.floor((iw - GAP * (COLS + 1)) / COLS),
        90, 1000)

    for i, entry in ipairs(self.cards) do
        if IsValid(entry.panel) then
            local col = (i - 1) % COLS
            local row = math.floor((i - 1) / COLS)
            entry.panel:SetPos(
                GAP + col * (card_w + GAP),
                GAP + row * (CARD_H + GAP))
            entry.panel:SetSize(card_w, CARD_H)
        end
    end
end

-- ── PaintCard – individual item card ─────────────────────────
function SHOP:PaintCard(panel, w, h, item)
    local owned    = sh_owned[item.id]
    local equipped = sh_equipped[equip_key(item)] == item.id
    local selected = self.sel_item and self.sel_item.id == item.id
    local hov      = panel:IsHovered()
    local aclr     = CAT_COLOR[item.category] or C.accent

    Box(6, 0, 0, w, h,
        selected and A(aclr, 30)
        or (hov and C.elevated or A(C.surface, 220)))
    Box(6, 0, 0, w, 3, aclr)
    Rect(0, 3, w, math.max(0, h - 3), Color(0, 0, 0, 0))

    if selected then
        surface.SetDrawColor(A(aclr, 200))
        surface.DrawOutlinedRect(0, 0, w, h, 1)
    end

    local py = 14
    if item.category == "tags" and item.data then
        Txt(item.data.text, "G.Bold", 10, py,
            Color(item.data.r, item.data.g, item.data.b))

    elseif item.category == "colors" and item.data then
        local nc = Color(item.data.r, item.data.g, item.data.b)
        Box(3, 10, py, w - 20, 20, A(nc, 40))
        Rect(10, py, 3, 20, nc)
        Txt("YourName", "G.Sm", 18, py + 4, nc)

    elseif item.category == "emojis" and item.data then
        -- ASCII symbols render cleanly in any GMod font.
        Txt((item.data.text or "") .. "  YourName", "G.Bold", 10, py, C.fg)

    elseif item.category == "props" and item.data then
        Txt("+" .. item.data.bonus .. " PROPS", "G.Bold", 10, py, aclr)

    elseif item.category == "tools" and item.data then
        Txt(string.upper(item.data.tool), "G.Sm", 10, py, aclr)

    elseif item.category == "models" and item.data then
        local mn = item.data.model:match("([^/]+)%.mdl$") or item.data.model
        Txt(mn, "G.Sm", 10, py, aclr)

    elseif item.category == "skins" and item.data then
        Txt(item.data.label or "", "G.Bold", 10, py, aclr)

    elseif item.category == "joinmsg" and item.data then
        local msg = (item.data.msg or "")
        Txt(msg:len() > 26 and msg:sub(1, 25) .. "..." or msg,
            "G.Sm", 10, py, C.sub)
    end

    Txt(item.name, "G.Bold", 10, h - 38, owned and C.fg or C.sub)

    if equipped then
        Box(4, w - 76, h - 22, 68, 16, A(C.ok, 50))
        Txt("EQUIPPED", "G.Sm", w - 76 + 34, h - 22 + 8, C.ok,
            TEXT_ALIGN_CENTER, TEXT_ALIGN_CENTER)
    elseif owned then
        Box(4, w - 64, h - 22, 56, 16, A(C.accent, 35))
        Txt("OWNED", "G.Sm", w - 64 + 28, h - 22 + 8, C.accent,
            TEXT_ALIGN_CENTER, TEXT_ALIGN_CENTER)
    else
        surface.SetFont("G.Bold")
        local price_str = tostring(item.price)
        local pw        = surface.GetTextSize(price_str)
        Txt(price_str, "G.Bold", w - 10, h - 26, C.gold, TEXT_ALIGN_RIGHT)
        Txt("T", "G.Sm", w - 14 - pw, h - 23, A(C.gold, 180), TEXT_ALIGN_RIGHT)
    end

    Rect(0, h - 1, w, 1, A(C.border, 80))
end

-- ── RefreshDetail – recreate action buttons ───────────────────
function SHOP:RefreshDetail()
    for _, child in ipairs(self.det:GetChildren()) do
        if IsValid(child) then child:Remove() end
    end

    local item = self.sel_item
    if not item then return end

    local dw      = self.det:GetWide()
    local dh      = self.det:GetTall()
    local owned   = sh_owned[item.id]
    local slot    = equip_key(item)
    local eqd     = sh_equipped[slot] == item.id
    local passive = item.category == "props" or item.category == "tools"
    local aclr    = CAT_COLOR[item.category] or C.accent

    if not owned then
        local can = sh_ticks >= item.price
        local btn = vgui.Create("DButton", self.det)
        btn:SetFont("G.Bold")
        btn:SetText("BUY  -  " .. item.price .. " T")
        btn:SetTextColor(can and Color(14, 14, 18) or C.sub)
        btn:SetSize(158, 34)
        btn:SetPos(dw - 170, dh - 48)
        btn:SetEnabled(can)
        btn.Paint = function(s, bw, bh)
            Box(5, 0, 0, bw, bh,
                not can          and A(C.border, 110)
                or s:IsHovered() and A(C.gold, 230)
                or                   A(C.gold, 160))
        end
        btn.DoClick = function()
            net.Start("Guardian.BuyItem")
                net.WriteString(item.id)
            net.SendToServer()
        end

    elseif not passive then
        local btn = vgui.Create("DButton", self.det)
        btn:SetFont("G.Sm")
        btn:SetSize(116, 32)
        btn:SetPos(dw - 128, dh - 46)

        if eqd then
            btn:SetText("UNEQUIP")
            btn:SetTextColor(C.fg)
            btn.Paint = function(s, bw, bh)
                Box(5, 0, 0, bw, bh, s:IsHovered() and A(C.err, 130) or A(C.err, 65))
            end
            btn.DoClick = function()
                net.Start("Guardian.EquipItem")
                    net.WriteString("")
                    net.WriteString(slot)   -- full key, e.g. "skins:weapon_pistol"
                net.SendToServer()
            end
        else
            btn:SetText("EQUIP")
            btn:SetTextColor(C.fg)
            btn.Paint = function(s, bw, bh)
                Box(5, 0, 0, bw, bh, s:IsHovered() and A(aclr, 200) or A(aclr, 90))
            end
            btn.DoClick = function()
                net.Start("Guardian.EquipItem")
                    net.WriteString(item.id)
                    net.WriteString(slot)   -- full key
                net.SendToServer()
            end
        end
    end
end

-- ── PaintDetail – informational section of detail drawer ──────
function SHOP:PaintDetail(w, h)
    local item = self.sel_item

    if not item then
        Txt("<- Select an item from the grid.",
            "G.Body", w * 0.5, h * 0.5, C.sub,
            TEXT_ALIGN_CENTER, TEXT_ALIGN_CENTER)
        return
    end

    local aclr    = CAT_COLOR[item.category] or C.accent
    local owned   = sh_owned[item.id]
    local eqd     = sh_equipped[equip_key(item)] == item.id
    local passive = item.category == "props" or item.category == "tools"

    Rect(0, 0, 3, h, aclr)

    Txt(item.name, "G.Bold", 14, 12, C.fg)
    Txt(item.desc, "G.Body", 14, 32, C.sub)

    local sy = 68
    if owned then
        if eqd then
            Txt("[+] Equipped", "G.Sm", 14, sy, C.ok)
        elseif passive then
            Txt("[+] Active (passive bonus applied)", "G.Sm", 14, sy, A(C.ok, 200))
        else
            local cur = sh_equipped[item.category]
            if cur and cur ~= "" then
                local other = Guardian.FindItem(cur)
                Txt("Currently equipped: " .. (other and other.name or cur),
                    "G.Sm", 14, sy, C.sub)
            end
            Txt("[+] Owned", "G.Sm", 14, sy, A(C.ok, 180))
        end
    else
        local can = sh_ticks >= item.price
        Txt((can and "[+]" or "[-]") ..
            "  " .. item.price .. " TICKS required",
            "G.Sm", 14, sy,
            can and C.gold or A(C.err, 200))
    end
end

-- ── PerformLayout ─────────────────────────────────────────────
function SHOP:PerformLayout(w, _)
    if IsValid(self.close_btn) then self.close_btn:SetPos(w + HDR_CLOSE_X, 8)  end
    if IsValid(self.inv_btn)   then self.inv_btn:SetPos(w + HDR_INV_X, 11)     end
    self:LayoutCards()
end

-- ── ESC to close ──────────────────────────────────────────────
function SHOP:OnKeyCodePressed(key)
    if key == KEY_ESCAPE then self:Remove() end
end

-- ── Background ────────────────────────────────────────────────
function SHOP:Paint(w, h)
    Box(8, 0, 0, w, h, C.bg)
end

vgui.Register("GuardianShop", SHOP, "DFrame")

-- ============================================================
--  Open helper
-- ============================================================
function Guardian.OpenShop()
    if IsValid(Guardian.ShopFrame) then Guardian.ShopFrame:Remove() end
    Guardian.ShopFrame = vgui.Create("GuardianShop")
    net.Start("Guardian.OpenShop")
    net.SendToServer()
end

-- ============================================================
--  Net receivers
-- ============================================================

net.Receive("Guardian.ShopData", function()
    sh_owned    = net.ReadTable()
    sh_equipped = net.ReadTable()
    sh_ticks    = net.ReadInt(32)

    if IsValid(Guardian.ShopFrame) then
        Guardian.ShopFrame:Rebuild()
        Guardian.ShopFrame:RefreshDetail()
    end
end)

net.Receive("Guardian.BuyResult", function()
    local ok  = net.ReadBool()
    local msg = net.ReadString()
    if ok then
        chat.AddText(C.ok, "[+] Purchased: " .. msg)
    else
        chat.AddText(C.err, "[-] " .. msg)
    end
end)

net.Receive("Guardian.EquipResult", function()
    local ok       = net.ReadBool()
    local item_id  = net.ReadString()
    local category = net.ReadString()
    if not ok then return end

    if item_id == "" then
        sh_equipped[category] = nil
    else
        sh_equipped[category] = item_id
    end

    if IsValid(Guardian.ShopFrame) then
        Guardian.ShopFrame:RefreshDetail()
    end
end)

net.Receive("Guardian.ChatMsg", function()
    local ply   = net.ReadEntity()
    local parts = net.ReadTable()
    if not IsValid(ply) then return end

    local out = {}
    for _, v in ipairs(parts) do
        if type(v) == "table" then
            table.insert(out, Color(v.r or 255, v.g or 255, v.b or 255))
        elseif type(v) == "string" then
            table.insert(out, v)
        end
    end
    chat.AddText(unpack(out))
end)

-- ============================================================
--  Chat command  (!shop  or  /shop)
-- ============================================================
hook.Add("OnPlayerChat", "Guardian.Shop.ChatCommand", function(ply, text)
    if ply ~= LocalPlayer() then return end
    local cmd = text:lower():match("^[!/](%a+)")
    if cmd == "shop" then
        timer.Simple(0, Guardian.OpenShop)
        return true
    end
end)

-- ============================================================
--  Scoreboard cosmetic patch
-- ============================================================
--  The GuardianPlayerPanel registered in guardian_cl_ui.lua draws
--  the player name with a plain Txt call. To show tags, emojis, and
--  coloured names in the scoreboard, replace that single Txt line
--  with the block below inside PLAYERPANEL:Paint :
--
--  ── REPLACE THIS LINE in PLAYERPANEL:Paint ─────────────────
--      Txt(ply:Nick(), "G.Bold", 52, math.floor((h - 15) * 0.5), C.fg)
--
--  ── WITH THIS BLOCK ─────────────────────────────────────────
--[[
    local g_tag  = ply:GetNWString("G_Tag",    "")
    local g_tcr  = ply:GetNWString("G_TagCR",  "")
    local g_ncr  = ply:GetNWString("G_NameCR", "")
    local g_emo  = ply:GetNWString("G_Emoji",  "")

    local name_col = (g_ncr ~= "") and parse_cr(g_ncr, 220, 220, 232) or C.fg
    local cx       = 52
    local cy       = math.floor((h - 15) * 0.5)

    if g_tag ~= "" then
        local tc = parse_cr(g_tcr, 255, 255, 255)
        surface.SetFont("G.Bold")
        local tw = surface.GetTextSize(g_tag .. " ")
        Txt(g_tag .. " ", "G.Bold", cx, cy, tc)
        cx = cx + tw
    end
    if g_emo ~= "" then
        surface.SetFont("G.Bold")
        local ew = surface.GetTextSize(g_emo .. " ")
        Txt(g_emo .. " ", "G.Bold", cx, cy, C.fg)
        cx = cx + ew
    end
    Txt(ply:Nick(), "G.Bold", cx, cy, name_col)
--]]