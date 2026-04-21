-- ============================================================
--  guardian_shop_sh.lua  –  Guardian Shop  (shared)
--  Item catalogue, category definitions, lookup helper.
--  Load order: must be included before _sv and _cl.
-- ============================================================

Guardian = Guardian or {}

-- ── Network strings (server-only registration) ───────────────
if SERVER then
    util.AddNetworkString("Guardian.OpenShop")
    util.AddNetworkString("Guardian.ShopData")
    util.AddNetworkString("Guardian.BuyItem")
    util.AddNetworkString("Guardian.BuyResult")
    util.AddNetworkString("Guardian.EquipItem")
    util.AddNetworkString("Guardian.EquipResult")
    util.AddNetworkString("Guardian.ChatMsg")
end

-- ── Category definitions (display order) ─────────────────────
Guardian.ShopCategories = {
    { id = "tags",    label = "Chat Tags"    },
    { id = "colors",  label = "Name Colors"  },
    { id = "emojis",  label = "Emojis"       },
    { id = "tools",   label = "Tools"        },
    { id = "props",   label = "Prop Limits"  },
    { id = "models",  label = "Models"       },
    { id = "skins",   label = "Weapon Skins" },
    { id = "joinmsg", label = "Join Message" },
}

-- ── Item catalogue ────────────────────────────────────────────
--  Fields
--    id        string   unique key
--    category  string   must match ShopCategories id
--    name      string   display name
--    desc      string   flavour / tooltip
--    price     number   tick cost
--    data      table    category-specific payload (see below)
--    stackable bool     (props only) can accumulate multiple purchases
--
--  data payload per category
--    tags    : text(string)  r g b(int 0-255)
--    colors  : r g b
--    emojis  : text(string)  – ASCII symbols only, no Unicode
--    tools   : tool(string)  – toolgun class name
--    props   : bonus(int)    – additional prop slots
--    models  : model(string) – model path
--    skins   : weapon(string) skin(int) label(string)
--    joinmsg : msg(string)   – {name} placeholder
-- ─────────────────────────────────────────────────────────────
Guardian.ShopItems = {

    -- ── TAGS ──────────────────────────────────────────────────
    {
        id = "tag_noob",   category = "tags",
        name = "[NOOB]",   price = 400,
        desc = "Embrace the grind. Irony included.",
        data = { text = "[NOOB]", r = 80, g = 200, b = 80 },
    },
    {
        id = "tag_afk",    category = "tags",
        name = "[AFK]",    price = 400,
        desc = "Gone fishing. Back never.",
        data = { text = "[AFK]", r = 155, g = 155, b = 178 },
    },
    {
        id = "tag_gg",     category = "tags",
        name = "[GG]",     price = 800,
        desc = "Good game. You know it.",
        data = { text = "[GG]", r = 65, g = 195, b = 100 },
    },
    {
        id = "tag_toxic",  category = "tags",
        name = "[TOXIC]",  price = 1500,
        desc = "For the chaotically inclined.",
        data = { text = "[TOXIC]", r = 255, g = 120, b = 30 },
    },
    {
        id = "tag_vip",    category = "tags",
        name = "[VIP]",    price = 2000,
        desc = "Show everyone you are part of the elite.",
        data = { text = "[VIP]", r = 255, g = 195, b = 50 },
    },
    {
        id = "tag_griefer", category = "tags",
        name = "[GRIEFER]", price = 1800,
        desc = "Chaos is the point.",
        data = { text = "[GRIEFER]", r = 255, g = 100, b = 60 },
    },
    {
        id = "tag_pro",    category = "tags",
        name = "[PRO]",    price = 3000,
        desc = "For the seasoned veteran.",
        data = { text = "[PRO]", r = 80, g = 160, b = 255 },
    },
    {
        id = "tag_tryhard", category = "tags",
        name = "[TRYHARD]", price = 2500,
        desc = "Maximum effort. Always.",
        data = { text = "[TRYHARD]", r = 255, g = 80, b = 180 },
    },
    {
        id = "tag_sigma",  category = "tags",
        name = "[SIGMA]",  price = 3500,
        desc = "Lone wolf. No rules.",
        data = { text = "[SIGMA]", r = 160, g = 80, b = 240 },
    },
    {
        id = "tag_chad",   category = "tags",
        name = "[CHAD]",   price = 4000,
        desc = "Walk tall. Walk loud.",
        data = { text = "[CHAD]", r = 50, g = 210, b = 220 },
    },
    {
        id = "tag_based",  category = "tags",
        name = "[BASED]",  price = 3200,
        desc = "Opinion delivered. Apology withheld.",
        data = { text = "[BASED]", r = 80, g = 200, b = 255 },
    },
    {
        id = "tag_lenny",  category = "tags",
        name = "( o_o )",  price = 5000,
        desc = "The face that says it all.",
        data = { text = "( o_o )", r = 240, g = 220, b = 140 },
    },
    {
        id = "tag_boss",   category = "tags",
        name = "[BOSS]",   price = 6000,
        desc = "The one in charge. Always.",
        data = { text = "[BOSS]", r = 200, g = 160, b = 30 },
    },
    {
        id = "tag_legend", category = "tags",
        name = "[LEGEND]", price = 7000,
        desc = "They will speak of you.",
        data = { text = "[LEGEND]", r = 255, g = 195, b = 50 },
    },
    {
        id = "tag_god",    category = "tags",
        name = "[GOD]",    price = 8000,
        desc = "Ascend above all mortals.",
        data = { text = "[GOD]", r = 220, g = 50, b = 50 },
    },
    {
        id = "tag_omega",  category = "tags",
        name = "[OMEGA]",  price = 10000,
        desc = "The last word. In everything.",
        data = { text = "[OMEGA]", r = 220, g = 50, b = 50 },
    },

    -- ── NAME COLORS ───────────────────────────────────────────
    {
        id = "col_red",    category = "colors",
        name = "Crimson",  price = 1000,
        desc = "Your name bleeds red.",
        data = { r = 220, g = 50,  b = 50  },
    },
    {
        id = "col_blue",   category = "colors",
        name = "Royal Blue", price = 1000,
        desc = "Noble and true.",
        data = { r = 80,  g = 140, b = 255 },
    },
    {
        id = "col_green",  category = "colors",
        name = "Emerald",  price = 1000,
        desc = "Fresh. Vibrant. Yours.",
        data = { r = 65,  g = 195, b = 100 },
    },
    {
        id = "col_orange", category = "colors",
        name = "Orange",   price = 1000,
        desc = "Bright like the sun.",
        data = { r = 255, g = 140, b = 40  },
    },
    {
        id = "col_cyan",   category = "colors",
        name = "Cyan",     price = 1000,
        desc = "Ice cold.",
        data = { r = 50,  g = 210, b = 220 },
    },
    {
        id = "col_purple", category = "colors",
        name = "Violet",   price = 1200,
        desc = "Regal and rare.",
        data = { r = 160, g = 80,  b = 240 },
    },
    {
        id = "col_pink",   category = "colors",
        name = "Hot Pink", price = 1200,
        desc = "Loud and proud.",
        data = { r = 255, g = 80,  b = 180 },
    },
    {
        id = "col_gold",   category = "colors",
        name = "Gold",     price = 1500,
        desc = "Worth every tick.",
        data = { r = 255, g = 195, b = 50  },
    },

    -- ── EMOJIS  (pure ASCII – no Unicode) ────────────────────
    {
        id = "emo_heart",     category = "emojis",
        name = "Heart  <3",   price = 600,
        desc = "Spread the love.",
        data = { text = "<3" },
    },
    {
        id = "emo_star",      category = "emojis",
        name = "Star  [*]",   price = 800,
        desc = "Shine before your name.",
        data = { text = "[*]" },
    },
    {
        id = "emo_diamond",   category = "emojis",
        name = "Diamond  <>", price = 800,
        desc = "Precious. Unmissable.",
        data = { text = "<>" },
    },
    {
        id = "emo_skull",     category = "emojis",
        name = "Skull  [X]",  price = 900,
        desc = "Death follows you.",
        data = { text = "[X]" },
    },
    {
        id = "emo_fire",      category = "emojis",
        name = "Fire  {!}",   price = 1000,
        desc = "Leave a mark wherever you go.",
        data = { text = "{!}" },
    },
    {
        id = "emo_lightning", category = "emojis",
        name = "Lightning /!/", price = 1200,
        desc = "Fast. Electric. Deadly.",
        data = { text = "/!/" },
    },
    {
        id = "emo_sword",     category = "emojis",
        name = "Swords  >|<", price = 1500,
        desc = "For the warrior at heart.",
        data = { text = ">|<" },
    },
    {
        id = "emo_crown",     category = "emojis",
        name = "Crown  (K)",  price = 2000,
        desc = "Reserved for royalty.",
        data = { text = "(K)" },
    },

    -- ── TOOLS ─────────────────────────────────────────────────
    {
        id = "tool_ballsocket", category = "tools",
        name = "Ballsocket",    price = 600,
        desc = "Pivot joints for articulated builds.",
        data = { tool = "ballsocket" },
    },
    {
        id = "tool_rope",       category = "tools",
        name = "Rope",          price = 800,
        desc = "Connect props with flexible rope.",
        data = { tool = "rope" },
    },
    {
        id = "tool_balloon",    category = "tools",
        name = "Balloon",       price = 1000,
        desc = "Lift props skyward.",
        data = { tool = "balloon" },
    },
    {
        id = "tool_weld",       category = "tools",
        name = "Weld",          price = 1000,
        desc = "Stick props together permanently.",
        data = { tool = "weld" },
    },
    {
        id = "tool_wheel",      category = "tools",
        name = "Wheel",         price = 1500,
        desc = "Build vehicles. Rule the roads.",
        data = { tool = "wheel" },
    },
    {
        id = "tool_thruster",   category = "tools",
        name = "Thruster",      price = 2000,
        desc = "Apply directional force to any prop.",
        data = { tool = "thruster" },
    },

    -- ── PROP LIMITS ───────────────────────────────────────────
    {
        id = "props_10",    category = "props",
        name = "+10 Props", price = 500,     stackable = true,
        desc = "A modest boost to your prop allowance.",
        data = { bonus = 10 },
    },
    {
        id = "props_25",    category = "props",
        name = "+25 Props", price = 1200,    stackable = true,
        desc = "Room to breathe and build.",
        data = { bonus = 25 },
    },
    {
        id = "props_50",    category = "props",
        name = "+50 Props", price = 2500,    stackable = true,
        desc = "Serious builder territory.",
        data = { bonus = 50 },
    },
    {
        id = "props_100",   category = "props",
        name = "+100 Props", price = 5000,   stackable = true,
        desc = "Maximum prop budget expansion.",
        data = { bonus = 100 },
    },

    -- ── PLAYER MODELS ─────────────────────────────────────────
    {
        id = "model_kleiner",  category = "models",
        name = "Dr. Kleiner",  price = 1000,
        desc = "Science demands it.",
        data = { model = "models/kleiner.mdl" },
    },
    {
        id = "model_barney",   category = "models",
        name = "Barney Calhoun", price = 1000,
        desc = "A cold one awaits.",
        data = { model = "models/barney.mdl" },
    },
    {
        id = "model_mossman",  category = "models",
        name = "Dr. Mossman",  price = 1200,
        desc = "Questionable loyalty included.",
        data = { model = "models/mossman.mdl" },
    },
    {
        id = "model_alyx",     category = "models",
        name = "Alyx Vance",   price = 1500,
        desc = "Ready for anything.",
        data = { model = "models/alyx.mdl" },
    },
    {
        id = "model_combine",  category = "models",
        name = "Combine Soldier", price = 1500,
        desc = "Serve the Overworld.",
        data = { model = "models/combine_soldier.mdl" },
    },

    -- ── WEAPON SKINS ──────────────────────────────────────────
    --  world_model / view_model: paths to custom replacement models.
    --  Standard HL2 weapon models have only one skin group, so the
    --  skin index approach does nothing on them. Add your custom
    --  model paths here; leave a field as "" to skip that override.
    {
        id = "skin_pistol_gold",   category = "skins",
        name = "Golden Pistol",    price = 2000,
        desc = "A sidearm worthy of a king.",
        data = {
            weapon      = "weapon_pistol",
            world_model = "",   -- e.g. "models/weapons/w_pistol_gold.mdl"
            view_model  = "",   -- e.g. "models/weapons/v_pistol_gold.mdl"
            label       = "Golden",
        },
    },
    {
        id = "skin_smg_chrome",    category = "skins",
        name = "Chrome SMG",       price = 2500,
        desc = "Mirror-finish submachine gun.",
        data = {
            weapon      = "weapon_smg1",
            world_model = "",
            view_model  = "",
            label       = "Chrome",
        },
    },
    {
        id = "skin_rifle_camo",    category = "skins",
        name = "Camo Rifle",       price = 3000,
        desc = "Blend in. Stand out.",
        data = {
            weapon      = "weapon_ar2",
            world_model = "",
            view_model  = "",
            label       = "Camo",
        },
    },
    {
        id = "skin_shotgun_dragon", category = "skins",
        name = "Dragon Shotgun",   price = 4000,
        desc = "Fire-breathing up close.",
        data = {
            weapon      = "weapon_shotgun",
            world_model = "",
            view_model  = "",
            label       = "Dragon",
        },
    },

    -- ── JOIN MESSAGES ─────────────────────────────────────────
    {
        id = "join_arrived",   category = "joinmsg",
        name = "Classic Arrival", price = 1000,
        desc = '"{name} has arrived!"',
        data = { msg = "{name} has arrived!" },
    },
    {
        id = "join_chaos",     category = "joinmsg",
        name = "Chaos Agent",  price = 1500,
        desc = '"{name} is here to cause chaos."',
        data = { msg = "{name} is here to cause chaos." },
    },
    {
        id = "join_blessed",   category = "joinmsg",
        name = "Humble Brag",  price = 2000,
        desc = '"{name} has blessed this server with their presence."',
        data = { msg = "{name} has blessed this server with their presence." },
    },
    {
        id = "join_descended", category = "joinmsg",
        name = "Divine Entry", price = 2500,
        desc = '"{name} has descended from the heavens!"',
        data = { msg = "{name} has descended from the heavens!" },
    },
    {
        id = "join_king",      category = "joinmsg",
        name = "Royal Entry",  price = 3000,
        desc = '"THE KING HAS ARRIVED: {name}"',
        data = { msg = "THE KING HAS ARRIVED: {name}" },
    },
}

-- ── Fast id → item lookup ─────────────────────────────────────
do
    local index = {}
    for _, item in ipairs(Guardian.ShopItems) do
        index[item.id] = item
    end
    function Guardian.FindItem(item_id)
        return index[item_id]
    end
end