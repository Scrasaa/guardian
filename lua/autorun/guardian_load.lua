Guardian = Guardian or {}

local function LoadServer()
    AddCSLuaFile("guardian/sh_init.lua")
    AddCSLuaFile("guardian/sh_shop.lua")
    AddCSLuaFile("guardian/client/cl_hud.lua")
    AddCSLuaFile("guardian/client/cl_chathistory.lua")
    AddCSLuaFile("guardian/client/cl_shop.lua")
    AddCSLuaFile("guardian/client/cl_anticheat.lua")
    AddCSLuaFile("guardian/client/cl_integrity.lua")

    include("guardian/sh_init.lua")
    include("guardian/sh_shop.lua")

    include("guardian/server/sv_ownership.lua")
    include("guardian/server/sv_restrictions.lua")
    include("guardian/server/sv_anticrash.lua")
    include("guardian/server/sv_anticheat.lua")
    include("guardian/server/sv_shop.lua")
    include("guardian/server/sv_integrity.lua")

    Guardian.Print("Server modules loaded")
end

local function LoadClient()
    include("guardian/sh_init.lua")
    include("guardian/sh_shop.lua")

    include("guardian/client/cl_hud.lua")
    include("guardian/client/cl_chathistory.lua")
    include("guardian/client/cl_shop.lua")
    include("guardian/client/cl_anticheat.lua")
    include("guardian/client/cl_integrity.lua")

    Guardian.Print("Client modules loaded")
end

if SERVER then
    LoadServer()
else
    LoadClient()
end

Guardian.Print("Bootstrap complete")