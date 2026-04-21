Guardian = Guardian or {}

if SERVER then
    Guardian.Print("Guardian ownership server loaded.")
end

local function SetOwner(ply, ent)
    if not IsValid(ent) or not IsValid(ply) then return end
    ent.GuardianOwner = ply
    ent:SetNWEntity("GuardianOwner", ply)
end

-- Override cleanup.Add to set ownership when entities are spawned
local oldCleanupAdd = cleanup.Add
function cleanup.Add(ply, Type, ent)
    if IsValid(ply) and IsValid(ent) then
        SetOwner(ply, ent)
    end
    return oldCleanupAdd(ply, Type, ent)
end

hook.Add("PlayerSpawnedProp", "Guardian.Ownership.Prop", SetOwner)

hook.Add("PlayerSpawnedRagdoll", "Guardian.Ownership.Ragdoll", SetOwner)
hook.Add("PlayerSpawnedEffect", "Guardian.Ownership.Effect", SetOwner)
hook.Add("PlayerSpawnedNPC", "Guardian.Ownership.NPC", SetOwner)
hook.Add("PlayerSpawnedSENT", "Guardian.Ownership.SENT", SetOwner)
hook.Add("PlayerSpawnedVehicle", "Guardian.Ownership.Vehicle", SetOwner)

-- Handle undo
hook.Add("PreUndo", "Guardian.Ownership.Undo", function(undoData)
    local ply = undoData.Owner
    local entities = undoData.Entities
    -- No specific restriction needed here for now, but good to know
end)

hook.Add("PlayerDisconnected", "Guardian.Ownership.Cleanup", function(ply)
    for _, ent in ipairs(ents.GetAll()) do
        if ent.GuardianOwner == ply then
            ent:Remove()
        end
    end
end)
