-- cl_chathistory.lua
-- Hooks the vanilla chat TextEntry via OnTextEntryGetFocus.
-- Persists history to data/guardian/chathistory.json per client.

if SERVER then return end

-- ─── Config ───────────────────────────────────────────────────────────────────

local HISTORY_MAX  = 100
local SAVE_DIR     = "guardian"
local SAVE_FILE    = "guardian/chathistory.json"

-- ─── State ────────────────────────────────────────────────────────────────────

local message_history = {}   -- list of strings, index 1 = oldest
local history_index   = 0    -- 0 = not browsing
local draft_buffer    = ""
local patched_entry   = nil  -- weak ref to the currently patched panel

-- ─── Persistence ──────────────────────────────────────────────────────────────

local function history_load()
    if not file.IsDir(SAVE_DIR, "DATA") then
        file.CreateDir(SAVE_DIR)
    end

    if not file.Exists(SAVE_FILE, "DATA") then return end

    local raw = file.Read(SAVE_FILE, "DATA")
    if not raw or raw == "" then return end

    local decoded = util.JSONToTable(raw)
    if not decoded or type(decoded) ~= "table" then return end

    message_history = decoded
    MsgN("[chat_history] Loaded " .. #message_history .. " history entries.")
end

local function history_save()
    if not file.IsDir(SAVE_DIR, "DATA") then
        file.CreateDir(SAVE_DIR)
    end
    file.Write(SAVE_FILE, util.TableToJSON(message_history))
end

-- ─── Helpers ──────────────────────────────────────────────────────────────────

local function reset_browsing()
    history_index = 0
    draft_buffer  = ""
end

local function push_message(text)
    if text == "" then return end
    if message_history[#message_history] == text then return end

    table.insert(message_history, text)

    if #message_history > HISTORY_MAX then
        table.remove(message_history, 1)
    end

    history_save()
end

local function navigate(entry, direction)
    local count = #message_history
    if count == 0 then return end

    if direction == -1 then -- UP: go older
        if history_index == 0 then
            -- Capture whatever the user had typed before browsing.
            draft_buffer = entry:GetText()
        end
        history_index = math.min(history_index + 1, count)
    else -- DOWN: go newer
        if history_index == 0 then return end
        history_index = history_index - 1
    end

    local text
    if history_index == 0 then
        text = draft_buffer
    else
        -- Index 1 = newest recalled, count = oldest recalled.
        text = message_history[count - history_index + 1]
    end

    entry:SetText(text)
    entry:SetCaretPos(#text)
end

-- ─── Entry Patch ──────────────────────────────────────────────────────────────

-- OnTextEntryGetFocus fires on the ENGINE TextEntry (not DTextEntry),
-- which is exactly what the vanilla chat box uses. Fired before the
-- panel receives any input, so patching here is safe and reliable.
hook.Add("OnTextEntryGetFocus", "chat_history_patch", function(panel)
    -- Only patch while chat is actually open and don't re-patch same panel.
    if not chat.IsOpen()        then return end
    if panel == patched_entry   then return end

    -- The vanilla chat entry is a raw TextEntry; it has GetText/SetText
    -- but NOT GetValue/SetValue (those are DTextEntry only).
    -- Confirm it's the right panel by checking chat is open (already done)
    -- and that it has the engine TextEntry methods.
    if not panel.GetText or not panel.SetText then return end

    patched_entry = panel

    local original_key = panel.OnKeyCodePressed
    panel.OnKeyCodePressed = function(self, code)
        if code == KEY_UP then
            navigate(self, -1)
            return  -- swallow: prevents default caret-to-start jump
        elseif code == KEY_DOWN then
            navigate(self, 1)
            return
        end
        if original_key then original_key(self, code) end
    end
end)

-- ─── Record & Reset ───────────────────────────────────────────────────────────

hook.Add("OnPlayerChat", "chat_history_record", function(ply, text)
    if ply ~= LocalPlayer() then return end
    push_message(text)
    reset_browsing()
end)

hook.Add("FinishChat", "chat_history_reset", function()
    reset_browsing()
    patched_entry = nil
end)

-- ─── Init ─────────────────────────────────────────────────────────────────────

history_load()