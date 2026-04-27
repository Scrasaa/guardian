-- ============================================================
--  guardian_ranks_sh.lua  –  Guardian Ranks  (shared)
--  Defines the rank table used by both server and client.
-- ============================================================

print("[Guardian] sh_ranks.lua loaded")

Guardian = Guardian or {}

-- Thresholds are in hours of playtime.
-- Order matters: highest threshold first so GetRank() short-circuits correctly.
Guardian.Ranks =
{
    { id = "unpaid_admin",    label = "Unpaid Admin",           hours = 400, color = Color(255, 195,  50) },
    { id = "prop_clipper",    label = "Prop Clipping Enthusiast", hours = 300, color = Color(180, 120, 255) },
    { id = "crash_report",    label = "Human Crash Report",     hours = 200, color = Color(240,  70,  70) },
    { id = "worked_yesterday",label = "\"It Worked Yesterday\"",hours =  100, color = Color(255, 140,  30) },
    { id = "osha",            label = "OSHA Violation",         hours =  50, color = Color(255, 185,  35) },
    { id = "liability",       label = "Server Liability",       hours =  25, color = Color(220,  80,  80) },
    { id = "error_msg",       label = "Walking Error Message",  hours =   20, color = Color(200,  80, 255) },
    { id = "lag_gen",         label = "Lag Generator",          hours =   10, color = Color( 80, 200, 255) },
    { id = "cert_problem",    label = "Certified Problem",      hours =   5, color = Color( 65, 195, 100) },
    { id = "pro_monkey",      label = "Professional Monkey",    hours =   0, color = Color(155, 155, 178) },
}

function Guardian.GetRank(seconds)
    local hours = seconds / 3600
    for _, rank in ipairs(Guardian.Ranks) do
        if hours >= rank.hours then
            return rank
        end
    end
    return Guardian.Ranks[#Guardian.Ranks]
end