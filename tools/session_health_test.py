"""Exercise the offline peer-quality and session-health policy."""
import os

import lupa.lua52 as lupa

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEALTH = open(os.path.join(REPO, "mod/mp_lockstep_1/res/scripts/mp/health.lua"), encoding="utf-8").read()
L = lupa.LuaRuntime(unpack_returned_tuples=True)
L.globals().HEALTH = HEALTH
T = L.execute(r'''
local CM = { ticks = 10, peers = {} }
local T = CM
local K = { PEER_STALE_TICKS = 25, SIM_STEP = 0.2, GOV_LAG_START = 3 }
local log = function() end
assert(load(HEALTH, "@health.lua"))()(CM, K, log)
function T.setPeer(step, rtt, jitter, cu, verdict)
    CM.peers.b = { at = 10, step = step, srtt = rtt, rttvar = jitter, cu = cu, verdict = verdict }
end
return CM
''')

fails = []


def check(name, condition):
    print(("ok   " if condition else "FAIL ") + name)
    if not condition:
        fails.append(name)


T.setPeer(50, 40, 8, False, None)
h = T.healthTick(10)
check("a low-latency peer is healthy", h.state == "healthy" and h.score == 100)

T.setPeer(20, 220, 70, True, None)
h = T.healthTick(10)
check("a slow catch-up peer is degraded", h.state == "degraded" and h.score < 75 and h.score >= 45)
allowed, state, score = T.healthAdmission()
check("degraded sessions still admit a peer", allowed and state == "degraded" and score == h.score)

T.setPeer(-100, 1000, 500, False, "DESYNC e vs a")
h = T.healthTick(10)
check("severe lag or desync is unstable", h.state == "unstable" and h.score < 45)
allowed, _, _ = T.healthAdmission()
check("unstable sessions block admission", allowed is False)

T.ticks = 40
h = T.healthTick(10)
check("stale peers do not keep a session degraded", h.state == "solo" and h.score == 100)
check("snapshot contains the session state", "state=solo" in str(T.healthSnapshot(10)))

raise SystemExit(1 if fails else 0)