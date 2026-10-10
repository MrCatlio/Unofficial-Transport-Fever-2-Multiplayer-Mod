-- mp/health.lua -- bounded peer quality and session health observations
return function(CM, K, log)
CM.health = { peers = {}, state = "solo", score = 100, updated = 0 }

local function clamp(value, low, high)
	return math.max(low, math.min(high, value))
end

local function fresh(peer)
	return peer and peer.at and CM.ticks - peer.at <= (K.PEER_STALE_TICKS or 25)
end

function CM.healthPeer(letter, peer, now)
	if not fresh(peer) then return { state = "offline", score = 0 } end
	local score = 100
	local rtt = tonumber(peer.srtt) or 0
	local jitter = tonumber(peer.rttvar) or 0
	local clock = (peer.step and peer.step * (K.SIM_STEP or 0.2)) or peer.time or now
	local lag = math.max(0, (tonumber(now) or 0) - clock)
	if rtt > 100 then score = score - math.min(25, (rtt - 100) / 20) end
	if jitter > 25 then score = score - math.min(20, (jitter - 25) / 5) end
	if lag > (K.GOV_LAG_START or 3) then score = score - math.min(35, (lag - (K.GOV_LAG_START or 3)) * 5) end
	if peer.cu then score = score - 20 end
	if peer.verdict and tostring(peer.verdict):sub(1, 6) == "DESYNC" then score = score - 50 end
	score = math.floor(clamp(score, 0, 100) + 0.5)
	local state = score >= 75 and "healthy" or score >= 45 and "degraded" or "unstable"
	return { state = state, score = score, rtt = rtt, jitter = jitter, lag = lag, catchup = peer.cu and true or false }
end

function CM.healthTick(now)
	local peers, worst, worstLetter, total = {}, 100, nil, 0
	for letter, peer in pairs(CM.peers or {}) do
		local item = CM.healthPeer(letter, peer, now)
		peers[letter] = item
		if item.state ~= "offline" then
			total = total + 1
			if item.score < worst then worst, worstLetter = item.score, letter end
		end
	end
	local state = total == 0 and "solo" or (worst < 45 and "unstable" or worst < 75 and "degraded" or "healthy")
	CM.health = { peers = peers, state = state, score = total == 0 and 100 or worst,
		worst = worstLetter, updated = tonumber(now) or 0 }
	return CM.health
end

function CM.healthAdmission()
	local health = CM.health or {}
	return health.state ~= "unstable", health.state or "solo", health.score or 100
end

function CM.healthWords()
	local health = CM.health or {}
	if health.state == "solo" then return "solo" end
	return string.format("%s %d/100%s", health.state, health.score or 0,
		health.worst and (" (peer " .. health.worst .. ")") or "")
end

function CM.healthSnapshot(now)
	local health = CM.healthTick(now)
	local out = { "state=" .. tostring(health.state), "score=" .. tostring(health.score),
		"worst=" .. tostring(health.worst or "-"), "t=" .. tostring(health.updated) }
	for letter, peer in pairs(health.peers) do
		out[#out + 1] = string.format("peer.%s=%s,%d,%.0f,%.0f,%.1f,%s", letter, peer.state,
			peer.score, peer.rtt or 0, peer.jitter or 0, peer.lag or 0, peer.catchup and "catchup" or "live")
	end
	table.sort(out)
	return table.concat(out, "\n") .. "\n"
end
end