local dns_resolver = require "resty.dns.resolver"

local _M = {}

local cache = ngx.shared.edge_searchbot_cache
local allowed_suffixes = {
    ".googlebot.com",
    ".google.com",
}

local nameservers

local function read_resolvers()
    if nameservers then
        return nameservers
    end
    nameservers = {}
    local file = io.open("/etc/resolv.conf", "r")
    if file then
        for line in file:lines() do
            local ns = line:match("^nameserver%s+([%d%.:]+)")
            if ns then
                table.insert(nameservers, ns)
            end
        end
        file:close()
    end
    if #nameservers == 0 then
        nameservers = { "8.8.8.8", "1.1.1.1" }
    end
    return nameservers
end

local function ipv4_to_arpa(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end
    return string.format("%s.%s.%s.%s.in-addr.arpa", d, c, b, a)
end

local function split(str, sep)
    local out = {}
    if str == "" then
        return out
    end
    for part in (str .. sep):gmatch("(.-)" .. sep) do
        if part ~= "" then
            table.insert(out, part)
        end
    end
    return out
end

local function expand_ipv6(ip)
    ip = ip:lower()
    if ip == "" then
        return nil
    end
    local left, right = ip:match("^(.-)::(.*)$")
    local parts = {}
    if left then
        local leftParts = split(left, ":")
        local rightParts = split(right, ":")
        local missing = 8 - (#leftParts + #rightParts)
        for _, part in ipairs(leftParts) do
            if part ~= "" then
                table.insert(parts, part)
            end
        end
        for _ = 1, missing do
            table.insert(parts, "0")
        end
        for _, part in ipairs(rightParts) do
            if part ~= "" then
                table.insert(parts, part)
            end
        end
    else
        parts = split(ip, ":")
    end
    while #parts < 8 do
        table.insert(parts, "0")
    end
    local expanded = {}
    for _, part in ipairs(parts) do
        if part == "" then
            part = "0"
        end
        local num = tonumber(part, 16)
        if not num then
            return nil
        end
        table.insert(expanded, string.format("%04x", num))
    end
    return table.concat(expanded, ":")
end

local function ipv6_to_arpa(ip)
    local expanded = expand_ipv6(ip)
    if not expanded then
        return nil
    end
    local hex = expanded:gsub(":", "")
    local out = {}
    for i = #hex, 1, -1 do
        out[#out + 1] = hex:sub(i, i)
    end
    return table.concat(out, ".") .. ".ip6.arpa"
end

local function to_arpa(ip)
    if ip:find(":", 1, true) then
        return ipv6_to_arpa(ip)
    end
    return ipv4_to_arpa(ip)
end

local function normalize_host(host)
    host = host or ""
    host = host:lower()
    if host:sub(-1) == "." then
        host = host:sub(1, -2)
    end
    return host
end

local function ends_with(host, suffix)
    return host:sub(-#suffix) == suffix
end

local function matches_google(host)
    host = normalize_host(host)
    for _, suffix in ipairs(allowed_suffixes) do
        if ends_with(host, suffix) then
            return true
        end
    end
    return false
end

local function has_ip(answers, ip)
    local target = normalize_host(ip)
    for _, ans in ipairs(answers or {}) do
        local addr = ans.address or ans.ipv6
        if addr then
            addr = normalize_host(addr)
            if addr == target then
                return true
            end
        end
    end
    return false
end

local function verify_ip(ip)
    local arpa = to_arpa(ip)
    if not arpa then
        return false
    end
    local res, err = dns_resolver:new{
        nameservers = read_resolvers(),
        retrans = 2,
        timeout = 2000,
    }
    if not res then
        ngx.log(ngx.ERR, "searchbot: resolver init failed: ", err)
        return false
    end
    local answers, qerr = res:query(arpa, { qtype = res.TYPE_PTR })
    if not answers or qerr or answers.errcode then
        return false
    end
    local ptr
    for _, ans in ipairs(answers) do
        if ans.ptrdname then
            ptr = normalize_host(ans.ptrdname)
            break
        end
    end
    if not ptr or not matches_google(ptr) then
        return false
    end
    local ok = false
    local forwardTypes = { res.TYPE_A, res.TYPE_AAAA }
    for _, qt in ipairs(forwardTypes) do
        local fwd, ferr = res:query(ptr, { qtype = qt })
        if fwd and not ferr and not fwd.errcode then
            if has_ip(fwd, ip) then
                ok = true
                break
            end
        end
    end
    return ok
end

function _M.verify()
    if ngx.var.edge_searchbot_key ~= "googlebot" then
        return
    end
    if ngx.var.edge_searchbot_range ~= "1" then
        return
    end
    local ip = ngx.var.remote_addr
    if not ip or ip == "" then
        return
    end
    if not cache then
        return
    end
    local cacheKey = "googlebot:" .. ip
    local cached = cache:get(cacheKey)
    if cached ~= nil then
        if cached == 1 then
            ngx.var.edge_searchbot_verified = "1"
        end
        return
    end
    local ok = verify_ip(ip)
    cache:set(cacheKey, ok and 1 or 0, ok and 86400 or 3600)
    if ok then
        ngx.var.edge_searchbot_verified = "1"
    end
end

return _M
