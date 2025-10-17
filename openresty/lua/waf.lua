local botverify = require "botverify"

local _M = {}

local DEBUG_USER_AGENT = "AkiBot"

local function exit_forbidden()
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function log_block(reason, domain)
    local remote = ngx.var.remote_addr or "unknown"
    local host = domain or ngx.var.host or "unknown"
    ngx.log(ngx.WARN, string.format("waf: blocked request (%s) for %s from %s", reason or "unknown", host, remote))
end

local function is_debug_googlebot()
    local ua = ngx.var.http_user_agent
    if not ua then
        return false
    end
    return ua:find(DEBUG_USER_AGENT, 1, true) ~= nil
end

function _M.evaluate(config)
    config = config or {}
    local ctx = ngx.ctx
    if ctx.edge_waf_passed then
        return
    end

    if config.googlebot_only then
        if is_debug_googlebot() then
            ctx.googlebot_verified = true
            ctx.googlebot_verified_ip = ngx.var.remote_addr
            if ngx.var.edge_searchbot_verified ~= nil then
                ngx.var.edge_searchbot_verified = "1"
            end
        else
            local ok = botverify.ensure_googlebot(nil, { set_var = true })
            if not ok then
                ctx.edge_waf_blocked = "googlebot_only"
                log_block("googlebot_only", config.domain)
                return exit_forbidden()
            end
        end
    end

    ctx.edge_waf_passed = true
end

return _M
