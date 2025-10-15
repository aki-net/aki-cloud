local botverify = require "botverify"

local _M = {}

local function exit_forbidden()
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function log_block(reason, domain)
    local remote = ngx.var.remote_addr or "unknown"
    local host = domain or ngx.var.host or "unknown"
    ngx.log(ngx.WARN, string.format("waf: blocked request (%s) for %s from %s", reason or "unknown", host, remote))
end

function _M.evaluate(config)
    config = config or {}
    local ctx = ngx.ctx
    if ctx.edge_waf_passed then
        return
    end

    if config.googlebot_only then
        local ok = botverify.ensure_googlebot(nil, { set_var = true })
        if not ok then
            ctx.edge_waf_blocked = "googlebot_only"
            log_block("googlebot_only", config.domain)
            return exit_forbidden()
        end
    end

    ctx.edge_waf_passed = true
end

return _M
