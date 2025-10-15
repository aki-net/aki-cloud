local botverify = require "botverify"

local _M = {}

function _M.verify()
    if ngx.var.edge_searchbot_key ~= "googlebot" then
        return
    end
    if ngx.var.edge_searchbot_range ~= "1" then
        return
    end
    botverify.ensure_googlebot(nil, { set_var = true })
end

return _M
