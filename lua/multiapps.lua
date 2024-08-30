-- --------------------------------------------------------------------------------------------------------------
-- --------------------------------------------------------------------------------------------------------------
-- IPAx multiapps
local _M = {}
local ipax = require("ipax")

local session_opts = {
	secret = os.getenv("SESSION_SECRET"),
	cookie = {
		persistent = os.getenv("SESSION_COOKIE_PERSISTENT"),
		lifetime   = os.getenv("SESSION_COOKIE_LIFETIME"),
		samesite   = os.getenv("SESSION_COOKIE_SAMESITE")
	}
}

function _M.get_res(oidc_opts, base_url)
	oidc_opts["renew_access_token_on_expiry"] = true
	oidc_opts["session_contents"] = {id_token=true, enc_id_token=true, access_token=true, user=true}
	oidc_opts["redirect_uri"] = base_url .. os.getenv("OIDC_REDIRECT_URI")
	oidc_opts["logout_path"] = os.getenv("OIDC_LOGOUT_URI")
	oidc_opts["post_logout_redirect_uri"] = base_url .. "/logoutSuccess.html"
	local res, err, target, session = require("resty.openidc").authenticate(oidc_opts, null, action, session_opts)
	session:close()
	local authentication_feedback = ipax.check_authentication(err)
	return res
end

function _M.get_userinfo_json(res)
	local json = require("json").encode(res.user)
	return json
end

function _M.get_id_token(res)
	return res.id_token
end

function _M.get_access_token(res)
	return res.access_token
end

function _M.get_userinfo_json(res)
	local json = require("json").encode(res.user)
	-- ngx.log(ngx.DEBUG, "userinfo_json: " .. json)
	return json
end

function _M.get_preferred_name_from_userinfo(res)
    local userinfo_json = _M.get_userinfo_json(res)
    local userinfo_table = require("json").decode(userinfo_json)
    local preferred_username = userinfo_table.preferred_username
    return preferred_username
end

function _M.get_preferred_username_from_userinfo_or_idtoken(res)
    local id_token = _M.get_id_token(res) 
    local preferred_username = id_token.preferred_username

	if preferred_username == nil then
		return _M.get_preferred_name_from_userinfo()
    else
		return preferred_username
    end
end

return _M
