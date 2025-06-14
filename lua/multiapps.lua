-- --------------------------------------------------------------------------------------------------------------
-- --------------------------------------------------------------------------------------------------------------
-- IPAx multiapps
local _M = {}
local ipax = require("ipax")
local ipax_openidc = require("ipax_openidc")

local session_opts = {
	secret = os.getenv("SESSION_SECRET"),
	cookie = {
		persistent = os.getenv("SESSION_COOKIE_PERSISTENT"),
		lifetime   = os.getenv("SESSION_COOKIE_LIFETIME"),
		samesite   = os.getenv("SESSION_COOKIE_SAMESITE")
	}
}

function _M.get_res(oidc_opts, base_url, prompt_override)
	oidc_opts["renew_access_token_on_expiry"] = true
	oidc_opts["session_contents"] = {id_token=true, enc_id_token=true, access_token=true, user=true}
	oidc_opts["redirect_uri"] = base_url .. os.getenv("OIDC_REDIRECT_URI")
	oidc_opts["logout_path"] = os.getenv("OIDC_LOGOUT_URI")
	oidc_opts["post_logout_redirect_uri"] = base_url .. "/logoutSuccess.html"
	ngx.log(ngx.DEBUG, "prompt_override: " .. prompt_override)
	if prompt_override ~= '' then
		oidc_opts["prompt"]=prompt_override
	end
	local res, err, target, session = require("resty.openidc").authenticate(oidc_opts, null, action, session_opts)
    --ngx.log(ngx.DEBUG, "refresh_token: " .. session:get("refresh_token"))
	res["refresh_token"] = session:get("refresh_token")	
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

function _M.get_refresh_token(res)
	return res.refresh_token
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
	if preferred_username == nil then
		return "(unknown)"
    else
		return preferred_username
    end
end

function _M.get_preferred_username_from_userinfo_or_idtoken(res)
    local id_token = _M.get_id_token(res) 
    local preferred_username = id_token.preferred_username

	if preferred_username == nil then
		return _M.get_preferred_name_from_userinfo(res)
    else
		return preferred_username
    end
end

local function get_kc_user_action_url(oidc_opts, kc_action)
	local headers = ngx.req.get_headers()
	local redirect_uri = ipax_openidc.get_scheme(headers) .. "://" .. ipax_openidc.get_host_name(headers) .. "/private/info"
	local params = {
		client_id = oidc_opts.client_id,
		response_type = "code",
		scope = "openid",
		redirect_uri = redirect_uri,
		kc_action = kc_action
	}
	ipax_openidc.openidc_ensure_discovered_data(oidc_opts)
	return oidc_opts.discovery.authorization_endpoint .. "?" .. ngx.encode_args(params)
end

function _M.get_user_actions(oidc_opts, kc_actions)
	local userActionsTable = {}

	if kc_actions.delete_account ~= '' then
		userActionsTable["kc_delete_account_action"]='<a id="delete-account-button" href="' .. get_kc_user_action_url(oidc_opts, kc_actions.delete_account) .. '">' .. os.getenv("KC_DELETE_ACCOUNT_LABEL") .. '</a>'
	end

	if kc_actions.update_password ~= '' then
		userActionsTable["kc_update_password_action"]='<a id="update-password-button" href="' .. get_kc_user_action_url(oidc_opts, kc_actions.update_password) .. '">' .. os.getenv("KC_UPDATE_PASSWORD_LABEL") .. '</a>'
	end

	if kc_actions.update_email ~= '' then
		userActionsTable["kc_update_email_action"]='<a id="update-email-button" href="' .. get_kc_user_action_url(oidc_opts, kc_actions.update_email) .. '">' .. os.getenv("KC_UPDATE_EMAIL_LABEL") .. '</a>'
	end

	if kc_actions.enrol_biometrics ~= '' then
		userActionsTable["kc_enrol_biometrics_action"]='<a id="enrol-biometrics-button" href="' .. get_kc_user_action_url(oidc_opts, kc_actions.enrol_biometrics) .. '">' .. os.getenv("KC_ENROL_BIOMETRICS_LABEL") .. '</a>'
	end

	return userActionsTable
end

return _M
