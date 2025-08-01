local _M = {}

local function is_true(input)
	if string.lower(input) == "true" then
		return true
	else
		return false
	end 
end

local function get_authorization_params(oidc_acr_values)
	ngx.log(ngx.DEBUG, "Starting")
	local authorization_params_table = {}
	if oidc_acr_values ~= '' then
		authorization_params_table["acr_values"]=oidc_acr_values
	end
	return authorization_params_table
end

function _M.get_var_or_env(ngx_var_key)
    local env_var_name = string.upper(ngx_var_key)
    if ngx.var[ngx_var_key] and ngx.var[ngx_var_key] ~= "" then
        return ngx.var[ngx_var_key]
    else
        return os.getenv(env_var_name)
    end
end

function _M.get_oidc_opts()
	ngx.log(ngx.DEBUG, "Starting")
	local ipax_base_url = _M.get_var_or_env("ipax_base_url")

	local oidc_redirect_uri
	if ngx.var.oidc_redirect_uri and ngx.var.oidc_redirect_uri ~= "" then
		oidc_redirect_uri = ngx.var.oidc_redirect_uri
	else
		oidc_redirect_uri = ipax_base_url .. os.getenv("OIDC_REDIRECT_URI")
	end

	local oidc_post_logout_redirect_uri
	if ngx.var.oidc_post_logout_redirect_uri and ngx.var.oidc_post_logout_redirect_uri ~= "" then
		oidc_post_logout_redirect_uri = ngx.var.oidc_post_logout_redirect_uri
	else
		oidc_post_logout_redirect_uri = ipax_base_url .. os.getenv("OIDC_POST_LOGOUT_REDIRECT_URI")
	end

	local logout_path = _M.get_var_or_env("oidc_logout_path")
	if os.getenv("IPAX_MODE")=='demoapps' then
		logout_path = "/" .. _M.get_var_or_env("ipax_app_name") .. logout_path
	end

	local oidc_opts = {
		discovery = _M.get_var_or_env("oidc_discovery"),
		ssl_verify = _M.get_var_or_env("oidc_ssl_verify"),
		client_id = _M.get_var_or_env("oidc_client_id"),
		use_pkce = is_true(_M.get_var_or_env("oidc_use_pkce")),
		scope = _M.get_var_or_env("oidc_scope"),
		redirect_uri = oidc_redirect_uri,
		logout_path = logout_path,
		post_logout_redirect_uri = oidc_post_logout_redirect_uri,
		authorization_params = get_authorization_params(_M.get_var_or_env("oidc_acr_values")),
		renew_access_token_on_expiry = true,
		session_contents = {id_token=true, enc_id_token=true, access_token=true, user=true},
        -- Custom shared dictionaries per instance
		jwks_uri_lua_shared_dict = _M.get_var_or_env("ipax_app_name") .. "_jwks",
		discovery_lua_shared_dict = _M.get_var_or_env("ipax_app_name") .. "_discovery",
		state_lua_shared_dict = _M.get_var_or_env("ipax_app_name") .. "_oidc_state",
		access_tokens_lua_shared_dict = _M.get_var_or_env("ipax_app_name") .. "_oidc_access_tokens",
		refresh_tokens_lua_shared_dict = _M.get_var_or_env("ipax_app_name") .. "_oidc_refresh_tokens",
		id_tokens_lua_shared_dict = _M.get_var_or_env("ipax_app_name") .. "_oidc_id_tokens"
	}
	local oidc_client_secret = _M.get_var_or_env("oidc_client_secret")
	if oidc_client_secret ~= '' then
		oidc_opts["client_secret"]=oidc_client_secret
	end
	local prompt_override = _M.get_var_or_env("oidc_prompt")
	if prompt_override ~= '' then
		oidc_opts["prompt"]=prompt_override
	end
	return oidc_opts
end

function _M.get_session_opts()
	ngx.log(ngx.DEBUG, "Starting")
	local session_opts = {
		cookie_name = _M.get_var_or_env("ipax_app_name") .. "_session",
		cookie_same_site = _M.get_var_or_env("session_cookie_same_site"),
		cookie_secure = is_true(_M.get_var_or_env("session_cookie_secure")),
		idling_timeout = tonumber(_M.get_var_or_env("session_idling_timeout")),
		remember = is_true(_M.get_var_or_env("session_remember")),
		remember_cookie_name = _M.get_var_or_env("ipax_app_name") .. "_remember",
		secret = _M.get_var_or_env("ipax_base_url") .. _M.get_var_or_env("session_secret"),
		cookie_http_only = true
	}
	return session_opts
end

function _M.get_id_token(res)
	ngx.log(ngx.DEBUG, "Starting")
	return res.id_token
end

function _M.get_access_token(res)
	ngx.log(ngx.DEBUG, "Starting")
	return res.access_token
end

local function get_refresh_token(res)
	ngx.log(ngx.DEBUG, "Starting")
	local refresh_token = res.refresh_token or nil
	return refresh_token
end

function _M.get_user(res)
	ngx.log(ngx.DEBUG, "Starting")
	local user = res.user or nil
	return user
end

function _M.get_userinfo_json(res)
	ngx.log(ngx.DEBUG, "Starting")
	local json = require("json").encode(res.user)
	ngx.log(ngx.DEBUG, "userinfo_json: " .. json)
	return json
end

local function get_preferred_name_from_userinfo(res)
	ngx.log(ngx.DEBUG, "Starting")
    local userinfo_json = _M.get_userinfo_json(res)
    local userinfo_table = require("json").decode(userinfo_json)
    local preferred_username = userinfo_table.preferred_username or "nil"
    ngx.log(ngx.DEBUG, "returning preferred_username: " .. preferred_username)
    return preferred_username
end

local function get_preferred_username_from_userinfo_or_idtoken(res)
	ngx.log(ngx.DEBUG, "Starting")
    local userinfo_preferred_username = get_preferred_name_from_userinfo(res)
	if userinfo_preferred_username == nil then
		local id_token = _M.get_id_token() 
    	return id_token.preferred_username
    else
		return userinfo_preferred_username
    end
end

function _M.get_res(oidc_opts, session_opts)
	ngx.log(ngx.DEBUG, "Starting for client_id: " .. oidc_opts.client_id)
	-- for k, v in pairs(oidc_opts) do
	-- 	ngx.log(ngx.DEBUG, "Using oidc_opts[" .. k .. "] = " .. tostring(v))
	-- end
	-- for k, v in pairs(session_opts) do
	-- 	ngx.log(ngx.DEBUG, "Using session_opts[" .. k .. "] = " .. tostring(v))
	-- end
	local res, err, target, session = require("resty.openidc").authenticate(oidc_opts, nil, nil, session_opts)
	if err then
		if string.find(err, "error=login_required") then
			ngx.redirect("../loginRequired.html", ngx.HTTP_MOVED_TEMPORARILY)
		else
			ngx.log(ngx.ERR, "Authentication failed: ", err)
			ngx.redirect("../loginError.html", ngx.HTTP_MOVED_TEMPORARILY)
		end
	end

	res["refresh_token"] = session:get("refresh_token")
	session:close()
	return res
end

local function get_kc_user_action_url(ipax_base_url, client_id, kc_action, authorization_endpoint)
	ngx.log(ngx.DEBUG, "Starting for client_id: " .. client_id)
	local redirect_uri = ipax_base_url .. "/private/info"
	local params = {
		client_id = client_id,
		response_type = "code",
		scope = "openid",
		redirect_uri = redirect_uri,
		kc_action = kc_action
	}
	return authorization_endpoint .. "?" .. ngx.encode_args(params)
end

local function get_discovery_document(oidc_opts)
	ngx.log(ngx.DEBUG, "Starting for discovery: " .. oidc_opts.discovery)
	local http = require("resty.http")
	local http = require("resty.http")
	local httpc = http.new()
	local res, err = httpc:request_uri(oidc_opts.discovery, { method = "GET", oidc_opts.ssl_verify })
	if not res then
		ngx.log(ngx.ERR, "failed to request discovery document: ", err)
		return nil
	end
	if res.status ~= 200 then
		ngx.log(ngx.ERR, "discovery document request failed with status: ", res.status)
		return nil
	end
	return require("cjson").decode(res.body)
end

local function get_user_actions(oidc_opts, ipax_base_url)
	ngx.log(ngx.DEBUG, "Starting for client_id: " .. oidc_opts.client_id)
	local userActionsTable = {}
	local discovery_document = get_discovery_document(oidc_opts)
	local authorization_endpoint = discovery_document.authorization_endpoint
	local client_id = oidc_opts.client_id

	local kc_delete_account_action = _M.get_var_or_env("kc_delete_account_action")
	if kc_delete_account_action ~= '' then
		userActionsTable["kc_delete_account_action"]='<a id="delete-account-button" href="' .. get_kc_user_action_url(ipax_base_url, client_id, kc_delete_account_action, authorization_endpoint) .. '">' .. _M.get_var_or_env("kc_delete_account_label") .. '</a>'
	end

	local kc_update_password_action = _M.get_var_or_env("kc_update_password_action")
	if kc_update_password_action ~= '' then
		userActionsTable["kc_update_password_action"]='<a id="update-password-button" href="' .. get_kc_user_action_url(ipax_base_url, client_id, kc_update_password_action, authorization_endpoint) .. '">' .. _M.get_var_or_env("kc_update_password_label") .. '</a>'
	end

	local kc_update_email_action = _M.get_var_or_env("kc_update_email_action")
	if kc_update_email_action ~= '' then
		userActionsTable["kc_update_email_action"]='<a id="update-email-button" href="' .. get_kc_user_action_url(ipax_base_url, client_id, kc_update_email_action, authorization_endpoint) .. '">' .. _M.get_var_or_env("kc_update_email_label") .. '</a>'
	end

	local kc_enrol_biometrics_action = _M.get_var_or_env("kc_enrol_biometrics_action")
	if kc_enrol_biometrics_action ~= '' then
		userActionsTable["kc_enrol_biometrics_action"]='<a id="enrol-biometrics-button" href="' .. get_kc_user_action_url(ipax_base_url, client_id, kc_enrol_biometrics_action, authorization_endpoint) .. '">' .. _M.get_var_or_env("kc_enrol_biometrics_label") .. '</a>'
	end

	return userActionsTable
end

function _M.get_info_data(oidc_opts, session_opts, ipax_display_name, ipax_app_name, ipax_base_url, headers)
	ngx.log(ngx.DEBUG, "Starting for client_id: " .. oidc_opts.client_id)
	local res = _M.get_res(oidc_opts, session_opts) 
	-- id_token is returned as a lua table
	local id_token = _M.get_id_token(res);
	-- access_token is returned as string
	local access_token = _M.get_access_token(res);
	-- ngx.log(ngx.DEBUG, "access_token: " .. access_token)
	local refresh_token = get_refresh_token(res);
	-- ngx.log(ngx.DEBUG, "refresh_token: " .. tostring(refresh_token))

	local data = {
		user = _M.get_user(res),
		headers = headers,
		access_token = access_token,
		refresh_token = refresh_token or "Not Provided in token endpoint response",
		id_token = id_token,
		userinfo_json = _M.get_userinfo_json(res),
		username = get_preferred_username_from_userinfo_or_idtoken(res) or "Not Informed",
		user_actions = get_user_actions(oidc_opts, ipax_base_url),
		logout_path = oidc_opts.logout_path,
		ipax_app_name = ipax_app_name,
		ipax_display_name = ipax_display_name
	}
	return data
end

return _M
