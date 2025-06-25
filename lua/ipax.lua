local _M = {}

local function is_true(input)
	if string.lower(input) == "true" then
		return true
	else
		return false
	end 
end

local function get_authorization_params(acr_values)
	local authorization_params_table = {}
	if acr_values ~= '' then
		authorization_params_table["acr_values"]=acr_values
	end
	return authorization_params_table
end

function _M.get_oidc_opts()
	local oidc_opts = {
		discovery = ngx.var.oidc_discovery or os.getenv("OIDC_DISCOVERY"),
		ssl_verify = os.getenv("OIDC_SSL_VERIFY"),
		client_id = ngx.var.client_id or os.getenv("OIDC_CLIENT_ID"),
		use_pkce = is_true(ngx.var.use_pkce or os.getenv("OIDC_USE_PKCE")),
		client_secret = ngx.var.client_secret or os.getenv("OIDC_CLIENT_SECRET"),
		scope = ngx.var.scope or os.getenv("OIDC_SCOPE"),
		redirect_uri = ngx.var.demoapp_base_url .. os.getenv("OIDC_REDIRECT_URI"),
		logout_path = ngx.var.demoapp_base_url .. os.getenv("OIDC_LOGOUT_URI"),
		post_logout_redirect_uri = os.getenv("OIDC_POST_LOGOUT_REDIRECT_URI") or ngx.var.demoapp_base_url .. "/logoutSuccess.html",
		authorization_params = get_authorization_params(ngx.var.acr_values or os.getenv("OIDC_ACR_VALUES")),
		renew_access_token_on_expiry = true,
		session_contents = {id_token=true, enc_id_token=true, access_token=true, user=true}
	}
	local prompt_override = ngx.var.oidc_prompt or ""
	if prompt_override ~= '' then
		oidc_opts["prompt"]=prompt_override
	end
	return oidc_opts
end

function _M.get_session_opts()
	local session_opts = {
		secret = ngx.var.session_secret or os.getenv("SESSION_SECRET"),
		cookie_http_only = true,
		cookie_secure = is_true(ngx.var.session_cookie_secure or os.getenv("SESSION_COOKIE_SECURE")),
		cookie_samesite = ngx.var.session_cookie_samesite or os.getenv("SESSION_COOKIE_SAMESITE"),
		idling_timeout = tonumber(ngx.var.session_idle_timeout or os.getenv("SESSION_IDLETIMEOUT")),
		remember = true
	}
	return session_opts
end

function _M.get_id_token(res)
	ngx.log(ngx.DEBUG, "ipax.get_id_token()")
	return res.id_token
end

function _M.get_access_token(res)
	ngx.log(ngx.DEBUG, "ipax.get_access_token()")
	return res.access_token
end

local function get_refresh_token(res)
	ngx.log(ngx.DEBUG, "ipax.get_refresh_token()")
	local refresh_token = res.refresh_token or nil
	return refresh_token
end

function _M.get_user()
	ngx.log(ngx.DEBUG, "ipax.get_user()")
	local res = _M.get_res()
	return res.user
end

function _M.get_userinfo_json()
	ngx.log(ngx.DEBUG, "ipax.get_userinfo_json()")
	local res = _M.get_res()
	local json = require("json").encode(res.user)
	ngx.log(ngx.DEBUG, "userinfo_json: " .. json)
	return json
end

local function get_preferred_name_from_userinfo()
	ngx.log(ngx.DEBUG, "ipax.get_preferred_name_from_userinfo()")
    local userinfo_json = _M.get_userinfo_json()
    local userinfo_table = require("json").decode(userinfo_json)
    local preferred_username = userinfo_table.preferred_username or "nil"
    ngx.log(ngx.DEBUG, "returning preferred_username: " .. preferred_username)
    return preferred_username
end

local function get_preferred_username_from_userinfo_or_idtoken()
	ngx.log(ngx.DEBUG, "ipax.get_preferred_username_from_userinfo_or_idtoken()")
    local userinfo_preferred_username = get_preferred_name_from_userinfo()
	if userinfo_preferred_username == nil then
		local id_token = _M.get_id_token() 
    	return id_token.preferred_username
    else
		return userinfo_preferred_username
    end
end

function _M.get_res(oidc_opts, session_opts)
	ngx.log(ngx.DEBUG, "ipax.get_res()")
	if not oidc_opts then
		oidc_opts = _M.get_oidc_opts_single()
	end
	if not session_opts then
		session_opts = _M.get_session_opts()
	end
	for k, v in pairs(oidc_opts) do
		ngx.log(ngx.DEBUG, "Using oidc_opts[" .. k .. "] = " .. tostring(v))
	end
	for k, v in pairs(session_opts) do
		ngx.log(ngx.DEBUG, "Using session_opts[" .. k .. "] = " .. tostring(v))
	end
	local res, err, target, session = require("resty.openidc").authenticate(oidc_opts, nil, nil, session_opts)
    --ngx.log(ngx.DEBUG, "refresh_token: " .. session:get("refresh_token"))
	res["refresh_token"] = session:get("refresh_token")
	session:close()
	-- local authentication_feedback = _M.check_authentication(err)
	return res
end

local function get_kc_user_action_url(base_url, client_id, kc_action, authorization_endpoint)
	local redirect_uri = base_url .. "/private/info"
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
	ngx.log(ngx.DEBUG, "ipax.get_discovery_document()")
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

local function get_user_actions(oidc_opts, base_url)
	local userActionsTable = {}
	local discovery_document = get_discovery_document(oidc_opts)
	local authorization_endpoint = discovery_document.authorization_endpoint
	local client_id = oidc_opts.client_id

	local kc_delete_account_action = os.getenv("KC_DELETE_ACCOUNT_ACTION")
	if kc_delete_account_action ~= '' then
		userActionsTable["kc_delete_account_action"]='<a id="delete-account-button" href="' .. get_kc_user_action_url(base_url, client_id, kc_delete_account_action, authorization_endpoint) .. '">' .. os.getenv("KC_DELETE_ACCOUNT_LABEL") .. '</a>'
	end

	local kc_update_password_action = os.getenv("KC_UPDATE_PASSWORD_ACTION")
	if kc_update_password_action ~= '' then
		userActionsTable["kc_update_password_action"]='<a id="update-password-button" href="' .. get_kc_user_action_url(base_url, client_id, kc_update_password_action, authorization_endpoint) .. '">' .. os.getenv("KC_UPDATE_PASSWORD_LABEL") .. '</a>'
	end

	local kc_update_email_action = os.getenv("KC_UPDATE_EMAIL_ACTION")
	if kc_update_email_action ~= '' then
		userActionsTable["kc_update_email_action"]='<a id="update-email-button" href="' .. get_kc_user_action_url(base_url, client_id, kc_update_email_action, authorization_endpoint) .. '">' .. os.getenv("KC_UPDATE_EMAIL_LABEL") .. '</a>'
	end

	local kc_enrol_biometrics_action = os.getenv("KC_ENROL_BIOMETRICS_ACTION")
	if kc_enrol_biometrics_action ~= '' then
		userActionsTable["kc_enrol_biometrics_action"]='<a id="enrol-biometrics-button" href="' .. get_kc_user_action_url(base_url, client_id, kc_enrol_biometrics_action, authorization_endpoint) .. '">' .. os.getenv("KC_ENROL_BIOMETRICS_LABEL") .. '</a>'
	end

	return userActionsTable
end

function _M.get_info_data(oidc_opts, session_opts, app_name, base_url, logout_uri, headers)
	ngx.log(ngx.DEBUG, "ipax.get_info_data()")
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
		user_actions = get_user_actions(oidc_opts, base_url),
		logout_uri = logout_uri,
		app_name = app_name
	}
	return data
end

return _M
