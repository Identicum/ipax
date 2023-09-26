-- --------------------------------------------------------------------------------------------------------------
-- --------------------------------------------------------------------------------------------------------------
-- https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua
local http = require("resty.http")
local function openidc_cache_get(type, key)
	local dict = ngx.shared[type]
	local value
	if dict then
	  value = dict:get(key)
	  if value then ngx.log(ngx.DEBUG, "cache hit: type=", type, " key=", key) end
	end
	return value
  end
  local function openidc_configure_timeouts(httpc, timeout)
	if timeout then
	  if type(timeout) == "table" then
		local r, e = httpc:set_timeouts(timeout.connect or 0, timeout.send or 0, timeout.read or 0)
	  else
		local r, e = httpc:set_timeout(timeout)
	  end
	end
  end
  -- Set outgoing proxy options
local function openidc_configure_proxy(httpc, proxy_opts)
	if httpc and proxy_opts and type(proxy_opts) == "table" then
		ngx.log(ngx.DEBUG, "openidc_configure_proxy : use http proxy")
	  httpc:set_proxy_options(proxy_opts)
	else
		ngx.log(ngx.DEBUG, "openidc_configure_proxy : don't use http proxy")
	end
  end
-- get the Discovery metadata from the specified URL
local function openidc_discover(url, ssl_verify, keepalive, timeout, exptime, proxy_opts, http_request_decorator)
	ngx.log(ngx.DEBUG, "openidc_discover: URL is: " .. url)
	local json, err
	local v = openidc_cache_get("discovery", url)
	if not v then
		ngx.log(ngx.DEBUG, "discovery data not in cache, making call to discovery endpoint")
		-- make the call to the discovery endpoint
		local httpc = http.new()
		openidc_configure_timeouts(httpc, timeout)
		openidc_configure_proxy(httpc, proxy_opts)
		local res, error = httpc:request_uri(url, decorate_request(http_request_decorator, {
			ssl_verify = (ssl_verify ~= "no"),
			keepalive = (keepalive ~= "no")
		}))
		if not res then
			err = "accessing discovery url (" .. url .. ") failed: " .. error
			ngx.log(ngx.DEBUG, err)
		else
			ngx.log(ngx.DEBUG, "response data: " .. res.body)
			json, err = openidc_parse_json_response(res)
			if json then
				openidc_cache_set("discovery", url, cjson.encode(json), exptime or 24 * 60 * 60)
			else
				err = "could not decode JSON from Discovery data" .. (err and (": " .. err) or '')
				ngx.log(ngx.DEBUG, err)
			end
		end
	else
		json = cjson.decode(v)
	end
	return json, err
end

-- turn a discovery url set in the opts dictionary into the discovered information
local function openidc_ensure_discovered_data(opts)
	local err
	if type(opts.discovery) == "string" then
		local discovery
		discovery, err = openidc_discover(opts.discovery, opts.ssl_verify, opts.keepalive, opts.timeout, opts.discovery_expires_in, opts.proxy_opts, opts.http_request_decorator)
		if not err then
			opts.discovery = discovery
		end
	end
	return err
end

local function get_first(table_or_string)
	local res = table_or_string
	if table_or_string and type(table_or_string) == 'table' then
		res = table_or_string[1]
	end
	return res
end

local function get_first_header(headers, header_name)
	local header = headers[header_name]
	return get_first(header)
end

local function get_first_header_and_strip_whitespace(headers, header_name)
	local header = get_first_header(headers, header_name)
	return header and header:gsub('%s', '')
end

local function get_forwarded_parameter(headers, param_name)
	local forwarded = get_first_header(headers, 'Forwarded')
	local params = {}
	if forwarded then
		local function parse_parameter(pv)
			local name, value = pv:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
			if name and value then
				if value:sub(1, 1) == '"' then
					value = value:sub(2, -2)
				end
				params[name:lower()] = value
			end
		end
		-- this assumes there is no quoted comma inside the header's value which should be fine as comma is not legal inside a node name, a URI scheme or a host name. The only thing that might bite us are extensions.
		local first_part = forwarded
		local first_comma = forwarded:find("%s*,%s*")
		if first_comma then
			first_part = forwarded:sub(1, first_comma - 1)
		end
		first_part:gsub("[^;]+", parse_parameter)
	end
	return params[param_name:gsub("^%s*(.-)%s*$", "%1"):lower()]
end

local function get_scheme(headers)
	return get_forwarded_parameter(headers, 'proto')
		or get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Proto')
		or ngx.var.scheme
end

local function get_host_name_from_x_header(headers)
	local header = get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Host')
	return header and header:gsub('^([^,]+),?.*$', '%1')
end
  
local function get_host_name(headers)
	return get_forwarded_parameter(headers, 'host')
		or get_host_name_from_x_header(headers)
		or ngx.var.http_host
end

-- --------------------------------------------------------------------------------------------------------------
-- --------------------------------------------------------------------------------------------------------------
-- IPAx module
local _M = {}


local function isTrue(input)
	if string.lower(input) == "true" then
		return true
	else
		return false
	end 
end

local function getAuthorizationParams()
	local authorizationParamsTable = {}

	local acr_values = os.getenv("OIDC_ACR_VALUES")
	if acr_values ~= '' then
		authorizationParamsTable["acr_values"]=acr_values
	end

	return authorizationParamsTable
end

local oidc_opts = {
	discovery = os.getenv("OIDC_DISCOVERY"),
	ssl_verify = os.getenv("OIDC_SSL_VERIFY"),
	client_id = os.getenv("OIDC_CLIENT_ID"),
	use_pkce = isTrue(os.getenv("OIDC_USE_PKCE")),
	client_secret = os.getenv("OIDC_CLIENT_SECRET"),
	scope = os.getenv("OIDC_SCOPE"),
	redirect_uri = os.getenv("OIDC_REDIRECT_URI"),
	logout_path = os.getenv("OIDC_LOGOUT_URI"),
	post_logout_redirect_uri = os.getenv("OIDC_POST_LOGOUT_REDIRECT_URI"),
	authorization_params = getAuthorizationParams(),
	renew_access_token_on_expiry = true,
	session_contents = {id_token=true, enc_id_token=true, access_token=true, user=true}
}

local session_opts = {
	secret = os.getenv("SESSION_SECRET"),
	cookie = {
		persistent = os.getenv("SESSION_COOKIE_PERSISTENT"),
		lifetime   = os.getenv("SESSION_COOKIE_LIFETIME")
	}
}

local function split(input, separator)
	if separator == nil then
		separator = "%s"
	end
	local t={}
	for str in string.gmatch(input, "([^" .. separator .. "]+)") do
		table.insert(t, str)
	end
	return t
end

local function check_authentication(err)
	if err then
		ngx.status = 500
		ngx.say(err)
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
		return false
	end
	return true
end

function _M.get_user()
	local res = _M.get_res()
	return res.user
end

function _M.get_userinfo_json()
	local res = _M.get_res()
	local json = require("json").encode(res.user)
	ngx.log(ngx.DEBUG, "userinfo_json: " .. json)
	return json
end

function _M.get_id_token()
	local res = _M.get_res()
	return res.id_token
end

function _M.get_access_token()
	local res = _M.get_res()
	return res.access_token
end

function _M.get_res()
	local res, err, target, session = require("resty.openidc").authenticate(oidc_opts, null, action, session_opts)
	session:close()
	local authentication_feedback = check_authentication(err)
	return res
end

function _M.check_multivalued_user_claim(claim_values, check_item)
	for index, value in pairs(claim_values) do
		-- ToDo: compare case-insensitive
		if value == check_item then
			return true
		end
	end
	ngx.exit(ngx.HTTP_FORBIDDEN)
	return false
end

function _M.is_value_in_list(value_list, check_item)
	for index, value in pairs(value_list) do
		if value == check_item then
			return true
		end
	end
	return false
end

function _M.get_names_from_dns(object_dns)
	local object_names={}
	if object_dns == nil then
		ngx.log(ngx.DEBUG, 'get_names_from_dns() object_dns is nil')
		return object_names
	end
	for index, value in pairs(object_dns) do
		local object_rdn = split(value, ",")[1]
		local object_name = split(object_rdn, "=")[2]
		object_names[index] = object_name
	end
	return object_names
end

function _M.get_group_names(claim_values, separator)
	if separator == nil then
		separator = "|"
	end
	local group_names = _M.get_names_from_dns(claim_values)
	return table.concat(group_names, separator)
end

local function get_kc_user_action_url(kc_action)
	local headers = ngx.req.get_headers()
	local redirect_uri = get_scheme(headers) .. "://" .. get_host_name(headers) .. "/private/info"
	local params = {
		client_id = oidc_opts.client_id,
		response_type = "code",
		scope = "openid",
		redirect_uri = redirect_uri,
		kc_action = kc_action
	}
	openidc_ensure_discovered_data(oidc_opts)
	return oidc_opts.discovery.authorization_endpoint .. "?" .. ngx.encode_args(params)
end

function _M.get_user_actions()
	local userActionsTable = {}


	local kc_update_password_action = os.getenv("KC_UPDATE_PASSWORD_ACTION")
	if kc_update_password_action ~= '' then
		userActionsTable["kc_update_password_action"]='<a id="update-password-button" href="' .. get_kc_user_action_url(kc_update_password_action) .. '">' .. os.getenv("KC_UPDATE_PASSWORD_LABEL") .. '</a>'
	end

	local kc_delete_account_action = os.getenv("KC_DELETE_ACCOUNT_ACTION")
	if kc_delete_account_action ~= '' then
		userActionsTable["kc_delete_account_action"]='<a id="delete-account-button" href="' .. get_kc_user_action_url(kc_delete_account_action) .. '">' .. os.getenv("KC_DELETE_ACCOUNT_LABEL") .. '</a>'
	end

	return userActionsTable
end

return _M
