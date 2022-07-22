local _M = {}


local function isTrue(input)
	if string.lower(input) == "true" then
		return true
	else
		return false
	end 
end

local oidc_opts = {
	discovery = os.getenv("OIDC_DISCOVERY"),
	ssl_verify = "no",
	client_id = os.getenv("OIDC_CLIENT_ID"),
	use_pkce = isTrue(os.getenv("OIDC_USE_PKCE")),
	client_secret = os.getenv("OIDC_CLIENT_SECRET"),
	scope = os.getenv("OIDC_SCOPE"),
	redirect_uri = os.getenv("OIDC_REDIRECT_URI"),
	logout_path = os.getenv("OIDC_LOGOUT_URI"),
	post_logout_redirect_uri = os.getenv("OIDC_POST_LOGOUT_REDIRECT_URI"),
	renew_access_token_on_expiry = true,
	session_contents = {id_token=true, access_token=true, user=true}
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

function _M.get_group_names(claim_values, separator)
	if claim_values == nil then
		ngx.log(ngx.DEBUG, 'claim_values is null.')
		return ""
	end
	if separator == nil then
		separator = "|"
	end
	local group_names = {}
	for index, value in pairs(claim_values) do
		local object_rdn = split(value, ",")[1]
		local object_name = split(object_rdn, "=")[2]
		group_names[index] = object_name
	end
	return table.concat(group_names, separator)
end

return _M
