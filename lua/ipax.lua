local _M = {}

local global_oidc_opts = {
	discovery = os.getenv("OIDC_DISCOVERY"),
	ssl_verify = "no",
	client_id = os.getenv("OIDC_CLIENT_ID"),
	client_secret = os.getenv("OIDC_CLIENT_SECRET"),
	scope = os.getenv("OIDC_SCOPE"),
	redirect_uri = os.getenv("OIDC_REDIRECT_URI"),
	session_contents = {user=true, id_token=false}
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
	local res, err = require("resty.openidc").authenticate(global_oidc_opts)
	local authentication_feedback = check_authentication(err)
	return res.user
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
