-- --------------------------------------------------------------------------------------------------------------
-- --------------------------------------------------------------------------------------------------------------
-- https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua
local _M = {}
local http = require("resty.http")
local cjson = require("cjson")
local cjson_s = require("cjson.safe")

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

local function decorate_request(http_request_decorator, req)
	return http_request_decorator and http_request_decorator(req) or req
end

-- parse the JSON result from a call to the OP
local function openidc_parse_json_response(response, ignore_body_on_success)
	local ignore_body_on_success = ignore_body_on_success or false
	local err
	local res
	-- check the response from the OP
	if response.status ~= 200 then
		err = "response indicates failure, status=" .. response.status .. ", body=" .. response.body
	else
		if ignore_body_on_success then
			return nil, nil
		end
		-- decode the response and extract the JSON object
		res = cjson_s.decode(response.body)
		if not res then
			err = "JSON decoding failed"
		end
	end
	return res, err
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
function _M.openidc_ensure_discovered_data(opts)
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

function _M.get_scheme(headers)
	return get_forwarded_parameter(headers, 'proto')
		or get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Proto')
		or ngx.var.scheme
end

local function get_host_name_from_x_header(headers)
	local header = get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Host')
	return header and header:gsub('^([^,]+),?.*$', '%1')
end
  
function _M.get_host_name(headers)
	return get_forwarded_parameter(headers, 'host')
		or get_host_name_from_x_header(headers)
		or ngx.var.http_host
end

return _M
