-- -*- Lua -*-
-- Copyright (c) 2006 - 2019 omobus-ddi authors, see the included COPYRIGHT file.

local config = require 'config'
local V = require 'version'
local scgi = require 'scgi'
local mime = require 'mime'
local uri = require 'url'
local log = require 'log'
local core = require 'core'
local stor = require 'stor'
local ldap = require 'bind_ldap'

function isuid(str)
    return str ~= nil and str:match('[^a-zA-Z0-9-._]') == nil
end

local function html_escape(s)
    return string.gsub(s, "[}{\">/<'&]", {
        ["&"] = "&amp;",
        ["<"] = "&lt;",
        [">"] = "&gt;",
        ['"'] = "&quot;",
        ["'"] = "&#39;",
        ["/"] = "&#47;"
    })
end

local function get(ld, uid, s)
    local a = nil

    if s.filter ~= nil then
	s.filter = s.filter:replace("%1", uid)
	s.filter = s.filter:replace("%uid", uid)
    end

    for dn, attrs in ld:search(s) do
	a = {}
	a.dn = dn
	a.attrs = attrs
	break
    end

    return a
end

local function page(uid, p, tb)
    local f = false
    local ar = {}
    table.insert(ar, '<!DOCTYPE html>')
    table.insert(ar, '<html>')
    table.insert(ar, '<head>')
    table.insert(ar, '<meta http-equiv="content-type" content="text/html; charset=utf-8" />')
    table.insert(ar, '<meta name="author" content="' .. V.package_name .. '/' .. V.package_version .. '">')
    table.insert(ar, '<meta http-equiv="Pragma" content="no-cache"/>')
    table.insert(ar, '<title>OMOBUS ddi service</title>')
    table.insert(ar, '<link rel="stylesheet" href="/ddi/ddi.css" />')
    table.insert(ar, '</head>')
    table.insert(ar, '<body>')
    table.insert(ar, '<h1>[' .. uid .. '] impersonation parameters</h1>')

    table.insert(ar, '<form action="/ddi/set" method="get">')
    table.insert(ar, '<select name="to">')
    if tb ~= nil then
	for _, x in ipairs(tb) do
	    if x.user_id == p.attrs.syncErpId then
		f = true
	    end
	    table.insert(ar, string.format('<option%s%s value="%s">%s: %s</option>"', 
		x.hidden == 1 and " disabled='disabled'" or "",
		x.user_id == p.attrs.syncErpId and " selected='selected'" or "",
		x.dev_login, x.dev_login, html_escape(x.descr)))
	end
	if f == false then
	    table.insert(ar, '<option disabled="disabled" selected="selected" value="">-</option>"')
	end
    end
    table.insert(ar, '</select>')
    table.insert(ar, '&nbsp;&nbsp;')
    table.insert(ar, '<input type="submit" value="  change impersonation >>  "></input>')
    table.insert(ar, '</form>')

    table.insert(ar, '<br/>')
    table.insert(ar, string.format('<div>syncErpId: <i>%s</i></div>', html_escape(p.attrs.syncErpId)))
    if p.attrs.groupName ~= nil then
	table.insert(ar, string.format('<div>groupName: <i>%s</i></div>', html_escape(p.attrs.groupName)))
    end
    if p.attrs.terminalList ~= nil then
	table.insert(ar, string.format('<div>terminals (only extra): <i>%s</i></div>', html_escape(p.attrs.terminalList)))
    end
    if p.attrs.serviceList ~= nil then
	table.insert(ar, string.format('<div>services (only extra): <i>%s</i></div>', html_escape(p.attrs.serviceList)))
    end
    table.insert(ar, '</body>')
    table.insert(ar, '</html>')
    return table.concat(ar, "\n")
end

function websvc_main()
    return {
	request_handler = function(env, content_size, content, res) -- request handler
	    assert(env.QUERY_STRING ~= nil, "invalid request. QUERY_STRING is unavailable.")
	    assert(env.REQUEST_METHOD ~= nil, "invalid request. REQUEST_METHOD is unavailable.")
	    assert(env.REMOTE_USER ~= nil, "invalid request. REMOTE_USER is unavailable.")
	    assert(isuid(env.REMOTE_USER), "invalid request. REMOTE_USER contains unsupported symbols.")

	    local script = env.PATH_INFO or env.SCRIPT_NAME
	    local params = uri.parseQuery(env.QUERY_STRING)
	    local uid = env.REMOTE_USER
	    local ld, err = ldap.open_simple(config.ldap.uri, config.ldap.bind_dn, config.ldap.bind_pw, config.ldap.tls)

	    if ld == nil or err then
		scgi.writeHeader(res, 500, {["Content-Type"] = mime.txt .. "; charset=utf-8"})
		scgi.writeBody(res, "Internal server error.")
		log.w(string.format("%s:%d %s", debug.getinfo(1,'S').short_src, debug.getinfo(1, 'l').currentline, err));
	    else
		local p = get(ld, uid, config.ldap.search.dev)

		if p == nil then
		    scgi.writeHeader(res, 401, {["Content-Type"] = mime.txt .. "; charset=utf-8"})
		    scgi.writeBody(res, string.format("Access to the [%s] user parameters is not allowed.", env.REMOTE_USER))
		    log.w(string.format("[audit] %s (IP: %s) -> permission denied", uid, env.REMOTE_ADDR))
		elseif script == '/ddi/set' and params.to ~= nil and isuid(params.to) and params.to ~= uid then
		    local z = get(ld, params.to, config.ldap.search.users)
		    if z == nil then
			scgi.writeHeader(res, 401, {["Content-Type"] = mime.txt .. "; charset=utf-8"})
			scgi.writeBody(res, string.format("Access to the [%s] user parameters is not allowed.", params.to))
			log.w(string.format("[audit] %s (IP: %s) -> permission denied to the %s attributes", 
			    uid, env.REMOTE_ADDR, params.to))
		    else
			local rep = {'='}
			rep.syncErpId = z.attrs.ErpId
			rep.groupName = z.attrs.groupName
			if p.attrs.serviceList ~= nil and z.attrs.serviceList ~= nil then
			    rep.serviceList = z.attrs.serviceList
			end
			if p.attrs.terminalList ~= nil and z.attrs.terminalList ~= nil then
			    rep.serviceList = z.attrs.terminalList
			end
			local add = {'+'};
			if p.attrs.serviceList == nil and z.attrs.serviceList ~= nil then
			    add.serviceList = z.attrs.serviceList
			end
			if p.attrs.terminalList == nil and z.attrs.terminalList ~= nil then
			    add.terminalList = z.attrs.terminalList
			end
			local del = {'-'};
			if p.attrs.serviceList ~= nil and z.attrs.serviceList == nil then
			    del.serviceList = p.attrs.serviceList
			end
			if p.attrs.terminalList ~= nil and z.attrs.terminalList == nil then
			    del.terminalList = p.attrs.terminalList
			end

			log.i(string.format("[audit] %s (IP: %s) -> rep: %s", uid, env.REMOTE_ADDR, json.encode(rep)))
			log.i(string.format("[audit] %s (IP: %s) -> add: %s", uid, env.REMOTE_ADDR, json.encode(add)))
			log.i(string.format("[audit] %s (IP: %s) -> del: %s", uid, env.REMOTE_ADDR, json.encode(del)))

			ld:modify(p.dn, rep, add, del)

			scgi.writeHeader(res, 302, {["Location"] = '/ddi/'})
			scgi.writeBody(res, json.encode(params))
		    end
		else
		    stor.init()
		    local tb, err = stor.get(function(tran, func_execute) return func_execute(tran,
[[
select user_id, descr, role, dev_login from users
    where role is not null and role <> '' and dev_login is not null and dev_login <> '' and (hidden = 0 or user_id = %uid%)
order by dev_login
]]
			, "//users", {uid = p.attrs.syncErpId}
		    ) end)
		    stor.cleanup()

		    if err then
			scgi.writeHeader(res, 500, {["Content-Type"] = mime.txt .. "; charset=utf-8"})
			scgi.writeBody(res, "Internal server error.")
		    else
			scgi.writeHeader(res, 200, {["Content-Type"] = mime.html .. "; charset=utf-8", ["Content-Security-Policy"] = "default-src 'self'",
			    ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"})
			scgi.writeBody(res, page(uid, p, tb))
		    end
		    log.i(string.format("[audit] %s (IP: %s) -> permission granted", uid, env.REMOTE_ADDR))
		end

		ld:close()
	    end

	    return 0
	end
    }
end
