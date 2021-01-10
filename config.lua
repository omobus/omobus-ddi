-- -*- Lua -*-
-- Copyright (c) 2006 - 2021 omobus-ddi authors, see the included COPYRIGHT file.

local M = {} -- public interface

-- *** LDAP server parameters ***
M.ldap		= {
    uri		= "ldap://127.0.0.1:389",
    bind_dn	= "uid=omobus-scgid,ou=services,dc=omobus,dc=local",
    bind_pw	= "0",
    tls		= false,
    search	= {
	dev = {
	    base	= "ou=_dev,ou=users,dc=omobus,dc=local",
	    scope 	= "subtree",
	    filter	= "(&(objectClass=omobusUser)(FTPStatus=enabled)(exchangeStatus=enabled)(syncErpId=*)(uid=%1))",
	    attrs	= {"uid", "syncErpId", "groupName", "terminalList", "serviceList"}
	},
	users = {
	    base	= "ou=users,dc=omobus,dc=local",
	    scope 	= "subtree",
	    filter	= "(&(objectClass=omobusUser)(FTPStatus=enabled)(ErpId=*)(groupName=*)(uid=%1))",
	    attrs	= {"uid", "ErpId", "groupName", "terminalList", "serviceList"}
	}
    }
}

-- *** Main data storage parameters ***
M.data 		= {
    server	= "hostaddr=127.0.0.1 port=5432",
    storage	= "omobus-proxy-db",
    user	= "omobus",
    password	= "omobus"
}

return M
