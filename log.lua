-- -*- Lua -*-
-- Copyright (c) 2006 - 2021 omobus-ddi authors, see the included COPYRIGHT file.

local M = {} -- public interface
local code = "(ddi) "

M.i = function(s) log_msg(code..s) end
M.w = function(s) log_warn(code..s) end
M.e = function(s) log_error(code..s) end
M.d = function(s) print(code.."[DEBUG] "..s) end

return M
