module("luci.controller.lisp.lisp", package.seeall)

function index()
	entry({"admin", "network", "interfaces"}, cbi("lisp/lisp"), "LISP Configuration", 30).dependent=false
end