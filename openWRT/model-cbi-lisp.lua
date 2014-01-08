m = Map("lispd", "Network") -- We want to edit the uci config file /etc/config/lispd

s = m:section(TypedSection, "map-resolver", translate("Map Resolver"))
s.addremove = true
s.anonymous = true
   s:option(Value, "address", "Address", "Encapsulated Map-Requests are sent to this map resolver (IPv4 or IPv6 or FQDN name)")

s = m:section(TypedSection, "ddt-client", "DDT Client")
   mode = s:option(ListValue, "enabled", translate("DDT Client enabled"), "DDT configuration has prefernece over map-resolver configuration")   
      mode.override_values = true   
      mode:value("on", translate("on"))   
      mode:value("off", translate("off"))

s = m:section(TypedSection, "ddt-root-node", "DDT root node")
   s.addremove = true
   s.anonymous = true
   s:option(Value, "address", "Address", "IPv4 or IPv6 address or FQDN name of the DDT root node")
   s:option(Value, "priority", "Priority", "DDT root nodes with lower values are more preferable")
   s:option(Value, "weight", "Weight", "Not yet implemented")


s = m:section(TypedSection, "map-server", "Map Server")
   s.addremove = true
   s.anonymous = true
   s:option(Value, "address", "Address", "Register to this map server (IPv4 or IPv6 or FQDN name)")
   mode = s:option(ListValue, "key_type", translate("Key Type"))
      mode.override_values = true
      mode:value("1", translate("HMAC-SHA-1-96"))
   s:option(Value, "key", "Key","Password to authenticate with the map-server")
   mode = s:option(ListValue, "proxy_reply", translate("Proxy Reply"),"Configure map-server to Map-Reply on behalf of the xTR")
      mode.override_values = true
      mode:value("on", translate("on"))
      mode:value("off", translate("off"))

s = m:section(TypedSection, "database-mapping", "Database Mapping")
   s.addremove = true
   s.anonymous = true
   s:option(Value, "eid_prefix", "EID prefix", "IPv4 or IPv6 network address of the OpenWrt LISP node / prefix length : x.x.x.x/x | y:y:y:y::y/y")
   ni = s:option(Value, "interface", translate("RLOC Interface"), "Interface containing theRLOCs associated to this EID")
   	ni.template    = "cbi/network_ifacelist"
   	ni.override_values = true
   	ni.widget = "radio"
   	ni.nobridges = false
   s:option(Value, "priority_v4", "IPv4 Priority","Priority of IPv4 locator of the interface for this EID. Locators with lower values are more preferable. A value of -1  means that IPv4 address of that interface is not used [0-255]")
   s:option(Value, "weight_v4", "IPv4 Weight", "Weight of IPv4 locator of the interface for this EID. When priorities are the same for multiple RLOCs, the Weight indicates how to balance unicast traffic between them [0-255]")
   s:option(Value, "priority_v6", "IPv6 Priority","Priority of IPv6 locator of the interface for this EID. Locators with lower values are more preferable. A value of -1  means that IPv6 address of that interface is not used [0-255]")
   s:option(Value, "weight_v6", "IPv6 Weight","Weight of IPv6 locator of the interface for this EID. When priorities are the same for multiple RLOCs, the Weight indicates how to balance unicast traffic between them [0-255]")

s = m:section(TypedSection, "proxy-etr", "Proxy ETR")
   s.addremove = true
   s.anonymous = true
   s:option(Value, "address", "Address", "Encapsulate packets for non-LISP sites to this Proxy-ETR (IPv4 or IPv6 or FQDN name)")
   s:option(Value, "priority", "Priority", "Proxy-ETR with lower values are more preferable")
   s:option(Value, "weight", "Weight", "When priorities are the same for multiple Proxy-ETRs, the Weight indicates how to balance unicast traffic between them")

s = m:section(TypedSection, "proxy-itr", "Proxy ITR")
   s.addremove = true
   s.anonymous = true
   s:option(Value, "address", "Address", "List of PITRs to SMR on handover (IPv4 or IPv6 or FQDN name) ")

s = m:section(TypedSection, "rloc-probing", "RLOC Probing")
   s:option(Value, "rloc_probe_interval", "Probe interval", "Interval at which periodic RLOC probes are sent (seconds). A value of 0 disables RLOC Probing") 
   s:option(Value, "rloc_probe_retries", "Probe retries", "RLOC Probe retries before setting the locator with status down. [0..5]")
   s:option(Value, "rloc_probe_retries_interval", "Probe retries interval", "Interval at which RLOC probes retries are sent (seconds) [1..#rloc_probe_interval]")

s = m:section(TypedSection, "nat-traversal", "NAT Traversal")
   mode = s:option(ListValue, "nat_aware", translate("NAT aware"), "Check if the node is behind NAT")   
      mode.override_values = true   
      mode:value("on", translate("on"))   
      mode:value("off", translate("off"))
   s:option(Value, "site_ID","Site ID" ,"64 bits to identify the site where the node is connected to. In hexadecimal. In doubt, keep the default value")
   s:option(Value, "xTR_ID","xTR ID" ,"128 bits to identify the xTR inside the site. In hexadecimal. In hexadecimal. In doubt, keep the default value")

return m -- Returns the map
