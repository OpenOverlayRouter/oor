m = Map("lispd", "Network") -- We want to edit the uci config file /etc/config/lispd

s = m:section(TypedSection, "map-resolver", "Map Resolver")
   s:option(Value, "address", "Address", "Encapsulated Map-Requests are sent to this map resolver")

s = m:section(TypedSection, "map-server", "Map Server")      
   s:option(Value, "address", "Address", "Register to this map server")   
   mode = s:option(ListValue, "key_type", translate("Key Type"))   
      mode.override_values = true   
      mode:value("1", translate("HMAC-SHA-1-96"))
   s:option(Value, "key", "Key")
   mode = s:option(ListValue, "proxy_reply", translate("Proxy Reply"))   
      mode.override_values = true   
      mode:value("on", translate("on"))   
      mode:value("off", translate("off"))   

s = m:section(TypedSection, "proxy-etr", "Proxy ETR")      
   s:option(Value, "address", "Address", "Encapsulate packets for non-LISP sites to this Proxy-ETR")   
   s:option(Value, "priority", "Priority")   
   s:option(Value, "weight", "Weight") 
   
s = m:section(TypedSection, "database-mapping", "Database Mapping")      
   s:option(Value, "eid_prefix", "EID prefix", "IPv4 or IPv6 EID of the OpenWrt LISP node")   
   ni = s:option(Value, "interface", translate("RLOC Interface"), "Interface containing the RLOCs associated to this EID")
   	ni.template    = "cbi/network_ifacelist"
   	ni.override_values = true   
   	ni.widget = "radio"
   	ni.nobridges = false
   s:option(Value, "priority_v4", "IPv4 Priority")  
   s:option(Value, "weight_v4", "IPv4 Weight")
   s:option(Value, "priority_v6", "IPv6 Priority")  
   s:option(Value, "weight_v6", "IPv6 Weight")
   
s = m:section(TypedSection, "proxy-itr", "Proxy ITR")      
   s:option(Value, "address", "Address", "List of PITRs to SMR on handover ") 
      
return m -- Returns the map
