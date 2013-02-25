m = Map("lispd", "Network") -- We want to edit the uci config file /etc/config/lispd

s = m:section(TypedSection, "map-resolver", "Map Resolver")
   s:option(Value, "address", "Address", "Encapsulated Map-Requests are sent to this map resolver")

s = m:section(TypedSection, "map-server", "Map Server")      
   s:option(Value, "address", "Address", "Register to this map server")   
   s:option(Value, "key-type", "Key Type")   
   s:option(Value, "key", "Key")   
   mode = s:option(ListValue, "verify", translate("Verify"))   
      mode.override_values = true   
      mode:value("on", translate("on"))   
      mode:value("off", translate("off"))   
   mode = s:option(ListValue, "proxy_reply", translate("Proxy Reply"))   
      mode.override_values = true   
      mode:value("on", translate("on"))   
      mode:value("off", translate("off"))   

s = m:section(TypedSection, "proxy-etr", "Proxy ETR")      
   s:option(Value, "address", "Address", "Encapsulate packets for non-LISP sites to this Proxy-ETR")   
   s:option(Value, "priority", "Priority")   
   s:option(Value, "weight", "Weight") 
   
s = m:section(TypedSection, "database-mapping", "Database Mapping")      
   s:option(Value, "eid_prefix", "EID prefix", "IPv4 EID of the OpenWrt LISP node")   
   mode = s:option(ListValue, "interface", translate("Interface"))   
      mode.override_values = true   
      mode:value("eth0", translate("eth0"))   
      mode:value("wlan0", translate("wlan0"))   
   s:option(Value, "priority", "Priority")  
   s:option(Value, "weight", "Weight")
   
s = m:section(TypedSection, "proxy-itr", "Proxy ITR")      
   s:option(Value, "address", "Address", "List of PITRs to SMR on handover ") 
      
return m -- Returns the map