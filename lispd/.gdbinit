# We want Ctrl-C to be passed to lispd
handle SIGINT pass

# Print IPv4 address; argument is (struct in_addr*)
define pip
    print (char*) inet_ntoa($arg0)
end

# Print IPv6 address; argument is (struct in6_addr*)
define pip6
    set $_buf = (void*) malloc(64)
    print (char*) inet_ntop(10,$arg0,$_buf,64)
end
