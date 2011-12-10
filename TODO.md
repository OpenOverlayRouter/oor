Small issues
------------

  * Add TTL support in the configuration file
  * When restarting the network, check if configuration actually changed befored sending SMRs
  * When RLOC is changed with ifconfig without route changes no SMRs are sent
  * Clean up whitespaces where needed
  * Create man pages for lispd and lispconf
  * Check XXX comments in code and fix
  * Create Debian/Ubuntu meta-packages to pull in build-deps (using equivs)

High priority features
----------------------

  * NAT traversal
  * Map-Server authentication framework
  * Merge lisp_int into lisp_mod, avoid hardcoded information
  * Create binary package repositories for major distros
    * PPA for Ubuntu
    * MeeGo ?
    * ... others?
  * Separate output messages into different log levels
  * Reload configuration file on SIGHUP
  * Documentation


Advanced features
-----------------

  * Multiple EIDs
  * Multihoming (handle priorities and weights)
  * Generalize code as xTR use, integrate with wireless router distros
  * Integrate wih NetworkManager
  * Integrate wih Connection Manager
  * Performance optimizations:
    * Packet buffering
