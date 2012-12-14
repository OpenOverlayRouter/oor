Small issues
------------

  * Add TTL support in the configuration file
  * When restarting the network, check if configuration actually changed befored sending SMRs
  * Clean up whitespaces where needed
  * Create man pages for lispd and lispconf
  * Check XXX comments in code and fix
  * Create Debian/Ubuntu meta-packages to pull in build-deps (using equivs)

High priority features
----------------------

  * NAT traversal
  * Map-Server authentication framework
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
  * Integrate wih NetworkManager
  * Integrate wih Connection Manager
  * Performance optimizations:
    * Packet buffering
