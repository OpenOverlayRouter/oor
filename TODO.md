Small issues
------------

  * Add TTL support in the configuration file
  * When restarting the network, check if configuration actually changed befored sending SMRs
  * Clean up whitespaces where needed
  * Create man pages for lispd and lispd.conf
  * Check XXX and TODO comments in code and fix
  * Create Debian/Ubuntu meta-packages to pull in build-deps (using equivs)

High priority features
----------------------

  * NAT traversal
  * RLOC Probing
  * Instance ID
  * Map-Server authentication framework
  * Create binary package repositories for major distros
    * PPA for Ubuntu
    * ... others?
  * Reload configuration file on SIGHUP
  * Documentation

Advanced features
-----------------

  * Integrate wih NetworkManager
  * Integrate wih Connection Manager

