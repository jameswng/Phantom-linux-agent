
##LINUXAGENT

*linuxagent* is an Phantom connector app for the Phantom security product.
```
This connector is to be used with the bundled demo endpoint agent.

Together, this app will obtain information on the endpoint running the Linux Agent and
allow limited commands to be invoked on the endpoint server.

This app utilize mutually verified SSL certificates to ensure security. This requires;

1. a X.509 certificate/key generated for this https service to be provided to the agent
   program on the endpoint.

2. The X.509 certificate (generated in step 1) identifying this service to be provided
   to the Phantom connector app on the Phantom appliance.

3. a X.509 certificate generated for the https client to be provided to the Phantom
   connector app on the Phantom appliance.

4. The X.509 certificate (generated in step 3) identifying the Phantom connector app to
   be provided to the agent progrom on the endpoint.

Potential focus for future enhancements
  Whitelist for path access validation
  Whitelist for ip access validation
  Listing package revisions
  Hashing/checksuming files
  Listing/killing process, sessions
  Starting/stopping services
  Rewriting http service to gracefully handle remote agent shutdown and restarts,
  potentially via the service/systemctl mechanism
