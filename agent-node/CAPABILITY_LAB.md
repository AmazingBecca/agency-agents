# AmazingBecca Local Capability Lab

`capability_lab.sh` recreates selected dormant user-space capabilities from an image that already contains their binaries. It does not modify product startup gates, Supervisor configuration, protected refs, credentials, billing, or system service configuration.

## Commands

```bash
bash agent-node/capability_lab.sh start
bash agent-node/capability_lab.sh status
bash agent-node/capability_lab.sh manifest
bash agent-node/capability_lab.sh stop
```

Runtime state defaults to `/tmp/amazingbecca-caplab-$UID` and can be changed with `AB_CAPLAB_STATE_ROOT`.

The launcher dynamically selects loopback ports and starts an isolated Xvfb display, session DBus, Openbox, Picom, Chromium with loopback CDP, password-protected loopback x11vnc, token-protected loopback Jupyter, and headless LibreOffice. Generated authentication material remains in the temporary state directory and is mode-restricted.

The generated `amazingbecca-capability-lab/v1` manifest records image/build identifiers, feature selector, cluster placement, product `CUA_DD_*` gates, service liveness, loopback ports, and SHA-256 identities for the executables used by the lab. It intentionally separates product-enabled state from locally-instantiable capability.

## Demonstrated current applied-CaaS run

A direct start/probe/manifest/stop cycle on image commit `770cc6d08333b9844b1b63135928991b70e3343b` successfully started all eight lab processes. Chromium reported `Chrome/144.0.7559.96` through loopback CDP, authenticated Jupyter returned HTTP 200, LibreOffice accepted its loopback socket, and cleanup left no lab network processes behind.

This demonstrates local instantiation of bundled software. It does not create new ChatGPT product-level tool bindings and does not convert dormant software into platform-granted authority.
