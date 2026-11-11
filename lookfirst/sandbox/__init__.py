"""The sandbox dry run (SPEC section 8): run the install inside a throwaway Docker container
and watch what it does.

- No folder from this computer is mounted, and never the Docker socket. The target is
  copied into the container, which has no capabilities and runs as an ordinary user.
- Its only way out is a recording proxy. By default, package registries and the
  project's own sites pass; every other request is recorded and answered locally.
- Decoy secrets sit in its home folder. strace, the proxy's records and `docker diff`
  show what the install read, sent and changed.
"""
