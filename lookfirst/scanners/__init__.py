"""The package check (SPEC section 7): outside scanners lookfirst runs as separate programs.

- osv-scanner: known vulnerabilities and known malware in the packages a project pins.
- GuardDog: code patterns that malicious packages use.

Neither is bundled or imported. If one isn't installed, the report says so and how to
install it.
"""
