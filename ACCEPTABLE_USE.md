# Acceptable Use

**The policy is published at <https://cvelab.tech/acceptable-use/>.** That
page is the authoritative version: it covers both this tool and the
cvelab.tech service, and the service's terms of service make it binding.
This file keeps the essentials so they travel with the source.

CVELab generates working proofs of concept for known vulnerabilities. Using it
means accepting these boundaries:

1. **Authorization.** Run CVELab, and anything it produces, only against
   systems you own or hold explicit written authorization to test. Verbal
   permission is not sufficient.
2. **Isolation.** Generated labs bind to loopback and an internal Docker
   network. Do not expose them to a LAN, a cloud network or the internet.
3. **Lawful artifacts.** Obtain closed-source software legally and use it
   within its license. CVELab will not bypass authentication, licensing or
   entitlement checks.
4. **Nondestructive payloads.** A proof of concept demonstrates an effect; it
   does not damage, destroy data or persist.

Never use it to attack systems without authorization, build or distribute
weaponized exploits or malware, evade monitoring, gain unauthorized access, or
break the law that applies to you.

The software is provided "AS IS" under the Apache License, Version 2.0, and
you are responsible for how you use it. Generated labs contain intentionally
vulnerable software: treat every lab directory as untrusted.

Report misuse to contact@syncbitsoft.com.
