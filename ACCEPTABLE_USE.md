# Acceptable Use

CVELab generates working proofs of concept for known vulnerabilities. That
capability is useful for defenders and dangerous when misdirected. Using
CVELab means accepting the boundaries below.

## Intended use

CVELab exists for:

- Validating whether a CVE affects software you run, before you prioritize
  patching it.
- Verifying that a vendor patch actually blocks the vulnerability.
- Building reproducible evidence for internal reports and remediation
  tracking.
- Security research, training, and education on infrastructure you control.
- Authorized penetration testing and red team engagements, within the scope of
  a written authorization.

## Required conditions

1. **Authorization.** Run CVELab only against systems you own or for which you
   hold explicit written authorization. Verbal permission is not sufficient.
2. **Local isolation.** Generated labs bind to loopback and to an internal
   Docker network. Do not expose them to a LAN, a cloud network, or the public
   internet, and do not modify the generated topology to do so.
3. **Lawful artifacts.** Closed-source images, binaries, and installers must be
   obtained legally and used within their license. CVELab will not bypass
   vendor authentication, licensing, or entitlement checks, and will not
   download pirated software.
4. **Nondestructive payloads.** Proofs of concept must demonstrate an effect,
   not cause damage, destroy data, or establish persistence.

## Prohibited use

Do not use CVELab, or anything it produces, to:

- Attack, scan, or test any system without authorization.
- Develop, package, or distribute weaponized exploits, malware, ransomware,
  botnets, or command-and-control tooling.
- Build capability intended to evade security monitoring or incident response.
- Obtain unauthorized access to data, accounts, or infrastructure.
- Circumvent licensing, DRM, or access controls on commercial software.
- Violate applicable law, including computer misuse, export control, and data
  protection law in your jurisdiction.

## Your responsibility

You are solely responsible for how you use CVELab and for the lawfulness of
your use. The software is provided on an "AS IS" basis, without warranties or
conditions of any kind, as stated in the Apache License, Version 2.0. The
maintainers accept no liability for misuse or for any consequence of running
generated code.

Generated labs contain intentionally vulnerable software. Treat every lab
directory as untrusted. Do not run labs on production hosts, on machines with
access to sensitive data, or on networks you share with others.

## Reporting misuse

Report misuse of this project, or of artifacts derived from it, to
contact@syncbitsoft.com, or through
[GitHub Security Advisories](https://github.com/AndreiIonascu17/cvelab/security/advisories/new)
when the report concerns a defect in CVELab.
