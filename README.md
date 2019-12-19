pmipt - Partially Managed IPTables
===========

Firewall management is a weakness in Linux's toolset. A successful  
management system must allow both live updates and persistence of  
rulesets across reboots. IPTables excels at handling live updates  
because it's designed from the ground up to be dynamically controlled  
via command-line tools.

Persistence, however, is less robust. The canonical management technique  
for IPTables is:

1. Set IPTables rules from the command line.
2. After IPTables rules match the desired state, save them to the  
   filesystem with `iptables-save > /etc/iptables.rules`.
3. Add `iptables-restore < /etc/iptables.rules` to the network start  
   scripts in `/etc/network/if-up.d/` to ensure the rules are loaded   
   after a reboot.
4. Repeat #2 after any change to the rules.

Because `iptables-save` and `iptables-restore` are all-or-nothing, this  
approach breaks when other systems add and remove their own rules.

Most notably, Docker actively modifies IPTables rules to ensure   
containers are properly NAT'd and ports exposed. When `iptables-save`  
is run, it captures all existing Docker rules alongside manually   
configured rules. On reboot, `iptables-restore` loads old Docker rules  
that apply NAT and open ports to containers that no longer exist. At  
best, this is innocuous pollution of the ruleset. At worst, it may open  
up security holes or cause NAT conflicts.

PMIPT sidesteps this issue by managing specific subsets of IPTables  
rules and ignoring the rest. Docker can happily manage its own rules and   
chains while PMIPT ensures that its own rules are present as expected.

How it works
============

PMIPT takes a very blunt approach to rule management.  
- Rules and chains are configured in a YAML file at /etc/pmipt.conf.  
- Chain names *must* follow the format `PMIPT[<name>]`.  
- Rules *may not* have comments in their specification.  
- PMIPT appends comments to its rules in the format `PMIPT[<digest>]`.  

`pmipt-changes` is responsible for outputting an `iptables-restore`  
configuration that will bring the current system into compliance with  
rules defined in /etc/pmipt.conf. It compares the configuration with  
input from `iptables-save` and takes the following actions:  
- Configured chains not present on the system are added.  
- Chains present on the system in `PMIPT[<name>]` format but not in the  
  configuration are deleted.  
- All rules with a `PMIPT[<digest>]` comment are deleted.  
- All configured rules are added with `PMIPT[<digest>]` comments.  

While the last two steps may seem needlessly heavy-handed, deleting and  
re-adding rules is a simple way to avoid complicated ordering logic. It  
does mean, however, that **PMIPT rules are consistently ordered in  
relation to each other and inconsistently in relation to non-PMIPT  
rules**. Policies should be written with this in mind.  

This approach depends on key behaviors of both `iptables-save` and  
`iptables-restore`:  
- **`iptables-save` always reports rules in -A format.**  
- **`iptables-restore` applies its changes atomically.**  

`pmipt-apply` is the primary interface to PMIPT. It stores the ouptut  
from `pmipt-changes` into a state directory, tests that output, then  
applies it with a proper `iptables-restore -n` call. Errors are logged  
and results are submitted to statsd.

Monitoring
==========

`pmipt-apply` reports four different metrics to statsd:
- `pmipt.error.check` is incremented if output fails validation.
- `pmipt.error.apply` is incremented if output fails to apply.
- `pmipt.success.check` is incremented if output validates cleanly.
- `pmipt.success.apply` is incremented if output applies cleanly.

Configuration
=============

PMIPT configuration is a YAML-formatted dictionary mapping tables to  
chains to rules.
- Not all tables must be defined.
- Chains *must* be builtins or in `PMIPT[<name>]` format. No non-PMIPT  
  user-defined chains may be used.
- Rules *may not* contain comments.
- Rules *may not* start with a command. All rules imply `-A <chain>`.

Format:
```<table>:
  <chain>:
    rules:
      - <rulespec>
      - <rulespec>
      - ...
  <chain>:
    rules:
      - <rulespec>
      - <rulespec>
      - ...
  ...
<table>:
  ...
```

Example:
```yaml
nat:
  INPUT:
    rules:
      - --src 0.0.0.0/0 -j ACCEPT
  OUTPUT:
    rules:
      - --dst 8.8.8.8/32 -p udp --dport 53 -j ACCEPT
      - --dst 8.8.4.4/32 -p udp --dport 53 -j ACCEPT
filter:
  PMIPT[chain1]:
    rules:
      - --dst 2.2.2.2/30 -p tcp --dport 80 -j DROP
      - --dst 3.3.3.3/32 -p tcp --dport 443 -j ACCEPT
  PMIPT[chain2]: {}
```


Usage
=====

- Distribute the managed ruleset to /etc/pmipt.conf via Ansible.
- Set upstart/systemd to call pmipt-apply once when the host boots.
- Set Ansible to call pmipt-apply again when /etc/pmipt.conf is changed.

Example Documentation
=====================
Refer to docs/Example_Provisioning_System_Networking.md
