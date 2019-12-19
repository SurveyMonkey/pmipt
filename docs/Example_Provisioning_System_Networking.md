# Example Provisioning System Networking

Copyright SurveyMonkey Inc., 2019
This work is licensed under the Creative Commons Attribution 4.0 License (CC-BY-4.0). A copy of the license may be found at https://creativecommons.org/licenses/by/4.0/legalcode or in the LICENSE file accompanying this document.

## Null network allocation

10.251.0.0/16 has been allocated to the Example Provisioning System as a null network for internal conventions. Blackhole-routing this network at the core switches ensures that the same network may be reused in each instance of Example Provisioning System across the globe.

Allocations from the null network are recorded here to prevent collisions.

<table>
  <tr>
    <td>CIDR</td>
    <td>Purpose</td>
  </tr>
  <tr>
    <td>10.251.0.0/16</td>
    <td>Example Provisioning System null network.</td>
  </tr>
  <tr>
    <td>10.251.0.0/24</td>
    <td>Subnet for virtual, intra-host routing.</td>
  </tr>
  <tr>
    <td>10.251.0.1/32</td>
    <td>Address redirected by IPTables to host loopback for whitelisted traffic.</td>
  </tr>
  <tr>
    <td>10.251.128.0/20</td>
    <td>Docker bridged container network.</td>
  </tr>
</table>


## Locally routed traffic

Services rely on supporting technology like statsd, syslog, and Consul. Traditionally, instances of supporting services listen on every host’s loopback address for local traffic. No service discovery is required and configuration is simplified by the universal destination 127.0.0.1.

Containers throw a wrench into this setup. In bridged networking mode (as opposed to host mode), containers are installed within their own network namespaces so 127.0.0.1 refers to the container’s localhost, not the host’s.

To make support services available to Docker containers, Example Provisioning System hosts redirect whitelisted traffic destined for 10.251.0.1 to the host loopback address. Note that there are many approaches for providing support services to containers: moving them from local instances to dedicated clusters, moving them from local instances to Docker containers with static addresses, setting local instances to listen on 0.0.0.0 and passing the host address to the Docker container’s environment, and so on. The IPTables routing strategy was selected because it requires no additional resources, doesn’t require special Docker container setup, and can be implemented with zero runtime impact.

For example, if port udp/19999 has been whitelisted:

```
shawnh@n9shtest300mgd1:~$ nc -l -u -p 19999 -s 127.0.0.1 &
[1] 9273
shawnh@n9shtest300mgd1:~$ sudo docker run -it --rm $IMG bash -c "echo hello world > /dev/udp/10.251.0.1/19999"
shawnh@n9shtest300mgd1:~$ hello world
```

The same address works from both Docker containers and the Docker host:

```
shawnh@n9shtest300mgd1:~$ nc -l -u -p 19999 -s 127.0.0.1 &
[1] 9734
shawnh@n9shtest300mgd1:~$ echo hello world > /dev/udp/10.251.0.1/19999
shawnh@n9shtest300mgd1:~$ hello world
```

### List of whitelisted services

The following services are locally routed. Instances listening on the Docker host’s loopback address are available at 10.251.0.1.

<table>
  <tr>
    <td>Port</td>
    <td>Service</td>
  </tr>
  <tr>
    <td>udp/8125</td>
    <td>statsd (Datadog)</td>
  </tr>
  <tr>
    <td>tcp/8126</td>
    <td>Datadog APM</td>
  </tr>
  <tr>
    <td>tcp/8400</td>
    <td>Consul RPC</td>
  </tr>
  <tr>
    <td>tcp/8500</td>
    <td>Consul HTTP</td>
  </tr>
  <tr>
    <td>tcp/8600</td>
    <td>Consul DNS (tcp)</td>
  </tr>
  <tr>
    <td>udp/8600</td>
    <td>Consul DNS (udp)</td>
  </tr>
</table>


This address and ports are available as variables provided by the default configuration:

```
null_loopback_address: "10.251.0.1"
null_loopback_ports:
    statsd: 8125
    datadog_apm: 8126
    consul_rpc: 8400
    consul_http: 8500
    consul_dns: 8600
```

### Whitelist a service

Service whitelists are set in the PMIPT configuration file (refer to default-config/pmipt.yaml). Adding a new service is as simple as adding a rule to the `mangle.PMIPT[mark_locally_routable].rules list`:

```
shawnh/network-docs$ git diff roles/base/files/pmipt.yaml
diff --git a/roles/base/files/pmipt.yaml b/roles/base/files/pmipt.yaml
index a5617122..76289fcd 100644
--- a/roles/base/files/pmipt.yaml
+++ b/roles/base/files/pmipt.yaml
@@ -11,6 +11,8 @@ mangle:
     rules:
       # statsd
       - --dst 10.251.0.1 -p udp --dport 8125 -j MARK --set-mark 0x12701
+      # test rule
+      - --dst 10.251.0.1 -p udp --dport 19999 -j MARK --set-mark 0x12701
   PREROUTING:
     rules:
       - -i docker0 --src 127.0.0.0/8 -j DROP
```

Only the protocol and port should change between rules. The destination and mark should remain exactly the same.

### Using a whitelisted service

Configure clients of the service to connect to 10.251.0.1.

