# AppArmor profiles for the `bwrap` backend

Ubuntu ≥ 23.10 restricts unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`):
a program needs an AppArmor profile that grants `userns`, or bwrap fails with
`loopback: Failed RTM_NEWADDR: Operation not permitted`. The distro `bubblewrap` package loads no
such profile ([ADR 0011](../../docs/adr/0011-scanner-sandbox.md)). Pick one of the two below, never
both: each attaches to `/usr/bin/bwrap`.

| | `bwrap-userns-restrict` (AppArmor) | `shieldmon-bwrap` (this directory) |
|---|---|---|
| Use on | shared hosts, any host with other local users | dedicated hosts, CI runners |
| bwrap itself | may create namespaces | may create namespaces |
| What bwrap starts | runs in `unpriv_bwrap`: no capabilities, no further privileged namespaces | unconfined by AppArmor |
| Other local users running bwrap | get namespaces without capabilities: the kernel surface the restriction removes stays removed | get namespaces with capabilities: the restriction is lifted for anything run through bwrap |
| Tested | ci/sandbox-apparmor-restrict | ci/test |

ShieldMon needs no capabilities inside the sandbox (the launcher sets `no_new_privs`, Landlock,
rlimits and seccomp without any), so both pass `scannertest.CheckSandbox`.

## `bwrap-userns-restrict` (recommended)

Shipped, not loaded, by AppArmor's `apparmor-profiles` package:

```sh
sudo apt-get install apparmor-profiles
profile=$(dpkg -L apparmor-profiles | grep -m1 '/bwrap-userns-restrict$')
sudo install -m 0644 "$profile" /etc/apparmor.d/bwrap-userns-restrict
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

## `shieldmon-bwrap`

Grants `userns` to `/usr/bin/bwrap` and leaves everything else unconfined. Install and removal
commands are in [its header](shieldmon-bwrap).

## Check

```sh
sudo aa-status | grep -i bwrap      # exactly one profile for /usr/bin/bwrap
shieldmon plugins                   # bwrap ... (available)
```
