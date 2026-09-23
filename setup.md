# Local setup

## /etc/hosts

All services are addressed as `*.example.local` (certs are issued for these names). Add:

```
127.0.0.1 sso.example.local auth.example.local gateway.example.local client1.example.local client2.example.local client3.example.local sso-client1 sso-client2 sso-client3
```

`sso-client1/2/3` are the gateway's route targets (`https://sso-client1:8081`, ...); they're docker service names, so locally they must resolve to loopback (the cert already has them as SANs).

Only needed for the docker-compose stack (container network aliases, not host entries): `postgres.example.local`, `mongo.example.local`.

## Certs

`./services.sh certs` (generates `certs/` if missing; `certs --force` regenerates). Trust `certs/ca.pem` in your browser/OS.

## Run

`./services.sh` (menu) or `./services.sh start|stop|restart|status|build`. Run `build` before the first start.
