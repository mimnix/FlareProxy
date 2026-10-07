# FlareProxy
FlareProxy is a transparent HTTP/HTTPS proxy adapter that seamlessly forwards client requests to FlareSolverr and bypass Cloudflare and DDoS-GUARD protection.

## Build
FlareProxy is shipped as a OCI container image, and can be built using the [Dockerfile](Dockerfile) provided in the repository root.

```bash
docker build -t flareproxy .
```

## Run
To run it replace the FLARESOLVERR_URL env var with the url of your FlareSolverr instance. FlareProxy exposes a plain HTTP proxy on port 8080 and a TLS proxy on port 8443.
```bash
docker run -e FLARESOLVERR_URL=http://localhost:8191/v1 -p 8080:8080 -p 8443:8443 flareproxy
```

### Environment variables
| Variable | Default | Description |
| --- | --- | --- |
| `FLARESOLVERR_URL` | `http://flaresolverr:8191/v1` | FlareSolverr API endpoint. |
| `FLAREPROXY_PORT` | `8080` | Plain HTTP proxy listener port. |
| `FLAREPROXY_HTTPS_PORT` | `8443` | TLS proxy listener port. |
| `FLAREPROXY_CERT_NAMES` | `localhost,127.0.0.1,flareproxy` | Comma separated names covered by the proxy's own TLS certificate (all added as SAN entries). |

## Usage
Set FlareProxy as a proxy in your browser or in your agent. You can connect over plain HTTP or over HTTPS (the proxy itself speaks TLS as well).

### Fetching over the plain HTTP proxy
```bash
curl --proxy 127.0.0.1:8080 http://www.google.com
```

### Fetching over the HTTPS proxy
FlareProxy's own listener on port 8443 presents a TLS certificate signed by its
local CA, so clients must trust that CA (see below). Use `https` for the proxy
scheme:
```bash
curl --proxy https://127.0.0.1:8443 --proxy-cacert /path/to/ca.crt https://www.google.com
```

### Fetching HTTPS sites through CONNECT
Because HTTPS targets are reached through a `CONNECT` tunnel that FlareProxy
intercepts (MITM), the proxy terminates TLS for `https://...` sites and relays
them through FlareSolverr. The client must trust the proxy's local CA for those
sites to validate. Any HTTPS target works transparently:
```bash
curl --proxy http://127.0.0.1:8080 --cacert /path/to/ca.crt https://www.google.com
```
When using the HTTPS proxy scheme, trust the CA once and both the tunnel to the
proxy and the intercepted site use it:
```bash
curl --proxy https://127.0.0.1:8443 --proxy-cacert /path/to/ca.crt --cacert /path/to/ca.crt https://www.google.com
```

### Trusting the CA
All certificates are **ephemeral**: a fresh local CA and leaf certificates are
generated at every startup inside a temporary directory and are deleted when the
process exits. Nothing is persisted to a user directory. Clients must therefore
download and trust the CA on each run. A convenience endpoint serves the CA in
PEM form:
```bash
curl -o ca.crt http://127.0.0.1:8080/__flareproxy/ca.crt
```
The path of the generated CA file is also printed in the startup banner.

You can use it as a proxy in [changedetection](https://github.com/dgtlmoon/changedetection.io), just navigate to settings -> CAPTCHA&Proxies and add it as an extra proxy in the list. Then you can setup your watch using any fetch method.

## Docker Compose
Add the snippet to your docker compose stack, i.e.:

```yaml
  flaresolverr:
    image: ghcr.io/flaresolverr/flaresolverr:latest
    container_name: flaresolverr
    environment:
      - LOG_LEVEL=${LOG_LEVEL:-info}
      - LOG_HTML=${LOG_HTML:-false}
      - CAPTCHA_SOLVER=${CAPTCHA_SOLVER:-none}
      - TZ=Europe/Rome
#    ports:
#    - "8191:8191"
    restart: always
  flareproxy:
    image: flareproxy
    container_name: flareproxy
    environment:
    - FLARESOLVERR_URL=http://flaresolverr:8191/v1
    - FLAREPROXY_PORT=8080
    - FLAREPROXY_HTTPS_PORT=8443
    - FLAREPROXY_CERT_NAMES=localhost,127.0.0.1,flareproxy
    - TZ=Europe/Rome
#    ports:
#    - "8080:8080"
#    - "8443:8443"
    restart: always
```


## Development
1. To run it locally use venv to prepare the development environment:

```bash
python3 -m venv flareproxy
source flareproxy/bin/activate
pip install -r requirements.txt
```
2. Run the proxy using the FLARESOLVERR_URL env var

```bash
FLARESOLVERR_URL=http://localhost:8191/v1 python3 flareproxy.py
```
3. Test it with curl

```bash
# plain HTTP target via the HTTP proxy
curl --proxy 127.0.0.1:8080 http://www.google.com
# HTTPS target through CONNECT (trust the ephemeral CA first)
curl -o ca.crt http://127.0.0.1:8080/__flareproxy/ca.crt
curl --proxy http://127.0.0.1:8080 --cacert ca.crt https://www.google.com
```

## Related projects
Shoutout to:

- [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr)
- [changedetection](https://github.com/dgtlmoon/changedetection.io)
- [urlwatch](https://github.com/thp/urlwatch)
