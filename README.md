# JWT Token Service

A Kubernetes-native service that issues signed RS256 JWTs to workloads running inside the cluster. Clients authenticate using their Kubernetes service account token; authorization is enforced via standard RBAC.

---

## How it works

```
Client pod                     JWT Token Service                  Kubernetes API
    |                                  |                                |
    |-- POST /api/jwt/create --------> |                                |
    |   Authorization: Bearer <SA token>                               |
    |                                  |-- TokenReview --------------> |
    |                                  |<-- authenticated: true -----  |
    |                                  |-- SubjectAccessReview ------> |
    |                                  |<-- allowed: true -----------  |
    |                                  |                                |
    |<-- { "token": "<signed JWT>" } - |
```

1. The client sends its Kubernetes service account token as a Bearer token.
2. The service validates it via the **TokenReview** API (authentication).
3. The service checks the caller has `create` on `tokens.auth.jwt-token-service.io` via **SubjectAccessReview** (authorization).
4. If both pass, a signed RS256 JWT is returned with the requested subject, audience, and scope.

---

## API

### `POST /api/jwt/create` — Issue a token

**Port:** `8080`
**Auth:** Kubernetes service account Bearer token (see [Client setup](#client-setup))

**Request body:** none

> The `sub`, `aud`, and `scope` claims are determined entirely by the service configuration — see [Configuration](#configuration).

**Response `201`:**
```json
{ "token": "<signed RS256 JWT>" }
```

**Error responses:**

| Status | Meaning |
|--------|---------|
| `400` | Missing required fields |
| `401` | Missing/invalid Authorization header or not authorized |
| `500` | Token signing failed |

---

### `GET /.well-known/jwks.json` — Public key discovery

**Port:** `8081` (unauthenticated, publicly accessible)

Returns the RSA public key set used to verify issued tokens:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "development-key-1",
      "alg": "RS256",
      "n":   "<base64url modulus>",
      "e":   "<base64url exponent>"
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `kty` | Key type — `RSA` |
| `use` | Key use — `sig` (signing) |
| `kid` | Key ID, matched against the `kid` header in issued JWTs |
| `alg` | Algorithm — RS256 (RSA + SHA-256) |
| `n` | RSA public key modulus (base64url) |
| `e` | RSA public exponent (base64url) |

---

### `GET /healthz` — Health check

**Port:** `8080` — returns `200 OK` when the service is ready.

---

## Client setup

Every workload that needs to call `/api/jwt/create` must have:

1. **A `ServiceAccount`** with `automountServiceAccountToken: true`
2. **A `Role`** granting `create` on `tokens` in the `auth.jwt-token-service.io` API group
3. **A `RoleBinding`** connecting the role to the service account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-sa
  namespace: my-namespace
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: jwt-token-requester
  namespace: my-namespace
rules:
  - apiGroups:
      - auth.jwt-token-service.io
    resources:
      - tokens
    verbs:
      - create
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: jwt-token-requester
  namespace: my-namespace
subjects:
  - kind: ServiceAccount
    name: my-service-sa
    namespace: my-namespace
roleRef:
  kind: Role
  name: jwt-token-requester
  apiGroup: rbac.authorization.k8s.io
```

Once applied, pods using `my-service-sa` can call the service:

```bash
curl -X POST http://jwt-token-service-api.<namespace>.svc.cluster.local:8080/api/jwt/create \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  | jq -r .token
```

---

## Deployment

### Prerequisites

- Kubernetes cluster (k3s or any CNCF-conformant distribution)
- Helm 3
- An image pull secret for `ghcr.io`

### Install

```bash
# Create the namespace
kubectl create namespace jwt-token-service

# Create the image pull secret
kubectl create secret docker-registry jwt-token-service-image-pull-secret \
  --docker-server=ghcr.io \
  --docker-username=<github-username> \
  --docker-password=<github-pat> \
  --namespace=jwt-token-service

# Install the chart
helm install dev ./deploy/helm/jwt-token-service \
  --namespace jwt-token-service
```

### Key Helm values

| Value | Default | Description |
|-------|---------|-------------|
| `image.repository` | `ghcr.io/hgochev/jwt-token-issuer` | Image repository |
| `image.tag` | Chart `appVersion` | Image tag |
| `jwt.audience` | `""` | **Required.** The `aud` claim for all issued tokens |
| `jwt.scope` | `""` | Space-separated scopes for all issued tokens |
| `apiService.port` | `8080` | Token issuance port |
| `jwksService.port` | `8081` | JWKS discovery port |
| `ingress.enabled` | `true` | Enable ingress |
| `ingress.hosts[0].host` | `jwt-token-service.local` | Ingress hostname |
| `autoscaling.enabled` | `false` | Enable HPA |

---

## Configuration

The service is configured entirely via environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_AUDIENCE` | yes | The `aud` claim for all issued tokens |
| `JWT_SCOPE` | no | Space-separated scopes set as the `scope` claim |

With Helm, set these in `values.yaml`:

```yaml
jwt:
  audience: "orders-api"
  scope: "orders:read orders:write"
```

Or at install/upgrade time:

```bash
helm upgrade dev ./deploy/helm/jwt-token-service \
  --namespace jwt-token-service \
  --set jwt.audience=orders-api \
  --set jwt.scope="orders:read orders:write"
```

### Upgrade

```bash
helm upgrade dev ./deploy/helm/jwt-token-service --namespace jwt-token-service
```

---

## Private key

The RSA private key is generated automatically by Helm at install time using `genSelfSignedCert` and stored in a Kubernetes Secret. It is mounted into the pod at `/etc/jwt/private.key`.

> **Important:** The key is regenerated on every `helm upgrade`. If you need a stable key across upgrades, generate one externally and supply it:
> ```bash
> openssl genrsa -out private.key 2048
> kubectl create secret generic <release>-jwt-token-service \
>   --from-file=private.key \
>   --namespace jwt-token-service
> ```
> Then set `helm upgrade --set ... ` to skip the secret template, or patch accordingly.

---

## CI/CD

The GitHub Actions workflow (`.github/workflows/build_and_push.yml`) runs on every push to `main`:

```
test → release → build-and-push
```

- **test** — runs `go test ./...` on every push and PR
- **release** — runs `semantic-release` to determine the next version from [Conventional Commits](https://www.conventionalcommits.org/) and creates a GitHub release; also updates `Chart.yaml` and `CHANGELOG.md`
- **build-and-push** — builds the Docker image and pushes it to `ghcr.io` tagged with the semantic version; only runs when a new version is actually released

### Commit message convention

| Prefix | Version bump | Example |
|--------|-------------|---------|
| `fix:` | patch | `fix: correct token expiry calculation` |
| `feat:` | minor | `feat: add scope validation` |
| `feat!:` / `BREAKING CHANGE:` | major | `feat!: redesign auth flow` |

---

## Development

```bash
# Run tests
go test ./...

# Run locally (requires a kubeconfig with cluster access)
go run ./cmd/issuer
```
