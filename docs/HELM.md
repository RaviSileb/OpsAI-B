# Helm chart (milník 10, v0.10.0)

Chart `helm/opsai` je alternativou ke Kustomize (`gitops/`) pro instalaci
serverového režimu. Výchozí hodnoty zrcadlí `gitops/base` (1 replika,
strategie Recreate, securityContexty, sondy, limity, ConfigMap, PVC 20Gi).

## Instalace

```sh
helm install opsai helm/opsai -n opsai --create-namespace \
  --set image.tag=v0.10.0
```

UI je za ClusterIP službou; bez ingressu pomůže port-forward
(vypíše ho `NOTES.txt`). Odinstalace smaže i namespace obsah:

```sh
helm uninstall opsai -n opsai
kubectl delete namespace opsai
```

## Hodnoty

| Hodnota | Výchozí | Význam |
|---|---|---|
| `image.repository` / `tag` / `pullPolicy` | `ghcr.io/ravisileb/opsai-a` / `latest` | obraz z release workflow |
| `service.type` / `port` | `ClusterIP` / `80` | služba |
| `config` | viz `values.yaml` | `OPSAI_*` proměnné (ConfigMap) |
| `persistence.enabled` / `size` | `true` / `20Gi` | PVC; `false` = `emptyDir` (dev) |
| `resources` | 250m/512Mi – 2/3Gi | requesty a limity |
| `secrets.masterKey` | `""` (nevytváří se) | `OPSAI_MASTER_KEY` (deployment ho čte volitelně) |
| `ingress.enabled` / `host` | `false` / `opsai.local` | volitelný Ingress |

Živě ověřeno na minikube: instalace → rollout → `/health/live`
`{"status":"ok"}` → odinstalace.

## CI a testy

- `tests/test_helm.py`: `helm lint` + render výchozí i přepsaných
  hodnot (parita s `gitops/base`, opt-in Secret/Ingress, `emptyDir`).
- CI job `Helm lint and template`: lint, oba templaty a
  `kubectl kustomize` nad base i overlayemi.
- ArgoCD: chart jde použít i jako zdroj místo Kustomize
  (`spec.source.chart`), repo zatím drží Kustomize cestu.
