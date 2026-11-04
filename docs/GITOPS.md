# GitOps (ArgoCD + Kustomize)

Zdrojem pravdy je adresář `gitops/` v tomto repozitáři.

```
gitops/
  base/                  deployment, service, config+pvc, kustomization
  overlays/staging/      namespace opsai-staging, DEBUG log, auto-sync
  overlays/production/   namespace opsai, restricted mode, ruční sync
  argocd/                projekt + 2 aplikace
```

## Tok

1. Tag `v*` spustí release pipeline: build + push
   `ghcr.io/ravisileb/opsai-a:<tag>` a `latest`, SBOM, GitHub release
   s `.deb`, AppImage a wheel.
2. ArgoCD Image Updater (staging) zapíše nový digest do gitu.
3. Staging se synchronizuje automaticky (`prune`, `selfHeal`).
4. Produkce se povyšuje ručně: bump tagu v
   `gitops/overlays/production/kustomization.yaml` + sync v ArgoCD.

## Instalace

```bash
kubectl apply -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml -n argocd
kubectl apply -f gitops/argocd/project.yaml
kubectl apply -f gitops/argocd/app-staging.yaml
kubectl apply -f gitops/argocd/app-production.yaml
```

Image Updater je volitelný (jen staging anotace); bez něj se tagy
bumpují ručně stejně jako v produkci.

## Tajemství v clusteru

Deployment čte volitelný `master-key` ze Secretu `opsai-secrets`
(`stringData`, base64 32 B). Vytvořte ho mimo git:

```bash
kubectl -n opsai create secret generic opsai-secrets \
  --from-literal=master-key="$(openssl rand -base64 32)"
```

API klíč Meta Model API patří do stejného Secretu (klíč
`meta-api-key` → `OPSAI_META_API_KEY`) s `env` mapováním v overlay
patchi — do gitu nikdy.
