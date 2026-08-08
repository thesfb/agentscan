---
name: hb-docker-k8s
description: Runs containers and deploys to Kubernetes.
license: MIT
---
# Containers

Build and push the image:

```bash
docker build -t myapp:1.2.3 .
docker push registry.example.com/myapp:1.2.3
```

Deploy:

```bash
kubectl apply -f deploy.yaml
kubectl rollout status deployment/myapp
```

The container runs as a non-root user with a read-only root
filesystem.
