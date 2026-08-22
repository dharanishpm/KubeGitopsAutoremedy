# remediation

Remediation agent that turns a confirmed root cause into a proposed fix: generates a
Helm/YAML patch, opens a GitHub pull request against the GitOps repo, and waits for
human approval before ArgoCD syncs the change to the cluster.
