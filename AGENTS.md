# Summit MCP Operations Contract

Before changing or deploying this service, read the canonical platform contract:

https://github.com/DDePuy2015/summit-mcp-ops

Required references:

- `PLATFORM_CONTEXT.md`
- `DEPLOYMENT_RUNBOOK.md`
- `SERVICE_MAP.yaml`

Every Azure deployment requires a new `deploy/datto/...` branch, a pull request
merged into `main`, an immutable ACR image digest, a staged Container Apps
rollout, and a deployment record in the operations repository. Keep this
repository limited to Datto RMM MCP code; do not add proxy, IT Glue,
Autotask, or Foundry implementation files here.
