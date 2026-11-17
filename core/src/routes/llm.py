"""Scoped API for the local inference pool."""

import ast
import json

from fastapi import HTTPException, Request, Response

from access import read_scope, request_effective_tenant, same_tenant, tenant_is_shared
import instance_vault
from llm_cloud import valid_endpoint
from llm_pool import diagnostic


async def validate_cloud_profiles(hub, profiles, session):
    """Project cloud settings onto Vault-only, same-tenant configuration records."""
    if not isinstance(profiles, list) or len(profiles) > 32:
        raise HTTPException(400, "Provide a list of at most 32 cloud profiles")
    output = []
    for row in profiles:
        if not isinstance(row, dict) or not valid_endpoint(row.get("url")):
            raise HTTPException(400, "A public cloud chat-completions HTTPS URL is required")
        tenant, model = row.get("tenant"), row.get("model")
        ref = row.get("vault_credential")
        if (not isinstance(tenant, str) or not hub.state.get_tenant(tenant)
                or not isinstance(model, str) or not 0 < len(model) <= 200
                or row.get("task") != "pr_summary" or not isinstance(ref, dict)
                or not isinstance(ref.get("bucket"), str)
                or not same_tenant(ref["bucket"], tenant)
                or not isinstance(ref.get("name"), str) or not ref["name"].strip()):
            raise HTTPException(400, "Supply a model, PR summary task, and same-tenant Vault reference")
        safe = {"url": row["url"], "tenant": tenant, "model": model, "task": "pr_summary",
                "vault_credential": {"bucket": ref["bucket"], "name": ref["name"]}}
        try:
            await instance_vault.validate_ref(
                hub, safe, session, is_admin=True, storage_key="llm_cloud_profiles")
        except HTTPException as exc:
            raise HTTPException(400, "Cloud credential could not be validated") from exc
        output.append(safe)
    return output


def register(app, hub, ctx):
    """Register the exact-model local inference endpoint."""

    def scoped_tenant(request, tenant):
        """Require an authenticated session and a concrete tenant scope."""
        session = ctx._session_user(request)
        if not session:
            raise HTTPException(401, "Authentication required")
        effective = request_effective_tenant(session, request, tenant)
        if (not effective or tenant_is_shared(effective)
                or (tenant and not same_tenant(tenant, effective))
                or not hub.state.get_tenant(effective)
                or read_scope(session, effective) != "full"):
            raise HTTPException(403, "Select a tenant you can access")
        return effective

    @app.get("/api/llm/models")
    async def models(request: Request, response: Response, tenant: str = None):
        """Return the caller's cached catalog without querying any worker."""
        effective = scoped_tenant(request, tenant)
        response.headers["Cache-Control"] = "no-store"
        return {"models": hub.llm_pool.models_for(effective),
                "issues": hub.llm_pool.diagnostics_for(effective)}

    @app.post("/api/llm/complete")
    async def complete(request: Request, response: Response, data: dict, tenant: str = None):
        """Run a bounded completion in the caller's selected tenant."""
        response.headers["Cache-Control"] = "no-store"
        return await hub.llm_pool.complete(scoped_tenant(request, tenant), data)

    @app.post("/api/llm/check")
    async def check(request: Request, response: Response, data: dict, tenant: str = None):
        """Replay a synthetic regression fixture through an exact model in the pool."""
        effective = scoped_tenant(request, tenant)
        response.headers["Cache-Control"] = "no-store"
        fixture = data.get("fixture")
        if fixture == "indentation":
            expected = "def classify(value):\n    if value > 0:\n        return 1\n    return 0\n"
            prompt = "Return this exact Python source, with no Markdown or explanation:\n" + expected
            output_format = "python"
        elif fixture == "json":
            expected = {"items": [{"label": "CPU", "count": 2}]}
            prompt = "Return only this exact JSON object:\n" + json.dumps(expected)
            output_format = "json"
        else:
            raise HTTPException(400, "Choose the json or indentation fixture")

        # Never use user data as a diagnostic prompt or return the raw test output.
        result = await hub.llm_pool.complete(effective, {
            "model": data.get("model"), "digest": data.get("digest"),
            "prompt": prompt, "format": output_format,
        })
        if result.get("status") != "SUCCESS":
            return result
        text = result.pop("text")
        try:
            matches = (ast.dump(ast.parse(text)) == ast.dump(ast.parse(expected))
                       if fixture == "indentation" else json.loads(text) == expected)
        except (SyntaxError, ValueError, RecursionError):
            matches = False
        if not matches:
            result.update(status="ERROR", **diagnostic("fixture_mismatch"))
        return {"fixture": fixture, **result}
