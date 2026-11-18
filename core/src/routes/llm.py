"""Scoped API for the local inference pool."""

import ast
import json
import re

from fastapi import HTTPException, Request, Response

from access import (read_scope, request_effective_tenant, safe_external_url, same_tenant,
                    tenant_is_shared, write_scope)
import instance_vault
from llm_cloud import TOKEN_LIMIT_FIELDS, valid_endpoint
from llm_pool import HARDWARE_LIMITS, SAMPLING_LIMITS, diagnostic, model_minimums, model_sampling, valid_model


POOL_SETTINGS = ("llm_task_models", "llm_ab_pr_repos", "llm_qualification_candidates", "llm_cloud_profiles")
TASK_KEY = r"[A-Za-z0-9_\-]{1,64}"
REPO_KEY = r"[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}"
SAN_LIMIT = 255

ROUTING_FORM_SCHEMA = {
    "addModel": [
        {"name": "task", "label": "Task", "required": True, "pattern": TASK_KEY, "placeholder": "pr_summary"},
        {"name": "artifact", "label": "Approved model", "required": True,
         "source": "models", "placeholder": "Select a reported model"},
        {"name": "vcpus", "label": "Minimum vCPUs", "type": "number", "maximum": HARDWARE_LIMITS["vcpus"]},
        {"name": "ram", "label": "Minimum RAM (bytes)", "type": "number", "maximum": HARDWARE_LIMITS["ram_bytes"]},
        {"name": "temperature", "label": "Temperature (blank = default)", "type": "number",
         "maximum": SAMPLING_LIMITS["temperature"], "step": 0.05},
        {"name": "top_p", "label": "Top-p (blank = default)", "type": "number",
         "maximum": SAMPLING_LIMITS["top_p"], "step": 0.05},
    ],
    "repo": [
        {"name": "repo", "label": "Repository", "required": True, "pattern": REPO_KEY, "placeholder": "owner/repo"},
        {"name": "tenant", "label": "Tenant", "required": True, "source": "tenants", "placeholder": "Select a tenant"},
        {"name": "certificate", "label": "AppBuilder certificate SAN", "required": True, "maxlength": SAN_LIMIT},
        {"name": "overflow", "label": "Allow cloud overflow for public PRs", "type": "checkbox"},
    ],
}


def cloud_profile_reference(row):
    """Project a profile onto fields safe to store or return to the browser."""
    ref = row.get("vault_credential") if isinstance(row, dict) else None
    if not isinstance(ref, dict) or not valid_endpoint(row.get("url")):
        return None
    if not all(isinstance(row.get(key), str) for key in ("tenant", "model", "task")):
        return None
    if not all(isinstance(ref.get(key), str) for key in ("bucket", "name")):
        return None
    limit_field = row.get("token_limit_field", "max_tokens")
    if limit_field not in TOKEN_LIMIT_FIELDS:
        return None
    return {**{key: row[key] for key in ("url", "tenant", "model", "task")},
            "token_limit_field": limit_field,
            "vault_credential": {key: ref[key] for key in ("bucket", "name")}}


def validate_pool_config(hub, config):
    """Validate routing and qualification policy before storing it."""
    if "llm_task_models" in config:
        tasks = config["llm_task_models"]
        if not isinstance(tasks, dict) or len(tasks) > 32 or any(
                not re.fullmatch(TASK_KEY, task)
                or not isinstance(models, list) or len(models) > 8
                or any(not isinstance(row, dict) or not valid_model(row.get("model"), row.get("digest"))
                       or model_minimums(row) is None
                       or model_sampling(row) is None
                       or row.keys() - {"model", "digest", "min_vcpus", "min_ram_bytes", *SAMPLING_LIMITS}
                       for row in models)
                for task, models in tasks.items()):
            raise HTTPException(400, "Task profiles require ordered lists of pinned model artifacts")
    if "llm_ab_pr_repos" in config:
        repos = config["llm_ab_pr_repos"]
        if not isinstance(repos, dict) or len(repos) > 256 or any(
                not re.fullmatch(REPO_KEY, name)
                or not isinstance(row, dict) or not isinstance(row.get("tenant"), str)
                or tenant_is_shared(row["tenant"]) or not hub.state.get_tenant(row["tenant"])
                or not isinstance(row.get("certificate"), str)
                or not 0 < len(row["certificate"].strip()) <= SAN_LIMIT
                or not isinstance(row.get("allow_public_cloud", False), bool)
                or row.keys() - {"tenant", "certificate", "allow_public_cloud"}
                for name, row in repos.items()):
            raise HTTPException(400, "Repository policies require a tenant and a pinned certificate SAN")
    if "llm_qualification_candidates" in config:
        candidates = config["llm_qualification_candidates"]
        if not isinstance(candidates, dict) or len(candidates) > 32 or any(
                not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key)
                or not isinstance(row, dict) or not isinstance(row.get("worker"), str)
                or not 0 < len(row["worker"]) <= 255 or not isinstance(row.get("label"), str)
                or not 0 < len(row["label"].strip()) <= 100
                or row.keys() - {"worker", "label"}
                for key, row in candidates.items()):
            raise HTTPException(400, "Candidate profiles require a key, worker and label")


async def validate_cloud_profiles(hub, profiles, session):
    """Project cloud settings onto Vault-only, same-tenant configuration records."""
    if not isinstance(profiles, list) or len(profiles) > 32:
        raise HTTPException(400, "Provide a list of at most 32 cloud profiles")
    output = []
    for supplied in profiles:
        row = cloud_profile_reference(supplied)
        if row is None or not safe_external_url(row["url"]):
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
        try:
            await instance_vault.validate_ref(
                hub, row, session, is_admin=True, storage_key="llm_cloud_profiles")
        except HTTPException as exc:
            raise HTTPException(400, "Cloud credential could not be validated") from exc
        output.append(row)
    return output


def register(app, hub, ctx):
    """Register the exact-model local inference endpoint."""

    def require_admin(request):
        """Restrict fleet diagnostics and synthetic jobs to global admins."""
        session = ctx._session_user(request)
        if not session:
            raise HTTPException(401, "Authentication required")
        if not ctx._is_admin(session):
            raise HTTPException(403, "Global administrator required")
        return session

    @app.get("/api/llm/admin/settings")
    async def settings(request: Request, response: Response):
        """Return fleet routing policies and Vault references, never secret values."""
        require_admin(request)
        response.headers["Cache-Control"] = "no-store"
        config = hub.state.get_global_config()
        cloud = config.get("llm_cloud_profiles")
        workers = hub.state.system_state.get("module_metadata", {})
        return {**{key: config.get(key, {}) for key in POOL_SETTINGS[:-1]},
                "routing_form_schema": ROUTING_FORM_SCHEMA,
                "llm_cloud_profiles": [row for item in (cloud if isinstance(cloud, list) else [])
                                       if (row := cloud_profile_reference(item)) is not None],
                "test_workers": [{"key": key, "label": hub.state.get_module_name(key)}
                                 for key, row in workers.items() if isinstance(row, dict)
                                 and row.get("module_type") == "llm"
                                 and tenant_is_shared(row.get("tenant_id"))
                                 and hub.approved_modules.get(key)]}

    @app.post("/api/llm/admin/settings")
    async def save_settings(request: Request, data: dict):
        """Validate and save only the supplied LLM settings."""
        session = require_admin(request)
        if not data or data.keys() - set(POOL_SETTINGS):
            raise HTTPException(400, "Only LLM settings can be saved here")
        validate_pool_config(hub, data)
        if "llm_cloud_profiles" in data:
            data["llm_cloud_profiles"] = await validate_cloud_profiles(
                hub, data["llm_cloud_profiles"], session)
        hub.state.system_state.setdefault("global_config", {}).update(data)
        hub.state._mark_dirty()
        return {"status": "ok"}

    @app.get("/api/llm/admin/dashboard")
    async def dashboard(request: Request, response: Response):
        """Read worker inventory and bounded prompt-free metrics."""
        require_admin(request)
        response.headers["Cache-Control"] = "no-store"
        return hub.llm_pool.dashboard()

    @app.post("/api/llm/admin/qualify", status_code=202)
    async def start_qualification(request: Request, data: dict):
        """Start qualification only on its configured Shared worker."""
        require_admin(request)
        candidate = data.get("candidate")
        if not isinstance(candidate, str) or not hub.llm_pool.start_qualification(candidate):
            raise HTTPException(409, "Candidate is not configured or its worker is unavailable")
        return {"status": "accepted"}

    def scoped_tenant(request, tenant, run=False):
        """Require a session in a concrete tenant; running a job also needs write access.

        Inference holds a CPU slot that other users, possibly in other tenants on
        Shared workers, are waiting for, so it is an action: a view-only member may
        list models but not run them.
        """
        session = ctx._session_user(request)
        if not session:
            raise HTTPException(401, "Authentication required")
        effective = request_effective_tenant(session, request, tenant)
        if (not effective or tenant_is_shared(effective)
                or (tenant and not same_tenant(tenant, effective))
                or not hub.state.get_tenant(effective)
                or read_scope(session, effective) != "full"):
            raise HTTPException(403, "Select a tenant you can access")
        if run and write_scope(session, effective) != "full":
            raise HTTPException(403, "Running LLM jobs requires edit access to this tenant")
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
        return await hub.llm_pool.complete(scoped_tenant(request, tenant, run=True), data)

    @app.post("/api/llm/check")
    async def check(request: Request, response: Response, data: dict, tenant: str = None):
        """Replay a synthetic regression fixture through an exact model in the pool."""
        effective = scoped_tenant(request, tenant, run=True)
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
