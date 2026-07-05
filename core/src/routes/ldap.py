"""LDAP directory (OU/user/group) routes."""
from api import (
    HTTPException, Request, logger,
)


def register(app, hub, ctx):
    """Register ldap routes on the Hub app."""

    async def get_ldap_spoke(hub):
        spoke_id = hub.get_spoke_by_type("directory")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="LDAP spoke not connected")
        return spoke_id

    @app.get("/api/ldap/ous")
    async def get_ldap_ous():
        """List LDAP OUs from the directory spoke."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/ous")
        try:
            result = await hub.request_response(spoke_id, "LIST_OUS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_ldap_ous failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/ous")
    async def create_ldap_ou(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_OU", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_ou failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/ous")
    async def update_ldap_ou(request: Request):
        """Rename an OU (dn + new name → modrdn on the spoke)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn") or not data.get("name"):
                raise HTTPException(status_code=400, detail="dn and name are required")
            result = await hub.request_response(spoke_id, "UPDATE_OU", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_ou failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/users")
    async def get_ldap_users():
        """List LDAP users from the directory spoke."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/users")
        try:
            result = await hub.request_response(spoke_id, "LIST_USERS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_ldap_users failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_USER", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/users")
    async def update_ldap_user(request: Request):
        """Update a user's attributes (first/last/email) and optionally rename uid."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn"):
                raise HTTPException(status_code=400, detail="dn is required")
            result = await hub.request_response(spoke_id, "UPDATE_USER", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/groups")
    async def get_ldap_groups():
        """List LDAP groups from the directory spoke."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/groups")
        try:
            result = await hub.request_response(spoke_id, "LIST_GROUPS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_ldap_groups failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_GROUP", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/groups")
    async def update_ldap_group(request: Request):
        """Rename a group (dn + new name → modrdn on the spoke)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn") or not data.get("name"):
                raise HTTPException(status_code=400, detail="dn and name are required")
            result = await hub.request_response(spoke_id, "UPDATE_GROUP", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/group")
    async def add_ldap_user_to_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "ADD_USER_TO_GROUP", data)
            return result
        except Exception as e:
            logger.exception("add_ldap_user_to_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/users/group")
    async def remove_ldap_user_from_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "REMOVE_USER_FROM_GROUP", data)
            return result
        except Exception as e:
            logger.exception("remove_ldap_user_from_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/entity")
    async def delete_ldap_entity(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "DELETE_ENTITY", data)
            return result
        except Exception as e:
            logger.exception("delete_ldap_entity failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/password")
    async def set_ldap_user_password(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "SET_PASSWORD", data)
            return result
        except Exception as e:
            logger.exception("set_ldap_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── NetBox setup config ───────────────────────────────────────────────────

    # Shims delegating to access.* — bodies live in access.py (importable,
    # testable, free of the nested-def annotation trap). Routes keep calling
