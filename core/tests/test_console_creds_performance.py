import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import time

import cred_vault

@pytest.fixture
def hub():
    hub_mock = MagicMock()
    hub_mock.state.system_state = {"global_config": {"cred_vault": {
        "secrets": {}, "buckets": {}, "blobs": {}
    }}}
    return hub_mock

@pytest.mark.asyncio
async def test_automation_cache_hits_and_invalidation(hub):
    cred_vault._AUTOMATION_CACHE.clear()
    
    cv = cred_vault._meta(hub)
    cv["secrets"] = {
        "bucket1": {
            "sec1": {"type": "console", "mode": "hub", "kv_name": "kv1", "updated_at": 1, "created_at": 1, "created_by": "test", "store": "local"}
        }
    }
    
    with patch('cred_vault._fetch_and_decrypt', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = {"username": "admin", "password": "123"}
        
        res1 = await cred_vault.automation_list_by_type(hub, "console")
        assert len(res1) == 1
        assert mock_fetch.call_count == 1
        
        # Second call hits cache
        res2 = await cred_vault.automation_list_by_type(hub, "console")
        assert len(res2) == 1
        assert mock_fetch.call_count == 1
        
        with patch('cred_vault._require_psk'):
            with patch('cred_vault._store_put', new_callable=AsyncMock):
                await cred_vault.put_secret(hub, "bucket1", "sec1", {"username": "admin2", "password": "321"}, mode="hub", sec_type="console")
        
        # Should fetch again
        res3 = await cred_vault.automation_list_by_type(hub, "console")
        assert len(res3) == 1
        assert mock_fetch.call_count == 2

        # Delete invalidates
        with patch('cred_vault._require_psk'):
            with patch('cred_vault._store_del', new_callable=AsyncMock):
                await cred_vault.delete_secret(hub, "bucket1", "sec1", psk="psk")
        
        res4 = await cred_vault.automation_list_by_type(hub, "console")
        assert len(res4) == 0

@pytest.mark.asyncio
async def test_automation_list_by_type_concurrent(hub):
    cred_vault._AUTOMATION_CACHE.clear()
    cv = cred_vault._meta(hub)
    cv["secrets"] = {
        "bucket1": {
            f"sec{i}": {"type": "console", "mode": "hub", "kv_name": f"kv{i}", "updated_at": 1, "created_at": 1, "created_by": "test", "store": "local"}
            for i in range(5)
        }
    }
    
    with patch('cred_vault._fetch_and_decrypt', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = {"username": "user", "password": "pw"}
        
        res = await cred_vault.automation_list_by_type(hub, "console")
        assert len(res) == 5
        assert mock_fetch.call_count == 5

# Test the FastAPI route directly
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from routes.console import register

def test_console_get_credentials_scoped(hub):
    app = FastAPI()
    app.state.hub = hub
    ctx = MagicMock()
    ctx._session_user.return_value = {"tenant_id": "t1"}
    ctx._is_admin.return_value = False
    ctx._is_tenant_admin.return_value = True
    ctx._effective_tenant = lambda req, ex: ex or "t1"
    
    register(app, hub, ctx)
    client = TestClient(app)
    
    async def mock_automation_list(hub, sec_type, buckets=None):
        if buckets == ["t1"]:
            return [{"value": {"credentials": [{"username": "u1", "password": "p1"}, {"username": "u2", "password": "p2"}]}}]
        elif buckets == ["__admin__"]:
            return [{"value": {"credentials": [{"username": "u2", "password": "p2"}, {"username": "admin", "password": "pw"}]}}]
        return []
    
    with patch('cred_vault.automation_list_by_type', new_callable=AsyncMock) as m:
        m.side_effect = mock_automation_list
        with patch('cred_vault.automation_get', new_callable=AsyncMock) as m_get:
            m_get.side_effect = Exception("Not found") # To avoid legacy __admin__ list secret
            
            resp = client.get("/api/console/credentials?tenant=t1")
            
            assert resp.status_code == 200
            data = resp.json()
            assert data["tenant"] == "t1"
            assert data["shared_global_count"] == 1  # admin user
            assert len(data["credentials"]) == 2
