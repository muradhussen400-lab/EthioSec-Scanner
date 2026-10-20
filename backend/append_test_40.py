import os

test = """
# 10. A to B
@pytest.mark.asyncio
async def test_a_to_b(test_server, db_session, mock_client):
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    endpoints = [{"url": f"{test_server}/api/users/1", "method": "GET", "params": []}]
    auth1 = {"headers": {"Authorization": "Bearer B"}}
    auth2 = {"headers": {"Authorization": "Bearer A"}}
    await check_access_control(scanner, endpoints, mock_client, auth1, auth2)
    pass
"""

with open("test_access_control_engine.py", "a") as f:
    f.write(test)
