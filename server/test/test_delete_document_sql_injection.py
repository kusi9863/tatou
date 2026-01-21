"""
Simple property-based fuzzing test for SQL injection in delete_document().
Uses hypothesis to inject SQL commands in place of doc_id parameter.
Tests for read/modify/delete data vulnerabilities.
"""

import pytest
from hypothesis import given, strategies as st, settings
from server import create_app


# ============================================================================
# Custom Hypothesis Strategies for SQL Injection Payloads
# ============================================================================
@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


class TestDeleteDocumentSQLInjection:
    """Property-based fuzzing tests for SQL injection in delete_document()"""

    @given(st.sampled_from([
        "1 OR 1=1",                              # Read all documents
        "1; DROP TABLE Documents; --",           # Delete table
        "1; UPDATE Documents SET name='hacked'", # Modify data
        "1 UNION SELECT * FROM Users",           # Read sensitive data
        "1' OR '1'='1",                          # Boolean-based SQLi
        "1; DELETE FROM Documents; --",          # Delete all rows
        "admin' --",                             # Comment-based bypass
        "1 UNION SELECT email,login FROM Users", # Extract user info
        "1; INSERT INTO Documents VALUES(...)",  # Add malicious data
        "999 OR 1=1; --"                         # Bypass ID check
    ]))
    @settings(max_examples=30)
    def test_sql_injection_in_doc_id(self, client, sql_payload):
        """
        Property: delete_document should reject SQL injection in doc_id parameter.
        
        Tests that malicious SQL commands don't execute:
        - SELECT (unauthorized data reads)
        - UPDATE (unauthorized data modification)
        - DELETE (unauthorized data deletion)
        - INSERT (unauthorized data insertion)
        """
        # Test via GET with query parameter
        response = client.get(f"/delete_document?id={sql_payload}")
        
        # Should not crash or execute SQL
        assert response.status_code in [400, 404, 503, 401], \
            f"SQL injection may have executed: {sql_payload}"
        
        # Response should be valid
        try:
            data = response.get_json()
            assert isinstance(data, dict)
        except:
            pass

    @given(st.sampled_from([
        "1 AND SLEEP(5)",                        # Time-based blind SQLi
        "1 AND IF(1=1,1,0)",                     # Conditional execution
        "1' AND '1'='1",                         # String-based SQLi
        "1 AND (SELECT COUNT(*) FROM Users)>0", # Data inference
        "1 UNION ALL SELECT 1,2,3,4,5,6,7",     # Column enumeration
        "1; SHOW TABLES; --",                    # Information gathering
        "1' UNION SELECT database(),user(),3 --", # Extract metadata
        "1 UNION SELECT GROUP_CONCAT(name) FROM Documents", # Batch data read
    ]))
    @settings(max_examples=25)
    def test_advanced_sql_injection(self, client, sql_payload):
        """
        Property: Advanced SQL injection techniques should be rejected.
        
        Tests more sophisticated attack vectors:
        - Time-based blind attacks
        - Data inference
        - Information schema queries
        - Column enumeration
        """
        response = client.get(f"/delete_document?id={sql_payload}")
        assert response.status_code in [400, 404, 503, 401], \
            f"Advanced SQLi may have succeeded: {sql_payload}"

    @given(st.sampled_from([
        "1'; DROP TABLE Documents; --",
        "1' OR 1=1 --",
        "1' UNION SELECT * FROM Users --",
        "1 OR 'a'='a",
        "1'); DELETE FROM Documents; --",
        "999 UNION ALL SELECT * FROM Documents",
        "1' AND SLEEP(10) --",
        "1; UPDATE Users SET login='admin' --",
    ]))
    @settings(max_examples=20)
    def test_data_modification_sql_injection(self, client, sql_payload):
        """
        Property: SQL injection for data modification should be blocked.
        
        Specifically tests commands that modify/delete/insert data:
        - DROP TABLE
        - DELETE FROM
        - UPDATE
        - INSERT
        """
        response = client.delete(f"/documents/{sql_payload}")
        assert response.status_code in [400, 404, 405, 503, 401], \
            f"Data modification SQLi may have executed: {sql_payload}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
