"""
Test cases for SQL injection safe-evidence downgrade.
Demonstrates when SQL construction is downgraded due to parameterization or allowlisting.
"""

import sqlite3
from typing import List


# ==========================================
# UNSAFE: No Safe Evidence (High Severity)
# ==========================================

def unsafe_direct_interpolation(user_id: int):
    """
    Direct interpolation without parameterization.
    Should be flagged as HIGH severity SQL injection.
    """
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    
    # INJECTION.SQL - HIGH severity, no safe evidence
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()


def unsafe_string_concat(username: str):
    """
    String concatenation without parameters.
    Should be flagged as HIGH severity.
    """
    # INJECTION.SQL - HIGH severity
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)


def unsafe_table_name_injection(table: str):
    """
    Dynamic table name without allowlist.
    Should be flagged as HIGH severity.
    """
    # INJECTION.SQL - HIGH severity
    query = f"SELECT * FROM {table} WHERE active = 1"
    cursor.execute(query)


# ==========================================
# SAFE EVIDENCE: Parameterized (Downgraded)
# ==========================================

def safe_with_placeholders(ids: List[int]):
    """
    Placeholder pattern with parameterized execute.
    Should be DOWNGRADED - safe evidence detected.
    """
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    
    # INJECTION.SQL - DOWNGRADED (safe evidence: placeholders+parameterized)
    placeholders = ",".join(["%s"] * len(ids))
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"
    cursor.execute(query, ids)
    return cursor.fetchall()


def safe_with_question_marks(user_ids: List[int]):
    """
    Question mark placeholders with parameterized execute.
    Should be DOWNGRADED.
    """
    # INJECTION.SQL - DOWNGRADED (safe evidence: placeholders+parameterized)
    placeholders = ",".join(["?"] * len(user_ids))
    query = f"SELECT * FROM orders WHERE user_id IN ({placeholders})"
    cursor.execute(query, user_ids)


def safe_params_nearby(user_id: int):
    """
    Parameterized execute detected nearby.
    Should be DOWNGRADED.
    """
    # INJECTION.SQL - DOWNGRADED (safe evidence: parameterized)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query, (user_id,))


def safe_with_tuple_params(email: str, status: str):
    """
    Parameterized execute with tuple.
    Should be DOWNGRADED.
    """
    # INJECTION.SQL - DOWNGRADED (safe evidence: parameterized)
    query = f"UPDATE users SET status = ? WHERE email = ?"
    cursor.execute(query, (status, email))


# ==========================================
# SAFE EVIDENCE: Allowlist (Downgraded)
# ==========================================

def safe_allowlist_table(table_name: str):
    """
    Table name from allowlist.
    Should be DOWNGRADED - allowlist evidence detected.
    """
    ALLOWED_TABLES = ['users', 'orders', 'products', 'sessions']
    
    # INJECTION.SQL - DOWNGRADED (safe evidence: allowlist)
    if table_name in ALLOWED_TABLES:
        query = f"SELECT * FROM {table_name}"
        cursor.execute(query)


def safe_allowlist_column(sort_column: str):
    """
    Column from allowlist.
    Should be DOWNGRADED.
    """
    ALLOWED_COLUMNS = ['id', 'name', 'created_at', 'updated_at']
    
    # INJECTION.SQL - DOWNGRADED (safe evidence: allowlist)
    if sort_column in ALLOWED_COLUMNS:
        query = f"SELECT * FROM users ORDER BY {sort_column}"
        cursor.execute(query)


def safe_dict_allowlist(field: str):
    """
    Field from dictionary keys (allowlist).
    Should be DOWNGRADED.
    """
    FIELD_MAP = {
        'username': 'user_name',
        'email': 'email_address',
        'status': 'account_status'
    }
    
    # INJECTION.SQL - DOWNGRADED (safe evidence: allowlist)
    column = FIELD_MAP.get(field)
    if column:
        query = f"SELECT {column} FROM users"
        cursor.execute(query)


def safe_validated_identifier(table: str):
    """
    Identifier validated against allowlist.
    Should be DOWNGRADED.
    """
    # INJECTION.SQL - DOWNGRADED (safe evidence: allowlist)
    if table in ['users', 'products']:
        query = f"DELETE FROM {table} WHERE expired = 1"
        cursor.execute(query)


# ==========================================
# MIXED: Partial Evidence
# ==========================================

def partial_safe_no_params(ids: List[int]):
    """
    Placeholder pattern but no parameterized execute visible.
    Might still be flagged but with some downgrade.
    """
    # May be downgraded if pattern is detected
    placeholders = ",".join(["%s"] * len(ids))
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"
    # No execute with params - might be flagged


def allowlist_but_complex(table: str, column: str):
    """
    One identifier from allowlist, one not.
    Mixed evidence - behavior depends on implementation.
    """
    ALLOWED_TABLES = ['users', 'orders']
    
    if table in ALLOWED_TABLES:
        # Table is safe, but column is not validated
        query = f"SELECT {column} FROM {table}"
        cursor.execute(query)


# Stub
def cursor():
    pass
