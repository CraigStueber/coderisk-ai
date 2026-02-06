"""
Safe version - SQL Injection Prevention
This file demonstrates proper SQL query parameterization.
"""
import sqlite3
from typing import Optional, List, Dict, Any


# SAFE: Using parameterized queries with sqlite3
def get_user_safe(name: str, conn: sqlite3.Connection) -> Optional[Dict]:
    """Safely retrieve user using parameterized query"""
    query = "SELECT * FROM users WHERE name = ?"
    cursor = conn.execute(query, (name,))
    return cursor.fetchone()


def get_user_by_id_safe(user_id: int, conn: sqlite3.Connection) -> Optional[Dict]:
    """Safely retrieve user by ID using parameterized query"""
    query = "SELECT * FROM users WHERE id = ?"
    cursor = conn.execute(query, (user_id,))
    return cursor.fetchone()


def search_users_safe(search_term: str, conn: sqlite3.Connection) -> List[Dict]:
    """Safely search users using parameterized query"""
    query = "SELECT * FROM users WHERE name LIKE ? OR email LIKE ?"
    search_pattern = f"%{search_term}%"
    cursor = conn.execute(query, (search_pattern, search_pattern))
    return cursor.fetchall()


# SAFE: Using named parameters
def update_user_email_safe(user_id: int, new_email: str, conn: sqlite3.Connection) -> bool:
    """Safely update user email using named parameters"""
    query = "UPDATE users SET email = :email WHERE id = :user_id"
    try:
        conn.execute(query, {"email": new_email, "user_id": user_id})
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        return False


def insert_user_safe(username: str, email: str, conn: sqlite3.Connection) -> int:
    """Safely insert new user using parameterized query"""
    query = "INSERT INTO users (name, email) VALUES (?, ?)"
    try:
        cursor = conn.execute(query, (username, email))
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        conn.rollback()
        raise


# SAFE: Using ORM (SQLAlchemy example pattern)
def get_user_by_name_orm(name: str, session) -> Optional[Any]:
    """
    Safely retrieve user using ORM (prevents SQL injection).
    This is a pattern example - actual implementation depends on ORM setup.
    """
    # Example: User.query.filter_by(name=name).first()
    # ORM automatically parameterizes queries
    pass


def search_users_orm(search_term: str, session) -> List[Any]:
    """
    Safely search users using ORM with parameterized filter.
    """
    # Example: User.query.filter(User.name.contains(search_term)).all()
    pass


# SAFE: Complex query with multiple parameters
def get_users_by_criteria_safe(
    min_age: int,
    max_age: int,
    country: str,
    conn: sqlite3.Connection
) -> List[Dict]:
    """Safely retrieve users with multiple criteria"""
    query = """
        SELECT * FROM users 
        WHERE age >= ? AND age <= ? AND country = ?
        ORDER BY name
    """
    cursor = conn.execute(query, (min_age, max_age, country))
    return cursor.fetchall()


# SAFE: Query with IN clause
def get_users_by_ids_safe(user_ids: List[int], conn: sqlite3.Connection) -> List[Dict]:
    """Safely retrieve multiple users by IDs using parameterized IN clause"""
    if not user_ids:
        return []
    
    # Create placeholders for each ID
    placeholders = ','.join('?' * len(user_ids))
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"
    cursor = conn.execute(query, user_ids)
    return cursor.fetchall()


# SAFE: Transaction with multiple parameterized queries
def transfer_funds_safe(
    from_account_id: int,
    to_account_id: int,
    amount: float,
    conn: sqlite3.Connection
) -> bool:
    """Safely transfer funds using transaction with parameterized queries"""
    try:
        # Start transaction
        conn.execute("BEGIN TRANSACTION")
        
        # Deduct from source account
        conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
            (amount, from_account_id)
        )
        
        # Add to destination account
        conn.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (amount, to_account_id)
        )
        
        # Log transaction
        conn.execute(
            "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
            (from_account_id, to_account_id, amount)
        )
        
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Transaction failed: {e}")
        return False


# SAFE: Prepared statements pattern
def create_prepared_statement_example(conn: sqlite3.Connection):
    """
    Example of using cursor for repeated queries with different parameters.
    """
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE age > ? AND country = ?"
    
    # Execute same query with different parameters
    results_us = cursor.execute(query, (18, 'US')).fetchall()
    results_uk = cursor.execute(query, (18, 'UK')).fetchall()
    
    return results_us, results_uk


# SAFE: Query builder with validation
def build_safe_query(
    table: str,
    columns: List[str],
    where_clause: Dict[str, Any],
    conn: sqlite3.Connection
) -> List[Dict]:
    """
    Build and execute safe query dynamically with validation.
    IMPORTANT: Only column/table names are dynamic, values are parameterized.
    """
    # Validate table name (whitelist approach)
    allowed_tables = ['users', 'accounts', 'transactions']
    if table not in allowed_tables:
        raise ValueError(f"Invalid table name: {table}")
    
    # Validate column names (whitelist approach)
    allowed_columns = {
        'users': ['id', 'name', 'email', 'age', 'country'],
        'accounts': ['id', 'user_id', 'balance'],
        'transactions': ['id', 'from_account', 'to_account', 'amount', 'timestamp']
    }
    
    for col in columns:
        if col not in allowed_columns.get(table, []):
            raise ValueError(f"Invalid column name: {col}")
    
    # Build query with parameterized values
    column_str = ', '.join(columns)
    where_parts = []
    where_values = []
    
    for col, value in where_clause.items():
        if col not in allowed_columns.get(table, []):
            raise ValueError(f"Invalid where column: {col}")
        where_parts.append(f"{col} = ?")
        where_values.append(value)
    
    where_str = ' AND '.join(where_parts)
    query = f"SELECT {column_str} FROM {table} WHERE {where_str}"
    
    cursor = conn.execute(query, where_values)
    return cursor.fetchall()
