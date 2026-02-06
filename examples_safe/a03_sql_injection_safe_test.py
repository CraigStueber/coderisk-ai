"""
Safe version - SQL Injection Prevention
This file demonstrates proper SQL query parameterization.
"""
import sqlite3
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, select


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


# SAFE: Query with IN clause using SQLAlchemy Core
def get_users_by_ids_safe(user_ids: List[int], conn: sqlite3.Connection) -> List[Dict]:
    """Safely retrieve multiple users by IDs using SQLAlchemy Core - NO SQL string building"""
    if not user_ids:
        return []
    
    # Create SQLAlchemy engine for in-memory database
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
        future=True
    )
    
    # Define metadata and reflect the users table
    metadata = MetaData()
    users_table = Table('users', metadata, autoload_with=engine)
    
    # Build SELECT using SQLAlchemy with IN expression (no string construction)
    stmt = select(users_table).where(users_table.c.id.in_(user_ids))
    
    # Execute query
    with engine.connect() as sqlalchemy_conn:
        result = sqlalchemy_conn.execute(stmt)
        return [dict(row._mapping) for row in result]


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


# SAFE: Query builder using SQLAlchemy Core (no SQL string construction)
def build_safe_query_sqlalchemy(
    table_key: str,
    column_keys: List[str],
    where_clause: Dict[str, Any],
    engine
) -> List[Dict]:
    """
    Build and execute safe query using SQLAlchemy Core.
    IMPORTANT: Uses SQLAlchemy Table and Column objects - NO SQL string construction.
    All identifiers are SQLAlchemy objects, not strings interpolated into SQL.
    """
    # Define metadata for reflection
    metadata = MetaData()
    
    # Define allowed tables as SQLAlchemy Table objects
    ALLOWED_TABLES = {
        'users': Table('users', metadata, autoload_with=engine),
        'accounts': Table('accounts', metadata, autoload_with=engine),
        'transactions': Table('transactions', metadata, autoload_with=engine)
    }
    
    # Validate table name
    if table_key not in ALLOWED_TABLES:
        raise ValueError(f"Invalid table name: {table_key}")
    
    validated_table = ALLOWED_TABLES[table_key]  # SQLAlchemy Table object
    
    # Define allowed columns as SQLAlchemy Column objects (not strings)
    ALLOWED_COLUMNS = {
        'users': {
            'id': validated_table.c.id,
            'name': validated_table.c.name,
            'email': validated_table.c.email,
            'age': validated_table.c.age,
            'country': validated_table.c.country
        } if table_key == 'users' else {},
        'accounts': {
            'id': ALLOWED_TABLES['accounts'].c.id,
            'user_id': ALLOWED_TABLES['accounts'].c.user_id,
            'balance': ALLOWED_TABLES['accounts'].c.balance
        } if table_key == 'accounts' else {},
        'transactions': {
            'id': ALLOWED_TABLES['transactions'].c.id,
            'from_account': ALLOWED_TABLES['transactions'].c.from_account,
            'to_account': ALLOWED_TABLES['transactions'].c.to_account,
            'amount': ALLOWED_TABLES['transactions'].c.amount,
            'timestamp': ALLOWED_TABLES['transactions'].c.timestamp
        } if table_key == 'transactions' else {}
    }
    
    # Validate and retrieve column objects
    allowed_cols = ALLOWED_COLUMNS.get(table_key, {})
    validated_columns = []
    for col_key in column_keys:
        if col_key not in allowed_cols:
            raise ValueError(f"Invalid column name: {col_key}")
        validated_columns.append(allowed_cols[col_key])  # SQLAlchemy Column object
    
    # Build SELECT statement using SQLAlchemy (no string construction)
    stmt = select(*validated_columns).select_from(validated_table)
    
    # Build WHERE clause using SQLAlchemy expressions (not strings)
    for col_key, value in where_clause.items():
        if col_key not in allowed_cols:
            raise ValueError(f"Invalid where column: {col_key}")
        col_obj = allowed_cols[col_key]  # SQLAlchemy Column object
        stmt = stmt.where(col_obj == value)  # SQLAlchemy expression, not string
    
    # Execute query
    with engine.connect() as conn:
        result = conn.execute(stmt)
        return [dict(row._mapping) for row in result]


# SAFE: Query builder using SQLAlchemy Core (replaces string-based approach)
def build_safe_query(
    table: str,
    columns: List[str],
    where_clause: Dict[str, Any],
    conn: sqlite3.Connection
) -> List[Dict]:
    """
    Build and execute safe query using SQLAlchemy Core - NO SQL string construction.
    Uses SQLAlchemy Table and Column objects exclusively.
    Compatible with sqlite3.Connection by creating temporary SQLAlchemy engine.
    """
    # Create SQLAlchemy engine from sqlite3 connection
    # Get database path from connection (for in-memory or file-based DBs)
    import re
    from sqlalchemy.pool import StaticPool
    
    # Create engine that uses the existing connection's database
    # For sqlite3 connections, create a new engine with the same database
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
        future=True
    )
    
    # Define metadata for reflection
    metadata = MetaData()
    
    # Define allowed tables as SQLAlchemy Table objects
    ALLOWED_TABLES = {
        'users': Table('users', metadata, autoload_with=engine),
        'accounts': Table('accounts', metadata, autoload_with=engine),
        'transactions': Table('transactions', metadata, autoload_with=engine)
    }
    
    # Validate table name
    if table not in ALLOWED_TABLES:
        raise ValueError(f"Invalid table name: {table}")
    
    validated_table = ALLOWED_TABLES[table]  # SQLAlchemy Table object
    
    # Define allowed columns as SQLAlchemy Column objects (not strings)
    ALLOWED_COLUMNS = {
        'users': {col: validated_table.c[col] for col in ['id', 'name', 'email', 'age', 'country']},
        'accounts': {col: ALLOWED_TABLES['accounts'].c[col] for col in ['id', 'user_id', 'balance']},
        'transactions': {col: ALLOWED_TABLES['transactions'].c[col] for col in ['id', 'from_account', 'to_account', 'amount', 'timestamp']}
    }
    
    # Validate and retrieve column objects
    allowed_cols = ALLOWED_COLUMNS.get(table, {})
    validated_column_objects = []
    for col in columns:
        if col not in allowed_cols:
            raise ValueError(f"Invalid column name: {col}")
        validated_column_objects.append(allowed_cols[col])  # SQLAlchemy Column object
    
    # Build SELECT statement using SQLAlchemy (no string construction)
    stmt = select(*validated_column_objects).select_from(validated_table)
    
    # Build WHERE clause using SQLAlchemy expressions (not strings)
    for col, value in where_clause.items():
        if col not in allowed_cols:
            raise ValueError(f"Invalid where column: {col}")
        col_obj = allowed_cols[col]  # SQLAlchemy Column object
        stmt = stmt.where(col_obj == value)  # SQLAlchemy expression with parameter binding
    
    # Execute query using SQLAlchemy engine
    with engine.connect() as sqlalchemy_conn:
        result = sqlalchemy_conn.execute(stmt)
        return [dict(row._mapping) for row in result]



# SAFE: Example usage of SQLAlchemy Core approach (eliminates SQL string construction)
def example_sqlalchemy_usage():
    """
    Demonstrates using build_safe_query_sqlalchemy() with SQLAlchemy Core.
    This approach completely eliminates SQL string construction.
    """
    # Create in-memory SQLite engine for demonstration
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    
    # Create sample table
    metadata = MetaData()
    users_table = Table(
        'users',
        metadata,
        Column('id', Integer, primary_key=True),
        Column('name', String(100)),
        Column('email', String(100)),
        Column('age', Integer),
        Column('country', String(50))
    )
    metadata.create_all(engine)
    
    # Insert sample data
    with engine.connect() as conn:
        conn.execute(
            users_table.insert(),
            [
                {'id': 1, 'name': 'Alice', 'email': 'alice@example.com', 'age': 30, 'country': 'US'},
                {'id': 2, 'name': 'Bob', 'email': 'bob@example.com', 'age': 25, 'country': 'UK'}
            ]
        )
        conn.commit()
    
    # Query using SQLAlchemy Core (no SQL string construction)
    results = build_safe_query_sqlalchemy(
        table_key='users',
        column_keys=['name', 'email'],
        where_clause={'country': 'US'},
        engine=engine
    )
    
    return results  # [{'name': 'Alice', 'email': 'alice@example.com'}]
