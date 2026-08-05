import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Any
from core.models import HostResult

def init_db(db_path: str) -> None:
    """Initializes the SQLite database schema."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create scans table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        total_subdomains INTEGER DEFAULT 0
    )
    """)
    
    # Create results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        subdomain TEXT NOT NULL,
        classification TEXT,
        confidence INTEGER,
        data TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
    )
    """)
    
    conn.commit()
    conn.close()

def save_scan_results(db_path: str, domain: str, results: Dict[str, HostResult]) -> None:
    """Saves the scan run and results to the SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Insert new scan record
    cursor.execute(
        "INSERT INTO scans (domain, timestamp, total_subdomains) VALUES (?, ?, ?)",
        (domain, datetime.now().isoformat(), len(results))
    )
    scan_id = cursor.lastrowid
    
    # Insert individual subdomain results
    for subdomain, res in results.items():
        res_json = json.dumps(res.to_dict(), ensure_ascii=False)
        cursor.execute(
            "INSERT INTO results (scan_id, subdomain, classification, confidence, data) VALUES (?, ?, ?, ?, ?)",
            (scan_id, subdomain, res.classification, res.confidence, res_json)
        )
        
    conn.commit()
    conn.close()
