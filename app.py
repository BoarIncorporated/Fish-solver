import concurrent.futures
import json
import logging
import os
import random
import secrets
import time
import traceback
import uuid
import base64
import asyncio
import aiohttp
import aiofiles
import sqlite3
from enum import Enum
from datetime import datetime, timezone
import threading
import signal

from hashlib import md5
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import flask
from flask import Flask, request, Response, jsonify, render_template
from asgiref.wsgi import WsgiToAsgi

from src.arkose_session.challenge import ChallengeSession
from src.arkose_session.game import Game
from src.bda.bda_template import FunCaptchaSession
from src.image.botmasterlabs import XEvil
from src.utilities.logger import log

DEBUG: bool = False
ONLY_PRINT_SOLVED: bool = False

FILE_LOCK = Lock()
DB_LOCK = Lock()
STATS_LOCK = Lock()

app = Flask(__name__)
log_console = logging.getLogger("werkzeug")
log_console.disabled = True

class StatsTracker:
    """
    Tracks statistics for different types of captcha outcomes
    and writes them to a file.
    """
    def __init__(self, stats_file="stats.txt"):
        self.stats_file = os.path.abspath(stats_file)
        self.stats = {
            "silent_passes": 0,
            "skipped_variants": 0,
            "failed_solves": 0,
            "successful_solves": 0
        }
        self._load_stats()

    def _load_stats(self):
        """Load existing stats from file if it exists"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.strip().split(':', 1)
                            key = key.strip().lower().replace(' ', '_')
                            try:
                                value = int(value.strip())
                                if key in self.stats:
                                    self.stats[key] = value
                            except ValueError:
                                pass
        except Exception as e:
            log.log_error(f"Error loading stats: {str(e)}")

    def increment(self, stat_type):
        """Thread-safe increment of a specific statistic"""
        with STATS_LOCK:
            if stat_type in self.stats:
                self.stats[stat_type] += 1
                self._save_stats()
                return True
            return False

    def _save_stats(self):
        """Save statistics to file"""
        try:
            with open(self.stats_file, 'w') as f:
                f.write(f"Silent Passes: {self.stats['silent_passes']}\n")
                f.write(f"Skipped Variants: {self.stats['skipped_variants']}\n")
                f.write(f"Failed Solves: {self.stats['failed_solves']}\n")
                f.write(f"Successful Solves: {self.stats['successful_solves']}\n")
        except Exception as e:
            log.log_error(f"Error saving stats: {str(e)}")

    def get_stats(self):
        """Get a copy of current statistics"""
        with STATS_LOCK:
            return self.stats.copy()

# Initialize stats tracker
stats_tracker = StatsTracker()

class Database:
    def __init__(self, db_file="keys.db"):
        self.db_file = os.path.abspath(db_file)
        os.makedirs(os.path.dirname(self.db_file) or '.', exist_ok=True)
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_file, timeout=60)

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    key TEXT PRIMARY KEY,
                    total_solves INTEGER,
                    remaining_solves INTEGER,
                    created_at TIMESTAMP,
                    last_used TIMESTAMP,
                    login_solves INTEGER DEFAULT 0,
                    signup_solves INTEGER DEFAULT 0,
                    order_id TEXT UNIQUE
                )
            ''')
            conn.commit()

    def create_key(self, total_solves: int, order_id: str = None) -> str:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if order_id:
                cursor.execute('SELECT key FROM api_keys WHERE order_id = ?', (order_id,))
                existing_key = cursor.fetchone()
                if existing_key:
                    return None

            api_key = f"SXVM#{uuid.uuid4().hex[:24].upper()}"
            cursor.execute(
                'INSERT INTO api_keys (key, total_solves, remaining_solves, created_at, last_used, order_id) VALUES (?, ?, ?, ?, ?, ?)',
                (api_key, total_solves, total_solves, datetime.now(), datetime.now(), order_id)
            )
            conn.commit()
            return api_key

    def validate_key(self, api_key: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT remaining_solves 
                FROM api_keys 
                WHERE key = ? 
                AND remaining_solves > 0
            ''', (api_key,))
            result = cursor.fetchone()
            return bool(result and result[0] > 0)

    def update_solves(self, api_key: str, method: str = None) -> bool:
        with DB_LOCK:
            with self.get_connection() as conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute('BEGIN IMMEDIATE')
                    
                    cursor.execute('SELECT remaining_solves FROM api_keys WHERE key = ?', (api_key,))
                    result = cursor.fetchone()
                    
                    if not result or result[0] <= 0:
                        conn.rollback()
                        return False

                    if method == "roblox_login":
                        cursor.execute('''
                            UPDATE api_keys 
                            SET remaining_solves = remaining_solves - 1,
                                last_used = ?,
                                login_solves = login_solves + 1
                            WHERE key = ? AND remaining_solves > 0
                        ''', (datetime.now(), api_key))
                    elif method == "roblox_signup":
                        cursor.execute('''
                            UPDATE api_keys 
                            SET remaining_solves = remaining_solves - 1,
                                last_used = ?,
                                signup_solves = signup_solves + 1
                            WHERE key = ? AND remaining_solves > 0
                        ''', (datetime.now(), api_key))
                    else:
                        cursor.execute('''
                            UPDATE api_keys 
                            SET remaining_solves = remaining_solves - 1,
                                last_used = ?
                            WHERE key = ? AND remaining_solves > 0
                        ''', (datetime.now(), api_key))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                except:
                    conn.rollback()
                    raise

    def get_key_info(self, api_key: str) -> dict:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM api_keys WHERE key = ?', (api_key,))
            result = cursor.fetchone()
            if result:
                return {
                    "key": result[0],
                    "total_solves": result[1],
                    "remaining_solves": result[2],
                    "created_at": result[3],
                    "last_used": result[4],
                    "login_solves": result[5],
                    "signup_solves": result[6]
                }
            return None

    def delete_key(self, api_key: str) -> bool:
        """
        Delete an API key from the database
        
        Args:
            api_key: The API key to delete
            
        Returns:
            True if the key was successfully deleted, False otherwise
        """
        with DB_LOCK:
            with self.get_connection() as conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute('BEGIN IMMEDIATE')
                    
                    cursor.execute('DELETE FROM api_keys WHERE key = ?', (api_key,))
                    deleted = cursor.rowcount > 0
                    
                    conn.commit()
                    return deleted
                except:
                    conn.rollback()
                    raise

# Initialize database
db = Database()

SUPPORTED_BROWSERS: List[str] = [
    "chrome",
    "opera",
    "edge",
    "firefox",
    "chrome mac",
    "firefox mac",
    "chrome linux",
    "chrome android",
    "firefox linux",
    "safari",
]

SUPPORTED_OS: List[Tuple[str, str]] = [
    ("windows", "Windows NT 11.0; Win64; x64"),
    ("mac", "Macintosh; Intel Mac OS X 14_7_1"), 
    ("linux", "Linux x86_64"),
    ("android", "Linux; Android 10; K"),
    ("iphone", "iPhone; CPU iPhone OS 15_5 like Mac OS X"),
]

async def download_image(session: aiohttp.ClientSession, image_url: str) -> bytes:
    """
    Asynchronously download an image from a URL
    """
    async with session.get(image_url) as response:
        return await response.read()

async def process_wave_async(game: Game, image_base64: str, wave_index: int) -> Tuple[int, str]:
    """
    Asynchronously process a single wave and return the result
    """
    result = await asyncio.to_thread(XEvil.solveImage, image_base64, game.game_variant)
    return wave_index, result

def process_wave(game: Game, image_base64: str) -> str:
    """
    Helper function to predict the answer for a single captcha wave.
    """
    return XEvil.solveImage(image_base64, game.game_variant)

async def process_waves_concurrent(game: Game) -> Dict[str, str]:
    """
    Process multiple waves concurrently using asyncio
    """
    answers = {}
    async with aiohttp.ClientSession() as session:
        tasks = []
        for wave_index in range(game.waves):
            image_base64, image_file_path, image_md5 = game.get_image(wave_index, download=True)
            task = asyncio.create_task(process_wave_async(game, image_base64, wave_index))
            tasks.append((task, image_file_path))
        
        for task, image_file_path in tasks:
            wave_index, answer = await task
            answers[image_file_path] = answer
            
    return answers

@app.route("/admin/sigma/create", methods=["POST", "GET"])
def generate_api_key():
    if "Starlight2Cool" not in request.headers:
        return Response(
            json.dumps({"error": "Unauthorized"}),
            content_type="application/json",
            status=401
        )

    data: Dict[str, Any] = request.get_json()["data"]
    quantity: int = int(data.get("quantity", 1))
    bought: int = 1000 * quantity
    order_id: str = data.get("order_id")

    new_key = db.create_key(bought, order_id)
    if not new_key:
        return Response(
            json.dumps({"error": "Order ID already has a key"}),
            content_type="application/json",
            status=400
        )

    return Response(
        json.dumps({"key": new_key}),
        content_type="application/json"
    )

@app.route("/", methods=["GET"])
def home():
    """
    Renders a simple index.html page. 
    """
    return render_template("index.html"), 200


class TaskStatus(Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

TASKS = {}
TASK_LOCK = Lock()

def create_task_id() -> str:
    """Generate a unique task ID"""
    return str(uuid.uuid4())

def save_task(task_id: str, status: TaskStatus, result: Dict[str, Any] = None) -> None:
    """Save task with thread safety"""
    with TASK_LOCK:
        TASKS[task_id] = {
            "status": status.value,
            "captcha": result,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    """Get task with thread safety"""
    with TASK_LOCK:
        return TASKS.get(task_id)

def clean_old_tasks() -> None:
    """Clean tasks older than 3 minutes"""
    while True:
        try:
            time.sleep(180)  # Run every 3 minutes
            with TASK_LOCK:
                current_time = datetime.now(timezone.utc)
                # Use list comprehension for faster filtering
                expired_tasks = [
                    task_id for task_id, task in TASKS.items()
                    if (current_time - datetime.fromisoformat(task["created_at"])).total_seconds() > 180  # 3 minutes
                ]
                # Batch delete expired tasks
                for task_id in expired_tasks:
                    del TASKS[task_id]
                
                # Log cleanup if DEBUG
                if DEBUG and expired_tasks:
                    log.log_debug(f"Cleaned {len(expired_tasks)} expired tasks")
        except Exception as e:
            if DEBUG:
                log.log_debug(f"Task cleanup error: {str(e)}")
            continue

# Start task cleanup thread
cleanup_thread = threading.Thread(target=clean_old_tasks, daemon=True)
cleanup_thread.start()

async def process_challenge_async(request_data: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Process challenge asynchronously"""
    try:
        proxy = request_data.get("proxy").replace("http://", "")
        blob = request_data.get("blob")
        browser = "safari"
        version = "18"
        os_ = "ios"
        accept_language = "en-GB"
        method = request_data.get("preset")
        referrer = request_data.get("document__referrer", None)
        cookie_dict = request_data.get("custom_cookies")

        matched_os = next((os_header for os_key, os_header in SUPPORTED_OS 
                         if os_key.lower() == os_.lower()), None)

        fun_captcha_session = FunCaptchaSession(method=method, blob=blob)
        challenge = ChallengeSession(
            fun_captcha_session,
            proxy=proxy,
            browser_data=(browser, version, matched_os, accept_language, cookie_dict),
            referrer=referrer,
            timeout=45,
        )

        arkose_token, browser_data = challenge.fetch_challenge_token()

        if "sup=1" in arkose_token:
            db.update_solves(key, method)
            log.solved_captcha(
                token=arkose_token.split("|")[0],
                waves="N/A",
                variant="Silent-Pass",
                game_type=4
            )
            stats_tracker.increment("silent_passes")
            return {
                "msg": "success",
                "solved": True,
                "token": arkose_token
            }

        game = challenge.fetch_challenge_game(arkose_token)
        
        log.console._print_challenge(
            token=arkose_token.split("|")[0],
            waves=game.waves,
            variant=game.game_variant,
            game_type=game.type if hasattr(game, 'type') else "Unknown"
        )

        if game.game_variant in ["iconrace", "orbit_match_game", "3d_rollball_animals_multi", "hopscotch_highsec"]:
            stats_tracker.increment("skipped_variants")
            return {
                "msg": "skipped",
                "solved": False,
                "token": challenge.arkose_token
            }
        
        #if game.game_variant == "3d_rollball_objects":
            #timestamp = int(time.time())
            #filename = f"3d/3d_rollball_objects({timestamp}).txt"
            #with open(filename, "w") as f:
                #f.write(browser_data)

        answer_result = game.solve_challenge()

        if answer_result["solved"]:
            db.update_solves(key, method)
            # Log success
            log.solved_captcha(
                token=arkose_token.split("|")[0],
                waves=game.waves,
                variant=game.game_variant,
                game_type=game.type if hasattr(game, 'type') else "Unknown"
            )
            # Increment successful solves counter
            stats_tracker.increment("successful_solves")
        else:
            # Log failure
            log.console._print_failed(
                token=arkose_token.split("|")[0],
                waves=game.waves,
                variant=game.game_variant,
                game_type=game.type if hasattr(game, 'type') else "Unknown"
            )
            # Increment failed solves counter
            stats_tracker.increment("failed_solves")

        return {
            "msg": "success" if answer_result["solved"] else "failed",
            "solved": answer_result["solved"],
            "token": challenge.arkose_token
        }

    except Exception as exc:
        stats_tracker.increment("failed_solves")
        return {
            "msg": "proxy issue 🤓🤓🤓",
            "solved": False,
            "token": None,
            "error": str(exc)
        }

@app.route("/createTask", methods=["POST"])
async def create_task():
    request_data = request.get_json()

    key = request_data.get("api_key", None)
    
    # Validate key
    if not db.validate_key(key):
        return jsonify({"error": "Invalid API key or no remaining solves"}), 401
    
    if not request_data.get("proxy"):
        return jsonify({"error": "proxy is required"}), 400

    if not request_data.get("blob"):
        return jsonify({"error": "blob is required"}), 400

    task_id = create_task_id()
    save_task(task_id, TaskStatus.PENDING)

    # Process task asynchronously
    async def process_task():
        result = await process_challenge_async(request_data, key)
        save_task(task_id, TaskStatus.COMPLETED if result["solved"] else TaskStatus.FAILED, result)

    asyncio.create_task(process_task())
    
    return jsonify({
        "task_id": task_id,
        "status": TaskStatus.PENDING.value
    })

@app.route("/balance", methods=["POST"])
def check_balance():
    if request.method != "POST":
        return jsonify({"error": "Method not allowed"}), 405

    request_data: Dict[str, Any] = request.get_json()
    key: Optional[str] = request_data.get("sxvm_key", None)

    if not key:
        return jsonify({"error": "API key is required"}), 400

    key_info = db.get_key_info(key)
    if not key_info:
        return jsonify({"error": "Invalid API key"}), 400

    return jsonify({
        "success": True,
        "key": key_info["key"],
        "total_purchased": key_info["total_solves"],
        "total_used": key_info["total_solves"] - key_info["remaining_solves"],
        "remaining_balance": key_info["remaining_solves"],
        "login_solves": key_info["login_solves"],
        "signup_solves": key_info["signup_solves"],
        "percent_used": f"{((key_info['total_solves'] - key_info['remaining_solves'])/key_info['total_solves'])*100:.2f}%"
    }), 200

@app.route("/getTask", methods=["GET", "POST"])
def get_task_status():
    """Get task status and result"""
    request_data = request.get_json()

    task_id = request_data.get("task_id")

    task = get_task(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    return jsonify(task)

@app.route("/stats", methods=["GET"])
def get_stats():
    """Get current statistics of solve types"""
    stats = stats_tracker.get_stats()
    total = sum(stats.values())
    
    return jsonify({
        "stats": stats,
        "total": total,
        "percentages": {
            "silent_passes": f"{(stats['silent_passes']/total)*100:.2f}%" if total > 0 else "0.00%",
            "skipped_variants": f"{(stats['skipped_variants']/total)*100:.2f}%" if total > 0 else "0.00%",
            "failed_solves": f"{(stats['failed_solves']/total)*100:.2f}%" if total > 0 else "0.00%",
            "successful_solves": f"{(stats['successful_solves']/total)*100:.2f}%" if total > 0 else "0.00%"
        }
    })

@app.route("/admin/deleteKey", methods=["POST"])
def delete_key():
    """
    Delete an API key from the database
    Required header: Starlight2Cool for authorization
    Required JSON body: {"key": "API_KEY_TO_DELETE"}
    """
    # Check authorization header
    if "Starlight2Cool" not in request.headers:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({"error": "Request must include JSON body"}), 400
            
        key = request_data.get("key")
        if not key:
            return jsonify({"error": "API key is required"}), 400
            
        # Check if key exists before deleting
        key_info = db.get_key_info(key)
        if not key_info:
            return jsonify({"error": "Key not found", "success": False}), 404
            
        # Delete the key
        success = db.delete_key(key)
        
        if success:
            return jsonify({
                "success": True, 
                "message": f"Key '{key}' successfully deleted", 
                "deleted_key_info": key_info
            })
        else:
            return jsonify({"error": "Failed to delete key", "success": False}), 500
            
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500

def signal_handler(signum, frame):
    """Handle shutdown gracefully"""
    log.log_info("Received shutdown signal...")
    
    # Log current statistics before shutdown
    current_stats = stats_tracker.get_stats()
    log.log_info(f"Final statistics: Silent Passes: {current_stats['silent_passes']}, "
                f"Skipped Variants: {current_stats['skipped_variants']}, "
                f"Failed Solves: {current_stats['failed_solves']}, "
                f"Successful Solves: {current_stats['successful_solves']}")
    
    log.log_info("Shutting down...")
    os._exit(0)

if __name__ == "__main__":
    try:
        os.system("clear" if os.name == "posix" else "cls")
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Log current statistics
        current_stats = stats_tracker.get_stats()
        log.log_info(f"Starting with statistics: Silent Passes: {current_stats['silent_passes']}, "
                    f"Skipped Variants: {current_stats['skipped_variants']}, "
                    f"Failed Solves: {current_stats['failed_solves']}, "
                    f"Successful Solves: {current_stats['successful_solves']}")
        
        app.run(host="0.0.0.0", port=5000)
    except Exception as e:
        log.log_info(f"Shutting down... {e}")
