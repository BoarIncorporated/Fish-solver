import requests
from concurrent.futures import ThreadPoolExecutor
import time
import random
from queue import Queue
import threading
from src.utilities.logger import log

class SessionPool:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.sessions = Queue()
                    cls._instance.initialize_sessions()
        return cls._instance

    def initialize_sessions(self, pool_size=50):
        for _ in range(pool_size):
            session = requests.Session()
            session.headers.update({
                'Connection': 'keep-alive',
                'Keep-Alive': 'timeout=60, max=1000'
            })
            self.sessions.put(session)

    def get_session(self):
        return self.sessions.get()

    def return_session(self, session):
        self.sessions.put(session)

class XEvil:
    session_pool = SessionPool()
    XEVIL_SERVERS = ["207.244.238.232"]

    @staticmethod
    def solve_water_icon_cup(img, var):
        try:
            body = {
                'image': img,
                'variant': var
            }
            
            response = requests.post(
                'https://class.fcap.fun/match_image',
                json=body,
                headers={'x-api-key': 'hamidpis'},
                timeout=30
            )
            result = response.json()
            
            if not result.get('success'):
                return random.randint(0, 4)
            
            return result['result']['best_match_index']
            
        except:
            return random.randint(0, 4)

    @staticmethod
    def solve_batch_sync(images, variants, key="d81490ac27983680e7f1aaf93b614b5a", timeout=30):
        session = XEvil.session_pool.get_session()
        try:
            results = {}
            task_queue = Queue()
            server_map = {}

            def submit_all():
                with ThreadPoolExecutor(max_workers=len(images)) as executor:
                    futures = []
                    for i, (img, var) in enumerate(zip(images, variants)):
                        server = XEvil.XEVIL_SERVERS[i % len(XEvil.XEVIL_SERVERS)]
                        futures.append(executor.submit(
                            session.post,
                            f"http://{server}/in.php",
                            data={"method": "base64", "key": key, "imginstructions": var, "body": img}
                        ))
                    for i, future in enumerate(futures):
                        try:
                            response = future.result()
                            if "|" in response.text:
                                task_id = response.text.split("|")[1]
                                server = XEvil.XEVIL_SERVERS[i % len(XEvil.XEVIL_SERVERS)]
                                server_map[task_id] = server
                                task_queue.put((i, task_id))
                            else:
                                results[i] = random.randint(0, 4)
                        except:
                            results[i] = random.randint(0, 4)

            def check_results():
                while len(results) < len(images):
                    try:
                        if task_queue.empty():
                            time.sleep(0.01)
                            continue
                            
                        idx, task_id = task_queue.get()
                        if idx in results:
                            continue

                        server = server_map.get(task_id, XEvil.XEVIL_SERVERS[0])
                        response = session.get(
                            f"http://{server}/res.php",
                            params={"action": "get", "key": key, "id": task_id}
                        )
                        
                        if "OK" in response.text:
                            results[idx] = int(response.text.split("|")[1]) - 1
                        elif any(x in response.text for x in ["FAILED", "ERROR"]):
                            results[idx] = random.randint(0, 4)
                        else:
                            task_queue.put((idx, task_id))
                    except:
                        results[idx] = random.randint(0, 4)

            submit_thread = threading.Thread(target=submit_all)
            submit_thread.start()

            checker_threads = []
            for _ in range(min(8, len(images))):
                t = threading.Thread(target=check_results)
                t.daemon = True
                t.start()
                checker_threads.append(t)

            submit_thread.join()

            start = time.time()
            while len(results) < len(images) and time.time() - start < timeout:
                time.sleep(0.01)

            return [results.get(i, random.randint(0, 4)) for i in range(len(images))]
        finally:
            XEvil.session_pool.return_session(session)

    @staticmethod
    def solveImage(img, var, host=None, key="28d035b8e9a385b8a87627790a047761", timeout=30):
        if var in ["waterIconCup", "Matchship", "pathfinder", "bowling"]:
            return XEvil.solve_water_icon_cup(img, var)
            
        session = XEvil.session_pool.get_session()
        try:
            server = host if host else random.choice(XEvil.XEVIL_SERVERS)
            r = session.post(f"http://{server}/in.php", 
                            data={"method": "base64", "key": key, "imginstructions": var, "body": img})
            if "|" not in r.text: 
                return random.randint(0, 4)
            taskId = r.text.split("|")[1]
            start = time.time()
            while time.time() - start < timeout:
                resp = session.get(f"http://{server}/res.php", 
                                  params={"action": "get", "key": key, "id": taskId})
                if "OK" in resp.text:
                    return int(resp.text.split("|")[1]) - 1
                if any(x in resp.text for x in ["FAILED", "ERROR"]): 
                    return random.randint(0, 4)
                time.sleep(0.01)
            return random.randint(0, 4)
        except:
            return random.randint(0, 4)
        finally:
            XEvil.session_pool.return_session(session)
