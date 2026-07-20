# quality_daemon.py
import os
import time
import httpx
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAE-Quality-Daemon")

class WorkspaceWatcher(FileSystemEventHandler):
    """Event handler that triggers proactive tribunal audits on file modification events."""
    
    def __init__(self, api_url: str):
        self.api_url = api_url
        self.client = httpx.Client(timeout=10.0)

    def on_modified(self, event):
        # Scan only python files and ignore hidden/temporary files
        if event.is_directory or not event.src_path.endswith(".py") or ".git" in event.src_path:
            return
            
        logger.info(f"🔍 Proactive Quality Sentry: File change detected: {event.src_path}")
        
        try:
            with open(event.src_path, "r", encoding="utf-8") as f:
                code_content = f.read()
                
            project_name = os.path.basename(os.path.dirname(os.path.dirname(event.src_path))) or "unnamed"
            
            # Post code to Sentinel Tribunal for dynamic quality check
            payload = {
                "code": code_content,
                "project": project_name,
                "importance": "medium"
            }
            
            resp = self.client.post(f"{self.api_url}/v2/quality/audit", json=payload)
            if resp.status_code == 200:
                result = resp.json()
                verdict = result.get("verdict")
                score = result.get("score")
                level = result.get("metadata", {}).get("seniority_level", "Unknown")
                
                logger.info(f"📊 Audit Result for '{os.path.basename(event.src_path)}': Verdict={verdict}, Score={score} ({level})")
                if verdict == "REJECTED":
                    logger.warning(f"❌ Code Quality drop detected! Phoenix auto-repair triggered in background.")
            else:
                logger.error(f"Failed to submit proactive audit: {resp.status_code}")
        except Exception as e:
            logger.error(f"Error executing proactive Sentinel audit: {e}")

class QualityDaemon:
    """Pro-active Quality Daemon that continuously watches workspace directories for modifications."""
    
    def __init__(self, watch_paths: list):
        self.watch_paths = [p for p in watch_paths if os.path.exists(p)]
        self.api_url = os.getenv("RAE_API_URL", "http://localhost:8000") # Local quality server
        self.observer = Observer()

    def start(self):
        logger.info(f"Starting pro-active Quality Sentry daemon (Kaizen loop)...")
        if not self.watch_paths:
            logger.warning("No valid watch paths configured. Daemon idling.")
            return

        handler = WorkspaceWatcher(self.api_url)
        for path in self.watch_paths:
            logger.info(f"👁️ Monitoring directory for real-time audits: {path}")
            self.observer.schedule(handler, path, recursive=True)
            
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

if __name__ == "__main__":
    # Resolve workspace paths dynamically
    from pathlib import Path
    default_base = Path(__file__).resolve().parents[3]
    base_cloud = os.getenv("RAE_CLOUD_ROOT", str(default_base))
    projects = ["billboard-marker", "screenwatcher_project", "RAE-agentic-memory"]
    
    watch_dirs = [os.path.join(base_cloud, p) for p in projects]
    
    daemon = QualityDaemon(watch_dirs)
    daemon.start()
