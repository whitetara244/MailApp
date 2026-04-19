import os
import multiprocessing
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Server socket
bind = os.getenv('GUNICORN_BIND', '0.0.0.0:5000')
backlog = 2048

# Worker processes
workers = os.getenv('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1)
worker_class = 'sync'  # or 'gevent' for async, 'gthread' for threaded
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = int(os.getenv('GUNICORN_TIMEOUT', 300))  # 5 min for token polling
graceful_timeout = 30
keepalive = 5

# Threading (if using gthread worker class)
threads = os.getenv('GUNICORN_THREADS', 2)

# Process naming
proc_name = 'm365_phisher'

# Logging
accesslog = os.getenv('GUNICORN_ACCESS_LOG', '-')  # '-' = stdout
errorlog = os.getenv('GUNICORN_ERROR_LOG', '-')
loglevel = os.getenv('GUNICORN_LOG_LEVEL', 'info')
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Daemon mode (set to True for background execution)
daemon = False

# PID file
pidfile = os.getenv('GUNICORN_PID_FILE', 'gunicorn.pid')

# User/group (uncomment to drop privileges)
# user = 'www-data'
# group = 'www-data'

# Temporary directory for uploaded files
tmp_upload_dir = '/tmp'

# SSL (uncomment if using HTTPS directly)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'

# Preload app for better performance and memory sharing
preload_app = True

# Reload on code changes (development only)
reload = False  # Set to True for development

# Check config
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting M365 Phisher with Gunicorn")
    server.log.info(f"Workers: {workers}, Threads: {threads}, Timeout: {timeout}")

def on_reload(server):
    """Called before reloading the application."""
    server.log.info("Reloading M365 Phisher...")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("M365 Phisher is ready to handle requests")
    server.log.info(f"Listening on {bind}")

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info(f"Worker {worker.pid} received INT/QUIT signal")

def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.info(f"Worker {worker.pid} aborted")

def pre_request(worker, req):
    """Called just before a request is processed."""
    worker.log.debug(f"Processing request: {req.method} {req.path}")

def post_request(worker, req, environ, resp):
    """Called after a request is processed."""
    worker.log.debug(f"Completed request: {req.method} {req.path} - Status: {resp.status_code}")

def child_exit(server, worker):
    """Called just after a worker has been killed."""
    server.log.info(f"Worker {worker.pid} exited")