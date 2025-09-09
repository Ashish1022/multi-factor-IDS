import smtplib
import json
import threading
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

def setup_logging(log_level: str = 'INFO') -> 'logging.Logger':
    """Setup centralized logging"""
    import logging
    import sys
    from pathlib import Path
    
    # Create logs directory
    Path('logs').mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/ids.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Setup component loggers
    loggers = [
        'MultiFactorIDS',
        'NetworkMonitor',
        'HostMonitor', 
        'BaselineEngine',
        'CorrelationEngine',
        'AlertManager'
    ]
    
    for logger_name in loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    return logging.getLogger('MultiFactorIDS')