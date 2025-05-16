# src/__init__.py
# This allows modules in the 'src' directory to be imported as part of 'TheWatcher' package.

from . import alerts
from . import alerts_gui
from . import cli
from . import dashboard
from . import devices_gui
from . import filters
from . import logging_setup
from . import main
from . import main_gui
from . import monitoring_core
from . import monitor_state
from . import network_scanner
from . import packets_gui
from . import packet_processing
from . import real_time_monitor
from . import retrieve_logs
from . import settings_gui
from . import traffic_summary
from . import utils

# This makes the 'database' subdirectory available as TheWatcher.database
from . import database
