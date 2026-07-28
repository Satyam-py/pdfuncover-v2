# modules/logging_config.py
"""
Shared logging configuration used across PDFUncover.

Every module used to repeat the same boilerplate:

    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename="logs/<name>.log",
        level=logging.ERROR,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    log = logging.getLogger(__name__)

Because logging.basicConfig() only has an effect on its *first* call
in a process, every module after the first one to import actually had
its basicConfig() call silently ignored (the root logger was already
configured) — so nearly all module-specific log files were never
actually written to. get_logger() replaces that pattern: each logger
gets its own FileHandler attached directly to it (not to the root
logger), so every module reliably logs to its own file regardless of
import order, while keeping the exact same log level and message
format every module already used.
"""

import logging
import os

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
_LOG_LEVEL = logging.ERROR

_configured_loggers = set()


def get_logger(name, log_file):
    """
    Return a logger named `name` that writes to `log_file` at ERROR
    level, using the shared format string every module previously
    configured individually via logging.basicConfig(). Safe to call
    repeatedly (e.g. once per module import) — configuration is only
    applied the first time a given logger name is requested.
    """

    logger = logging.getLogger(name)

    if name not in _configured_loggers:

        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))

        logger.addHandler(handler)
        logger.setLevel(_LOG_LEVEL)
        logger.propagate = False

        _configured_loggers.add(name)

    return logger