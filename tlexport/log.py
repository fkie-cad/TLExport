import logging

class CustomFormatter(logging.Formatter):
    """Custom logging formatter to add colors and custom prefixes, with dynamic format based on log level."""
    
    # Define prefix, color, and format for each log level
    FORMAT = {
        logging.DEBUG: "\033[96m[DEBUG] %(filename)s : %(message)s\033[0m",  # Cyan for DEBUG, including file name
        logging.INFO: "\033[92m[+] %(message)s\033[0m",  # Green for INFO
        logging.WARNING: "\033[93m[W] %(message)s\033[0m",  # Orange for WARNING
        logging.ERROR: "\033[91m[-] %(message)s\033[0m",  # Red for ERROR
    }
    
    def format(self, record):
        self._style._fmt = self.FORMAT.get(record.levelno, self.FORMAT[logging.ERROR])  # Default to ERROR format
        return logging.Formatter.format(self, record)


class LogFilter(logging.Filter):
    def __init__(self, files_to_filter):
        self.files = files_to_filter

    def filter(self, record: logging.LogRecord) -> bool:
        if record.filename in self.files:
            return True
        return False


def set_logger(args):
    log_level = logging.ERROR  # Default to ERROR
    match args.debug:
        case "INFO":
            log_level = logging.INFO
        case "WARNING":
            log_level = logging.WARNING
        case "DEBUG":
            log_level = logging.DEBUG
        case _:
            log_level = logging.ERROR

    log_filter = logging.Filter()

    if args.filter is not None:
        log_filter = LogFilter(args.filter)
    logging.basicConfig(level=log_level)

    logger = logging.getLogger()

    logger.addFilter(log_filter)

    # Remove all handlers associated with the logger object.
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create a console handler with the custom formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    logger.addHandler(console_handler)
