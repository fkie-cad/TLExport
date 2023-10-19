import logging


class LogFilter(logging.Filter):
    def __init__(self, files_to_filter):
        self.files = files_to_filter

    def filter(self, record: logging.LogRecord) -> bool:
        if record.filename in self.files:
            return True
        return False


def set_logger(args):
    match args.debug:
        case "INFO":
            log_level = logging.INFO
        case "WARNING":
            log_level = logging.WARNING
        case _:
            log_level = logging.ERROR

    log_filter = logging.Filter()

    if args.filter is not None:
        log_filter = LogFilter(args.filter)
    logging.basicConfig(level=log_level, format="%(levelname)s : %(filename)s : %(message)s")

    logger = logging.getLogger()

    logger.addFilter(log_filter)
