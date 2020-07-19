import logging
import logging.config
import os.path as path

log_path = "logging.conf"

log_file_path = path.join(path.dirname(path.abspath(__file__)),log_path)


logging.config.fileConfig(log_file_path)

log_root = logging.getLogger('netsuit')
log_sys= logging.getLogger('netsuit.sys')

log_root.info('test hello')
