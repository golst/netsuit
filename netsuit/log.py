import logging
import logging.config
import os.path as path

__all__ = ['log_root','log_sys']

_log_path = "logging.conf"

_log_file_path = path.join(path.dirname(path.abspath(__file__)),_log_path)


logging.config.fileConfig(_log_file_path)

log_root = logging.getLogger('netsuit')
log_sys= logging.getLogger('netsuit.sys')

log_root.info('test hello')
