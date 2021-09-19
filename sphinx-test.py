import pymysql.cursors
from queue import SimpleQueue
import logging
import sys
from threading import Thread
import json
import os

CONFIG_FILE = f'{os.getcwd()}/config.json'

logger = logging.getLogger(__name__)
log_handler = logging.StreamHandler(stream=sys.stdout)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(log_handler)


class MySQLConnector:
    def __init__(self, **kwargs):
        self.connection = pymysql.connect(host=kwargs['host'],
                                          port=kwargs['port'],
                                          user=kwargs['user'],
                                          password=kwargs['passwd'],
                                          database=kwargs['db'],
                                          cursorclass=pymysql.cursors.DictCursor)

    def make_req(self, req):
        with self.connection.cursor() as cursor:
            try:
                cursor.execute(req)
                result = cursor.fetchone()
                return result
            except pymysql.err.ProgrammingError as e:
                logger.error(e)


def configure():
    try:
        with open(CONFIG_FILE) as config:
            conf = json.load(config)
    except FileNotFoundError:
        logger.warning(f'Cannot find {CONFIG_FILE}, will use params from env')
        conf = {
            'conn_params': {
                'host': os.getenv('SPHINX_TEST_HOST', 'localhost'),
                'port': os.getenv('SPHINX_TEST_PORT', 9306),
                'user': os.getenv('SPHINX_TEST_USER', ''),
                'passwd': os.getenv('SPHINX_TEST_PASSWD', ''),
                'db': os.getenv('SPHINX_TEST_DB', '')
            },
            'debug': os.getenv('SPHINX_TEST_DEBUG', False),
            'sphinxql_log': os.getenv('SPHINX_TEST_SPHINXQL_LOG', './queries.log'),
            'threads': os.getenv('SPHINX_TEST_THREADS', 10)
        }

    logger.setLevel(logging.DEBUG if conf.get('debug') else logging.INFO)
    return conf


def run_task():
    connector = MySQLConnector(**conf.get('conn_params'))
    while not req_queue.empty():
        req_num, request = req_queue.get()
        logger.info('[req_num: %s]: %s', req_num, request)
        logger.info('[response to req_num: %s]: %s', req_num, connector.make_req(request))


if __name__ == '__main__':
    conf = configure()
    req_queue = SimpleQueue()

    with open(conf.get('sphinxql_log')) as sphinxql_log:
        req_num = 0
        # parse request from sphinx logfile
        for elem in (line[line.rfind('SELECT'):line.rfind(';')] for line in sphinxql_log):
            req_queue.put((req_num, elem))
            req_num += 1

    for i in range(0, conf.get('threads', 10)):
        Thread(target=run_task).start()
