import pymysql.cursors
from queue import SimpleQueue
import logging
import sys
from threading import Thread
import json
import os
import scapy.all as sc
import time

CONFIG_FILE = f'{os.getcwd()}/config.json'

logger = logging.getLogger(__name__)
log_handler = logging.StreamHandler(stream=sys.stdout)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(log_handler)


class SphinxQLReplayer:
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


class SphinxapiReplayer:
    def __init__(self, replay_host, replay_port):
        self.packets_queue = SimpleQueue()
        self.total_answers = 0
        self.replay_host = replay_host
        self.replay_port = replay_port

    def replay(self, pkt):
        # Use packet timestamp as its ID
        pkt_id = pkt.time
        logger.debug('[ID: %s] Got packet ', pkt_id)
        if pkt.haslayer(sc.packet.Raw):
            payload = pkt.getlayer(sc.packet.Raw).load
            if payload.startswith(b'\x00\x00\x01\x18\x00\x00'):
                s = sc.socket.socket()
                logger.debug('Connecting...')
                try:
                    s.connect((self.replay_host, self.replay_port))
                    logger.debug('Receive sphinx proto handshake: %s', s.recv(4))
                    logger.debug('Send sphinx proto handshake: %s', s.send(b"\x00\x00\x00\x01"))
                    logger.info('[ID: %s] Send query: %s', pkt_id, payload)
                    s.send(payload)
                    logger.info('[ID: %s] Receive answer: %s', pkt_id, s.recv(16384))
                    self.total_answers += 1
                    logger.debug('Close connection...')
                    s.close()
                except Exception as e:
                    logger.error('Something went wrong, got exception: ', e)
            else:
                logger.debug('[ID: %s] Not a sphinxapi query packet, skip', pkt_id)
        else:
            logger.debug('[ID: %s] Packet without payload, skip', pkt_id)

    def load_from_pcap_file(self, fl):
        pcap = None
        try:
            pcap = sc.rdpcap(fl)
            logger.info('Loaded %s packets from file', len(pcap))
        except Exception as e:
            logger.error('Cannot load packets from file: %s', e)
            exit(1)
        for pkt in pcap:
            self.packets_queue.put(pkt)

    # TODO
    def sniff_on_interface(self, filter, iface, printer_func):
        pass
#        sc.sniff(store=False, filter=filter, prn=printer_func, iface=iface, count=SNIFF_PACKETS_COUNT)


def show_stats(rp):
    while not rp.packets_queue.empty():
        logger.info('Packets in queue: %s', rp.packets_queue.qsize())
        logger.info('Answers received: %s', rp.total_answers)
        time.sleep(5)
    logger.info('All done, answers received: %s', rp.total_answers)


def task(rp):
    while not rp.packets_queue.empty():
        rp.replay(rp.packets_queue.get())


def configure():
    try:
        with open(CONFIG_FILE) as config:
            conf = json.load(config)
    except FileNotFoundError:
        logger.warning(f'Cannot find {CONFIG_FILE}, will use params from env')
        conf = {
            'target_host': os.getenv('SPHINX_TEST_TARGET_HOST', 'localhost'),
            'target_port': int(os.getenv('SPHINX_TEST_TARGET_PORT', '')),
            'pcap_file': os.getenv('PCAP_FILE', './dump.pcap'),
            'sql_conn_params': {
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


def run_sql_requests(conf):
    connector = SphinxQLReplayer(**conf.get('sql_conn_params'), host=conf['target_host'], port=conf['target_port'])
    while not task_queue.empty():
        req_id, request = task_queue.get()
        logger.info('[ID: %s]: %s', req_id, request)
        logger.info('[Resp to %s]: %s', req_id, connector.make_req(request))


def parse_sphinx_log(logfile, queue):
    logger.debug('Open %s for parsing', logfile)
    with open(logfile) as sphinxql_log:
        # parse request from sphinx logfile
        for elem in (line[line.rfind('SELECT'):line.rfind(';')] for line in sphinxql_log):
            prepare_task_queue(queue, elem)
    logger.debug('Added %s requests in queue', queue.qsize())


def prepare_task_queue(queue, item):
    item_id = str(time.time())
    queue.put((item_id, item))


if __name__ == '__main__':
    conf = configure()
    task_queue = SimpleQueue()
    if sys.argv[1] == 'sphinxql':
        parse_sphinx_log(conf.get('sphinxql_log'), task_queue)
        for i in range(conf.get('threads')):
            Thread(target=run_sql_requests, args=[conf]).start()
    elif sys.argv[1] == 'sphinxapi':
        rhost, rport = conf.get('target_host'), conf.get('target_port')
        replayer = SphinxapiReplayer(rhost, rport)
        replayer.load_from_pcap_file(conf.get('pcap_file'))
        for i in range(conf.get('threads')):
            Thread(target=task, args=[replayer]).start()
        Thread(target=show_stats, args=[replayer]).start()
    else:
        logger.error('No replay type provided')
        exit(1)
