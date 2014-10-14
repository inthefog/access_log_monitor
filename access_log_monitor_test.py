__author__ = 'pavel'

from sh import curl
import time, random

def send_requests(hostname, throughput, duration, sections_number):
    """

    :param str hostname: destination host or IP
    :param int throughput: number of requests per sec
    :param int duration: in [s]
    :param int sections_number: number of sections
    :return:
    """

    print 'Sending {0} requests per sec for {1} seconds ... '.format(throughput, duration)
    sleep_time = 1 / float(throughput)
    print 'Sleeping {0}[s] between requests.'.format(sleep_time)
    for i in range(0, duration * throughput):
        section_id = random.randint(0, sections_number-1)
        url_path = 'http://{0}/{1}/{2}'.format(hostname, section_id, 'test.html')
        curl(url_path, silent=True)
        print url_path
        time.sleep(sleep_time)

def simple_test():
    """
    This test is going to send normal_throughput requests per second for normal_duration seconds.
    Then high_throughput requests per second for high_duration seconds,
    Then again normal_throughput requests per second for normal_duration seconds.
    The requests are split in random way over sections [0-sections_number)
    Page name is not important and therefore always test.html
    :return:
    """

    normal_throughput = 1 # requests per sec
    normal_duration = 180 # seconds
    high_throughput = 10 # requests per sec
    high_duration = 10 # seconds
    sections_number = 3 # number of sections
    hostname = '127.0.0.1'

    send_requests(hostname, normal_throughput, normal_duration, sections_number)
    send_requests(hostname, high_throughput, high_duration, sections_number)
    send_requests(hostname, normal_throughput, normal_duration, sections_number)

    print 'Done.'

if __name__ == '__main__':
    simple_test()