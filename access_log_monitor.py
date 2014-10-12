__author__ = 'pavel'

from sh import tail
from collections import deque
import traceback, sys, re, time
from threading import Thread, Lock

###########################################################################
class AccessLogParser():
    """
    Class which implements parsing functionality
    """

    def __init__(self):
        """

        :return:
        """

        self._line_pattern = '^([\\d.]+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\d+) \"([^\"]+)\" \"([^\"]+)\"'
        self._line_regex = re.compile(self._line_pattern)
        self._section_pattern = '^(.*/.*/)'
        self._section_regex = re.compile(self._section_pattern)

    def parse(self, log_line):
        """

        :param str log_line: log line
        :return object: dictionary with sample properties
        """

        match_result = self._line_regex.match(log_line)

        try:

            sample = {'ip' : match_result.group(1),
                    'timetag' : match_result.group(4),
                    'request' : match_result.group(5),
                    'response' : match_result.group(6),
                    'bytes_sent' : match_result.group(7),
                    'referer' : match_result.group(8),
                    'user_agent' : match_result.group(9)}

            sample['request_url'] = sample['request'].split(' ')[1]
            sample['request_section'] = self._section_regex.match(sample['request_url']).group(0)
            return sample

        except Exception as e:
            print 'Error: ' + e.message
            print 'Error info: ' + sys.exc_info()
            print 'Error trace: ' + traceback.format_exc()
            return None

###########################################################################
class AccessLogStats():

    def __init__(self, other = None):
        """

        :param AccessLogStats other: optional for initialization
        :return:
        """
        self.reset()
        self += other

    def reset(self):
        self.section_hits = {}
        self.total_hits = 0

    def add_sample(self, sample):
        self._add_section_hints(sample['request_section'])

    def _add_section_hints(self, section, hints_number = 1):
        """

        :param str section: section name
        :param int hints_number: number of hints
        :return:
        """
        if (section in self.section_hits):
            self.section_hits[section] += hints_number
        else:
            self.section_hits[section] = hints_number

        self.total_hits += hints_number

    def __iadd__(self, other):
        if (other is not None):
            for section in other.section_hits:
                self._add_section_hints(section, other.section_hits[section])

        return self

    def get_monitor_data(self, most_popular_sections=False):
        """

        :return object: monitor data
        """

        monitor_data = {'section_hits': self.section_hits, 'total_hits': self.total_hits}

        if (most_popular_sections):
            sorted_section_hits = sorted(self.section_hits.items(),key=lambda x:x[1],reverse=True) #sorting by hits in reverse order
            most_popular_section = sorted_section_hits[0][0] if len(sorted_section_hits) > 0 else None
            monitor_data['most_popular_section'] = most_popular_section

        return monitor_data

###########################################################################
class AccessLogMonitor:

    def __init__(self):
        self._refresh_time = 10 #sec
        self._alert_time = 120 #sec
        self._alert_threshold = 10 #maximum number of hits per alert time
        self._alert_triggered = False #just flag
        self._access_log_path = '/var/log/apache2/access.log'
        self._parser = AccessLogParser()

        self._draft_stats = AccessLogStats() #Draft stats that being reset every refresh time.
        self._draft_stats_lock = Lock() #Lock for safe concurrency. Locks are bad for true production!

        self._monitor_stats = AccessLogStats() #Accumulator of all draft stats, for monitoring. Reset is optional

        alert_prob_window_size = self._alert_time / self._refresh_time
        self._alert_window = deque([0] * alert_prob_window_size,  maxlen=alert_prob_window_size) #Alert sliding window initialized with zeros
        self._alert_window_hits = 0 #Current alert window hits.
        self._alert_windows_hits_sum = 0
        self._alert_windows_nums = 0


    def _monitor_bg_process(self):
        """
        Running in background thread.
        :return:
        """

        while True:
            time.sleep(self._refresh_time)

            #Releasing lock first
            self._draft_stats_lock.acquire()
            draft_stats = AccessLogStats(self._draft_stats)
            self._draft_stats.reset()
            self._draft_stats_lock.release()

            self._monitor_stats += draft_stats
            self._alert_window_hits += (draft_stats.total_hits - self._alert_window.popleft())
            self._alert_window.append(draft_stats.total_hits)

            if (self._alert_windows_nums > 0):

                alert_window_average_hits = self._alert_windows_hits_sum / self._alert_windows_nums
                alert_message = None
                if (self._alert_triggered):
                    if (self._alert_window_hits <= alert_window_average_hits + self._alert_threshold):
                        self._alert_triggered = False
                else:
                    if (self._alert_window_hits > alert_window_average_hits + self._alert_threshold):
                        self._alert_triggered = True

            self._alert_windows_hits_sum += self._alert_window_hits
            self._alert_windows_nums += 1

            print str(self._monitor_stats.get_monitor_data(most_popular_sections=True))


    def run(self):

        bg_thread = Thread(target=self._monitor_bg_process)
        bg_thread.start()

        for line in tail('-f', '-n 0', self._access_log_path, _iter=True):
            sample = self._parser.parse(line)
            if (sample is not None):
                self._draft_stats_lock.acquire()
                self._draft_stats.add_sample(sample)
                self._draft_stats_lock.release()

        bg_thread.join()


###########################################################################
if __name__ == '__main__':
    AccessLogMonitor().run()

