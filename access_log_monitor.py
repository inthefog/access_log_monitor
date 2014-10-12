__author__ = 'pavel'

from sh import tail
from collections import deque
from time import gmtime, strftime
import traceback, sys, re, time, sys
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
    """
    Class that implements statistics functionality
    """

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
    """
    Class that implements monitor functionality.
    """

    def __init__(self):
        self._refresh_time = 1 #sec
        self._alert_time = 10 #sec
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

        try:
            while True:
                time.sleep(self._refresh_time)
                timestamp = strftime("%Y-%m-%d %H:%M:%S", gmtime())

                #Releasing lock first
                self._draft_stats_lock.acquire()
                draft_stats = AccessLogStats(self._draft_stats)
                self._draft_stats.reset()
                self._draft_stats_lock.release()

                #Adding draft stats to monitor stats
                self._monitor_stats += draft_stats

                #Updating total hits number in alert sliding window
                self._alert_window_hits += (draft_stats.total_hits - self._alert_window.popleft())
                #Updating alert sliding window
                self._alert_window.append(draft_stats.total_hits)

                alert_message = None

                if (self._alert_windows_nums % 10 == 0):
                    alert_message = 'aaa'

                if (self._alert_windows_nums > 0):
                    alert_window_average_hits = self._alert_windows_hits_sum / self._alert_windows_nums

                    if (self._alert_triggered):
                        #If alert was already triggered, check if traffic was back to normal
                        if (self._alert_window_hits <= alert_window_average_hits + self._alert_threshold):
                            self._alert_triggered = False
                            alert_message = 'ALERT: Traffic back to normal. Hits {0} vs average {1}. Time: {2}'.format(self._alert_window_hits, alert_window_average_hits, timestamp)
                    else:
                        if (self._alert_window_hits > alert_window_average_hits + self._alert_threshold):
                            self._alert_triggered = True
                            alert_message = 'ALERT: Traffic is high! Hits {0} vs average {1}. Time: {2}'.format(self._alert_window_hits, alert_window_average_hits, timestamp)

                #Updating alert windows statistics used for average calculation.
                self._alert_windows_hits_sum += self._alert_window_hits
                self._alert_windows_nums += 1

                if (alert_message is not None):
                    sys.stdout.write(alert_message + '\n')
                    alert_message = None

                sys.stdout.write('\r{0}: {1}'.format(timestamp, self._monitor_stats.get_monitor_data(most_popular_sections=True)))
                sys.stdout.flush()



        except (KeyboardInterrupt, SystemExit):
            print 'Interrupted.'

    def run(self):

        try:

            #Starting background thread which process and cleans draft statistics periodically
            bg_thread = Thread(target=self._monitor_bg_process)
            bg_thread.daemon = True
            bg_thread.start()

            #Reading last line from tailing the log and appending it to draft statistics.
            for line in tail('-f', '-n 0', self._access_log_path, _iter=True):
                sample = self._parser.parse(line)
                if (sample is not None):
                    #Adding even if request was for non-existing resource. Easier to write test.
                    self._draft_stats_lock.acquire()
                    self._draft_stats.add_sample(sample)
                    self._draft_stats_lock.release()

            bg_thread.join()

        except (KeyboardInterrupt, SystemExit):
            print 'Interrupted.'


###########################################################################
if __name__ == '__main__':
    AccessLogMonitor().run()

