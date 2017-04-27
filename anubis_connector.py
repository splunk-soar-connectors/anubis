# --
# File: anubis_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult
from phantom.vault import Vault

from anubis_consts import *

# Other imports used by this connector
import requests
from datetime import datetime, timedelta
import time
import xmltodict
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

SECLAB_BASE_URL = 'http://anubis.iseclab.org'
SECLAB_SUBMIT_URL = SECLAB_BASE_URL + '/submit.php'
SECLAB_RESULT_URL = SECLAB_BASE_URL + '/?action=result&'

POLL_INTERVAL = 60


class AnubisConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "detonate file"
    ACTION_ID_QUERY_URL = "detonate url"
    ACTION_ID_DETONATION_RESULT = "get report"

    def __init__(self):

        # Call the BaseConnectors init first
        super(AnubisConnector, self).__init__()

    def _lookup_and_parse_results(self, url):
      self.send_progress('Polling for analysis results ({})...', datetime.utcnow())
      job_url = url + '&format=html'
      xml_url = url + '&format=xml'
      xml_results = None
      start_time = datetime.utcnow()
      time_limit = start_time + timedelta(seconds=self.anubis_timeout)
      results = {}
      self.anubis_action_result.add_data(results)
      count = 1
      while not xml_results:
        r = requests.get(xml_url)
        status = None
        if r.headers.get('anubisapi.info.result'):
          results[RESULT_STATUS_KEY] = status = r.headers['anubisapi.info.result']
          self.save_progress('Status update: {status}', status=status)
        if r.status_code != requests.codes.ok:  # pylint: disable=E1101
          error = r.headers.get('anubisapi.error.result',
                                'Error on HTTP request to {!r} code {}'.format(url, r.status_code))
          self.anubis_action_result.set_status(phantom.APP_ERROR, error)
        if status == ANALYSIS_PENDING_STATUS:
            # find expected timeout
          if datetime.utcnow() > time_limit:
            self.save_progress('Polling for updates to  {} timed out.', url)
            break
          self.send_progress('Polling attempt {count}. ({status}) {url!r}.', count=count, status=status, url=xml_url)
          count += 1
          time.sleep(POLL_INTERVAL)
        else:
          error = r.headers.get('anubisapi.error.result')
          if error:
            if 'anubisapi.data.analysis_error' in r.headers:
              error += ' - ' + r.headers['anubisapi.data.analysis_error']
            self.anubis_action_result.set_status(phantom.APP_ERROR, error)
            return None
          obj = xmltodict.parse(r.text)
          if obj:
            self.anubis_action_result.set_status(phantom.APP_SUCCESS,
                                    'Successfully retrieved analysis results for {!r}',
                                    None, url)
            results[RESULT_REPORT_KEY] = obj
            target = 'Unknown'
            analysis_type = ANALYSIS_TYPE_FILE
            subject = obj.get('analysis').get('analysis_subject', [])
            if type(subject) != list:
              subject = [subject]
            for analysis in subject:
              if analysis.get(ANALYSIS_GENERAL_KEY, {}).get(PRIMARY_ANALYSIS_KEY) == PRIMARY_ANALYSIS_VALUE:
                gen = analysis.get('general', {})
                if gen.get('sha1'):
                  analysis_type = ANALYSIS_TYPE_FILE
                  target = gen.get('submission_fn', gen.get('virtual_fn', 'Unknown'))
                else:
                  analysis_type = ANALYSIS_TYPE_URL
                  target = gen.get('submission_fn', 'Unknown')
            self.anubis_action_result.update_summary({
              TARGET_KEY: target,
              ANALYSIS_TYPE_KEY: analysis_type,
              RESULTS_URL_KEY: job_url,
            })
          else:
            self.anubis_action_result.set_status(phantom.APP_ERROR,
                                    'Error. Response from Anubis for {!r} did not contain data.',
                                    None, url)
          return obj
      return None

    def _queue_analysis(self, query, files, key):

        error_code = None
        message = None
        try:
            r = requests.post(SECLAB_SUBMIT_URL, data=query, files=files)
            self.debug_print('Anubis returned status_code: ', str(r.status_code))

            self.send_progress('Parsing Query Response')

            task_id = r.headers.get('taskid')

            if (r.status_code == requests.codes.ok) and (task_id):  # pylint: disable=E1101

                self.save_progress('Analysis queued.', query)

                results_url = '{}task_id={}'.format(SECLAB_RESULT_URL, task_id)

                self.anubis_action_result.set_status(phantom.APP_SUCCESS, 'Successfully queued analysis. Result at {}', None, results_url)

                self.anubis_action_result.update_summary({RESULTS_URL_KEY: results_url, TASK_ID_KEY: task_id, TARGET_KEY: key})

                return self._lookup_and_parse_results(results_url)

            error_code = r.headers['anubisapi.error.result']

            self.save_progress('Analysis failed. Response error code: {0}'.format(error_code))
            # possibly try to parse the html
            soup = BeautifulSoup(r.text)
            text = soup.get_text(strip=True)
            self.debug_print("Anubis Response text: ", text)
            message = "Anubis returned Error Code: {error_code}".format(error_code=error_code)

        except Exception as e:
            error_code = True
            self.save_progress('Could not contact Anubis')
            self.debug_print(str(e))
            message = 'Could not contact Anubis'
        finally:
            if error_code:
                self.anubis_action_result.set_status(phantom.APP_ERROR, message)
                return phantom.APP_ERROR
        raise Exception('unreachable')

    def _sandbox_results(self, param):
      task_id = param[TASK_ID_KEY]
      url = '{}task_id={}'.format(SECLAB_RESULT_URL, task_id)
      self.anubis_action_result.update_summary({
        RESULTS_URL_KEY: url,
        TASK_ID_KEY: task_id,
      })

      self._lookup_and_parse_results(url)

    def _query_url(self, param):
      url = param['url']
      if not url.startswith('http'):
        url = 'http://' + url
      query = {
        'analysisType': 'url',
        'url': url,
        'notification': 'browser',
        'email': '',
      }
      self._queue_analysis(query, None, param['url'])

    def _query_file(self, param):
      vault_id = param['vault_id']
      filename = param.get('file_name')
      if not filename:
         filename = vault_id
      try:
         payload = open(Vault.get_file_path(vault_id), 'rb')
      except:
          self.anubis_action_result.set_status(phantom.APP_ERROR, 'File not found in vault ("{}")'.format(vault_id))
          return
      content_type = 'application/octet-stream'
      query = {
        'analysisType': 'file',
        'notification': 'browser',
        'email': '',
        # 'executable': {'content': payload, 'filename': filename, 'content-type': content_type}
      }

      files = {'executable': (filename, payload, content_type)}

      if param.get('force_analysis'):
        query['force_analysis'] = 'on'
      self._queue_analysis(query, files, vault_id)

    def _test_connectivity(self, param):

        try:
            r = requests.get(SECLAB_BASE_URL)
        except Exception as e:
            return self.set_status_save_progress(phantom.APP_ERROR, "Test connectivity failed. Exception: '{0}'".format(str(e)))

        if r.status_code != requests.codes.ok:  # pylint: disable=E1101
            status_message = 'Connection to "{0}" failed. HTTP status_code: {1}, reason:\n\n {2}'.format(SECLAB_BASE_URL, r.status_code, r.text)
            self.save_progress(status_message)
            self.anubis_action_result.set_status(phantom.APP_ERROR, '{}', status_message)
            return self.set_status_save_progress(phantom.APP_ERROR, "Test connectivity failed.")

        self.anubis_action_result.set_status(phantom.APP_SUCCESS)
        return self.set_status_save_progress(phantom.APP_SUCCESS, 'Test connectivity succeeded')

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        config = self.get_config()
        self.anubis_timeout = int(config.get('timeout', 10))
        action = self.get_action_identifier()
        result = ActionResult(dict(param))
        self.add_action_result(result)
        self.anubis_action_result = result
        if (action == self.ACTION_ID_QUERY_FILE):
            self._query_file(param)
        elif (action == self.ACTION_ID_QUERY_URL):
            self._query_url(param)
        elif (action == self.ACTION_ID_DETONATION_RESULT):
            self._sandbox_results(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            self._test_connectivity(param)

        return result.get_status()
