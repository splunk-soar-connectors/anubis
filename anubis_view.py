# --
# File: anubis_view.py
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

from collections import OrderedDict
import json
from datetime import datetime

from phantom.app import APP_SUCCESS

from anubis_consts import *

ANUBIS_DATE_FORMAT = '%m/%d/%y, %H:%M:%S UTC'


def all_results(provides, all_results, context):
  view = context['QS'].get('view', [None])[0]
  if view == '_ph_query':
    return unfinished(all_results, context)
  elif view == 'info':
    return info_view(all_results, context)
  elif view == 'proc':
    return proc_view(all_results, context, int(context['QS'].get('id', [-1])[0]))
  else:
    return menu_view(all_results, context)


def unfinished(all_results, context):
  context['rows'] = rows = []
  context['headers'] = ['Results Link', 'Task ID']
  context['allow_links'] = (0,)
  for summary, action_results in all_results:
    for result in action_results:
      new_row = []
      new_row.append({'value': result.get_summary().get(RESULTS_URL_KEY)})
      new_row.append({'value': result.get_summary().get(TASK_ID_KEY),
                      'contains': ['anubis task id'],
                      'id': result.id,
                      'data_path': 'action_result.summary.{}'.format(TASK_ID_KEY)})
      rows.append(new_row)

  return '/widgets/generic_table.html'


def info_view(all_results, context):
  context['data'] = data = []
  for summary, action_results in all_results:
    for result in action_results:
      item = result.get_data()[0].get(RESULT_REPORT_KEY, {}).get('analysis', {})
      subject = item.get('analysis_subject', [])
      if type(subject) != list:
        subject = [subject]
      bugged_summary = item.get('report_version', {}).get('summary')
      if bugged_summary:
        item['summary'] = bugged_summary
      for analysis in subject:
        if analysis.get(ANALYSIS_GENERAL_KEY, {}).get(PRIMARY_ANALYSIS_KEY) == PRIMARY_ANALYSIS_VALUE:
          item['phantom_target'] = analysis
          gen = analysis.get(ANALYSIS_GENERAL_KEY, {})
          if gen.get('sha1'):
            item['phantom_type'] = ANALYSIS_TYPE_FILE
            analysis['phantom_filename'] = gen.get('submission_fn', gen.get('virtual_fn', 'Unknown'))
          else:
            item['phantom_type'] = ANALYSIS_TYPE_URL
            analysis['phantom_url'] = gen.get('submission_fn', 'Unknown')
      dt = item.get('configuration', {}).get('report_created')
      if dt:
        item['configuration']['report_created'] = datetime.strptime(dt, ANUBIS_DATE_FORMAT)
      item['phantom_results_url'] = result.get_summary().get(RESULTS_URL_KEY)
      item['phantom_task_id'] = result.get_summary().get(TASK_ID_KEY)
      data.append(item)
  return 'info.html'


def proc_view(all_results, context, proc_id):
  context['data'] = data = []
  for summary, action_results in all_results:
    for result in action_results:
      item = result.get_data()[0].get(RESULT_REPORT_KEY, {}).get('analysis', {})
      subject = item.get('analysis_subject', [])
      if type(subject) != list:
        subject = [subject]
      proc = subject[proc_id]
      data.append(proc)
      ACTIVITIES_KEYS = {
        'registry_activities': [
          'reg_value_modified',
          'reg_value_read',
          'reg_key_monitored',
        ],
        'file_activities': [
          'section_object_created',
          'file_read',
          'file_modified',
          'fs_control_communication',
        ],
        'misc_activities': [
          'mutex_created',
          'key_was_checked',
          'exception_occurred',
        ],
        'process_activities': [
          'process_created',
          'foreign_mem_area_read',
          'foreign_mem_area_write',
          'remote_thread_created',
        ],
      }
      for k, subk in ACTIVITIES_KEYS.items():
        act = proc.get('activities', {}).get(k)
        if not act:
          continue
        for k2 in subk:
          sub_act = act.get(k2)
          if type(sub_act) == dict:
            proc['activities'][k][k2] = [sub_act]
      act = proc.get('dll_dependencies', {}).get('loaded_dll')
      if type(act) == dict:
        proc['dll_dependencies']['loaded_dll'] = [act]
  return 'proc.html'


def json_dump_view(all_results, context, section):
  j = []
  for summary, action_results in all_results:
    for result in action_results:
      j.append(result.get_data()[0][RESULT_REPORT_KEY]['analysis'][section])
  context['json'] = [json.dumps(item, separators=(',', ':'), sort_keys=True, indent=4) for item in j]
  return 'json_dump.html'


def menu_view(all_results, context):
  tasks = {}
  for summary, action_results in all_results:
    for result in action_results:
      if result.get_status() == APP_SUCCESS:
        tid = result.get_summary().get(TASK_ID_KEY)
        data = result.get_data()
        if not data:
          continue
        data = data[0]
        dt = data.get(RESULT_REPORT_KEY, {}).get('analysis', {}).get('configuration', {}).get('report_created')
        if dt:
          dt = datetime.strptime(dt, ANUBIS_DATE_FORMAT)
        if tid in tasks:
          if dt and dt > tasks[tid][0]:
            tasks[tid] = (dt, result, 'Unknown')
        else:
          tasks[tid] = (dt, result, 'Unknown')
        target = result.get_summary().get(TARGET_KEY)
        if target:
          tasks[tid] = (tasks[tid][0], tasks[tid][1], target)

  context['menu'] = menu = {}
  for tid, result in tasks.items():
    target = '{} (run: {})'.format(result[2], tid)
    result = result[1]
    data = result.get_data()[0]
    app_run_id = result.id

    menu[target] = submenu = OrderedDict()
    report = data.get(RESULT_REPORT_KEY, {}).get('analysis')
    if report:
      submenu['info'] = ['/app/anubis_a76a681c-aed4-4b58-944d-1313328d3770/all?app_run={}&view=info'.format(app_run_id)]
      subject = report.get('analysis_subject', [])
      if type(subject) != list:
        subject = [subject]
      for i, proc in enumerate(subject):
        info = proc.get(ANALYSIS_GENERAL_KEY, {})
        proc_name = info.get('submission_fn')
        if not proc_name:
          proc_name = info.get('virtual_fn')
        name = proc_name
        if info.get('sha1'):
          name += ' (sha1: {})'.format(info['sha1'])
        submenu[name] = ['/app/anubis_a76a681c-aed4-4b58-944d-1313328d3770/all?app_run={}&view=proc&id={}'.format(app_run_id, i)]
    else:
      submenu['Get Report'] = ['/app/anubis_a76a681c-aed4-4b58-944d-1313328d3770/all?app_run={}&view=_ph_query'.format(app_run_id)]
  context['has_maximize'] = True
  context['title1'] = 'Anubis'
  return '/widgets/uber_widget.html'
