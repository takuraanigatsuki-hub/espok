# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name: sfp__stor_stdout
# Purpose: ЕПСОК OSINT Worker — stream SpiderFoot events to Orchestrator (no SQLite).
#
# Drop-in replacement for sfp__stor_db in SpiderFoot modules directory.
# Requires: EPSOK_ORCHESTRATOR_URL, EPSOK_JOB_ID environment variables.
# -------------------------------------------------------------------------------

import json
import os
import urllib.error
import urllib.request

from spiderfoot import SpiderFootPlugin


class sfp__stor_stdout(SpiderFootPlugin):

    meta = {
        'name': "Storage (EPSOK stdout)",
        'summary': "Streams scan events to EPSOK Orchestrator; does not persist locally."
    }

    _priority = 0

    opts = {
        'maxstorage': 4096,
        '_store': True
    }

    optdescs = {
        'maxstorage': "Maximum bytes per event sent to Orchestrator (0 = unlimited)."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]
        self._orchestrator_url = os.environ.get('EPSOK_ORCHESTRATOR_URL', '').rstrip('/')
        self._job_id = os.environ.get('EPSOK_JOB_ID', '')

    def watchedEvents(self):
        return ["*"]

    def handleEvent(self, sfEvent):
        if not self.opts['_store']:
            return

        data = sfEvent.data
        if self.opts['maxstorage'] and len(data) > self.opts['maxstorage']:
            data = data[: self.opts['maxstorage']]

        payload = {
            'eventType': sfEvent.eventType,
            'data': data,
            'module': sfEvent.module,
            'generated': sfEvent.generated,
            'confidence': sfEvent.confidence,
            'visibility': sfEvent.visibility,
            'risk': sfEvent.risk,
            'sourceEventHash': sfEvent.sourceEventHash,
        }
        if sfEvent.sourceEvent is not None:
            payload['sourceEventType'] = sfEvent.sourceEvent.eventType

        line = json.dumps(payload, ensure_ascii=False)
        print(line, flush=True)

        if self._orchestrator_url and self._job_id:
            self._post_event(payload)

    def _post_event(self, payload):
        url = f"{self._orchestrator_url}/internal/jobs/{self._job_id}/events"
        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=body,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status >= 400:
                    self.error(f"Orchestrator returned {resp.status}")
        except urllib.error.URLError as e:
            self.error(f"Failed to POST event to Orchestrator: {e}")
