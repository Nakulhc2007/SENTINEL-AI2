import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lotl import storage
from lotl.agents import verification_agent
from lotl.engine import build_baseline, evaluate_event
from lotl.orchestrator import get_events
from lotl.orchestrator import decide, run_workflow
from lotl.scenarios import scenario_bundle


class LivingOffTheLandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sentinel-lotl-test-')
        self.previous_path = storage.DATABASE_PATH
        storage.DATABASE_PATH = Path(self.temp.name) / 'test.sqlite3'
        storage.initialize()
        self.now = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        storage.DATABASE_PATH = self.previous_path
        self.temp.cleanup()

    def run_named(self, scenario_id):
        scenario = scenario_bundle(scenario_id, self.now)
        for event in scenario['events']:
            event['organization_domain'] = 'corporate'
        result = run_workflow(scenario_id, scenario['name'], scenario['events'], 'corporate', scenario['maintenance'])
        return scenario, result

    def test_normal_and_approved_maintenance_are_not_incidents(self):
        normal, normal_result = self.run_named('normal-administration')
        approved, approved_result = self.run_named('approved-maintenance')
        self.assertEqual(normal_result['incidents'], [])
        self.assertEqual(approved_result['incidents'], [])
        self.assertIn('expected maintenance', normal_result['classifications'])
        self.assertTrue(all(row == 'expected maintenance' for row in approved_result['classifications']))
        self.assertTrue(all({'detection', 'investigation', 'risk_assessment', 'response', 'verification'} <= row.keys() for row in approved_result['workflow']))

    def test_maintenance_scope_mismatch_is_flagged(self):
        scenario = scenario_bundle('approved-maintenance', self.now)
        event = scenario['events'][0] | {'action': 'view_secrets'}
        result = evaluate_event(event, build_baseline(get_events(), event['username']), scenario['maintenance'], get_events())
        self.assertFalse(result['expected_maintenance'])
        self.assertTrue(result['suspicious'])
        self.assertIn('Maintenance scope mismatch', {factor['factor'] for factor in result['factors']})

    def test_night_activity_creates_explained_high_risk_incident(self):
        _, result = self.run_named('suspicious-night-activity')
        self.assertEqual(len(result['incidents']), 1)
        incident = result['incidents'][0]
        self.assertGreaterEqual(incident['risk_assessment']['score'], 65)
        self.assertTrue(incident['risk_assessment']['factors'])
        self.assertEqual(incident['response']['status'], 'pending_human_approval')
        self.assertEqual(
            {item['resource'] for item in incident['verification']['affected_documents']},
            {'/production/payroll.xlsx', '/production/customer-backup.csv'},
        )
        self.assertEqual(len(result['workflow']), 2)

    def test_gradual_misuse_is_correlated_across_sessions(self):
        _, result = self.run_named('gradual-credential-misuse')
        self.assertTrue(result['incidents'])
        incident = result['incidents'][0]
        factor_names = {item['factor'] for item in incident['risk_assessment']['factors']}
        self.assertIn('Gradual deviation across sessions', factor_names)
        self.assertGreaterEqual(incident['investigation']['related_event_count'], 4)

    def test_human_approval_is_simulated_and_verifiable(self):
        _, result = self.run_named('suspicious-night-activity')
        incident_id = result['incidents'][0]['incident_id']
        approved = decide(incident_id, 'approve', 'Demo reviewer', 'Approved for safe simulation.')
        self.assertEqual(approved['verification']['status'], 'verified')
        self.assertTrue(approved['verification']['simulated'])
        self.assertIn('no external account', approved['verification']['result'])
        self.assertTrue(approved['verification']['affected_documents'])

    def test_verification_identifies_document_and_checks_supplied_hashes(self):
        event = {
            'event_id': 'EVT-DOC-1',
            'resource': r'\production\payroll.xlsx',
            'action': 'document_export',
            'process_category': 'document_management',
            'document_hash_before': 'a' * 64,
            'document_hash_after': 'b' * 64,
        }
        result = verification_agent(
            {'decision': 'pending', 'decided_at': None, 'suspicious': True},
            [event],
        )
        self.assertEqual(result['affected_documents'][0]['resource'], event['resource'])
        self.assertEqual(result['affected_documents'][0]['integrity_status'], 'changed')
        self.assertTrue(result['integrity_checked'])
        self.assertIn(event['resource'], result['result'])

    def test_verification_reports_unknown_document_when_resource_is_not_a_file(self):
        result = verification_agent(
            {'decision': 'pending', 'decided_at': None, 'suspicious': True},
            [{'event_id': 'EVT-1', 'resource': '/production/payroll', 'action': 'grant_admin'}],
        )
        self.assertEqual(result['affected_documents'], [])
        self.assertIn('cannot be identified', result['result'])

    def test_duplicate_event_ids_do_not_create_duplicate_incidents(self):
        scenario, first = self.run_named('suspicious-night-activity')
        repeated = run_workflow(scenario['id'], scenario['name'], scenario['events'], 'corporate', scenario['maintenance'])
        self.assertEqual(len(first['incidents']), 1)
        self.assertEqual(repeated['duplicate_events'], len(scenario['events']))
        self.assertIsNone(repeated['run_id'])


if __name__ == '__main__':
    unittest.main()
