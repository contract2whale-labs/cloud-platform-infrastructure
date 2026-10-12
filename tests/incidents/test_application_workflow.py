# -*- coding: utf-8 -*-
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location("app_check",ROOT/"automation/check_application_workflow.py")
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

BASE={"on":{"pull_request":{}},"permissions":{"contents":"read"},"jobs":{"check":{"steps":[{"uses":"actions/checkout@"+"a"*40},{"run":"npm test"}]}}}

class PermissionBoundaryTests(unittest.TestCase):
    def test_read_only_pr_without_deployment_credentials(self):
        self.assertTrue(MODULE.validate(BASE))

    def test_oidc_and_repository_credential_are_rejected(self):
        for mutation in ("oidc","secret","action_tag","protected_event"):
            document=copy.deepcopy(BASE)
            if mutation=="oidc":document["jobs"]["check"]["permissions"]={"contents":"read","id-token":"write"}
            if mutation=="secret":document["jobs"]["check"]["steps"].append({"run":"npm test","env":{"TOKEN":"${{ secrets.APP_PRIVATE_KEY }}"}})
            if mutation=="action_tag":document["jobs"]["check"]["steps"][0]["uses"]="actions/checkout@main"
            if mutation=="protected_event":document["on"]={"pull_request_target":{}}
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):MODULE.validate(document)

if __name__=="__main__":unittest.main()
