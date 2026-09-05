"""Unit-test the fixed comparison script with in-memory DOM doubles, not a browser.

Uses Python's existing unittest harness and Node's built-in vm/assert modules.
No HTML file is opened, no network is used, and this is not visual/keyboard QA.
"""

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HTML_SOURCE = ROOT / "crates/termivar-scanner/src/reporting/comparison/html.rs"
EXAMPLE = ROOT / "docs/examples/report-compare"

HARNESS = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const script = process.argv[1];
const scenario = process.argv[2];
const element = (extra={}) => Object.assign({hidden:false,textContent:'',events:{},
 attributes:{},addEventListener(name,callback){this.events[name]=callback},
 setAttribute(name,value){this.attributes[name]=value}}, extra);
const groups = ['only_in_after','only_in_before','changed','unchanged'];
const items = groups.map((group,index)=>element({dataset:{group},
 textContent:['After title and repair guidance','Before title','Changed title',
 '<img src=x onerror=never> Unchanged title'][index]}));
const buttons = ['all',...groups].map(filter=>element({dataset:{filter}}));
const details = [element({open:false}),element({open:true})];
const nodes = {
 controls:element({hidden:true}), search:element({value:''}),
 'visible-count':element(), 'empty-filter':element({hidden:true})
};
const window = element();
const document = {
 getElementById(id){assert.ok(id in nodes);return nodes[id]},
 querySelectorAll(selector){
  if(selector==='[data-filter]')return buttons;
  if(selector==='article[data-group]')return items;
  if(selector==='details')return details;
  throw new Error('Unexpected DOM access');
 }
};
vm.runInNewContext(script,{document,window},{timeout:1000});
const visible = () => items.filter(item=>!item.hidden).map(item=>item.dataset.group);
const select = group => buttons.find(button=>button.dataset.filter===group).events.click();
const search = value => {nodes.search.value=value;nodes.search.events.input()};
assert.equal(nodes.controls.hidden,false);
assert.deepEqual(visible(),groups);
assert.equal(nodes['visible-count'].textContent,'4 of 4 observations shown');
if(scenario==='groups'){
 for(const group of groups){
  select(group); assert.deepEqual(visible(),[group]);
  assert.equal(nodes['visible-count'].textContent,'1 of 4 observations shown');
  for(const button of buttons)assert.equal(button.attributes['aria-pressed'],String(button.dataset.filter===group));
 }
 select('all');assert.deepEqual(visible(),groups);
}else if(scenario==='search'){
 search('  REPAIR Guidance  ');assert.deepEqual(visible(),['only_in_after']);
 search('<img src=x');assert.deepEqual(visible(),['unchanged']);
 search('missing term');assert.deepEqual(visible(),[]);
 assert.equal(nodes['empty-filter'].hidden,false);
 assert.equal(nodes['visible-count'].textContent,'0 of 4 observations shown');
 search('');assert.deepEqual(visible(),groups);assert.equal(nodes['empty-filter'].hidden,true);
}else if(scenario==='combined'){
 search('Before');select('changed');assert.deepEqual(visible(),[]);
 select('only_in_before');assert.deepEqual(visible(),['only_in_before']);
 select('only_in_before');assert.deepEqual(visible(),['only_in_before']);
 search('');select('all');assert.deepEqual(visible(),groups);
}else if(scenario==='print'){
 select('changed');window.events.beforeprint();
 assert.deepEqual(details.map(detail=>detail.open),[true,true]);
 window.events.afterprint();assert.deepEqual(details.map(detail=>detail.open),[false,true]);
 assert.deepEqual(visible(),['changed']);
 window.events.beforeprint();window.events.afterprint();
 assert.deepEqual(details.map(detail=>detail.open),[false,true]);
}else{throw new Error('Unknown test scenario')}
"""


class ReportComparisonScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if cls.node is None:
            raise RuntimeError("Node is required for fixed-script unit tests")
        source = HTML_SOURCE.read_text(encoding="utf-8")
        scripts = re.findall(r'const SCRIPT: &str = r#"(.*?)"#;', source, re.DOTALL)
        if len(scripts) != 1:
            raise AssertionError("Expected exactly one fixed comparison script")
        cls.script = scripts[0]

    def exercise(self, scenario):
        result = subprocess.run(
            [self.node, "-e", HARNESS, self.script, scenario],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_each_group_is_exclusive_and_all_restores_items(self):
        self.exercise("groups")

    def test_literal_search_case_whitespace_empty_state_and_reset(self):
        self.exercise("search")

    def test_search_and_group_intersection_is_deterministic(self):
        self.exercise("combined")

    def test_print_opens_details_then_restores_user_state(self):
        self.exercise("print")

    def test_checked_in_cli_example_matches_recorded_bytes_and_counts(self):
        provenance = json.loads((EXAMPLE / "provenance.json").read_text(encoding="utf-8"))
        comparison = json.loads((EXAMPLE / "comparison.json").read_text(encoding="utf-8"))

        for section in ("inputs", "outputs"):
            for filename, expected in provenance[section].items():
                actual = hashlib.sha256((EXAMPLE / filename).read_bytes()).hexdigest()
                self.assertEqual(actual, expected, filename)

        self.assertEqual(comparison["schema"], "termivar-report-comparison/v1")
        for group, expected in provenance["expected_group_counts"].items():
            self.assertEqual(len(comparison[group]), expected, group)

        html = (EXAMPLE / "comparison.html").read_text(encoding="utf-8")
        self.assertEqual(html.count('<article class="item"'), 4)
        self.assertIn("Disappearance is not verified remediation.", html)


if __name__ == "__main__":
    unittest.main()
