import os
from os.path import isfile, join
import subprocess
import json

def equal(vulns_1, vulns_2):
    vulns_1.sort()
    vulns_2.sort()

    if len(vulns_1) != len(vulns_2):
        return False

    for i in range(len(vulns_1)):
        v1 = vulns_1[i]
        v2 = vulns_2[i]

        keys1 = v1.keys()
        keys2 = v2.keys()

        keys1.sort()
        keys2.sort()

        if keys1 != keys2:
            return False

        for key in keys1:
            if v1[key] != v2[key]:
                return False

    return True

tests = []

tests_path = './public_basic_tests'
tests_advanced_path = './public_advanced_tests'

basic_files = [f.split('.')[0] for f in os.listdir(tests_path) if isfile(join(tests_path, f)) and '.output.json' in f]
basic_files.sort()

tests.append({ "path": tests_path, "files": basic_files})

advanced_files = [f.split('.')[0] for f in os.listdir(tests_advanced_path) if isfile(join(tests_advanced_path, f)) and '.output.json' in f]
advanced_files.sort()

tests.append({ "path": tests_advanced_path, "files": advanced_files})

for t in tests:
    files = t["files"]
    path = t["path"]

    for f in files:
        filename_in = f + '.json'
        filename_result = f + '.output.json'

        with open(os.devnull, 'wb') as devnull:
            try:
                subprocess.check_call(['python', './bo-analyser.py', '{0}/{1}'.format(path, filename_in)], stdout=devnull, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                print '-- Exited with error: ' + filename_in
                continue

        try:
            f_result = open(filename_result, 'r')
            result = json.loads(f_result.read())
        except IOError:
            print '\033[91m (0/0) %s \033[0m' % (filename_in)

        f_solution = open('{0}/{1}'.format(path, filename_result), 'r')
        solution = json.loads(f_solution.read())

        if equal(result, solution):
            print '\033[92m (%d/%d) %s \033[0m' % (len(result), len(solution), filename_in)
            subprocess.call(['rm', './' + filename_result])
        else:
            print '\033[91m (%d/%d) %s \033[0m' % (len(result), len(solution), filename_in)

            missing = ''
            not_in_solution = ''

            for s in solution:
                if s not in result:
                    if len(missing) == 0:
                        missing += 'Missing:\n'
                    missing += json.dumps(s, indent=4, separators=(',', ': ')) + '\n'

            for r in result:
                if r not in solution:
                    if len(not_in_solution) == 0:
                        not_in_solution += 'Not in solution:\n'
                    not_in_solution += json.dumps(r, indent=4, separators=(',', ': ')) + '\n'

            if len(missing) > 0:
                print missing
            if len(not_in_solution) > 0:
                print not_in_solution