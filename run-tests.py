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

tests_path = './public_basic_tests'
files = [f.split('.')[0] for f in os.listdir(tests_path) if isfile(join(tests_path, f)) and '.output.json' in f]
files.sort()

for f in files:
    filename_in = f + '.json'
    filename_result = f + '.output.json'

    with open(os.devnull, 'wb') as devnull:
        subprocess.check_call(['python', './bo-analyser.py', '{0}/{1}'.format(tests_path, filename_in)], stdout=devnull, stderr=subprocess.STDOUT)

    f_result = open(filename_result, 'r')
    result = json.loads(f_result.read())

    f_solution = open('{0}/{1}'.format(tests_path, filename_result), 'r')
    solution = json.loads(f_solution.read())

    if equal(result, solution):
        print '+ [PASSED] ' + filename_in
        subprocess.call(['rm', './' + filename_result])
    else:
        print '  [FAILED] ' + filename_in
