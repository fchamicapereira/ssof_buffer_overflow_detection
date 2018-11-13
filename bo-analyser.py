# -*- coding: utf-8 -*-
import json
import sys
import os

global state
global program
global file_out
global vulnerabilities
global retOvf

# ----------------------------------
#             HELPERS
# ----------------------------------

class State:
    def __init__(self):
        self.registers = {}
        for reg in (
            'rax', 'rbx', 'rcx', 'rdx', 'rdi',
            'rsi', 'r8', 'r9', 'r10', 'r11',
            'r12', 'r13', 'r14', 'r15',
            'rbp', 'rsp', 'rip'
        ):
            self.registers[reg] = None

        self.args = {
            "regs": ("rdi","rsi","rdx","rcx","r8","r9"),
            "saved": []
        }

    def args_add(self, reg, value):
        data = { "reg": reg, "value": value }

        for x in self.args["saved"]:
            if x["reg"] == reg:
                x["value"] = value
                return

        self.args["saved"].insert(0, data)

    def args_reset(self):
        self.args["saved"] = []

    def read(self, reg):
        return None if reg not in self.registers.keys() else self.registers[reg]

    def write(self, reg, value):
        print "+++ saved %s with %s" % (reg, json.dumps(value))

        self.registers[reg] = value

        if reg in self.args["regs"]:
            self.args_add(reg, value)

    def isRegistryDestination(self, inst):
        if "args" not in inst.keys() or "dest" not in inst["args"].keys():
            return False
        
        reg = inst["args"]["dest"]
        
        if reg not in state.registers.keys():
            return False

        return True

def setup():
    global file_in, file_out
    global program
    global vulnerabilities
    global retOvf

    if len(sys.argv) < 2:
        print "Missing json argument"
        exit()

    file_in = sys.argv[1]
    filename_split = os.path.splitext(file_in)
    vulnerabilities = []
    retOvf = None

    if filename_split[len(filename_split) - 1] != ".json":
        print "Invalid extension"
        exit()      

    file_out = os.path.basename(filename_split[0]) + ".output.json"
    f = open(file_in, 'r')
    program_json = f.read()
    program = json.loads(program_json)

def analyse_frame(func):
    global state
    global program

    printArgs()

    print "begin <%s>" % (func)

    for inst in program[func]["instructions"]:
        printInst(inst)
        op = inst["op"]
        handleOp(op, func, inst)

    print "end <%s>" % (func)

def run():
    global state
    global file_out
    global vulnerabilities

    setup()
    state = State()
    analyse_frame("main")

    vulnerabilities = [
        {
            "vulnerability": "RBPOVERFLOW",
            "overflow_var": "buf4",
            "vuln_function": "main",
            "address": "4005ad",
            "fnname": "strcat"
        },
        {
            "vulnerability": "RETOVERFLOW",
            "overflow_var": "buf4",
            "vuln_function": "main",
            "address": "4005ad",
            "fnname": "strcat"
        },
        {
            "overflown_address": "rbp+0x10",
            "fnname": "strcat",
            "vuln_function": "main",
            "address": "4005ad",
            "vulnerability": "SCORRUPTION",
            "overflow_var": "buf4"
        }
    ]

    f = open(file_out, 'w')
    f.write(json.dumps(vulnerabilities, indent=4, separators=(',', ': ')))

# ----------------------------------
#         VULNERABILITIES
# ----------------------------------

def rbpOvf(vuln_func, addr, fnname, var):
    global vulnerabilities
    global retOvf

    if retOvf != None and vuln_func != retOvf:
        return

    vuln = {
        "vulnerability": "RBPOVERFLOW",
        "fnname": fnname,
        "address": addr,
        "overflow_var": var,
        "vuln_function": vuln_func
    }

    vulnerabilities.append(vuln)

def varOvf(vuln_func, addr, fnname, var, overflown_var):
    global vulnerabilities
    global retOvf

    if retOvf != None and vuln_func != retOvf:
        return

    vuln = {
        "vulnerability": "VAROVERFLOW",
        "fnname": fnname,
        "address": addr,
        "overflow_var": var,
        "vuln_function": vuln_func,
        "overflown_var": overflown_var
    }

    vulnerabilities.append(vuln)

def retOvf(vuln_func, addr, fnname, var):
    global vulnerabilities
    global retOvf

    if retOvf != None and vuln_func != retOvf:
        return

    vuln = {
        "vulnerability": "RETOVERFLOW",
        "fnname": fnname,
        "address": addr,
        "overflow_var": var,
        "vuln_function": vuln_func
    }

    retOvf = vuln_func

    vulnerabilities.append(vuln)

def invalidAccs(vuln_func, addr, fnname, var, overflown_addr):
    global vulnerabilities
    global retOvf

    if retOvf != None and vuln_func != retOvf:
        return

    vuln = {
        "vulnerability": "INVALIDACCS",
        "fnname": fnname,
        "address": addr,
        "overflow_var": var,
        "vuln_function": vuln_func,
        "overflown_address": overflown_addr
    }

    vulnerabilities.append(vuln)

def sCorruption(vuln_func, addr, fnname, var, overflown_addr):
    global vulnerabilities
    global retOvf

    if retOvf != None and vuln_func != retOvf:
        return

    vuln = {
        "vulnerability": "SCORRUPTION",
        "fnname": fnname,
        "address": addr,
        "overflow_var": var,
        "vuln_function": vuln_func,
        "overflown_address": overflown_addr
    }

    vulnerabilities.append(vuln)

# ----------------------------------
#       DANGEROUS FUNC HANDLERS
# ----------------------------------

def handleDng(func):
    def gets():
        global program
        global state
        # TODO

    def strcpy():
        global program
        global state
        # TODO

    def strcat():
        global program
        global state
        # TODO

    def fgets():
        global program
        global state
        # TODO

    def strncpy():
        global program
        global state
        # TODO

    def strncat():
        global program
        global state
        # TODO

    # --------- ADVANCED ---------

    def sprintf():
        global program
        global state
        # TODO

    def scanf():
        global program
        global state
        # TODO

    def fscanf():
        global program
        global state
        # TODO

    def snprintf():
        global program
        global state
        # TODO

    def read():
        global program
        global state
        # TODO

    dng = {
        "gets": gets,
        "strcpy": strcpy,
        "strcat": strcat,
        "fgets": fgets,
        "strncpy": strncpy,
        "strncat": strncat,
        "sprintf": sprintf,
        "scanf": scanf,
        "fscanf": fscanf,
        "snprintf": snprintf,
        "read": read
    }

    dng[func]()

# ----------------------------------
#          OPERATOR HANDLERS
# ----------------------------------

def handleOp(op, func, inst):
    def call(func, inst):
        global program
        global state

        newFunc = inst["args"]["fnname"][1:-1] # <funcion-name> or <function-name>@plt

        if newFunc in program.keys():
            analyse_frame(newFunc)

        elif '@' in newFunc:
            newFunc = newFunc.split('@')[0]
            printArgs()
            handleDng(newFunc)

        state.args_reset()

    def lea(func, inst):
        global program

        vars = program[func]["variables"]

        value = inst["args"]["value"]
        dest = inst["args"]["dest"]

        if value[0] == '[':
            value = value[1:-1]
            match = filter(lambda var: var["address"] == value, vars)
            
            if len(match) < 1:
                print "Not found. Searching in the registers (%s)" % json.dump(inst)
                match = state.read(value)

                if match == None:
                    print "Not found on the registers"
                    exit()

                var = match

            else:
                var = match[0]

            state.write(dest, var)

    def mov(func, inst):
        global state
        
        vars = program[func]["variables"]

        if not state.isRegistryDestination(inst):
            return

        dest = inst["args"]["dest"]
        value = inst["args"]["value"]

        if "WORD" in value:
            value = value.split(' ')[2][1:-1]
            match = filter(lambda var: var["address"] == value, vars)

            if len(match) < 1:
                state.write(dest, value)
            else:
                state.write(dest, match[0])

        else:
            content = state.read(value)

            if content != None:
                state.write(dest, content)

    op_handlers = {
        "call": call,
        "lea": lea,
        "mov": mov
    }

    if op in op_handlers.keys():
        op_handlers[op](func, inst)

# ----------------------------------
#              DEBUG
# ----------------------------------

def printInst(inst):
    s = "{0}: {1} ".format(inst["pos"], inst["op"])

    if "args" in inst.keys():
        if "fnname" in inst["args"].keys():
            s += "{0} 0x{1} ".format(inst["args"]["fnname"], inst["args"]["address"])

        if "dest" in inst["args"].keys():
            s += inst["args"]["dest"] + ' '

        if "value" in inst["args"].keys():
            s += inst["args"]["value"] + ' '

        if "obs" in inst["args"].keys():
            s += inst["args"]["obs"] + ' '

    print s

def printArgs():
    global state
    print "\nargs: " + str(state.args["saved"])

def __main__():
    run()

__main__()