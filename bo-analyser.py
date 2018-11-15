# -*- coding: utf-8 -*-
import json
import sys
import os

global states
global program
global file_out
global vulnerabilities
global currentRetOvf

# ----------------------------------
#             HELPERS
# ----------------------------------

class State:
    def __init__(self, vars, args=[]):
        self.registers = {}
        self.registers_names = (
            ['rax', 'eax', 'ax', 'al'],
            ['rbx', 'ebx', 'bx', 'bl'],
            ['rcx', 'ecx', 'cx', 'cl'],
            ['rdx', 'edx', 'dx', 'dl'],
            ['rdi', 'edi', 'di', 'dil'],
            ['rsi', 'esi', 'si', 'sil'],
            ['r8', 'r8d', 'r8w', 'r8b'],
            ['r9', 'r9d', 'r9w', 'r9b'],
            ['r10', 'r10d', 'r10w', 'r10b'],
            ['r11', 'r11d', 'r11w', 'r11b'],
            ['r12', 'r12d', 'r12w', 'r12b'],
            ['r13', 'r13d', 'r13w', 'r13b'],
            ['r14', 'r14d', 'r14w', 'r14b'],
            ['r15', 'r15d', 'r15w', 'r15b'],
            ['rbp', 'ebp', 'bp', 'bpl'],
            ['rsp', 'esp', 'sp', 'spl'],
            ['rip']
        )

        for reg in self.registers_names:
            self.registers[reg[0]] = None

        self.registers["rsp"] = 0
        self.args = {
            "regs": ("rdi","rsi","rdx","rcx","r8","r9"),
            "saved": [],
            "current": args
        }

        self.vars = []
        self.non_assigned_mem = []

        result = []
        for v in vars:
            v["rbp_rel_pos"] = int(v["address"][3:], 16) # pos relative to rbp
            result.append(v)
        
        # sort by position in stack
        result = sorted(result, key = lambda v: v['rbp_rel_pos']) 

        self.vars = result
        self.calc_non_assigned_memory()

    def getRegKeyFromRegisters(self, reg):
        reg_key = ''
        for register_name in self.registers_names:
            if reg in register_name:
                return register_name[0]
        return None

    def args_add(self, reg, value):
        reg = self.getRegKeyFromRegisters(reg)
        data = { "reg": reg, "value": value }

        for x in self.args["saved"]:
            if x["reg"] == reg:
                x["value"] = value
                return

        self.args["saved"].insert(0, data)

    def args_get(self, reg):
        reg = self.getRegKeyFromRegisters(reg)

        if reg == None:
            return None

        for arg in self.args["current"]:
            
            if not isinstance(arg["value"], dict):
                continue

            if "address" in arg["value"].keys() and arg["value"]["address"] == reg:
                return arg["value"]

        return None

    def calc_non_assigned_memory(self):
        self.non_assigned_mem = []
        saved_pos = None
        saved_size = None
        
        if len(self.vars) == 0:
            return

        rsp = self.read("rsp")

        if len(self.vars) > 0 and rsp < self.vars[0]["rbp_rel_pos"]:
            self.non_assigned_mem.append({
                "start": rsp,
                "end": self.vars[0]["rbp_rel_pos"]
            })
        
        for var in self.vars:
            size = var["bytes"]
            pos = var["rbp_rel_pos"]

            if saved_pos != None and saved_size != None and pos > saved_pos + saved_size:
                self.non_assigned_mem.append({
                    "start": saved_pos + saved_size,
                    "end": pos - 1
                })

            saved_pos = pos
            saved_size = size
        
        if saved_pos + saved_size < 0:
            self.non_assigned_mem.append({
                "start": saved_pos + saved_size,
                "end": -1
            })

        print 'nam', self.non_assigned_mem

    def read(self, reg):
        reg = self.getRegKeyFromRegisters(reg)
        return None if reg == None else self.registers[reg]

    def write(self, reg, value):
        reg = self.getRegKeyFromRegisters(reg)        
        
        if reg == None:
            return

        print "\n+++ [%s] <-- %s\n" % (reg, json.dumps(value))

        self.registers[reg] = value

        if reg in self.args["regs"]:
            self.args_add(reg, value)

def setup():
    global states
    global file_in, file_out
    global program
    global vulnerabilities
    global currentRetOvf

    if len(sys.argv) < 2:
        print "Missing json argument"
        exit()
    
    states = []
    file_in = sys.argv[1]
    filename_split = os.path.splitext(file_in)
    vulnerabilities = []
    currentRetOvf = None

    if filename_split[len(filename_split) - 1] != ".json":
        print "Invalid extension"
        exit()      

    file_out = os.path.basename(filename_split[0]) + ".output.json"
    f = open(file_in, 'r')
    program_json = f.read()
    program = json.loads(program_json)

def analyse_frame(func):
    global states
    global program

    vars = program[func]["variables"]

    if len(states) > 0 and states[len(states) - 1].args["saved"]:
        args = states[len(states) - 1].args["saved"]
        states.append(State(vars, args))
    else:
        states.append(State(vars))

    print "begin <%s>" % (func)

    for inst in program[func]["instructions"]:
        printInst(inst)
        op = inst["op"]
        handleOp(op, func, inst)

    states.pop()

    print "end <%s>" % (func)

def run():
    global states
    global file_out
    global vulnerabilities

    setup()
    analyse_frame("main")

    f = open(file_out, 'w')
    f.write(json.dumps(vulnerabilities, indent=4, separators=(',', ': ')))

# ----------------------------------
#         VULNERABILITIES
# ----------------------------------

def rbpOvf(vuln_func, addr, fnname, var):
    global vulnerabilities
    global currentRetOvf

    if currentRetOvf != None and vuln_func != currentRetOvf:
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
    global currentRetOvf

    if currentRetOvf != None and vuln_func != currentRetOvf:
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
    global currentRetOvf

    if currentRetOvf != None and vuln_func != currentRetOvf:
        return

    vuln = {
        "vulnerability": "RETOVERFLOW",
        "fnname": fnname,
        "address": addr,
        "overflow_var": var,
        "vuln_function": vuln_func
    }

    currentRetOvf = vuln_func

    vulnerabilities.append(vuln)

def invalidAccs(vuln_func, addr, fnname, var, overflown_addr):
    global vulnerabilities
    global currentRetOvf

    if currentRetOvf != None and vuln_func != currentRetOvf:
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

def sCorruption(vuln_func, addr, fnname, var):
    global vulnerabilities
    global currentRetOvf

    if currentRetOvf != None and vuln_func != currentRetOvf:
        return

    vuln = {
        "vulnerability": "SCORRUPTION",
        "fnname": fnname,
        "address": addr,
        "overflow_var": var,
        "vuln_function": vuln_func,
        "overflown_address": "rbp+0x10"
    }

    vulnerabilities.append(vuln)

# ----------------------------------
#       DANGEROUS FUNC HANDLERS
# ----------------------------------

def handleDng(dngFunc, vuln_func, inst):
    
    # with this function, everything can be overflown
    def gets(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        addr = inst["address"]
        arg = state.args["saved"][0]["value"]
        vars = list(filter(lambda v: "rbp_rel_pos" in v.keys() and v["rbp_rel_pos"] > arg["rbp_rel_pos"], state.vars))
        
        retOvf(vuln_func, addr, dngFunc, arg["name"])

        # variable overflow
        for v in vars:
            varOvf(vuln_func, addr, dngFunc, arg["name"], v["name"])

        # RBP overflow
        rbpOvf(vuln_func, addr, dngFunc, arg["name"])

        # invalid write access to non-assigned memory
        for mem in state.non_assigned_mem:
            mem_addr = "rbp" + hex(mem["start"])
            invalidAccs(vuln_func, addr, dngFunc, arg["name"], mem_addr)
        
        # invalid write access to memory out of the current frame
        sCorruption(vuln_func, addr, dngFunc, arg["name"])

    def strcpy(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        addr = inst["address"]
        dest = state.args["saved"][0]["value"]
        src = state.args["saved"][1]["value"]

        # in case there is a strcpy without an assignment to the source buffer
        srcSize = src.get("size", 0)

        # no overflow
        if srcSize <= dest["bytes"]:
            return

        # TODO v["rbp_rel_pos"] might not exist?
        vars = list(filter(lambda v: v["address"] != dest["address"] and v["rbp_rel_pos"] > dest["rbp_rel_pos"], state.vars))

        # variable overflow
        for v in vars:
            if "rbp_rel_pos" in v.keys() and dest["rbp_rel_pos"] + srcSize > v["rbp_rel_pos"]:
                varOvf(vuln_func, addr, dngFunc, dest["name"], v["name"])

        # invalid write access to non-assigned memory
        for mem in state.non_assigned_mem:
            mem_addr = "rbp" + hex(mem["start"])
            if dest["rbp_rel_pos"] + srcSize > mem["start"]:
                invalidAccs(vuln_func, addr, dngFunc, dest["name"], mem_addr)

        # RBP overflow
        if srcSize + dest["rbp_rel_pos"] > 0:
            rbpOvf(vuln_func, addr, dngFunc, dest["name"])

        # RET overflow
        if srcSize + dest["rbp_rel_pos"] > 8:
            retOvf(vuln_func, addr, dngFunc, dest["name"])

        # invalid write access to memory out of the current frame
        if srcSize + dest["rbp_rel_pos"] > 16:
            sCorruption(vuln_func, addr, dngFunc, dest["name"])


    def strcat(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]

        addr = inst["address"]

        # char * strcat(char *restrict s1, const char *restrict s2);
        # append s2 to s1
        # copies N-1 bytes from s2 and appends to N-1 bytes from s1
        # total size is 2N-2 + \0 (2N-1)
        
        dest = state.args["saved"][0]["value"]
        src = state.args["saved"][1]["value"]

        dest["size"] = dest["size"] + src["size"] - 1

        # everything is ok
        if dest["size"] <= dest["bytes"]:
            return
            print 'no ovf'

        reach = dest["rbp_rel_pos"] + dest["size"]

        # overflow
        vars = list(filter(lambda v: "rbp_rel_pos" in v.keys() and v["rbp_rel_pos"] > dest["rbp_rel_pos"], state.vars))

        # variable overflow
        for v in vars:
            if reach >= v["rbp_rel_pos"]:
                varOvf(vuln_func, addr, dngFunc, dest["name"], v["name"])

        # RBP overflow
        if reach >= 0:
            rbpOvf(vuln_func, addr, dngFunc, dest["name"])

        # invalid write access to non-assigned memory
        for mem in state.non_assigned_mem:
            mem_addr = "rbp" + hex(mem["start"])

            if reach > mem["start"]:
                invalidAccs(vuln_func, addr, dngFunc, dest["name"], mem_addr)
        
        # invalid write access to memory out of the current frame
        
        if reach > 0x10:
            sCorruption(vuln_func, addr, dngFunc, arg["name"])

    def fgets(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]

        # char * fgets(char * restrict str, int size, FILE * restrict stream);
        # reads $size - 1 bytes but writes $size (last byte is \0)

        dest = state.args["saved"][0]["value"]
        size = state.args["saved"][1]["value"]

        dest["size"] = size

        # no overflow
        if size <= dest["bytes"]:
            return

        # overflow
        excess = dest["bytes"] - size
        print '!!! overflow of %d bytes with fgets' % excess

        # TODO

    def strncpy(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]



        # TODO

    def strncat(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]

        # TODO

    # --------- ADVANCED ---------

    def sprintf(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        # TODO

    def scanf(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        # TODO

    def fscanf(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        # TODO

    def snprintf(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        # TODO

    def read(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
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

    if dngFunc in dng.keys():
        dng[dngFunc](vuln_func, inst)

# ----------------------------------
#          OPERATOR HANDLERS
# ----------------------------------

def handleOp(op, func, inst):
    def call(func, inst):
        global program
        global states

        state = states[len(states) - 1]
        printArgs()

        newFunc = inst["args"]["fnname"][1:-1] # <funcion-name> or <function-name>@plt

        if newFunc in program.keys():
            analyse_frame(newFunc)

        elif '@' in newFunc:
            newFunc = newFunc.split('@')[0]
            handleDng(newFunc, func, inst)
        
        state.args["saved"] = []

    def lea(func, inst):
        global program
        global states

        state = states[len(states) - 1]

        value = inst["args"]["value"]
        dest = inst["args"]["dest"]

        if value[0] == '[':
            value = value[1:-1]
            match = filter(lambda var: var["address"] == value, state.vars)
            
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
        global states

        state = states[len(states) - 1]

        # TODO handle all the possible cases of mov arguments (are all needed?)
        # register to register
        # register to pointer
        # pointer to register
        # number to register
        # umber to pointer
        
        vars = program[func]["variables"]

        dest = inst["args"]["dest"]
        value = inst["args"]["value"]

        dest_reg = state.getRegKeyFromRegisters(dest)
        if dest_reg == None:
            return
        
        if "WORD" in value:
            value = value.split(' ')[2][1:-1]

            if state.args_get(value) != None:
                state.write(dest, state.args_get(value))
            
            else:
                match = filter(lambda var: var["address"] == value, vars)
                
                if len(match) < 1:
                    state.write(dest, value)
                else:
                    state.write(dest, match[0])

        elif state.read(value) != None:
            content = state.read(value)
            state.write(dest, content)

        elif state.args_get(value) != None:
            content = state.args_get(value)
            state.write(dest, content)

        elif '0x' in value:
            value = int(value, 16)
            state.write(dest, value)

        else:
            state.write(dest, value)

    def sub(func, inst):
        global states

        state = states[len(states) - 1]

        dest = inst["args"]["dest"]
        value = inst["args"]["value"]

        if dest == "rsp":
            rsp = state.read(dest)
            state.write(dest, rsp - int(value, 16))

    op_handlers = {
        "call": call,
        "lea": lea,
        "mov": mov,
        "sub": sub
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
    global states
    state = states[len(states) - 1]

    if len(state.args["saved"]) == 0:
        return

    s = '\nArguments:\n'
    for arg in state.args["saved"]:
        s += '  {} \n'.format(json.dumps(arg["value"]))
    print s

def __main__():
    run()

__main__()