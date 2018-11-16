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
    def __init__(self, vars, args=[], regs=None):
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

        if regs == None:
            for reg in self.registers_names:
                self.registers[reg[0]] = None
            self.registers["rsp"] = 0
        else:
            self.registers = regs

        self.args = {
            "regs": ("rdi","rsi","rdx","rcx","r8","r9"),
            "saved": [],
            "current": args
        }

        # saved pointers
        self.pointers = {}

        # local variables
        self.vars = []

        # non assigned memory
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

    def savePointer(self, addr, value):
        self.pointers[addr] = value
        print "\n+++ [%s] <-- %s\n" % (addr, json.dumps(value))

    def getPointer(self, addr):
        for saved_pointer_addr in self.pointers.keys():
            if saved_pointer_addr == addr:
                return self.pointers[saved_pointer_addr]
        return None

    def calc_non_assigned_memory(self):
        self.non_assigned_mem = []
        saved_pos = None
        saved_size = None
        
        if len(self.vars) == 0:
            return

        rsp = self.read("rsp")

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

        print self.non_assigned_mem
        
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

    if len(states) > 0:
        state = states[len(states) - 1]
        args = state.args["saved"]
        regs = state.registers

        states.append(State(vars, args, regs))
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

    def overflowReach(state, vuln_func, inst, addr, var):
        vars = list(filter(lambda v: "rbp_rel_pos" in v.keys() and v["rbp_rel_pos"] > var["rbp_rel_pos"], state.vars))

        reach = var["realSize"] + var["rbp_rel_pos"]

        for v in state.vars:
            print 'vars', v
        # variable overflow
        for v in vars:
            if reach >= v["rbp_rel_pos"]:
                varOvf(vuln_func, addr, dngFunc, var["name"], v["name"])

        # invalid write access to non-assigned memory
        for mem in state.non_assigned_mem:
            mem_addr = "rbp" + hex(mem["start"])
            print mem_addr, mem["start"], reach

            if reach > mem["start"]:
                invalidAccs(vuln_func, addr, dngFunc, var["name"], mem_addr)
        print var["name"], var["rbp_rel_pos"], var["realSize"], reach
        # RBP overflow
        if reach >= 0:
            rbpOvf(vuln_func, addr, dngFunc, var["name"])

        # RET overflow
        if reach >= 8:
            retOvf(vuln_func, addr, dngFunc, var["name"])

        # invalid write access to memory out of the current frame
        if reach >= 16:
            sCorruption(vuln_func, addr, dngFunc, var["name"])
    
    # with this function, everything can be overflown
    def gets(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        addr = inst["address"]

        arg = state.args["saved"][0]["value"]
        arg["realSize"] = -1 * arg["rbp_rel_pos"] + 100 # just to make it overflow everything
        arg["zeroFlag"] = False

        overflowReach(state, vuln_func, inst, addr, arg)

    def strcpy(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        addr = inst["address"]

        dest = state.args["saved"][0]["value"]
        src = state.args["saved"][1]["value"]

        # in case there is a strcpy without an assignment to the source buffer
        dest["realSize"] = src.get("realSize", 0)
        dest["zeroFlag"] = src["zeroFlag"]

        print 'TEST', dest["realSize"], dest["zeroFlag"]
        # must check if the src has /0

        # no overflow
        if dest["realSize"] < dest["bytes"] and src["zeroFlag"]:
            return

        # TODO deal with other datatypes
        if not dest["zeroFlag"]:
            for v in list(filter(lambda v: "rbp_rel_pos" in v.keys() and v["rbp_rel_pos"] > dest["rbp_rel_pos"], state.vars)):
                dest["realSize"] += v["realSize"] if "realSize" in v.keys() else v["bytes"]
                if "zeroFlag" in v.keys() and v["zeroFlag"]:
                    dest["zeroFlag"] = True
                    break

        print 'TEST', dest["realSize"], dest["zeroFlag"]
        overflowReach(state, vuln_func, inst, addr, dest)

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

        dest["realSize"] = dest["realSize"] + src["realSize"] 
        dest["zeroFlag"] = True

        # everything is ok
        if dest["realSize"] <= dest["bytes"]:
            return

        # overflow
        overflowReach(state, vuln_func, inst, addr, dest)

    def fgets(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        addr = inst["address"]

        # char * fgets(char * restrict str, int size, FILE * restrict stream);
        # reads $size - 1 bytes but writes $size (last byte is \0)

        dest = state.args["saved"][0]["value"]
        size = state.args["saved"][1]["value"]

        dest["realSize"] = size - 1
        dest["zeroFlag"] = True

        # no overflow
        if size <= dest["bytes"]:
            return

        # overflow
        overflowReach(state, vuln_func, inst, addr, dest)

    def strncpy(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        addr = inst["address"]
        
        # char *strncpy(char *dest, const char *src, size_t n)
        # strncpy produces  an  unterminated  string in dest if srcSize > size (doesn't write /0)
        # copies n bytes including /0, it it exists in src[n]
        
        dest = state.args["saved"][0]["value"]
        src = state.args["saved"][1]["value"]
        size = state.args["saved"][2]["value"]
        
        if src["realSize"] == size:
            dest["zeroFlag"] = src["zeroFlag"]
        elif src["realSize"] < size:
            dest["zeroFlag"] = True
        else:
            dest["zeroFlag"] = False

        dest["realSize"] = size - 1 if dest["zeroFlag"] else size

        # no overflow
        if size < dest["bytes"] and dest["zeroFlag"]:
            return

        # overflow
        overflowReach(state, vuln_func, inst, addr, dest)


    def strncat(vuln_func, inst):
        global program
        global states

        state = states[len(states) - 1]
        addr = inst["address"]

        # char *strncat(char *dest, const char *src, size_t n);
        
        dest = state.args["saved"][0]["value"]
        size = state.args["saved"][2]["value"]

        dest["realSize"] = dest["realSize"] + size
        dest["zeroFlag"] = True
        
        # no overflow
        if size <= dest["bytes"]:
            return
        
        # overflow
        overflowReach(state, vuln_func, inst, addr, dest)

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
        addr = inst["address"]
        
        # int snprintf(char *str, size_t size, const char *format, ...);
        
        dest = state.args["saved"][0]["value"]
        size = state.args["saved"][1]["value"]

        dest["realSize"] = size

        # no overflow
        if size <= dest["bytes"]:
            return
        
        # overflow
        overflowReach(state, vuln_func, inst, addr, dest)

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
                print "Not found. Searching in the registers"
                match = state.read(value)

                #TODO cant find rdi, for example, create new register?

                if match == None:
                    print "Not found on the registers. Exiting"
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
        
        # number to pointer
        
        vars = program[func]["variables"]

        dest = inst["args"]["dest"]
        value = inst["args"]["value"]

        dest_reg = state.getRegKeyFromRegisters(dest)
        value_reg = state.getRegKeyFromRegisters(value)

        # to register
        if dest_reg != None:

            # from pointer   
            if "PTR" in value:
                value = value.split(' ')[2][1:-1]
                
                if state.args_get(value) != None:
                    state.write(dest, state.args_get(value))
                    return
                
                match = filter(lambda var: var["address"] == value, vars)

                if len(match) > 0:
                    print vars, match
                    if len(match) < 1:
                        state.write(dest, value)
                    else:
                        state.write(dest, match[0])

                    return

                content = state.getPointer(value)
                print 'content of', value, content
                if content != None:
                    state.write(dest, content)
                    return

            if state.read(value) != None:
                content = state.read(value)
                state.write(dest, content)

            elif state.args_get(value) != None:
                content = state.args_get(value)
                state.write(dest, content)

            elif '0x' in value and 'rip' not in value:
                value = int(value, 16)
                state.write(dest, value)

            else:
                state.write(dest, value)

        # from register
        if value_reg != None:
            content = state.read(value_reg)
            
            # to pointer
            if 'PTR' in dest:
                dest = dest.split(' ')[2][1:-1]
                state.savePointer(dest, content)

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