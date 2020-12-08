import idaapi
import idautils
import idc
import ida_bytes
import ida_frame
import ida_struct
import httplib
import re

class FunctionMapper():

    _moduleBase = 0x140000000
    verbose = False
    dryRun = False
    filePath = ""
    namePrefix = "AutoName::"
    appendAddressToName = True
    fails = []

    staticSet = 0
    sigSet = 0

    def __init__(self, filePath, dryRun = False, namePrefix = "AutoName::", appendAddressToName = False):
        self.filePath = filePath
        self.dryRun = dryRun
        self.namePrefix = namePrefix
        self.appendAddressToName = appendAddressToName

    def begin(self):
        print('\n\nStarting nFunctionMapper')
        self.parseAersFile()
        self.parseFile()

        print("\nFunctionMapper Complete")
        print("Signatures Found: {}".format(self.sigSet))
        print("Static Addresses Named: {}".format(self.staticSet))
        print("Error Count: {}".format(len(self.fails)))


        if (len(self.fails) > 0):
            print("\nErrors:")
            for e in self.fails:
                print("  - {}".format(e))

    def parseAersFile(self):
        print("Fetching Aers File")
        conn = httplib.HTTPSConnection("raw.githubusercontent.com")
        conn.request("GET", "/aers/FFXIVClientStructs/main/ida/ffxiv_idarename.py")
        response = conn.getresponse()
        if response.status == 200:
            string = response.read()
            exec(string)
        else:
            print("Failed to get AERS file")
        
    def parseFile(self):
        with open(self.filePath, 'r') as functionSigFile:
            buildingLine = ''
            for i, line in enumerate(functionSigFile):
                line = line.strip()
                if len(line) == 0 or line[0] == '#':
                    continue
                
                line = line.split('#')[0].strip()
                if (len(line) == 0):
                    continue

                buildingLine += line

                if (line[-1] == ','):
                    continue

                if (line[-1] == '_'):
                    buildingLine = buildingLine[:-1]
                    continue
                
                self.parseLine(buildingLine)
                buildingLine = ''

            if len(buildingLine) > 0:
                self.parseLine(buildingLine)
        
            
    def parseLine(self, line):
        if self.verbose:
            print(line)
        time.sleep(0.01)
        split = line.split(',')
        if (len(split) < 2):
            self.fails.append(line)
            return
        
        name = split[0]
        search = split[1]
        addr = False
        static = False
        if (search[:2] == '0x'):
            # Static Address
            addr = long(search[2:], 16)
            static = True
        else:
            # Signature Scan
            addr = idc.FindBinary(0, SEARCH_DOWN, search)
            if (addr < self._moduleBase or addr > self._moduleBase * 2):
                self.fails.append('Failed to find address for {} using signature scan.'.format(name))
                return
            addr, error = self.followAddress(addr)
            if (error):
                self.fails.append(error)
                return
        if (addr):
            fullName = self.nameAddress(addr, name)
            if (static):
                self.staticSet += 1
            else:
                self.sigSet += 1
            if (len(split[2:]) > 0):
                self.nameArguments(addr, split[2:], fullName)

    def followAddress(self, address):
        b = idaapi.get_byte(address)
        if (b == 0xE8):
            callOffset = ida_bytes.get_dword(address + 1)
            if (callOffset > 2147483647):
                callOffset -= 4294967296
            address = address + 5 + callOffset
            return address, False
        elif (b == 0xE9):
            # Lazy and none of my signatures use this yet...
            return address, "JMP Instruction signatures not supported yet"
        else:
            return address, False

    def nameAddress(self, address, name):
        if (name[0] == '$'):
            name = name[1:]
        else:
            name = self.namePrefix + name
            if (self.appendAddressToName):
                name = name + '_' + format(address, 'X')
        print(format(address, 'X') + " => " + name)
        if (self.dryRun == False):
            idc.MakeName(address, name)
        return name
    
    def nameArguments(self, address, argList, fullName):
        # cursed string manipulation...
        cfunc = idaapi.decompile(address)
        lvars = cfunc.get_lvars()
        i = 0
        for lvar in lvars:
            if (i >= len(argList)):
                break
            if lvar.is_arg_var:
                lvar.name = argList[i]
                i += 1
        t = idaapi.tinfo_t()
        cfunc.get_func_type(t)
        s = "{}".format(t)
        z = s.index("(")
        s = s[:z] + " sub" + s[z:]
        idc.SetType(address, s)

if __name__ == '__main__':
    FunctionMapper(os.path.dirname(os.path.abspath(__file__)) + "/ffxiv_dx11.fm").begin()