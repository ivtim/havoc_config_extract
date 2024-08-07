import re
import sys
from struct import pack, unpack
import json


# Havoc constants
SLEEPOBF_NO_OBF  = 0
SLEEPOBF_EKKO    = 1
SLEEPOBF_ZILEAN  = 2
SLEEPOBF_FOLIAGE = 3

SLEEPOBF_BYPASS_NONE   = 0
SLEEPOBF_BYPASS_JMPRAX = 1
SLEEPOBF_BYPASS_JMPRBX = 2

PROXYLOADING_NONE             = 0
PROXYLOADING_RTLREGISTERWAIT  = 1
PROXYLOADING_RTLCREATETIMER   = 2
PROXYLOADING_RTLQUEUEWORKITEM = 3

AMSIETW_PATCH_NONE   = 0
AMSIETW_PATCH_HWBP   = 1
AMSIETW_PATCH_MEMORY = 2


class Unpacker:
    def __init__(self, new_bytes):
        self.buffer : bytes = new_bytes
        self.size   : int   = len(new_bytes)
        self.pointer: int   = 0
    
    def getint(self):
        int_buffer = self.buffer[self.pointer : self.pointer + 4]
        b = unpack('<i', int_buffer)
        self.pointer += 4
        return b[0]
    
    def getulong(self):
        int_buffer = self.buffer[self.pointer : self.pointer + 4]
        b = unpack('<L', int_buffer)
        self.pointer += 4
        return b[0]
    
    def getlong(self):
        int_buffer = self.buffer[self.pointer : self.pointer + 4]
        b = unpack('<l', int_buffer)
        self.pointer += 8
        return b[0]
    
    def getWstr(self):
        len = self.getulong()
        
        temp_array = self.buffer[self.pointer : self.pointer + len]
        b = unpack('<{}s'.format(len), temp_array)

        wstr = temp_array.decode('utf-16_le')
        wstr = wstr.strip()
        wstr = wstr.removesuffix('\x00')

        self.pointer += len
        return wstr


def parse_config(havoc_config):
    Config = {}

    unpacker = Unpacker(havoc_config)

    Config['Sleep']    = unpacker.getint()
    Config['Jitter']   = unpacker.getint()

    ConfigAlloc = unpacker.getint()
    if ConfigAlloc == 0:
        Config['Alloc'] = 'None'
    elif ConfigAlloc == 1:
        Config['Alloc'] = 'Win32'
    elif ConfigAlloc == 2:
        Config['Alloc'] = 'Native/Syscall'

    ConfigExecute  = unpacker.getint()
    if ConfigExecute == 0:
        Config['Execute'] = 'None'
    elif ConfigExecute == 1:
        Config['Execute'] = 'Win32'
    elif ConfigExecute == 2:
        Config['Execute'] = 'Native/Syscall'

    Config['ConfigSpawn64'] = unpacker.getWstr()
    Config['ConfigSpawn32'] = unpacker.getWstr()

    ConfigObfTechnique = unpacker.getint()
    if ConfigObfTechnique == SLEEPOBF_NO_OBF:
        Config['ObfTechnique'] = 'WaitForSingleObjectEx'
    elif ConfigObfTechnique == SLEEPOBF_FOLIAGE:
        Config['ObfTechnique'] = 'Foliage'
    elif ConfigObfTechnique == SLEEPOBF_EKKO:
        Config['ObfTechnique'] = 'Ekko'
    elif ConfigObfTechnique == SLEEPOBF_ZILEAN:
        Config['ObfTechnique'] = 'Zilean'


    ConfigObfBypass    = unpacker.getint()
    if ConfigObfBypass == SLEEPOBF_BYPASS_JMPRAX:
        Config['ObfBypass'] = 'BYPASS_JMPRAX'
    elif ConfigObfBypass == SLEEPOBF_BYPASS_JMPRBX:
        Config['ObfBypass'] = 'BYPASS_JMPRBX'


    Config['StackSpoof']   = unpacker.getint()

    ConfigProxyLoading = unpacker.getint()
    if ConfigProxyLoading == PROXYLOADING_NONE:
        Config['ProxyLoading'] = 'None (LdrLoadDll)'
    elif ConfigProxyLoading == PROXYLOADING_RTLREGISTERWAIT:
        Config['ProxyLoading'] = 'RtlRegisterWait'
    elif ConfigProxyLoading == PROXYLOADING_RTLCREATETIMER:
        Config['ProxyLoading'] = 'RtlCreateTimer'
    elif ConfigProxyLoading == PROXYLOADING_RTLQUEUEWORKITEM:
        Config['ProxyLoading'] = 'RtlQueueWorkItem'

    Config['Syscall']     = unpacker.getint()

    ConfigAmsiPatch    = unpacker.getint()
    if ConfigAmsiPatch == AMSIETW_PATCH_HWBP:
        Config['AmsiPatch'] = 'Hardware breakpoints'
    elif ConfigAmsiPatch == AMSIETW_PATCH_NONE:
        Config['AmsiPatch'] = 'None'

    # Listener Config
    Config['KillDate'] = unpacker.getlong()
    Config['WorkingHours'] = unpacker.getint()
    Config['Methode'] = unpacker.getWstr()
    Config['HostRotation'] = unpacker.getint()

    HostsLen = unpacker.getint()
    Config['Hosts'] = []
    for i in range(HostsLen):
        ip = unpacker.getWstr()
        port = unpacker.getint()
        Config['Hosts'].append('{}:{}'.format(ip, port))

    Config['Secure'] = unpacker.getint()
    Config['UserAgent'] = unpacker.getWstr()

    HeaderLen = unpacker.getint()
    Config['Headers'] = []
    for i in range(HeaderLen):
        headers = unpacker.getWstr()
        Config['Headers'].append(headers)

    UrisLen = unpacker.getint()
    Config['Uris'] = []
    for i in range(UrisLen):
        uris = unpacker.getWstr()
        Config['Uris'].append(uris)

    Config['ProxyEnabled'] = unpacker.getint()
    if Config['ProxyEnabled']:
        Config['ProxyUrl'] = unpacker.getWstr()
        Config['ProxyUsername'] = unpacker.getWstr()
        Config['ProxyPassword'] = unpacker.getWstr()
    
    return Config


def main():
    if len(sys.argv) != 2:
        print("Need to specify the path to the file")
        return

    fh = open(sys.argv[1], 'rb')
    content = fh.read()
    fh.close()

    # search havoc config
    content_hex = content.hex().upper()
    pattern = "(.([1-9a-fA-f].{6}))(.([1-9a-fA-f].{6}))((0(0|1|2|3)0{6}))((0(0|1|2|3)0{6}))(.{6}00).{5,500}50004F00530054"
    result = re.search(pattern, content_hex)
    if result == None:
        print("Can't find config in file")
        return
    
    try:
        found_index = int(result.start() / 2)
        config_raw = content[found_index:found_index+3000]
        parsed_config = parse_config(config_raw)
        json_config = json.dumps(parsed_config, indent=4)
        print(json_config)
    except:
        print("Error parse config")



if __name__ == "__main__":
    main()
