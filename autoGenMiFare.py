#!/usr/bin/env python
#
# Authors: Iordache, Rovetta, Tambu

import argparse
import chamtool
import Chameleon
import struct
import os
import sys

def chameleonCommunication(response, dump = None, uid = None):
    logFile = "temp.bin"
    chameleon = Chameleon.Device()
    connected = False
    
    while not connected:
        print(Chameleon.Device.listDevices())
        port = input("Insert device port: ")
        connected = chameleon.connect(port)
        if not connected:
            print ("Connection failed!")
    
    if response == "0":
        chameleon.cmdClearLog()
        print(chamtool.cmdUpload(chameleon, dump))
        print(chamtool.cmdUID(chameleon, uid))
        print(chamtool.cmdRedLED(chameleon, "CODEC_RX"))
        print(chamtool.cmdLogMode(chameleon, "MEMORY"))
    elif response == "1":
        print(chamtool.cmdLog(chameleon, logFile))
        
    chameleon.disconnect()
    return logFile

def challangeResponseDetector(binaryStream):
    challangeResponses=[None] * 2
    counter=0
    while True:
        header = binaryStream.read(struct.calcsize('<BBH'))
        if (header is None or len(header) < struct.calcsize('<BBH')):
            # No more data available
            return None
        
        (event, dataLength, time) = struct.unpack_from('>BBH', header)
        time -= 0
        # Break if there are no more events
        if (Chameleon.Log.eventTypes[event]['name'] == 'EMPTY'):
            return None

        binaryStream.read(dataLength)
        if event == 0x90: #APP AUTH
            header = binaryStream.read(struct.calcsize('<BBH'))
            (event, dataLength, time) = struct.unpack_from('>BBH', header)
            logData = binaryStream.read(dataLength)
            nt = Chameleon.Log.eventTypes[event]['decoder'](logData)
            
            header = binaryStream.read(struct.calcsize('<BBH'))
            (event, dataLength, time) = struct.unpack_from('>BBH', header)
            logData = binaryStream.read(dataLength)
            logData = Chameleon.Log.eventTypes[event]['decoder'](logData)

            nr = logData[:8]
            ar = logData[8:]
            entry = {
                    "nt": nt,
                    "nr": nr,
                    "ar": ar
                }
            challangeResponses[counter]=entry
            counter += 1
            if counter >= 2:
                return challangeResponses

def main():
    desc="A program to automatize the charge of the dump.bin into the Chameleon, change of UID and than the elaboration of the log resulting from a failed challange-response."
    desc2=" It is important that chamtool.py and the 'Chameleon' directory are located in the same directory of this file."
    argParser=argparse.ArgumentParser(description=desc+desc2)
    argGroup=argParser.add_argument_group(title="Command list")
    argGroup.add_argument("-t", "--type", dest="type", required=True, nargs=1, help="To Configure the chameleon(0) otherwise to read the log(1)")
    argGroup.add_argument("-u", "--uid", dest="uid", nargs=1, help="The UID of the new MiFare card; mandatory with -t 1")    
    argGroup.add_argument("-d", "--dump", dest="dump", nargs=1, help="The complete correct dump.bin file of the MiFare card; mandatory with -t 1")    

    args=argParser.parse_args()
    
    if args.type[0] == "1":
        fileName = chameleonCommunication(args.type[0])
    elif args.type[0] == "0":
        fileName = chameleonCommunication(args.type[0], args.dump[0], args.uid)
    try:
        if os.stat(fileName).st_size > 100 and args.type[0] == "1":
            with open(fileName, "rb") as logFile:
                binaryChallangeResponses = challangeResponseDetector(logFile)
                os.remove(fileName)
                if binaryChallangeResponses is not None:
                    if len(binaryChallangeResponses) >= 2:
                        print(binaryChallangeResponses)
                    elif len(binaryChallangeResponses) < 2:
                        print("Log containg only one challange-response")
                else:
                    print("Log not containing challange-responses")
        else:
            os.remove(fileName)
    except FileNotFoundError:
        if args.type[0] == "0":
            sys.exit()
        else:
            sys.exit("Error")
    

if __name__ == "__main__":
    main()