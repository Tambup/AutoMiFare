#!/usr/bin/env python
#
# Authors: Iordache, Rovetta, Tambu

import argparse
import chamtool
import Chameleon
import struct

def challangeResponseDetector(binaryStream):
    challangeResponses=[None] * 2
    counter=0
    while True:
        header = binaryStream.read(struct.calcsize('<BBH'))
        if (header is None):
            # No more data available
            break

        if (len(header) < struct.calcsize('<BBH')):
            # No more data available
            break
        
        (event, dataLength, time) = struct.unpack_from('>BBH', header)
        # Break if there are no more events
        if (Chameleon.Log.eventTypes[event]['name'] == 'EMPTY'):
            break

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
    desc2=" It is important that chamlog.py, chamtool.py, the 'Chamelon' directory and 'EM4233_010Editor_Template.bt' are located in the same directory of this file."
    argParser=argparse.ArgumentParser(description=desc+desc2)
    argGroup=argParser.add_argument_group(title="Command list")
    argGroup.add_argument("-u", "--uid", dest="uid", required=True, nargs=1, help="The UID of the new MiFare card")    
    argGroup.add_argument("-d", "--dump", dest="dump", nargs=1, required=True, help="The complete correct dump.bin file of the MiFare card")    

    args=argParser.parse_args()
    dump=args.dump[0]
    uid=args.uid
    #TODO qui va aggiunta la parte riguardante la comunicazione col chameleon
    
    #TODO questo file andra' acquisito dal Chameleon ed eliminata l'uguaglianza
    logName=dump
    logFile=open(logName, "rb")
    binaryChallangeResponses = challangeResponseDetector(logFile)
    logFile.close()
    print(binaryChallangeResponses)


if __name__ == "__main__":
    main()