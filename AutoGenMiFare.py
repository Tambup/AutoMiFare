    #!/usr/bin/env python
#
# Authors: Iordache, Rovetta, Tambu

import argparse


def main():
    desc="A program to automatize the charge of the dump.bin into the Chameleon, change of UID and than the elaboration of the log resulting from a failed challange-response."
    desc2=" It is important that chamlog.py and chamtool.py are located in the same directory of this file."
    argParser=argparse.ArgumentParser(description=desc+desc2)
    argGroup=argParser.add_argument_group(title="Command list")
    argGroup.add_argument("-u", "--uid", dest="uid", required=True, nargs=1, help="The UID of the new MiFare card")    
    argGroup.add_argument("-d", "--dump", dest="dump", nargs=1, required=True, help="The complete correct dump.bin file of the MiFare card")    


    args=argParser.parse_args()
    #with open(args.dump[0]) as dump:
    #    print(dump.read())

if __name__ == "__main__":
    main()