import argparse
import lief
import io
import struct

def extract(resource):
    buffer = io.BytesIO(resource)
    index = 0
    i = 0
    while index != -1:
        toFind = b"Picture.Data"
        index = content.find(toFind, index + 1)
        
        if index != -1:
            buffer.seek(index + len(toFind) + 1)
            buffer.read(4)
            classNameLen, = struct.unpack("<B", buffer.read(1))
            name = buffer.read(classNameLen)
            
            format = ".jpg"
            if b"TBitmap" in name:
                format = ".bmp"
            
            currentPicLen, = struct.unpack("<I", buffer.read(4))
            
            print("Extracting:", str(index) + format)
            open(str(index) + format, mode="wb").write(buffer.read(currentPicLen))
            i += 1
            
    print("Extracted", i, "resource(s)")

parser = argparse.ArgumentParser(prog="nossplash", description="Simple script utility that allows you extract and set custom splash inside EWSF.EWS")
parser.add_argument("ewsf", help="Path to EWSF.EWS")
parser.add_argument("--extract", help="Extracts all splashes stored inside EWSF file", type=bool, nargs="?", default=False, const=True)

args = parser.parse_args()
ewsf = open(args.ewsf, mode="rb")
binary = lief.parse(ewsf.read())

content = None
for child in binary.resources.childs:
    for child_next in child.childs:
        if child_next.name == "TNOSSPLASHFORM_F":
            print(child_next.childs[0])
            content = bytes(child_next.childs[0].content)
            
            
if not content:
    exit
    
if args.extract:
    extract(content)

