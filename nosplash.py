import argparse
import lief
import io
import struct

end_payload = b"\x07\x53\x74\x72\x65\x74\x63\x68\x09\x00\x00\x06\x54\x49\x6D\x61\x67\x65\x06\x49\x6D\x61\x67\x65\x32\x00\x00\x06\x54\x49\x6D\x61\x67\x65\x06\x49\x6D\x61\x67\x65\x33\x00\x00\x00"

def find_and_get_index(content, phrase, currentIndex=0):
    index = content.find(phrase, currentIndex)
    if index > -1:
        return index + len(phrase)
        
    return index

def extract(resource):
    buffer = io.BytesIO(resource)
    index = 0
    i = 0
    while index != -1:
        index = find_and_get_index(content, b"Picture.Data", index + 1)
        
        if index != -1:
            buffer.seek(index + 1)
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
    
def calculate_resource_free_space(resource):
    start = find_and_get_index(content, b"Picture.Data") + 1
    
    return len(resource) - start - len(payload)

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

