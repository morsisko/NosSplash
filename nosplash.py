import argparse
import lief
import io
import struct
import sys
from PIL import Image

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
parser.add_argument("ewsf", help="Path to EWSF.EWS", type=str)
parser.add_argument("--extract", help="Extracts all splashes stored inside EWSF file", type=bool, nargs="?", default=False, const=True)
parser.add_argument("-in", help="Your image that will be displayed during game start", type=str, dest="in_name")
parser.add_argument("-quality", help="Quality of the JPEG image, only if format=jpeg", type=int, default=95, choices=range(1,101), metavar="[1-100]")
parser.add_argument("-format", help="Format of the output image", type=str, default="bmp", choices=["jpeg", "bmp"])

args = parser.parse_args()
ewsf = open(args.ewsf, mode="rb")
file_content = ewsf.read()
binary = lief.parse(file_content)

content = None
for child in binary.resources.childs:
    for child_next in child.childs:
        if child_next.name == "TNOSSPLASHFORM_F":
            content = bytes(child_next.childs[0].content)
            
            
if not content:
    print("Couldn't find resource. Are you sure it's EWSF.EWS file?")
    sys.exit()
    
if find_and_get_index(content, b"Picture.Data") <= 0:
    print("Couldn't find any picture inside resource. Are you sure you pass correct EWSF.EWSF file?")
    sys.exit()
    
if args.extract is False and args.in_name is None:
    print("You need to specify either --extract or -in parameter")
    sys.exit()
    
if args.extract:
    extract(content)
    
else:
    imageFile = Image.open(args.in_name)
    pos_of_res_in_file = file_content.find(content)
        
    if args.format == "bmp":
        print("Bitmap")
        im_binary = io.BytesIO()
        imageFile.save(im_binary, format="bmp")
        im_binary.seek(0)
        
    elif args.format == "jpeg":
        print("Jpeg")
        im_binary = io.BytesIO()
        imageFile.save(im_binary, format="jpeg", quality=95)
        im_binary.seek(0)
    else:
        print("Unknown format")
        
print(args)
    

