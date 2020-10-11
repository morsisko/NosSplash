import argparse
import lief
import io
import struct
import sys
import re
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
    start = find_and_get_index(resource, b"Picture.Data") + 1
    
    return len(resource) - start - len(end_payload)
    
def main():
    parser = argparse.ArgumentParser(prog="nossplash", description="Simple script utility that allows you extract and set custom splash inside EWSF.EWS")
    parser.add_argument("ewsf", help="Path to EWSF.EWS", type=str)
    parser.add_argument("--extract", help="Extracts all splashes stored inside EWSF file", type=bool, nargs="?", default=False, const=True)
    parser.add_argument("-in", help="Your image that will be displayed during game start", type=str, dest="in_name")
    parser.add_argument("-quality", help="Quality of the JPEG image, only if format=jpeg", type=int, default=95, choices=range(1,101), metavar="[1-100]")
    parser.add_argument("-format", help="Format of the output image", type=str, default="bmp", choices=["jpeg", "bmp"])
    parser.add_argument("-out", help="Output filename, works only in non extract mode", type=str, default="out.EWS")

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
        output_file = open(args.out, mode="wb")
        im = Image.open(args.in_name)
        pos_of_res_in_file = file_content.find(content)
        pos_of_res_end = pos_of_res_in_file + len(content)
        
        im_binary = io.BytesIO()
        
        if args.format == "bmp":
            im.save(im_binary, format="bmp")
            
        elif args.format == "jpeg":
            if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
                im = im.convert("RGB")
                    
            im.save(im_binary, format="jpeg", quality=args.quality)
            
        else:
            print("Unknown format")
            sys.exit()
            
        im_binary.seek(0)
        image = im_binary.read()
        
        if len(image) > calculate_resource_free_space(content):
            print("You image is too big to fit into this file. Try to use jpeg output format or set lower image quality.")
            sys.exit()
            
        r = re.compile(b"\x53\x8B\xD8\xBA....\x8B\xC3\xE8....\xBA....\x8B\xC3\xE8....\xA1")
        match = r.search(file_content)
        
        if match:
            bfile_content = bytearray(file_content)
            bfile_content[match.start()+4:match.start()+6] = struct.pack("<H", im.height)
            bfile_content[match.start()+16:match.start()+18] = struct.pack("<H", im.width)
            file_content = bytes(bfile_content)
            
        ClientHeightOff = find_and_get_index(content, b"ClientHeight", 0) + 1
        ClientWidthOff = find_and_get_index(content, b"ClientWidth", 0) + 1

        imageIndexOff = find_and_get_index(content, b"Image1", 0)

        ImageHeightOff = find_and_get_index(content, b"Height", imageIndexOff) + 1
        ImageWidthOff = find_and_get_index(content, b"Width", imageIndexOff) + 1
        
        bcontent = bytearray(content)
        bcontent[ImageHeightOff:ImageHeightOff+2] = struct.pack("<H", im.height)
        bcontent[ImageWidthOff:ImageWidthOff+2] = struct.pack("<H", im.width)
        bcontent[ClientHeightOff:ClientHeightOff+2] = struct.pack("<H", im.height - 1)
        bcontent[ClientWidthOff:ClientWidthOff+2] = struct.pack("<H", im.width - 1)
        content = bytes(bcontent)
        
        output_file.write(file_content[:pos_of_res_in_file])
        pictureDataIndex = find_and_get_index(content, b"Picture.Data", 0) + 1
        
        output_file.write(content[:pictureDataIndex])
        
        if args.format == "bmp":
            output_file.write(struct.pack("<I", 1 + len(b"TBitmap") + 4 + len(image)))
            output_file.write(b"\x07")
            output_file.write(b"TBitmap")
        
        if args.format == "jpeg":
            output_file.write(struct.pack("<I", 1 + len(b"TJPEGImage") + 4 + len(image)))
            output_file.write(b"\x0A")
            output_file.write(b"TJPEGImage")
            
        output_file.write(struct.pack("<I", len(image)))
        output_file.write(image)
        output_file.write(end_payload)
        output_file.write(bytes([0 for i in range(pos_of_res_end - output_file.tell())]))
        output_file.write(file_content[output_file.tell():])
    
if __name__ == "__main__":
    main()