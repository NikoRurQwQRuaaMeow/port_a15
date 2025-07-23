import sys
import struct
from ctypes import Structure, sizeof, c_uint32, c_uint8

SPARSE_MAGIC = b'\x3a\xff\x26\xed'
EROFS_MAGIC = b'\xe2\xe1\xf5\xe0'
EXT_MAGIC = b'\x53\xef'
F2FS_MAGIC = (b'\x10 \xf5\xf2', b'\x10\x20\xf5\xf2')
BOOT_MAGIC = (b'ANDROID!', b'VNDRBOOT')
AVB_MAGIC = b'AVB0'
SUPER_GEOMETRY_MAGIC = 0x616c4467
SUPER_HEADER_MAGIC = 0x414C5030

class LpMetadataGeometry(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("struct_size", c_uint32),
        ("checksum", c_uint8 * 32),
        ("metadata_max_size", c_uint32),
        ("metadata_slot_count", c_uint32),
        ("logical_block_size", c_uint32),
    ]
    _pack_ = 1

def detect_super(path):
    try:
        with open(path, 'rb') as f:
            f.seek(4096)
            geo_data = f.read(sizeof(LpMetadataGeometry))
            if len(geo_data) < sizeof(LpMetadataGeometry):
                return False
            
            geometry = LpMetadataGeometry.from_buffer_copy(geo_data)
 
            if geometry.magic != SUPER_GEOMETRY_MAGIC:
                return False
            if geometry.metadata_slot_count == 0:
                return False
            if geometry.logical_block_size % 512 != 0:
                return False

            primary_header_offset = 4096 + 4096
            f.seek(primary_header_offset)
            header_magic = f.read(4)
            if struct.unpack('<I', header_magic)[0] == SUPER_HEADER_MAGIC:
                return True

            backup_header_offset = 4096 + 4096 * 2
            f.seek(backup_header_offset)
            backup_magic = f.read(4)
            return struct.unpack('<I', backup_magic)[0] == SUPER_HEADER_MAGIC

    except Exception as e:
        return False

def detect_sparse(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4) == SPARSE_MAGIC
    except:
        return False

def detect_erofs(path):
    try:
        with open(path, 'rb') as f:
            f.seek(1024)
            return f.read(4) == EROFS_MAGIC
    except:
        return False

def detect_ext(path):
    try:
        with open(path, 'rb') as f:
            f.seek(1080)
            return f.read(2) == EXT_MAGIC
    except:
        return False

def detect_f2fs(path):
    try:
        with open(path, 'rb') as f:
            f.seek(1024)
            data = f.read(4)
            return data in F2FS_MAGIC
    except:
        return False

def detect_bootimg(path):
    try:
        with open(path, 'rb') as f:
            return f.read(8)[:8] in BOOT_MAGIC
    except:
        return False

def detect_vbmeta(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4) == AVB_MAGIC
    except:
        return False

def get_img_type(path):
    detectors = [
        (detect_sparse, 'sparse'),
        (detect_bootimg, 'kernel'),
        (detect_vbmeta, 'vbmeta'),
        (detect_erofs, 'erofs'),
        (detect_ext, 'ext4'),
        (detect_f2fs, 'f2fs'),
        (detect_super, 'super')
    ]
    
    for detector, img_type in detectors:
        if detector(path):
            return img_type
    return 'unknown'

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python gettype.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    print(f"{get_img_type(file_path)}")
