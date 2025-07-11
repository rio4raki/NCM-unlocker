# ncm_converter_final.py

import base64
import json
import os
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("错误：未找到 PyCryptodome 库。")
    print("请使用 'pip install pycryptodome' 命令进行安装。")
    exit()

try:
    from mutagen.flac import FLAC, Picture
    from mutagen.id3 import APIC, ID3, TALB, TIT2, TPE1
    from mutagen.mp3 import MP3
except ImportError:
    print("错误：未找到 mutagen 库。")
    print("请使用 'pip install mutagen' 命令进行安装。")
    exit()

# 使用bytes数组定义密钥，避免任何编码问题
CORE_KEY = bytes([0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57])
MODIFY_KEY = bytes([0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28])

def set_mp3_meta(mp3_file, meta_data, cover_data):
    """为 MP3 文件写入元数据和封面"""
    try:
        audio = MP3(mp3_file, ID3=ID3)
        if audio.tags is None:
            audio.tags = ID3()

        if cover_data:
            mime_type = 'image/jpeg'
            if cover_data.startswith(b'\x89PNG\r\n\x1a\n'):
                mime_type = 'image/png'
            audio.tags.add(APIC(encoding=3, mime=mime_type, type=3, desc='Cover', data=cover_data))

        if meta_data:
            audio.tags.add(TIT2(encoding=3, text=meta_data.get('musicName', 'Unknown')))
            audio.tags.add(TALB(encoding=3, text=meta_data.get('album', 'Unknown')))
            artists = '/'.join(arr[0] for arr in meta_data.get('artist', [['Unknown']]))
            audio.tags.add(TPE1(encoding=3, text=artists))
        
        audio.save()
    except Exception as e:
        print(f"警告: 写入MP3元数据失败: {e}")

def set_flac_meta(flac_file, meta_data, cover_data):
    """为 FLAC 文件写入元数据和封面"""
    try:
        audio = FLAC(flac_file)
        if meta_data:
            audio['title'] = meta_data.get('musicName', 'Unknown')
            audio['album'] = meta_data.get('album', 'Unknown')
            artists = '/'.join(arr[0] for arr in meta_data.get('artist', [['Unknown']]))
            audio['artist'] = artists

        if cover_data:
            pic = Picture()
            pic.data = cover_data
            pic.mime = "image/png" if cover_data.startswith(b'\x89PNG\r\n\x1a\n') else "image/jpeg"
            pic.type = 3
            audio.add_picture(pic)
            
        audio.save()
    except Exception as e:
        print(f"警告: 写入FLAC元数据失败: {e}")

def decrypt_ncm(ncm_file_path, output_folder):
    """解密单个 NCM 文件"""
    file_name = Path(ncm_file_path).name
    try:
        with open(ncm_file_path, 'rb') as f:
            header = f.read(8)
            if header[:4] != b'CTEN' or header[4:] != b'FDAM':
                print(f"文件 {file_name} 不是一个有效的 ncm 文件，已跳过。")
                return

            f.seek(2, 1)

            # --- Core Key 解密 ---
            key_len = int.from_bytes(f.read(4), 'little')
            key_data = f.read(key_len)
            key_data = bytes([b ^ 0x64 for b in key_data])
            
            aes_cipher_core = AES.new(CORE_KEY, AES.MODE_ECB)
            # 关键修复：C++实现会忽略末尾不足16字节的数据，Python在这里需要手动对齐
            music_key_encrypted = aes_cipher_core.decrypt(key_data)
            # 使用标准的PKCS7 unpad
            music_key = unpad(music_key_encrypted, AES.block_size, style='pkcs7')[17:]

            # --- 构建 RC4-like 密钥流 ---
            key_box = bytearray(range(256))
            c = 0
            last_byte = 0
            key_offset = 0
            for i in range(256):
                swap = key_box[i]
                c = (swap + last_byte + music_key[key_offset]) & 0xff
                key_offset = (key_offset + 1) % len(music_key)
                key_box[i], key_box[c] = key_box[c], swap
                last_byte = c
            
            # --- 元数据解密 ---
            meta_len = int.from_bytes(f.read(4), 'little')
            meta_data = None
            if meta_len > 0:
                meta_encrypted = f.read(meta_len)
                meta_decrypted = bytes([b ^ 0x63 for b in meta_encrypted])
                try:
                    meta_base64_decoded = base64.b64decode(meta_decrypted[22:])
                    aes_cipher_modify = AES.new(MODIFY_KEY, AES.MODE_ECB)
                    meta_json_bytes = aes_cipher_modify.decrypt(meta_base64_decoded)
                    meta_json_str = unpad(meta_json_bytes, AES.block_size, style='pkcs7').decode('utf-8')
                    meta_data = json.loads(meta_json_str[6:]) # 去除 "music:" 前缀
                except Exception as e:
                    print(f"警告: 文件 {file_name} 的元数据解析失败: {e}")
            else:
                print(f"警告: 文件 {file_name} 缺少元数据信息。")

            # --- 封面图片读取 ---
            f.seek(5, 1)
            image_space = int.from_bytes(f.read(4), 'little')
            image_size = int.from_bytes(f.read(4), 'little')
            cover_data = f.read(image_size) if image_size > 0 else None
            if image_space > image_size:
                f.seek(image_space - image_size, 1)

            # --- 音频数据解密与写入 ---
            output_extension = f".{meta_data['format']}" if meta_data and 'format' in meta_data else '.mp3'
            output_path = Path(output_folder) / f"{Path(file_name).stem}{output_extension}"

            with open(output_path, 'wb') as out_f:
                while True:
                    chunk = f.read(0x8000)
                    if not chunk:
                        break
                    decrypted_chunk = bytearray(len(chunk))
                    for i, byte in enumerate(chunk):
                        j = (i + 1) & 0xff
                        decrypted_chunk[i] = byte ^ key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                    out_f.write(decrypted_chunk)
            
            # --- 写入元数据 ---
            if output_extension == '.mp3':
                set_mp3_meta(output_path, meta_data, cover_data)
            elif output_extension == '.flac':
                set_flac_meta(output_path, meta_data, cover_data)

            print(f"✅ 成功转换: {file_name} -> {output_path.name}")

    except Exception as e:
        print(f"❌ 处理文件 {file_name} 时发生严重错误: {e}")


if __name__ == "__main__":
    input_dir = "ncm_files"
    output_dir = "converted_music"

    Path(input_dir).mkdir(exist_ok=True)
    Path(output_dir).mkdir(exist_ok=True)

    print(f"▶️  开始批量转换 '{input_dir}' 文件夹中的 ncm 文件...")
    print("-" * 40)

    ncm_file_list = list(Path(input_dir).glob("*.ncm"))
    
    if not ncm_file_list:
        print(f"⚠️  在 '{input_dir}' 文件夹中没有找到任何 .ncm 文件。")
        print("请将需要转换的 ncm 文件放入该文件夹。")
    else:
        for ncm_file in ncm_file_list:
            decrypt_ncm(ncm_file, output_dir)
        print("-" * 40)
        print("🎉 所有文件转换完成。")