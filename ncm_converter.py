# ncm_converter_multithread_v4_pretty_progress.py

import base64
import json
import os
from pathlib import Path
import configparser
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 依赖库检查 ---
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

try:
    from tqdm import tqdm
except ImportError:
    print("错误：未找到 tqdm 库。")
    print("请使用 'pip install tqdm' 命令进行安装。")
    exit()

# --- 全局常量 ---
CORE_KEY = bytes([0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57])
MODIFY_KEY = bytes([0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28])
CONFIG_FILE = Path('config.ini')

# --- 元数据写入函数 ---
def set_mp3_meta(mp3_file, meta_data, cover_data):
    """为 MP3 文件写入元数据和封面"""
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

def set_flac_meta(flac_file, meta_data, cover_data):
    """为 FLAC 文件写入元数据和封面"""
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

# --- 核心解密函数 ---
def decrypt_ncm(ncm_file_path, output_folder, delete_original, main_pbar, position):
    """
    解密单个 NCM 文件，并在指定位置显示其独立进度条。
    所有文本输出都通过主进度条的 .write() 方法，以避免显示混乱。
    """
    file_name = Path(ncm_file_path).name
    conversion_successful = False

    try:
        total_size = os.path.getsize(ncm_file_path)
        with open(ncm_file_path, 'rb') as f, tqdm(
            total=total_size, 
            desc=f"  - {file_name[:25]:<25}",
            unit='B', unit_scale=True, unit_divisor=1024,
            position=position, # 关键：为这个文件的进度条指定一个固定的行
            leave=False       # 关键：完成后自动移除此进度条
        ) as pbar_file:
            header = f.read(8); pbar_file.update(8)
            if header[:4] != b'CTEN' or header[4:] != b'FDAM':
                main_pbar.write(f"文件 {file_name} 不是一个有效的 ncm 文件，已跳过。")
                return

            f.seek(2, 1); pbar_file.update(2)

            key_len = int.from_bytes(f.read(4), 'little'); pbar_file.update(4)
            key_data = f.read(key_len); pbar_file.update(key_len)
            key_data = bytes([b ^ 0x64 for b in key_data])
            
            aes_cipher_core = AES.new(CORE_KEY, AES.MODE_ECB)
            music_key_encrypted = aes_cipher_core.decrypt(key_data)
            music_key = unpad(music_key_encrypted, AES.block_size, style='pkcs7')[17:]

            key_box = bytearray(range(256))
            c = 0; last_byte = 0; key_offset = 0
            for i in range(256):
                swap = key_box[i]
                c = (swap + last_byte + music_key[key_offset]) & 0xff
                key_offset = (key_offset + 1) % len(music_key)
                key_box[i], key_box[c] = key_box[c], swap
                last_byte = c
            
            meta_len = int.from_bytes(f.read(4), 'little'); pbar_file.update(4)
            meta_data = None
            if meta_len > 0:
                meta_encrypted = f.read(meta_len); pbar_file.update(meta_len)
                meta_decrypted = bytes([b ^ 0x63 for b in meta_encrypted])
                try:
                    meta_base64_decoded = base64.b64decode(meta_decrypted[22:])
                    aes_cipher_modify = AES.new(MODIFY_KEY, AES.MODE_ECB)
                    meta_json_bytes = aes_cipher_modify.decrypt(meta_base64_decoded)
                    meta_json_str = unpad(meta_json_bytes, AES.block_size, style='pkcs7').decode('utf-8')
                    meta_data = json.loads(meta_json_str[6:])
                except Exception:
                    main_pbar.write(f"警告: 文件 {file_name} 的元数据解析失败。")
            else:
                main_pbar.write(f"警告: 文件 {file_name} 缺少元数据信息。")

            f.seek(5, 1); pbar_file.update(5)
            image_space = int.from_bytes(f.read(4), 'little'); pbar_file.update(4)
            image_size = int.from_bytes(f.read(4), 'little'); pbar_file.update(4)
            cover_data = f.read(image_size) if image_size > 0 else None
            pbar_file.update(image_size)
            if image_space > image_size:
                f.seek(image_space - image_size, 1)
                pbar_file.update(image_space - image_size)

            output_extension = f".{meta_data['format']}" if meta_data and 'format' in meta_data else '.mp3'
            output_path = Path(output_folder) / f"{Path(file_name).stem}{output_extension}"

            with open(output_path, 'wb') as out_f:
                while True:
                    chunk = f.read(0x8000)
                    if not chunk: break
                    pbar_file.update(len(chunk))
                    decrypted_chunk = bytearray(len(chunk))
                    for i, byte in enumerate(chunk):
                        j = (i + 1) & 0xff
                        decrypted_chunk[i] = byte ^ key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                    out_f.write(decrypted_chunk)
            
            conversion_successful = True
            
            try:
                if output_extension == '.mp3':
                    set_mp3_meta(output_path, meta_data, cover_data)
                elif output_extension == '.flac':
                    set_flac_meta(output_path, meta_data, cover_data)
            except Exception as e:
                main_pbar.write(f"警告: 为文件 {output_path.name} 写入元数据时出错: {e}")

    except Exception as e:
        main_pbar.write(f"❌ 处理文件 {file_name} 时发生严重错误: {e}")
    
    if conversion_successful and delete_original:
        try:
            os.remove(ncm_file_path)
            main_pbar.write(f"  - 原始文件 {file_name} 已删除。")
        except Exception as e:
            main_pbar.write(f"❌ 删除原始文件 {file_name} 失败: {e}")

# --- 配置加载函数 ---
def load_config():
    """加载配置文件，如果不存在则创建默认配置"""
    config = configparser.ConfigParser()

    if not CONFIG_FILE.exists():
        print("未找到 config.ini 文件，将创建默认配置文件。")
        config['Settings'] = {
            'delete_on_completion': 'false',
            'output_directory': 'converted_music',
            'max_workers': str(os.cpu_count() or 1)
        }
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write("# 转换完成后是否删除原始的 .ncm 文件 (true/false)\n")
            f.write("# 指定转换后文件的输出目录 (如果留空则为 'converted_music')\n")
            f.write("# 最大并发转换任务数 (建议设置为你的 CPU 核心数, 留空则自动检测)\n")
            config.write(f)

    config.read(CONFIG_FILE, encoding='utf-8')
    delete = config.getboolean('Settings', 'delete_on_completion', fallback=False)
    output_dir = config.get('Settings', 'output_directory', fallback='converted_music').strip() or 'converted_music'
    
    try:
        max_workers = config.getint('Settings', 'max_workers')
        if max_workers <= 0:
            max_workers = os.cpu_count() or 1
    except (ValueError, configparser.NoOptionError):
        max_workers = os.cpu_count() or 1

    return delete, output_dir, max_workers

# --- 主函数 ---
def main():
    """主执行函数"""
    input_dir = "ncm_files"
    delete_original, output_dir, max_workers = load_config()

    Path(input_dir).mkdir(exist_ok=True)
    Path(output_dir).mkdir(exist_ok=True)
    
    ncm_file_list = list(Path(input_dir).glob("*.ncm"))
    
    if not ncm_file_list:
        print(f"[警告]  在 '{input_dir}' 文件夹中没有找到任何 .ncm 文件。")
        print("       请将需要转换的 ncm 文件放入该文件夹。")
    else:
        print(f"[开始]  即将开始转换 '{input_dir}' 文件夹中的 {len(ncm_file_list)} 个 ncm 文件...")
        print(f"   - 输出目录: {output_dir}")
        print(f"   - 完成后删除原文件: {'是' if delete_original else '否'}")
        print(f"   - 最大并发任务数: {max_workers}")
        print("-" * 40)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 创建主进度条，位置固定在最上方 (position=0)
            with tqdm(total=len(ncm_file_list), desc="总体进度", unit="个", position=0) as pbar:
                # 为每个文件提交一个任务，并分配一个唯一的、递增的 position
                # position=0 被主进度条占用，所以文件进度条从 1 开始
                futures = [
                    executor.submit(decrypt_ncm, ncm_file, output_dir, delete_original, pbar, i + 1)
                    for i, ncm_file in enumerate(ncm_file_list)
                ]
                
                for future in as_completed(futures):
                    # 等待任务完成，然后更新主进度条
                    future.result() # 获取结果（主要是为了捕获线程中的异常）
                    pbar.update(1)
        
        print("\n" * (min(len(ncm_file_list), max_workers) + 1)) # 在最后输出足够多的换行符，避免光标位置错乱
        print("-" * 40)
        print("[完成!] 所有文件转换完成。")

if __name__ == "__main__":
    main()
    input("\n按任意键退出...")