# ncm_converter_final_v2.py

import base64
import json
import os
from pathlib import Path
import configparser
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import signal
import sys
import queue
import time

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

CORE_KEY = bytes([0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57])
MODIFY_KEY = bytes([0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28])

# 全局变量
completed_files = 0
total_files = 0
shutdown_requested = False
progress_lock = threading.Lock()
message_queue = queue.Queue()

def signal_handler(signum, frame):
    """处理Ctrl+C信号"""
    global shutdown_requested
    shutdown_requested = True
    print("\n⚠️  检测到 Ctrl+C，正在安全退出...")
    print("🔄 等待正在处理的文件完成...")
    sys.exit(0)

def print_message(message):
    """线程安全的消息打印"""
    message_queue.put(message)

def process_message_queue():
    """处理消息队列中的消息"""
    while True:
        try:
            message = message_queue.get(timeout=0.1)
            print(message)
            message_queue.task_done()
        except queue.Empty:
            break

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

def decrypt_ncm(ncm_file_path, output_folder, delete_original, thread_id):
    """解密单个 NCM 文件（多线程版本）"""
    global completed_files, total_files, shutdown_requested
    
    if shutdown_requested:
        return
    
    file_name = Path(ncm_file_path).name
    conversion_successful = False
    
    # 创建线程专用的进度条前缀
    thread_prefix = f"[线程{thread_id:02d}]"

    try:
        total_size = os.path.getsize(ncm_file_path)
        
        # 创建该文件的进度条
        with tqdm(
            total=total_size, 
            desc=f"{thread_prefix} {file_name[:25]:<25}",
            unit='B', unit_scale=True, unit_divisor=1024,
            leave=False,
            position=thread_id + 1,  # 为总进度条预留position 0
            ncols=100,
            disable=shutdown_requested
        ) as pbar_file:
            
            if shutdown_requested:
                return
            
            with open(ncm_file_path, 'rb') as f:
                header = f.read(8)
                pbar_file.update(8)
                if header[:4] != b'CTEN' or header[4:] != b'FDAM':
                    print_message(f"{thread_prefix} ❌ 文件 {file_name} 不是一个有效的 ncm 文件，已跳过。")
                    return

                f.seek(2, 1)
                pbar_file.update(2)

                key_len = int.from_bytes(f.read(4), 'little')
                pbar_file.update(4)
                key_data = f.read(key_len)
                pbar_file.update(key_len)
                key_data = bytes([b ^ 0x64 for b in key_data])
                
                aes_cipher_core = AES.new(CORE_KEY, AES.MODE_ECB)
                music_key_encrypted = aes_cipher_core.decrypt(key_data)
                music_key = unpad(music_key_encrypted, AES.block_size, style='pkcs7')[17:]

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
                
                meta_len = int.from_bytes(f.read(4), 'little')
                pbar_file.update(4)
                meta_data = None
                if meta_len > 0:
                    meta_encrypted = f.read(meta_len)
                    pbar_file.update(meta_len)
                    meta_decrypted = bytes([b ^ 0x63 for b in meta_encrypted])
                    try:
                        meta_base64_decoded = base64.b64decode(meta_decrypted[22:])
                        aes_cipher_modify = AES.new(MODIFY_KEY, AES.MODE_ECB)
                        meta_json_bytes = aes_cipher_modify.decrypt(meta_base64_decoded)
                        meta_json_str = unpad(meta_json_bytes, AES.block_size, style='pkcs7').decode('utf-8')
                        meta_data = json.loads(meta_json_str[6:])
                    except Exception:
                        print_message(f"{thread_prefix} ⚠️ 警告: 文件 {file_name} 的元数据解析失败。")

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
                        if shutdown_requested:
                            return
                        chunk = f.read(0x8000)
                        if not chunk: break
                        pbar_file.update(len(chunk))
                        decrypted_chunk = bytearray(len(chunk))
                        for i, byte in enumerate(chunk):
                            j = (i + 1) & 0xff
                            decrypted_chunk[i] = byte ^ key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                        out_f.write(decrypted_chunk)
                
                # 标记核心转换成功
                conversion_successful = True
                
                # --- 独立的元数据写入步骤 ---
                try:
                    if output_extension == '.mp3':
                        set_mp3_meta(output_path, meta_data, cover_data)
                    elif output_extension == '.flac':
                        set_flac_meta(output_path, meta_data, cover_data)
                except Exception as e:
                    print_message(f"{thread_prefix} ⚠️ 警告: 为文件 {file_name} 写入元数据时出错: {e}")

    except Exception as e:
        print_message(f"{thread_prefix} ❌ 处理文件 {file_name} 时发生严重错误: {e}")
    
    # --- 独立的文件删除步骤 ---
    # 只有在核心转换成功且用户设置为删除时才执行
    if conversion_successful and delete_original:
        try:
            os.remove(ncm_file_path)
        except Exception as e:
            print_message(f"{thread_prefix} ❌ 删除原始文件 {file_name} 失败: {e}")
    
    # 更新全局进度计数器
    with progress_lock:
        completed_files += 1
        if conversion_successful:
            print_message(f"{thread_prefix}  {file_name} 转换完成！({completed_files}/{total_files})")
        else:
            print_message(f"{thread_prefix}  {file_name} 转换失败 ({completed_files}/{total_files})")

def get_optimal_thread_count():
    """获取最佳线程数量"""
    cpu_count = os.cpu_count()
    if cpu_count is None:
        return 2
    # 使用CPU核心数，但不超过8个线程，避免过度竞争
    return min(cpu_count, 8)

def load_config():
    """加载配置文件，如果不存在则创建默认配置"""
    config_file = Path('config.ini')
    config = configparser.ConfigParser()

    if not config_file.exists():
        print("未找到 config.ini 文件，将创建默认配置文件。")
        config['Settings'] = {
            'delete_on_completion': 'false',
            'output_directory': 'converted_music'
        }
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write("# 转换完成后是否删除原始的 .ncm 文件 (true/false)\n")
            f.write("# 指定转换后文件的输出目录 (如果留空则为 'converted_music')\n")
            config.write(f)

    config.read(config_file, encoding='utf-8')
    delete_on_completion = config.getboolean('Settings', 'delete_on_completion', fallback=False)
    output_directory = config.get('Settings', 'output_directory', fallback='converted_music').strip()
    if not output_directory:
        output_directory = 'converted_music'

    return delete_on_completion, output_directory

if __name__ == "__main__":
    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
    input_dir = "ncm_files"
    delete_original, output_dir = load_config()

    Path(input_dir).mkdir(exist_ok=True)
    Path(output_dir).mkdir(exist_ok=True)
    
    ncm_file_list = list(Path(input_dir).glob("*.ncm"))
    
    if not ncm_file_list:
        print(f"⚠️  在 '{input_dir}' 文件夹中没有找到任何 .ncm 文件。")
        print("请将需要转换的 ncm 文件放入该文件夹。")
    else:
        total_files = len(ncm_file_list)
        thread_count = get_optimal_thread_count()
        
        print(f"🎵 NCM 文件转换器 - 多线程版本")
        print("=" * 60)
        print(f"📁 输入目录: {input_dir}")
        print(f"📁 输出目录: {output_dir}")
        print(f"📊 待转换文件数: {total_files}")
        print(f"🔧 使用线程数: {thread_count} (系统CPU核心数: {os.cpu_count()})")
        print(f"🗑️ 完成后删除原文件: {'是' if delete_original else '否'}")
        print("=" * 60)
        print("💡 按 Ctrl+C 随时退出")
        print()
        
        start_time = time.time()
        
        try:
            # 创建简洁的总体进度条
            with tqdm(total=total_files, desc="🎯 总进度", unit="个", 
                     bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
                     ncols=80, position=0) as main_pbar:
                
                # 使用线程池执行器
                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    # 创建任务
                    futures = []
                    for i, ncm_file in enumerate(ncm_file_list):
                        thread_id = (i % thread_count) + 1
                        future = executor.submit(decrypt_ncm, ncm_file, output_dir, delete_original, thread_id)
                        futures.append(future)
                    
                    # 监控任务完成情况
                    completed_count = 0
                    
                    while completed_count < total_files:
                        # 检查是否有退出请求
                        if shutdown_requested:
                            break
                        
                        # 处理消息队列
                        process_message_queue()
                        
                        # 检查已完成的任务
                        with progress_lock:
                            new_completed = completed_files
                        
                        if new_completed > completed_count:
                            main_pbar.update(new_completed - completed_count)
                            completed_count = new_completed
                        
                        # 短暂休眠，避免过度占用CPU
                        time.sleep(0.2)
                    
                    # 等待所有线程完成
                    concurrent.futures.wait(futures)
                    
                    # 处理剩余的消息
                    process_message_queue()
        
        except KeyboardInterrupt:
            print("\n⚠️  检测到 Ctrl+C，正在安全退出...")
            print("🔄 等待正在处理的文件完成...")
            shutdown_requested = True
            # 清理进度条
            tqdm._instances.clear()
            sys.exit(0)
        
        if not shutdown_requested:
            end_time = time.time()
            elapsed_time = end_time - start_time
            
            print("\n" + "=" * 60)
            print(f"🎉 转换完成！")
            print(f"⏱️  总耗时: {elapsed_time:.2f} 秒")
            print(f"🚀 平均速度: {total_files/elapsed_time:.2f} 文件/秒")
            print(f"💪 多线程效率: {thread_count} 个线程并行处理")
            print("=" * 60)
        
        # 清理进度条
        tqdm._instances.clear()