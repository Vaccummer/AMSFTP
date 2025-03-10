from http import client
from AMSFTP import *
import am_store as am
import os
from glob import glob
def filename_cb(filename: str):
    print(filename)

def error_cb(error: str, error_code: TransferErrorCode):
    print(error, error_code)

def progress_cb(progress: int, total: int):
    print(round(progress / total * 100, 2), "%")

hostname = "172.28.14.64"
username = "am"
password = "1984"

port = 22
src = r'F:\Windows_Data\Desktop_File\New folder (3).rar'
dst = '/home/am/test2.rar'
size_t = os.path.getsize(src)
request = ConRequst(hostname=hostname, username=username, password=password, tar_system=TarSystemType.Unix, compression=False, port=port, trash_dir=r'/home/am/rm_trash', test_path='/home/am')
keys = [str(i) for i in glob(r'C:\Users\am\.ssh\*')]
set = TransferSet(transfer_type=TransferType.LocalToRemote, force_write=True)

callback = TransferCallback(progress_cb=progress_cb, filename_cb=filename_cb, error_cb=error_cb,cb_interval_ms=1000, total_bytes=size_t, need_error_cb=False, need_progress_cb=True, need_filename_cb=True,)

tasks = [
    TransferTask(src=src, dst=dst, path_type=PathType.FILE, size=size_t)
]
client = AMSFTPClient(request, keys)

