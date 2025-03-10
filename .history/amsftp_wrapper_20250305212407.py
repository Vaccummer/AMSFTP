from AMSFTP import AMSFTPClient, ConRequst, TransferSet, TransferCallback, TransferTask, PathInfo, BufferSizePair, BufferSet, ErrorInfo, TransferErrorCode

class SFTPClient:
    def __init__(self, request: ConRequst, keys: list[str]):
        self.client = AMSFTPClient(request, keys)

    def init(self)->TransferErrorCode:
        return self.client.init()

    def check(self)->TransferErrorCode:
        return self.client.check()
    
    def reconnect(self)->TransferErrorCode:
        return self.client.reconnect()
    
    def ensure_dir(self, path: str)->TransferErrorCode:
        return self.client.ensure_dir(path)
    
    def stat(self, path: str)->PathInfo|TransferErrorCode:
        return self.client.stat(path)
    
    def exists(self, path: str)->TransferErrorCode:
        return self.client.exists(path)
    
    def is_dir(self, path: str)->TransferErrorCode:
        return self.client.is_dir(path)
    
    def is_file(self, path: str)->TransferErrorCode:
        return self.client.is_file(path)

    def is_symlink(self, path: str)->TransferErrorCode:
        return self.client.is_symlink(path)
    
    def listdir(self, path: str)->list[PathInfo]|TransferErrorCode:
        return self.client.listdir(path)
    
    def mkdir(self, path: str)->TransferErrorCode:
        return self.client.mkdir(path)
    
    def mkdir_p(self, path: str)->TransferErrorCode:
        return self.client.mkdir_p(path)
    
    def rmfile(self, path: str)->TransferErrorCode:
        return self.client.rmfile(path)
    
    def rmdir(self, path: str)->TransferErrorCode:
        return self.client.rmdir(path)
    
    def rm_trash(self, path: str)->TransferErrorCode:
        return self.client.rm_trash(path)
    
    def safe_rm(self, path: str)->TransferErrorCode:
        return self.client.safe_rm(path)
    
    
