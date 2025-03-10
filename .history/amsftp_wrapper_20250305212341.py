from AMSFTP import AMSFTPClient, ConRequst, TransferSet, TransferCallback, TransferTask, PathInfo, BufferSizePair, BufferSet, ErrorInfo, TransferErrorCode

class SFTPClient:
    def __init__(self, request: ConRequst, keys: list[str]):
        self.client = AMSFTPClient(request, keys)

    def init(self)->TransferErrorCode:
        return self.client.init()
    
