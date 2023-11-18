import math
import random
import pyDes
import base64
from datetime import datetime
# 随机获取一段3DES算法加密的密文，其中的参数会发送到服务器作为返回q4w的密文参数
pageId=""
def get_uuid():
    guid=""
    for i in range(1, 32):
        n=str(hex(int(str(math.floor(random.random()*16.0))))).replace("0x", "")
        guid+=n
    #pageId=guid
    return guid

def get_pageId():
    return get_uuid()


pageId=get_pageId()
print(pageId)
