import requests as request
from requests.utils import dict_from_cookiejar
# import urllib2
import re
import json
import math
import random
import pyDes
import base64
from datetime import datetime
import time

# session = request.session()

__RequestVerificationToken=""
redirectData=""
pageId=""
iv=""
ciphertext=""
# session="568eca32-bff1-44c6-a021-4fe03edbe3c0"
SESSION=""
wzws_sessionid=""
usedUserInfoData="username=18734967966&password=LZvhKECFXr7I1kb36B2Eytd5MHdBO2Nyb8QpMosEjt6kMCXUP6vbzfRBWlvtIW8Bwwsov854ndvhx8Cj%252BztgYDgCHdIASslCQL%252Br0bI1fWY1ZhvcxsnkfGOmCqnrkPj9ks4lDiCKEhQ7h5SVPOq51pbiKA3pDZn6xn5vQlDORknwGZSIVke9JDLl3u8b2yoM15Gc4oCpeiNFdr12pj2CgTXlZl%252B54VoiINtPbGrZ4lgO2BHqacW9ikTzjSvEiLvNTJCqNtUYYR9SGPjQsBcvyNKXJ469cFBl5SmCiEFwLdLSM6Ip5VSgLQyQhhaZCBxNjxwGk55W1trJV2WyFQ97zA%253D%253D&appDomain=wenshu.court.gov.cn"
userInfoData="username=13068089939&password=jwFyLYO8o979BxpgKHLhF%252FtMAIcEvv8T6BUnhYGNIQxhTa%252BHJH9%252BF7HB0WJ3Nfk7SyTZRVhBmyhxplXO194%252B1Q6YBxHQn%252BvbgwV8SpyB%252FqDSCNXLiGohBZrCMu%252FnXHAiqymEFzOqHsXH1K79cnorYDe%252FxTUhs3lH4LhX6yvvVPfKGwgbGE3W4NVFQzKYdEiR67BE4Rqb20rJnNFyKSmQmIAUdebZ151gP3K8xEEFZEAUiyGZSpMxdSIqYDAAUiuKpsbpgs%252FPy0p2VSenB7dS68Hosc%252BHLbRdwzorgioWMEbAee55%252BXi3kTBzw6SVtZz5cdmxvEBROQdNFl9aMqqePw%253D%253D&appDomain=wenshu.court.gov.cn"
_bl_uid="v8lC4oats3suvLevy8twggszvw5e"

################### 有关算法 ####################
# 获取uuid随机值，为获取pageId和docId做准备
def get_uuid():
    guid=""
    for i in range(1, 32):
        n=str(hex(int(str(math.floor(random.random()*16.0))))).replace("0x", "")
        guid+=n
    #pageId=guid
    return guid

# 获取随机值生成的24位__RequestVerificationToken
def refresh__RequestVerificationToken():
    length=24
    chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    result=""
    for i in range(0, length):
        result+=chars[random.randint(0, len(chars)-1)]
    __RequestVerificationToken=result
    return result

# cookies转字符串
def cookiesToString(cookies):
    cookieDict=cookies.get_dict()
    cookieHeader=""
    for cookie in cookieDict:
        cookieHeader+=f"{cookie}={cookieDict[cookie]};"
    return cookieHeader[:len(cookieHeader)-1]

# 随机获取一段3DES算法加密的密文，其中的参数会发送到服务器作为返回q4w的密文参数
def get_ciphertext():
    date=datetime.now()
    timestamp=str(datetime.now().timestamp())
    length=24
    chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    salt=""
    for i in range(0, length):
        salt+=chars[random.randint(0, len(chars)-1)]
    year=str(date.year)
    month=""
    if date.month < 10:
        month="0"+str(date.month+1)
    else:
        month=str(date.month)
    day=""
    if date.day < 10:
        day="0"+str(date.day)
    else:
        day=str(date.day)
    iv=year+month+day
    # print(iv)
    des3 = TripleDesUtils(mode="CBC", pad_mode="PAD_PKCS5", key=salt, iv=iv, trans_base64=True)
    encodedS=des3.encryption(timestamp)
    ciphertext="+".join(format(c, "b") for c in bytearray(encodedS, "utf-8"))
    return ciphertext

# 解码3DES加密密文
class TripleDesUtils:
    des_mode = {"CBC": pyDes.CBC, "ECB": pyDes.ECB}
    des_pad_mode = {"PAD_PKCS5": pyDes.PAD_PKCS5, "PAD_NORMAL": pyDes.PAD_NORMAL}

    def __init__(self, mode, pad_mode, key, iv, pad=None, trans_base64=False):
        """
        :param mode: des 加密模式，目前支持 CBC，ECB
        :param pad_mode: 目前支持 PAD_PKCS5，PAD_NORMAL
        :param trans_base64: 加密结果是否以 base64 格式输出
        :param key: 密钥
        :param iv: 偏移量
        :param pad:
        """
        self.trans_base64 = trans_base64
        # 3des
        self.k = pyDes.triple_des(key, TripleDesUtils.des_mode.get(mode), iv, pad, TripleDesUtils.des_pad_mode.get(pad_mode))
        # des
        # self.k = pyDes.des(key, TripleDesUtils.des_mode.get(mode), iv, pad, TripleDesUtils.des_pad_mode.get(pad_mode))

    def encryption(self, data: str) -> str:
        """
        3des 加密
        说明: 3DES数据块长度为64位，所以IV长度需要为8个字符（ECB模式不用IV），密钥长度为16或24个字符（8个字符以内则结果与DES相同
        IV与密钥超过长度则截取，不足则在末尾填充'\0'补足
        :param data: 待加密数据
        :return:
        """
        _encryption_result = self.k.encrypt(data)
        if self.trans_base64:
            _encryption_result = self._base64encode(_encryption_result)
        return _encryption_result.decode()

    def decrypt(self, data: str) -> str:
        """
        3des 解密
        :param data: 待解密数据
        :return:
        """
        if self.trans_base64:
            data = self._base64decode(data)
        _decrypt_result = self.k.decrypt(data)
        # 根据情况转义， 有的时候不需要 decode
        return _decrypt_result.decode('utf-8')

    @staticmethod
    def _base64encode(data):
        """
        base 64 encode
        :param data: encode data
        :return:
        """
        try:
            _b64encode_result = base64.b64encode(data)
        except Exception as e:
            raise Exception(f"base64 encode error:{e}")
        return _b64encode_result

    @staticmethod
    def _base64decode(data):
        """
        base 64 decode
        :param data: decode data
        :return:
        """
        try:
            _b64decode_result = base64.b64decode(data)
        except Exception as e:
            raise Exception(f"base64 decode error:{e}")
        return _b64decode_result

# 返回随机生成的pageId
def get_pageId():
    return get_uuid()


reqsession=request.session()
cookieHeader=""
ciphertext=get_ciphertext()
headers={
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'Connection': 'keep-alive',
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Cookie": cookieHeader,
    'Referer': '',
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
}
body = f"pageId={pageId}&cprqStart=2023-11-16&cprqEnd=2023-11-17&sortFields=s50%3Adesc&ciphertext={ciphertext}&pageNum=1&queryCondition=%5B%7B%22key%22%3A%22cprq%22%2C%22value%22%3A%222023-11-16+TO+2023-11-17%22%7D%5D&cfg=com.lawyee.judge.dc.parse.dto.SearchDataDsoDTO%40queryDoc&__RequestVerificationToken={__RequestVerificationToken}&wh=907&ww=829&cs=0"

# 第一步，请求Login页面获取未赋予权限的session和登录凭证HOLDONKEY
print('正在尝试请求登录...')
res=reqsession.post(f'https://account.court.gov.cn/api/login?{userInfoData}', headers=headers)
if(res.json().get("code")=='000000'):
    print(f"[请求状态] {res.json().get('message')}")
else:
    print(f"\n失败！\n[请求状态] {res.json().get('message')}")
    exit()
headers['Cookie']=cookiesToString(res.cookies)
time.sleep(3)

# 第二步，获取第一次重定向链接
res=reqsession.post(f'https://wenshu.court.gov.cn/tongyiLogin/authorize', headers=headers)
redirectData=res.text
print(res.headers)
pattern=r'SESSION=(.*?);'
SESSION=re.findall(pattern, res.headers['Set-Cookie'])[0]
# headers['Cookie'].replace(re.findall(r'SESSION=(.*?)$', headers['Cookie'])[0], SESSION)
if not (res.headers['Set-Cookie'].find("wzws_sessionid")==-1):
    pattern=r"wzws_sessionid=(.*?);"
    wzws_sessionid=re.findall(pattern, res.headers['Set-Cookie'])[0]

time.sleep(4)
# headers['Cookie'].replace(re.findall(pattern, headers['Cookie'])[0], wzws_sessionid)
# print(f"SESSION = {SESSION}")
# print(f"wzws_sessionid= = {wzws_sessionid}")

# 第三步，获取第二次重定向链接
HOLDONKEY=re.findall(r'HOLDONKEY=(.*?);', headers['Cookie'])[0]
headers['Cookie']=f"SESSION={SESSION};HOLDONKEY={HOLDONKEY};wzws_sessionid={wzws_sessionid}; _bl_uid={_bl_uid}"
headers['Accept']="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
headers['Referer']=f"https://account.court.gov.cn/app?back_url={redirectData}"
res=reqsession.get(redirectData, headers=headers, allow_redirects=False)
if not (res.headers['Set-Cookie'].find("wzws_sessionid")==-1):
    pattern=r"wzws_sessionid=(.*?);"
    wzws_sessionid=re.findall(pattern, res.headers['Set-Cookie'])[0]

# res = reqsession.get("https://wenshu.court.gov.cn/website/wenshu/181029CR4M5A62CH/index.html?", headers=headers)
# pattern=r"wzws_sessionid=(.*?);"
# wzws_sessionid=re.findall(pattern, res.headers['Cookie'])[0]
# headers['Cookie']=f"SESSION={SESSION};HOLDONKEY={HOLDONKEY};wzws_sessionid={wzws_sessionid}"
# res=reqsession.get(redirectData, headers=headers)
# print(redirectData)
res=reqsession.post('https://wenshu.court.gov.cn/website/parse/rest.q4w', data=body, headers=headers)
print(f"body: {res.text}")
print(f"headers: {res.headers}")
exit()

# headers['Cookie']+=';'+str(resjson.get('Set-Cookie'))
# res=reqsession.post('https://wenshu.court.gov.cn/website/parse/rest.q4w', data=body, headers=headers)

# print(headers)