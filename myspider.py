import requests as request
from requests.utils import dict_from_cookiejar
import json
import math
import random
import pyDes
import base64
from datetime import datetime

#发送请求需要的数据
redirectData=""
ciphertext=""
userInfoData="username=18734967966&password=O%252Fy%252FOUI31LqaItC3ovPXWbC8Yx8RpH8aIy18ViG6e5SPqy3viKLmoD%252Bq73SJIOYyI%252FrhghiqGqwRocX%252BWj6nZFXYGjc0V2IfMfOFDzTuwtbcl38oo2WFqtXiFpyk0NHIZspY%252FhGBL7WcnWJJVtP3n1pDjaUye8cM7cR5n4m7ZnHdr9Qg%252FzqaJcZg3YEKpGTfk554FbM9%252F6QirN1QKvoBk037mJWFz%252Bita9cjqoWx4qqRFuZ6z2gMwmAqghl5V2KoHujpJN%252Fh58uiBS%252F%252Bc%252B6IbCABWH8OLphRtKvzkIp5RMWQNKVxr%252By7dNdB3%252BRJLOcvezy1i4eHVdA6UCTUdObTOg%253D%253D&appDomain=wenshu.court.gov.cn"
session = request.session() #爱死这个自动配制session的功能了TAT，被它卡了好几天了呜呜呜
__RequestVerificationToken=""
pageId=""
iv=""


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
    ciphertext=" ".join(format(c, "b") for c in bytearray(encodedS, "utf-8"))
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
################################################

# 配置cookies
# jar = request.cookies.RequestsCookieJar()
# jar.set('wzws_sessionid', 'oGVXBuWBYzAyZmNhgjZmNjkwMYAyMTguMjYuMTU5LjIzNg==', domain='wenshu.court.gov.cn', path='/')
# jar.set('SESSION', '52428406-c0f7-4d05-ac6d-3720d4f6a5db', domain='wenshu.court.gov.cn', path='/')
# jar.set('wzws_reurl', 'L3dlYnNpdGUvd2Vuc2h1L2ltYWdlcy95dWFuZGlhbi5wbmc=', domain='wenshu.court.gov.cn', path='/')
# 配置headers
headers={
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    #'Referer': 'https://wenshu.court.gov.cn/?open=login',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cors',
    'Sec-Fetch-User': '?0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'sec-ch-ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
    #'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"'
}

################### 登录操作 ###################
res = session.post("https://wenshu.court.gov.cn/tongyiLogin/authorize", headers=headers)#, cookies=jar)
redirectData = res.text 
session.get(redirectData, headers=headers) #模拟打开Login动态登录界面
session.get('https://account.court.gov.cn/app', headers=headers)
session.get('https://account.court.gov.cn/app?back_url=' + redirectData, headers=headers) #模拟打开app池
accountInfo=session.get('https://account.court.gov.cn/captcha/getBase64?appDomain=wenshu.court.gov.cn', headers=headers).json() #获取用户数据，转化为JSON格式
session.post('https://account.court.gov.cn/api/login', headers=headers, data=userInfoData) #模拟登录操作

# #解析Set-Cookies中的cookies字段
# set_cookie = res.headers.get('Set-Cookie')
# cookie_dict = dict_from_cookiejar(res.cookies)
# session.cookies.add_dict_to_cookiejar(session.cookies, cookie_dict)
# for(cookie in cookie_dict):
#     session.Cookies.update()
# 原来requests库自动处理了，他真的，我哭死

session.get(redirectData) #模拟重新进入登录后的主页
################################################

################### 检索操作 ####################
session.post('https://wenshu.court.gov.cn/api/fp/gjjsClick', headers=headers) #模拟点击高级检索按钮
session.post('https://wenshu.court.gov.cn/api/fp/cprq', headers=headers, data="inputCprqStartVal=2023-11-17") #模拟在审判日期（开始时间）控件进行了操作
session.post('https://wenshu.court.gov.cn/api/fp/cprq', headers=headers, data="inputCprqEndVal=2023-11-18") #模拟在审判日期（结束时间）控件进行了操作
res=session.post('https://wenshu.court.gov.cn/website/parse/rest.q4w', headers=headers, data=f"cfg=com.lawyee.judge.dc.parse.dto.SearchDataDsoDTO%40wsCountSearch&__RequestVerificationToken={refresh__RequestVerificationToken()}&wh=907&ww=913&cs=0") #电脑挂起，无操作时会自动想服务器发送ＰＯＳＴ请求
print(res.text)
session.post('https://wenshu.court.gov.cn/api/fp/cprq', headers=headers, data="inputCprqStartVal=2023-11-16&inputCprqEndVal=2023-11-17&gjjsSubmit=1") #模拟在审判日期控件操作结束，检索开始的标志
pageId=get_pageId()
session.get (f'https://wenshu.court.gov.cn/website/wenshu/181217BMTKHNT2W0/index.html?pageId={get_pageId()}',headers=headers ) #打开检索后的页面
headers={
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    #'Pragma': 'no-cache',
    'Referer': f'https://wenshu.court.gov.cn/website/wenshu/181217BMTKHNT2W0/index.html?pageId={pageId}d&cprqStart=2023-11-16&cprqEnd=2023-11-17',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?0',
    #'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'sec-ch-ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
    #'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'X-Requested-With': '"XMLHttpRequest"'
}
__RequestVerificationToken=refresh__RequestVerificationToken()
ciphertext=get_ciphertext()
res=session.post("https://wenshu.court.gov.cn/website/parse/rest.q4w", headers=headers, data=f"pageId={pageId}&cprqStart=2023-11-16&cprqEnd=2023-11-17&cfg=com.lawyee.wbsttools.web.parse.dto.AppUserDTO%40currentUser&__RequestVerificationToken={__RequestVerificationToken}Pegs&wh=907&ww=917&cs=0")
session.post("https://wenshu.court.gov.cn/website/parse/rest.q4w", headers=headers, data=f"pageId={pageId}&cprqStart=2023-11-16&cprqEnd=2023-11-17&sortFields=s50%3Adesc&ciphertext={get_ciphertext()}&pageNum=1&queryCondition=%5B%7B%22key%22%3A%22cprq%22%2C%22value%22%3A%222023-11-16+TO+2023-11-17%22%7D%5D&cfg=com.lawyee.judge.dc.parse.dto.SearchDataDsoDTO%40queryDoc&__RequestVerificationToken={__RequestVerificationToken}&wh=907&ww=917&cs=0")
print(ciphertext)
resjson=res.json()
secretKey=resjson.get('secretKey')
result=resjson.get('result')
des3=TripleDesUtils(mode="CBC", pad_mode="PAD_PKCS5", key=secretKey, iv=iv, trans_base64=True)
relwenshu=des3.decrypt(result)

################################################

################### 浏览文章 ####################

################################################

print(res.text)