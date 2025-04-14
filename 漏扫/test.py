import requests
from datetime import datetime
proxies = { #代理,流量导向burp
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


def extract_version(version_str):
    """从包含镜像名的字符串中提取纯净版本号"""
    try:
        # 分割字符串并提取版本部分
        return version_str.split(':')[-1]  # 处理 "minio/minio:RELEASE.xxx" 格式
    except (IndexError, AttributeError):
        return None
def is_vulnerable_version(version_str):
    """比较版本号"""
    min_version = "RELEASE.2019-12-17T23-16-33Z"
    max_version = "RELEASE.2023-03-20T20-16-18Z"

    def parse_time(v):
        """解析时间字符串为datetime对象"""
        try:
            time_part = v.split("RELEASE.")[-1]
            return datetime.strptime(time_part, "%Y-%m-%dT%H-%M-%SZ")
        except (ValueError, IndexError, TypeError):
            return None

    # 提取纯净版本号
    clean_version = extract_version(version_str)
    if not clean_version:
        return False

    # 转换为时间对象
    target_time = parse_time(clean_version)
    min_time = parse_time(min_version)
    max_time = parse_time(max_version)

    # 有效性检查
    if not all([target_time, min_time, max_time]):
        return False

    return min_time <= target_time < max_time
def main():
    url = "minio/minio:RELEASE.2020-03-12T18-04-18Z"
    print(is_vulnerable_version(url))


if __name__ == "__main__":
    main()