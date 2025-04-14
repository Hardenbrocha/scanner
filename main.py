import module
# main.py
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import module
import sys
from collections import defaultdict


def get_all_cve_functions():
    """获取module.py中所有CVE开头的漏洞函数"""
    functions = []
    for name in dir(module):
        # if name.startswith("CVE_"):
        func = getattr(module, name)
        if callable(func):
            cve_id = name.replace("_", "-")
            functions.append((cve_id, func))
    return functions


def scan_task_wrapper(task):
    """任务执行包装函数"""
    url, cve_id, func, args = task
    try:
        is_vulnerable = func(url, args)
        return (url, cve_id, is_vulnerable)
    except Exception as e:
        print(f"[ERROR] {url} {cve_id}: {str(e)}")
        return (url, cve_id, False)


def main():
    # 参数解析
    parser = argparse.ArgumentParser(description='漏洞扫描工具')
    parser.add_argument('--func', help='指定单个漏洞函数（如CVE-2020-1346）')
    parser.add_argument('--args', help='传递给漏洞函数的参数')
    args = parser.parse_args()

    # 读取URL列表
    try:
        with open('urls.txt', 'r',encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("错误: 未找到 urls.txt 文件")
        sys.exit(1)

    # 准备扫描任务
    tasks = []
    if args.func:  # 单个漏洞模式
        func_name = args.func.replace("-", "_")
        try:
            func = getattr(module, func_name)
            cve_functions = [(args.func, func)]
        except AttributeError:
            print(f"错误: 未找到 {args.func} 检测函数")
            sys.exit(1)
    else:  # 全漏洞模式
        cve_functions = get_all_cve_functions()
        if not cve_functions:
            print("错误: 未找到任何漏洞检测函数")
            sys.exit(1)

    # 生成任务队列
    for cve_id, func in cve_functions:
        tasks.extend([(url, cve_id, func, args.args) for url in urls])

    # 执行并发扫描
    results = defaultdict(list)
    total_tasks = len(tasks)

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_task_wrapper, task) for task in tasks]

        with tqdm(total=total_tasks, desc="扫描进度", unit="task") as pbar:
            for future in as_completed(futures):
                url, cve_id, is_vuln = future.result()
                if is_vuln:
                    results[url].append(cve_id)
                # print("\n")
                pbar.update(1)


    # 打印结果
    print(f"扫描完成！发现 {sum(len(v) for v in results.values())} 个漏洞")


if __name__ == "__main__":
    main()