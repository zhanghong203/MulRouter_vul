
import os
import sys
import time
import subprocess
from pathlib import Path

# ==================== 配置 ====================

os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

MODEL_ID = "BAAI/bge-m3"

# 下载到当前项目下的 models/bge-m3
PROJECT_ROOT = Path(__file__).resolve().parent
MODEL_DIR = PROJECT_ROOT / "models" / "bge-m3"

# 优先官方地址，失败后尝试镜像
ENDPOINTS = [
    "https://huggingface.co",
]

MAX_RETRIES = 3
MAX_WORKERS = 4

# ==================== 下载 ====================

def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print(f"模型名称: {MODEL_ID}")
    print(f"保存目录: {MODEL_DIR}")
    print("=" * 60)

    # 子进程下载代码
    download_code = """
from huggingface_hub import snapshot_download
from huggingface_hub.utils import enable_progress_bars

enable_progress_bars()

snapshot_download(
    repo_id="BAAI/bge-m3",
    local_dir=__import__("sys").argv[1],
    max_workers=4,
    etag_timeout=30,
)
"""

    for endpoint in ENDPOINTS:
        for attempt in range(1, MAX_RETRIES + 1):
            print(f"\n下载源: {endpoint}", flush=True)
            print(
                f"第 {attempt}/{MAX_RETRIES} 次尝试",
                flush=True
            )

            env = os.environ.copy()
            env["HF_ENDPOINT"] = endpoint
            env["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"
            env["HF_HUB_ETAG_TIMEOUT"] = "30"
            env["HF_HUB_DOWNLOAD_TIMEOUT"] = "120"
            env["PYTHONUNBUFFERED"] = "1"

            try:
                # 继承终端输出，实时显示下载进度条
                subprocess.run(
                    [
                        sys.executable,
                        "-u",
                        "-c",
                        download_code,
                        str(MODEL_DIR),
                    ],
                    env=env,
                    check=True,
                )

                print("\n" + "=" * 60)
                print("模型下载成功！")
                print(f"保存位置: {MODEL_DIR}")
                print("=" * 60)
                return

            except subprocess.CalledProcessError:
                print(
                    f"\n下载失败，尝试次数: {attempt}",
                    flush=True
                )

                if attempt < MAX_RETRIES:
                    print("5秒后重试...")
                    time.sleep(5)

        print(f"\n{endpoint} 不可用，切换下载源。")

    raise RuntimeError(
        "所有下载源均失败，请检查网络、代理或SSL配置。"
    )


if __name__ == "__main__":
    main()
