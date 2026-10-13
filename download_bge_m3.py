import re
import json
import argparse
import os
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from control_flow.control_flow.vuln_flow_analyzer import analyze_code_str
from retrieval import search_by_query, parse_cwe_xml, get_weakness_by_id
from openai import OpenAI
from tqdm import tqdm
from metrics_tracker import VulnerabilityMetricsTracker

client = None
PROJECT_DIR = Path(__file__).resolve().parent
MODEL_NAME = "siliconflow/deepseek-v3.2"
retrieval_lock = threading.Lock()


def get_client():
    """Create the API client from environment variables without storing secrets in code."""
    global client
    if client is None:
        api_key = "sk-ws-H.PPHYIMM.e3Gc.MEUCIDIAL61n2XJJ3qBC6syPaWde_Qk0TKEyCI6Mcf6OJtTPAiEAlqYXQcDCmkAAj6PNJD7KyYr56Ny8-YtDCfpnTbuuir0"
        if not api_key:
            raise RuntimeError("未设置 OPENAI_API_KEY 环境变量")
        client = OpenAI(
            api_key=api_key,
            base_url="https://llm-1neu7kbunsxvfi48.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
            max_retries=3,
            timeout=120.0,
        )
    return client

user_prompt1 = (
    "You are a senior software engineer and static code analyst.\n"
    "Your task is to understand the functionality of the given source code.\n\n"

    "Instructions:\n"
    "1. Carefully analyze the code to determine its main functionality.\n"
    "2. Identify important operations such as input handling, memory operations, file operations, or system calls.\n"
    "3. Describe how data flows through the program when possible.\n"
    "4. Think through the logic internally step-by-step, but DO NOT output your reasoning process.\n"
    "5. Only describe behavior that can be directly inferred from the code.\n"
    "6. Do NOT speculate about functionality that is not visible in the code.\n"
    "7. Do NOT repeat or quote the code.\n"
    "8. Do NOT use markdown, bullet points, or special formatting.\n"
    "9. Keep the summary concise and factual.\n\n"

    "If the code is incomplete or unclear, describe only the observable behavior rather than guessing the intended functionality.\n\n"
)

user_prompt2 = (
    "You are a senior application security expert and professional code auditor. "
    "Your task is to analyze the provided source code and identify realistic security vulnerabilities.\n\n"

    "Instructions:\n"
    "1. Carefully analyze the target code.\n"
    "2. Identify vulnerabilities that are realistically present or highly likely.\n"
    "3. Think step-by-step internally, but do NOT output your reasoning process.\n"
    "4. You may report AT MOST TWO vulnerability types.\n"
    "5. If only one vulnerability exists, report only one.\n"
    "6. If no vulnerabilities are found, output: 'No'\n"
    "7. You should be bold in predicting code vulnerabilities.\n\n"

    "Output Format (STRICT):\n"
    "1. Vulnerability Type: Description of the vulnerability type (describe the general vulnerability concept only, do NOT reference the specific code).\n"
    "2. Vulnerability Type: Description of the vulnerability type.\n\n"

    "Rules:\n"
    "- Maximum of TWO vulnerabilities.\n"
    "- The description should explain the vulnerability class in general terms.\n"
    "- Do not reference specific variables, functions, or code snippets.\n"
    "- Do not include reasoning or analysis steps.\n\n"
)

VULN_DETECTION_PROMPT = """
You are a senior software security auditor specializing in static code analysis and vulnerability detection.
Your task is to compare the two pieces of code and their respective auxiliary information, and then determine whether there are any vulnerabilities in the codes.
Fully scan all vulnerabilities, including high, medium, and low, without missing any known vulnerability patterns.

-----------------------------------------------
Input Description
-----------------------------------------------

{Code-1}
[Source Code]
The target source code to analyze.

[Source Code Description]
A high-level explanation of the code logic.

[Static Structural Information]
Static analysis results such as control flow graph, call graph, and structural features.

[Possible Vulnerability Description and Example]
A description of a possible vulnerability pattern and example vulnerable code.

{Code-2}
The type of content is the same as that of Code-1.

-----------------------------------------------
Internal Analysis Procedure (DO NOT OUTPUT)
-----------------------------------------------

1. Understand the functionality and purpose of the source code.
2. Identify potential security-sensitive operations (memory operations, system calls, input handling).
3. Trace possible data flows from external inputs to sensitive operations.
4. Determine whether any input validation, sanitization, or boundary checks exist.

-----------------------------------------------
Critical Reasoning Rules (DO NOT OUTPUT)
-----------------------------------------------

1. As long as there is a little bit of security risk, unsafe, must be determined as a vulnerability.
2. The output consists of two lines. The first line is the judgment of Code-1, and the second line is the judgment of Code-2. Both should only contain 'Yes' or 'No'.
3. Do NOT use markdown, bullet points, or special formatting.
4. Key checks: SQL injection, XSS, command injection, ultra vires, buffer overflow, null pointer, unvalidated input, weak encryption scheme, permission issues.
5. Don't leave out any possible code vulnerabilities, because they can lead to unexpected losses.

-----------------------------------------------
Output Format (STRICT)
-----------------------------------------------

Yes/No (for Code-1)
Yes/No (for Code-2)
"""


def call_gpt(gpt_prompt):
    """
    :param prompt: 你的提问/指令（字符串）
    :return: 模型的回答结果
    """
    try:
        completion = get_client().chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "user", "content": gpt_prompt},
            ],
            temperature=0,
            seed=42,
            max_tokens=1024,
        )

        content = completion.choices[0].message.content
        if not content or not content.strip():
            raise RuntimeError("API 返回了空内容")
        return content.strip()

    except Exception as e:
        raise RuntimeError(f"模型 API 调用失败（model={MODEL_NAME}）：{e}") from e


def process_string_to_array(raw_str: str) -> list:
    """
    移除行头数字+顿号，将字符串转为按行分割的数组
    :param raw_str: 原始带行号的字符串
    :return: 清理后的字符串数组（每行一个元素，无空行）
    """
    lines = raw_str.split('\n')

    pattern = re.compile(r'^\d+.\s*')

    result = []
    for line in lines:
        cleaned_line = pattern.sub('', line).strip()
        if cleaned_line:
            result.append(cleaned_line)

    return result


def read_jsonl_iteratively(file_path):
    """
    迭代读取 JSONL 文件，每次返回两条数据的 target 和 func 字段
    :param file_path: JSONL 文件路径
    :yield: 包含两个字典的元组，每个字典包含 target 和 func
    """
    buffer = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                # 提取 target 和 func 字段
                result = {
                    "target": data.get("target"),
                    "func": data.get("func")
                }
                buffer.append(result)

                if len(buffer) == 2:
                    yield buffer[0], buffer[1]
                    buffer = []

            except json.JSONDecodeError as e:
                print(f"第 {line_num} 行 JSON 解析失败：{e}")
                continue

        if len(buffer) == 1:
            print(f"警告：文件末尾剩余 1 条数据，无法配对")


def count_lines_in_jsonl(file_path):
    """
    统计 JSONL 文件的有效行数（非空行）
    :param file_path: 文件路径
    :return: 有效行数
    """
    count = 0
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def get_knowledge(query_content):
    knowledge = ''
    if query_content == "No":
        knowledge += "No obvious vulnerabilities were initially found.Further analysis of potential vulnerabilities is required."
        print("未发现可能的漏洞，无查询项")
    else:
        query_array = process_string_to_array(query_content)
        order = 1
        id_list = []
        for query in query_array:
            # BGEM3FlagModel is shared by all workers. Serialize GPU inference
            # while allowing static analysis and remote API calls to overlap.
            with retrieval_lock:
                query_result = search_by_query(query, top_k=1)

            for ID, score in query_result:
                if ID in id_list:
                    continue
                else:
                    id_list.append(ID)
                XML_FILE = PROJECT_DIR / "cwec_latest.xml" / "cwec_v4.19.1.xml"
                # 解析XML并构建映射
                weakness_dict = parse_cwe_xml(XML_FILE)
                result = get_weakness_by_id(weakness_dict, ID)

                if result:
                    code = ""
                    for segment in result['Bad_Example_Code']:
                        code += segment

                    knowledge = knowledge + "\n" + str(order) + "、" + result['Name'] + "：" + result[
                        'Description'] \
                                + " Examples of Vulnerable Code:" + code
                    order += 1
    return knowledge


def extract_preds(output_text):
    """
    从指定格式的输出文本中提取标签
    :param output_text: 输入文本，包含两行，每行是Yes/No（大小写/空格不敏感）
    :return: 两个标签组成的列表，[代码1的标签, 代码2的标签]
    """
    if not isinstance(output_text, str):
        raise ValueError(f"模型输出不是字符串：{type(output_text).__name__}")

    # Accept the official two-line format as well as harmless wrappers such as
    # code fences, numbering, or "Code-1: Yes" labels.
    matches = []
    line_pattern = re.compile(
        r"^(?:(?:code\s*[-_ ]?\s*[12]|[12])\s*[:：.)-]?\s*)?(yes|no)[.!。]?$",
        re.IGNORECASE,
    )
    for raw_line in output_text.replace("```", "").splitlines():
        match = line_pattern.match(raw_line.strip())
        if match:
            matches.append(match.group(1).lower())

    if len(matches) != 2:
        preview = output_text.replace("\n", "\\n")[:500]
        raise ValueError(
            "无法从模型输出中提取两个 Yes/No 标签。"
            f"原始输出前500字符：{preview!r}"
        )

    return [1 if value == "yes" else 0 for value in matches]


def process_pair(pair_index, item1, item2, wotask):
    """Process one PrimeVul pair without mutating shared metric state."""
    code_content1, label1 = item1["func"], item1["target"]
    code_content2, label2 = item2["func"], item2["target"]

    cf_info1 = ""
    cf_info2 = ""
    understanding1 = ""
    understanding2 = ""
    knowledge1 = ""
    knowledge2 = ""

    if wotask != "nan":
        if wotask != "wo_ctrl_info_pth" and code_content1 and code_content2:
            result1 = analyze_code_str(code_content1, detail_level="C")
            result2 = analyze_code_str(code_content2, detail_level="C")
            cf_info1 = result1["results"]["C"]["prompt_text"]
            cf_info2 = result2["results"]["C"]["prompt_text"]

        if wotask != "wo_exp_pth" and code_content1 and code_content2:
            agent1_prompt1 = user_prompt1 + f"Target Code:\n```\n{code_content1}\n```"
            agent1_prompt2 = user_prompt1 + f"Target Code:\n```\n{code_content2}\n```"
            understanding1 = call_gpt(agent1_prompt1)
            understanding2 = call_gpt(agent1_prompt2)

        if wotask != "wo_rag_pth" and code_content1 and code_content2:
            agent2_prompt1 = user_prompt2 + f"Target Code:\n```\n{code_content1}\n```"
            agent2_prompt2 = user_prompt2 + f"Target Code:\n```\n{code_content2}\n```"
            query_content1 = call_gpt(agent2_prompt1)
            query_content2 = call_gpt(agent2_prompt2)
            knowledge1 = get_knowledge(query_content1)
            knowledge2 = get_knowledge(query_content2)

    prompt = (
        VULN_DETECTION_PROMPT
        + "\n\n### Input\n"
        + "{Code-1}"
        + "\n[Source Code]\n"
        + code_content1
    )

    if wotask != "wo_exp_pth" and understanding1:
        prompt += "\n\n[Source Code Description]\n" + understanding1
    if wotask != "wo_ctrl_info_pth" and cf_info1:
        prompt += "\n\n[Static Structural Information]" + cf_info1
    if wotask != "wo_rag_pth" and knowledge1:
        prompt += "\n\n[Possible Vulnerability Description and Example]" + knowledge1

    prompt += "\n\n{Code-2}" + "\n[Source Code]\n" + code_content2

    if wotask != "wo_exp_pth" and understanding2:
        prompt += "\n\n[Source Code Description]\n" + understanding2
    if wotask != "wo_ctrl_info_pth" and cf_info2:
        prompt += "\n\n[Static Structural Information]" + cf_info2
    if wotask != "wo_rag_pth" and knowledge2:
        prompt += "\n\n[Possible Vulnerability Description and Example]" + knowledge2

    inference = call_gpt(prompt)
    preds = extract_preds(inference)
    return pair_index, preds, (label1, label2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run vulnerability detection with ablation study')
    parser.add_argument('--wotask', type=str, default='all',
                        choices=['all', 'wo_ctrl_info_pth', 'wo_rag_pth', 'wo_exp_pth', 'nan'],
                        help='Ablation mode: all (all modules), wo_ctrl_info_pth (without control flow), '
                             'wo_rag_pth (without RAG), wo_exp_pth (without code understanding), '
                             'nan (without any auxiliary info)')
    parser.add_argument('--jsonl_file', type=str, default='primevul_test_paired.jsonl',
                        help='Path to JSONL file')
    parser.add_argument('--metrics_file', type=str, default='metrics_log.txt',
                        help='Output file for real-time metrics logging')
    parser.add_argument('--workers', type=int, default=4,
                        help='Number of concurrent sample-pair workers (default: 4)')

    args = parser.parse_args()

    if args.workers < 1:
        parser.error('--workers must be at least 1')

    print(f"Running in mode: {args.wotask}")

    jsonl_file = args.jsonl_file
    total_cases = count_lines_in_jsonl(jsonl_file)

    metrics_tracker = VulnerabilityMetricsTracker(output_file=args.metrics_file)

    pairs = list(read_jsonl_iteratively(jsonl_file))
    # Validate credentials before submitting hundreds of jobs.
    get_client()

    executor = ThreadPoolExecutor(max_workers=args.workers)
    futures = {
        executor.submit(process_pair, index, item1, item2, args.wotask): index
        for index, (item1, item2) in enumerate(pairs, start=1)
    }

    try:
        with tqdm(total=len(pairs), desc="处理样本对", unit="pair") as pbar:
            for future in as_completed(futures):
                pair_index = futures[future]
                try:
                    _, preds, labels = future.result()
                except Exception as exc:
                    raise RuntimeError(f"第 {pair_index} 对样本处理失败：{exc}") from exc

                metrics_tracker.update_pair_metrics(
                    preds[0], preds[1], labels[0], labels[1]
                )
                tqdm.write(f"pair={pair_index} preds={preds}")
                pbar.update(1)
    except Exception:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)

    metrics_tracker.print_summary(mode=args.wotask)
