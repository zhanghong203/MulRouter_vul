# 从固定 Top-k 到风险—成本自适应路由：MulVul 改进方案与相关工作定位

## 摘要

MulVul 使用固定 Top-k Router 将代码分派给类别专用 Detector，能够控制专家调用数量，但不能根据样本难度、路由置信度或 Detector 反馈调整计算预算。本报告考察三个问题：RQ1，如何把不确定性、动态候选集、Detector 反馈和成本停止统一为可实现的方法；RQ2，已有工作分别覆盖了哪些机制；RQ3，剩余创新空间是否足以支撑研究工作。检索结果表明，通用 LLM 路由已经覆盖置信度级联、预算约束和动态多 Agent 选择，漏洞检测也已有验证或交互反馈框架，因此任何单独模块都不宜宣称全新。尚未检索到的组合是：面向 CWE 层级多标签检测，用经校准的集合路由保证类别覆盖，再以隔离 Detector 的结构化反馈更新后验，并以漏报风险—误报风险—调用成本的边际效用执行序贯停止。该组合具有明确研究空间，但贡献必须建立在风险覆盖、校准与成本—效果 Pareto 改善上，而不能只表述为“动态 Top-k”。

## 1. 研究问题与判断标准

本文冻结以下研究问题：

- RQ1：怎样构造既保留 MulVul Detector 隔离性、又允许反馈纠错的闭环路由流程？
- RQ2：不确定性路由、动态 Agent 选择、反馈重路由和成本早停是否已有高度重合工作？
- RQ3：怎样定义可被实验否证、并足以区别于已有工作的核心贡献？

目标读者是准备基于 MulVul 开展后续研究的研究者。判断“类似”时区分任务、机制和完整问题定义：仅共享 entropy 或早停不等于同一工作，但如果完整状态、动作、目标和评测方式均相同，则创新性会显著受限。

## 2. 检索方法

检索覆盖截至 2026 年 10 月可获取的论文页面和摘要，围绕四组关键词展开：uncertainty-aware LLM routing / conformal routing；dynamic multi-agent routing / topology；cost-aware cascade / early termination；multi-agent vulnerability detection / validation feedback。纳入标准是原始论文页面、正式会议页面或可核验预印本；无法确认题名与摘要的条目不用于结论。最终重点比较 14 项工作，包括 MulVul、CP-Router、AutoMix、FrugalGPT、RouteLLM、PILOT、MasRouter、RouteMoA、CascadeDebate、EvoRoute、AgentSlimming、EET、VulAgent 和 SecVulEval。

## 3. 攐进方案：CARVE

建议将方法命名为 **CARVE（Calibrated Adaptive Re-routing for Vulnerability Experts）**，定位为一个面向多标签漏洞检测的序贯决策层，而不是重新设计 MulVul 的全部组件。

### 3.1 总体状态与动作

对代码样本 x，Router 首先产生 M 个粗粒度 CWE 类别的分数，并经验证集校准得到 p(c_m|x)。控制器维护状态：

\[
s_t=(p_t, A_t, F_t, B_t, q_t)
\]

其中 p_t 是当前类别后验，A_t 是已调用 Detector 集合，F_t 是结构化反馈，B_t 是剩余预算，q_t 是检索质量与分布外信号。每一步动作是：调用一个尚未运行的 Detector、扩大某个 Detector 的检索、停止并输出、或在高风险条件下 abstain 并交给人工。

### 3.2 模块一：校准的不确定性与自适应候选集

不建议仅依赖 LLM 自报 confidence。优先使用可获得的 log probabilities；否则用多次低温采样的一致性、类别排序分数和检索相似度训练一个轻量校准器。校准输入可以包括 entropy、Top-1/Top-2 margin、剩余概率质量、最近邻相似度、代码长度和 Router 多次输出的一致率。

候选集最好用 conformal prediction 构造，而不是手工把 entropy 切成 k=1/2/3：

\[
C_0(x)=\{c_m:s_m(x)\ge \tau_m\}
\]

在交换性假设下，它能够把“真正类别不在候选集内”的风险控制在预设水平。由于 PrimeVul 长尾严重，应采用 class-conditional 或分组校准，避免总体 coverage 掩盖稀有 CWE 类别漏路由。候选集大小自然随样本变化，即动态 k。

### 3.3 模块二：渐进式 Detector 调度

不要一次并行调用整个 C_0(x)。按风险调整后的优先级逐个或小批调用：

\[
Priority(c_m)=\frac{p_t(c_m)\cdot R_m(x)}{Cost_m}
\]

R_m(x) 表示调用 Detector m 预期减少的漏报或不确定性，Cost_m 综合 token、价格和延迟。第一版可以用验证集统计的类别条件收益估计 R_m；后续再考虑 contextual bandit。并行调用虽然降低墙钟时间，却无法在获得早期正/负证据后省掉后续调用，因此主方法应采用 sequential 或小批次策略，并把纯并行作为延迟优先的部署变体。

### 3.4 模块三：隔离式 Detector 反馈与后验更新

保持 Detector 之间不直接通信，只允许它们向中央控制器返回受限字段：类别、decision（positive/negative/abstain）、校准置信度、evidence support、retrieval quality、reason code，以及可选的 out-of-category cue。不得将完整 Chain-of-Thought 传给其他 Detector。

控制器用验证集学习的似然或轻量 reranker 更新类别后验：

\[
p_{t+1}(c_m)\propto p(F_t|c_m,x)p_t(c_m)
\]

negative 或 abstain 不是“代码无漏洞”的充分条件；它们只降低当前类别后验。out-of-category cue 只作为提升另一类别优先级的弱证据，不能直接生成漏洞结论。最多允许一至两次重新路由，并检测重复状态，以限制错误级联和无限循环。

### 3.5 模块四：风险—成本停止

停止规则以“继续调用的预期边际效用”为中心：

\[
\Delta U(j|s_t)=\mathbb{E}[L(\hat Y_t,Y)-L(\hat Y_{t+1},Y)|j,s_t]-\lambda C_j
\]

若所有未调用 Detector 的 ΔU 均不为正，则停止。损失 L 不能只使用普通错误率，应显式区分漏报、误报和稀有 CWE：

\[
L=\lambda_{FN}FN+\lambda_{FP}FP+\lambda_{rare}FN_{rare}
\]

部署时提供三种 operating point：Economy、Balanced、Safety。Safety 模式允许更大候选集，并在路由不确定或检索分布外时 abstain；Economy 模式在保证最低风险覆盖后更早停止。这样“成本感知”不是固定 token 阈值，而是可调风险约束下的最小成本决策。

### 3.6 推荐的最小可行版本

第一阶段不使用强化学习：保留 MulVul 的 Router 和 Detector，仅增加温度校准、class-conditional conformal candidate set、顺序调用、结构化反馈与阈值式停止。第二阶段再用轻量 learning-to-rank 或 contextual bandit 学习下一 Detector 的价值。这样能把收益来源分开，也避免复杂控制策略掩盖 Router 校准问题。

## 4. 相关工作地图

### 4.1 不确定性与级联路由

FrugalGPT、AutoMix 与 RouteLLM 都研究性能—成本路由，但分别以学习式 LLM cascade、带 noisy self-verification 的 POMDP、以及偏好数据训练的强弱模型选择为核心；它们选择的是模型能力层级，不是 CWE 专家集合。CP-Router 更接近你的第一、二点：它使用 conformal prediction 与 entropy 在普通 LLM 和 reasoning model 之间动态选择。因此，“用 entropy 判断不确定性并动态分配计算”已经存在，新的贡献必须来自多标签 CWE coverage、长尾 class-conditional calibration 和专家集合调度。

PILOT 把模型路由建模成 contextual bandit，并使用 knapsack 处理预算；这与成本感知决策直接相关。不过它解决的是为请求选择一个模型，而你的问题是顺序选择多个类别 Detector，并允许运行后反馈改变后续动作。两者目标相邻，但动作空间和反馈时序不同。

### 4.2 动态多 Agent 选择与成本控制

MasRouter 已经联合决定协作模式、Agent 角色和 LLM；RouteMoA 先用轻量 scorer 筛选模型，再用已有输出作 posterior correction，并结合性能、成本和延迟排序；EvoRoute 进一步利用历史经验在每一步选择 Pareto-optimal backbone。三者共同说明“动态 Agent 路由”和“后验修正”本身不能作为首创点。与它们相比，CARVE 的差异应限定为：路由对象是 CWE 专家，标签是多标签层级结构，反馈是漏洞证据状态，且停止需控制安全漏报风险。

CascadeDebate 根据置信度只在不确定样本上激活轻量多 Agent 讨论，并用在线阈值调节 escalation；AgentSlimming 则离线删除或替换冗余 Agent。这些工作与 CARVE 都追求 adaptive test-time compute，但前者通过讨论或工作流压缩获得效率，CARVE 通过校准候选集和序贯类别排除获得效率。实验中应把固定 Top-k、一次性动态 Top-k 和反馈式序贯路由分开，否则难以证明闭环的额外贡献。

### 4.3 反馈和早停

AutoMix 已经明确把初步输出的自验证作为后续路由依据，RouteMoA 用 self/cross-assessment 修正初筛分数，CascadeDebate 在 escalation 边界加入讨论，说明“根据下游结果再次决定”已有丰富先例。EET 在软件工程 Agent 中利用既往轨迹经验识别无效迭代，证明早停可以显著降低调用成本而几乎不损害任务完成率，但它处理的是补丁生成迭代，不是漏洞类别覆盖。

因此，Detector 反馈的创新不应描述为一般 feedback loop，而应具体落在三个技术点：类别条件的反馈可靠性建模；不泄露自由推理文本的隔离式反馈协议；多标签剩余风险驱动的重新路由与停止。

### 4.4 漏洞检测中的相邻工作

MulVul 是直接起点：固定 Top-k、1+k 次调用、Detector 隔离、Router 用 Recall@k 优化。VulAgent 采用 hypothesis-validation，通过条件和 trigger path 验证漏洞报告以降低误报；SecVulEval 展示 Normalization、Planning、Context、Detection 和 Validation Agent 流程，并在 Validation 不同意时反馈给 Detection；MAVUL 也强调漏洞分析 Agent 间的交互 refinement。由此可见，“Detector—Validator 反馈”在漏洞检测里并非空白。

不过，这些相邻工作主要验证或修正一个漏洞判断，没有检索到它们同时完成以下闭环：以校准不确定性生成可变 CWE 候选集，基于每个类别 Detector 的结构化反馈重新排序未调用专家，并在显式漏报风险和成本约束下停止。因此，完整交叉点仍有研究空间，但“尚未检索到”不等于可绝对宣称 first；投稿前还应做一次针对 2026 年下半年预印本的更新检索。

## 5. 方法重合度与创新边界

| 你的构想 | 已有工作重合度 | 可保留的创新边界 |
|---|---:|---|
| entropy/margin 判断不确定性 | 高 | CWE 多标签校准、长尾 class-conditional coverage、检索质量联合不确定性 |
| 动态 Top-k | 高 | conformal CWE prediction set，而非经验阈值；以漏路由风险控制候选集 |
| Detector 反馈后重路由 | 中高 | 隔离式结构化反馈、类别条件可靠性、对未调用 CWE 专家的后验重排 |
| 成本感知停止 | 高 | 漏报/误报/稀有 CWE 风险约束下的 sequential stopping |
| 四者在 MulVul 中统一 | 中低 | 当前最有希望的主贡献，但需更新检索并用完整消融证明 |

核心判断是：**模块级新颖性较弱，问题定义和系统级组合仍有潜力。** 若论文只做 entropy 阈值决定 k，很容易被评价为通用 adaptive routing 在 MulVul 上的直接应用；若能给出 class-conditional coverage、反馈后验更新和风险—成本停止的统一形式，并证明在相同 Macro-F1 下显著减少成本、或相同成本下显著提高稀有 CWE recall，则贡献会扎实得多。

## 6. 实验设计

数据应至少覆盖 PrimeVul，并增加一个跨数据集或跨语言测试，以避免阈值只适配 C/C++。训练、校准、阈值选择和最终测试必须分离；conformal calibration 不能复用测试集。除 Macro-P/R/F1 外，报告 micro 指标、per-CWE recall、rare-CWE recall、路由 coverage、set size、ECE、Brier score、平均/P95 调用数、token、价格和串行/并行延迟。

主要比较包括：固定 k=1…5；entropy 动态 k；conformal 动态候选集；无反馈顺序调用；带结构化反馈；不考虑成本的完整调用；以及完整 CARVE。必须画 quality—cost Pareto 曲线，并比较 equal-cost F1 与 equal-F1 cost。Oracle 使用真实标签选择最小 Detector 集合，给出动态路由的上界。

关键消融包括：entropy 与 margin；未校准与温度校准；marginal 与 class-conditional conformal；自由文本反馈与结构化反馈；无重路由、一次重路由和多次重路由；统一成本与真实 token/延迟成本；不同的 FN/FP 风险权重。

失败分析应专门统计四类事件：Router 漏掉真类别；Detector negative 错误导致早停；out-of-category cue 纠正路由；反馈误导路由。若反馈纠正率不显著高于误导率，就不能声称闭环有效。

## 7. 可投稿的主张形式

建议把工作定义为：

> 在层级、多标签漏洞检测中，将专家选择建模为风险约束的序贯决策；通过 class-conditional calibrated prediction sets 控制漏路由，通过隔离式 Detector 反馈更新类别后验，并根据边际检测收益与推理成本自适应停止。

三个贡献可写成：一是面向长尾 CWE 的校准候选集路由；二是保持专家隔离的证据反馈重路由；三是同时报告检测风险与真实推理成本的停止策略和评测协议。不要使用“首个 uncertainty-aware router”“首个 dynamic multi-agent router”或“首个 feedback vulnerability detector”之类表述，因为已有文献足以反驳。

## 8. 结论

RQ1：四点可以统一为一个中央控制、Detector 隔离的序贯流程，关键是用校准 prediction set 代替任意 confidence，用结构化反馈代替自由 Agent 对话，并以剩余多标签风险决定停止。

RQ2：四个单点都有类似工作；CP-Router、AutoMix、PILOT、MasRouter、RouteMoA、CascadeDebate、EET 以及 VulAgent/SecVulEval 分别覆盖主要机制。当前检索没有发现完整重合于 CWE 多标签闭环路由的工作。

RQ3：这个方向值得做，但创新性取决于是否形成安全风险可解释、成本可度量的统一方法。最弱版本是 entropy 阈值动态 k；较强版本是 class-conditional conformal coverage + Detector posterior update + cost-sensitive sequential stopping。

## References

[1] Zihan Wu et al., "MulVul: Retrieval-augmented Multi-Agent Code Vulnerability Detection via Cross-Model Prompt Evolution," ACL, 2026.

[2] Jiayuan Su et al., "CP-Router: An Uncertainty-Aware Router Between LLM and LRM," AAAI, 2026.

[3] Lingjiao Chen, Matei Zaharia, James Zou, "FrugalGPT: How to Use Large Language Models While Reducing Cost and Improving Performance," arXiv:2305.05176, 2023.

[4] Pranjal Aggarwal et al., "AutoMix: Automatically Mixing Language Models," NeurIPS, 2024.

[5] Isaac Ong et al., "RouteLLM: Learning to Route LLMs with Preference Data," ICLR, 2025.

[6] Pranoy Panda et al., "Adaptive LLM Routing under Budget Constraints," Findings of EMNLP, 2025.

[7] Yanwei Yue et al., "MasRouter: Learning to Route LLMs for Multi-Agent Systems," ACL, 2025.

[8] Jize Wang et al., "RouteMoA: Dynamic Routing without Pre-Inference Boosts Efficient Mixture-of-Agents," ACL, 2026.

[9] Raeyoung Chang et al., "CascadeDebate: Multi-Agent Deliberation for Cost-Aware LLM Cascades," ACL Industry Track, 2026.

[10] Guibin Zhang et al., "EvoRoute: Experience-Driven Self-Routing LLM Agent Systems," ACL, 2026.

[11] Yulang Chen et al., "AgentSlimming: Towards Efficient and Cost-Aware Multi-Agent Systems," ACL, 2026.

[12] Yaoqi Guo et al., "EET: Experience-Driven Early Termination for Cost-Efficient Software Engineering Agents," Findings of ACL, 2026.

[13] VulAgent authors, "VulAgent: Hypothesis-Validation based Multi-Agent Vulnerability Detection," Findings of ACL, 2026.

[14] SecVulEval authors, "SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection," OpenReview, 2026.
