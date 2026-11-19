# -*- coding: utf-8 -*-
"""报告插图工具（合并自 svg2png.py + make_fig7.py）。

用法（.venv/Scripts/python -X utf8 图源工具.py <命令>）：
  convert   全部 SVG（图1~6、8）经 Edge headless 截图为 fig{1..6,8}.png
  fig7      matplotlib 重绘图7 性能测试图 → fig7.png
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

D = Path(__file__).parent
EDGE = shutil.which("msedge") or r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
TMP = Path(tempfile.gettempdir())

FIGS = [  # (svg 名, 尺寸 w,h)
    ("图1-系统总体架构图", (1220, 730)),
    ("图2-全链路工作流程图", (920, 1160)),
    ("图3-智能体决策闭环图", (1180, 650)),
    ("图4-六路路由决策图", (1180, 670)),
    ("图5-富化三级裁决漏斗图", (1180, 630)),
    ("图6-数据模型ER简图", (1200, 650)),
    ("图8-问答请求时序图", (1200, 790)),
]
# 第7项(时序图)输出为 fig8；fig7 由 matplotlib 生成（见 fig7 命令）
FIG_MAP = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 8}


def convert() -> None:
    for i, (name, (w, h)) in enumerate(FIGS, 1):
        src = D / f"{name}.svg"
        n = FIG_MAP[i]
        tmp = TMP / f"report_fig{n}.png"
        r = subprocess.run(
            [EDGE, "--headless", "--disable-gpu", "--no-sandbox",
             f"--screenshot={tmp}", f"--window-size={w},{h}",
             src.as_uri()], capture_output=True, timeout=60)
        dst = D / f"fig{n}.png"
        shutil.copyfile(tmp, dst)
        print(dst.name, dst.stat().st_size // 1024, "KB", "rc=", r.returncode)


def fig7() -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    BG, PANEL, NAVY, BLUE, RED, GRAY = "#ffffff", "#f5f6f8", "#1f3a5f", "#5f7ca3", "#b91c1c", "#4b5563"
    plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams.update({
        "figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG,
        "text.color": "#111827", "axes.edgecolor": "#6b7280", "axes.labelcolor": "#111827",
        "xtick.color": "#111827", "ytick.color": "#111827",
    })

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.5, 4.6), dpi=150)
    fig.suptitle("性能测试结果（全部来自系统实测）", fontsize=14, fontweight="bold", color="#111827", y=0.99)

    # ── 左：检索质量（39/39 + top1 相似度） ──
    cats = ["min", "median", "max"]
    vals = [0.5152, 0.6359, 0.7983]
    bars = ax1.bar(cats, vals, width=0.52, color=["#9db2cc", "#5f7ca3", NAVY], edgecolor="#1f3a5f", linewidth=0.6)
    ax1.axhline(0.3, color=RED, ls="--", lw=1.6)
    ax1.text(2.35, 0.315, "命中阈值 0.3", color=RED, fontsize=9.5, ha="right")
    for b, v in zip(bars, vals):
        ax1.text(b.get_x() + b.get_width() / 2, v + 0.014, f"{v:.4f}", ha="center",
                 fontsize=10.5, fontweight="bold", color=NAVY)
    ax1.set_ylim(0, 0.9)
    ax1.set_ylabel("top1 余弦相似度")
    ax1.set_title("大规模检索基准：39/39 全命中（8 类目全过）\ntop1 相似度分布 vs 命中阈值", fontsize=11.5)
    ax1.spines[["top", "right"]].set_visible(False)
    ax1.text(0.02, 0.95, "嵌入一致性门 10/10（cosine≈1.00）", transform=ax1.transAxes,
             fontsize=9.5, color="#15803d", va="top")

    # ── 右：端到端延迟分解（实测 11~33s；检索层实测 0.5~2.7s CPU） ──
    labels = ["端到端最短", "端到端最长"]
    retrieval = [0.5, 2.7]
    generation = [11 - 0.5, 33 - 2.7]
    x = range(len(labels))
    ax2.bar(x, retrieval, width=0.45, color="#5f7ca3", label="检索层（本地 CPU）", edgecolor="#1f3a5f", linewidth=0.6)
    ax2.bar(x, generation, width=0.45, bottom=retrieval, color=NAVY, label="LLM 生成段（DeepSeek）", edgecolor="#1f3a5f", linewidth=0.6)
    for i, (r, g) in enumerate(zip(retrieval, generation)):
        ax2.text(i, r + g + 0.6, f"{r + g:.0f}s", ha="center", fontsize=12, fontweight="bold", color=NAVY)
        ax2.text(i, r + g / 2, f"生成 {g:.0f}s\n({g / (r + g) * 100:.0f}%)", ha="center",
                 fontsize=10, color="#ffffff", fontweight="bold")
    ax2.set_xticks(list(x), labels)
    ax2.set_ylim(0, 38)
    ax2.set_ylabel("耗时（秒）")
    ax2.set_title("端到端问答延迟分解：生成主导（≥85%）\n检索层本地 CPU 仅 0.5~2.7s —— 结构化路由毫秒级", fontsize=11.5)
    leg = ax2.legend(fontsize=9.5, loc="upper left", frameon=False)
    for t in leg.get_texts():
        t.set_color("#111827")
    ax2.spines[["top", "right"]].set_visible(False)

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    plt.savefig(D / "fig7.png", bbox_inches="tight", facecolor=BG)
    print("fig7.png 已生成")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "convert":
        convert()
    elif cmd == "fig7":
        fig7()
    else:
        print(__doc__)
