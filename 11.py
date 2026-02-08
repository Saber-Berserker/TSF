import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import os

# 自动选择中文字体
if os.name == "nt":  # Windows
    zh_font = "Microsoft YaHei"
elif os.name == "posix":  # macOS / Linux
    if os.path.exists("/System/Library/Fonts/STHeiti Medium.ttc"):  # macOS
        zh_font = "STHeiti"
    else:  # Linux
        zh_font = "SimHei"  # 确保系统已安装 sudo apt install fonts-noto-cjk
else:
    zh_font = "SimHei"

plt.rcParams['font.sans-serif'] = [zh_font]  # 设置字体
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

# OWASP Top 10 数据
data = [
    ["A01", "访问控制失效", "不信前端，后端必查", "水平越权 / 垂直越权 / IDOR", "URL改参数能看到别人数据，属于哪种漏洞？如何防御？"],
    ["A02", "加密失败", "不存明文，算法要强", "弱加密、明文存储、证书校验", "为什么不能用MD5存密码？如何正确存储？"],
    ["A03", "注入漏洞", "不拼SQL，用占位符", "SQL、NoSQL、OS命令注入", "写出防止SQL注入的三种方法。"],
    ["A04", "不安全设计", "设计先防，少留口子", "威胁建模、零信任、最小化攻击面", "安全设计和安全实现漏洞区别？"],
    ["A05", "安全配置错误", "默认不安全，调试要关", "管理口暴露、弱口令、未打补丁", "如何发现并修复Tomcat默认配置风险？"],
    ["A06", "漏洞组件", "组件要新，源要可信", "依赖漏洞、供应链攻击", "如何检测依赖库漏洞？用什么工具？"],
    ["A07", "身份验证失败", "强认证，勤过期", "弱密码、无MFA、JWT安全问题", "JWT有哪些安全风险？"],
    ["A08", "软件/数据完整性失败", "验签+来源可信", "CI/CD安全、供应链攻击", "如何防止恶意库注入生产环境？"],
    ["A09", "日志与监控失败", "有日志，防泄密", "日志脱敏、SIEM、告警", "为什么不能在日志中记录明文密码？"],
    ["A10", "SSRF", "不信URL，限协议IP", "内网访问、云元数据泄露", "如何防御SSRF？"]
]

columns = ["编号", "漏洞名称", "口诀记忆", "核心考点", "常见考题"]
df = pd.DataFrame(data, columns=columns)

# 绘制表格
fig, ax = plt.subplots(figsize=(20, 8))
ax.axis('off')

table_plot = ax.table(
    cellText=df.values,
    colLabels=df.columns,
    cellLoc='center',
    loc='center'
)

# 样式调整
table_plot.auto_set_font_size(False)
table_plot.set_fontsize(10)
table_plot.scale(1.2, 1.5)

# 表头颜色
for (row, col), cell in table_plot.get_celld().items():
    if row == 0:
        cell.set_facecolor("#555555")
        cell.set_text_props(color="white", weight='bold', fontproperties=fm.FontProperties(fname=fm.findfont(zh_font)))
    else:
        cell.set_facecolor("#f5f5dc")
        cell.set_text_props(fontproperties=fm.FontProperties(fname=fm.findfont(zh_font)))

# 保存 PNG
plt.savefig("OWASP_Top10_速记表.png", dpi=300, bbox_inches='tight')

# 保存 PDF
plt.savefig("OWASP_Top10_速记表.pdf", dpi=300, bbox_inches='tight')

print("已生成 OWASP_Top10_速记表.png 和 OWASP_Top10_速记表.pdf（支持中文显示）")
