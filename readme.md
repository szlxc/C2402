# 🏡 2402的小窝 · 班级网站

> 自信二班 · 永创辉煌

这是一个为 **C2402 班级** 打造的静态网站，托管在 GitHub Pages，完全免费，用于存放班级资料、活动记录和共同回忆。

🔗 **在线访问**：https://szlxc.github.io/C2402/

---

## 📂 网站结构

| 页面 | 说明 |
|------|------|
| `index.html` | 首页，班级介绍 + 板块入口 |
| `resources.html` | 资源站，存放课件、班歌、学习资料等 |
| `article.html` | 班级青春手札（第一篇纪念文章） |

---

## 🛠️ 如何更新内容

所有页面都采用 **数据驱动** 的设计，更新时只需要修改 JavaScript 数组，不需要动 HTML 结构。

### 1️⃣ 在首页增加新板块

编辑 `index.html`，找到 `mainBlocks` 数组，添加新对象：

```javascript
{
    id: 2,
    title: "🏆 运动会热血时刻",
    subText: "为拼搏喝彩",
    link: "sports.html",
    emoji: "🏅"
}