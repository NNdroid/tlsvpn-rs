//! 面板内联 <script> 的词法检查，对齐 Go 仓库的 `dashboard_script_test.go`。
//!
//! `DASHBOARD_HTML` 是一段上千行的 HTML/JS 单体字符串，仓库里没有任何构建期校验。
//! 括号少一个的时候整段脚本 SyntaxError，面板只剩静态骨架，而浏览器控制台只给一行
//! "(索引):N Unexpected token ';'"——那行分号本身没问题，真正错的地方在上游几十行，
//! 只能靠肉眼翻。
//!
//! 这里做词法层面的检查，跳过字符串与注释：
//! 1. `()` `[]` `{}` 是否成对，未闭合时报出 src/api.rs 的绝对行号；
//! 2. 两个字符串字面量不得直接相邻（JS 里永远是语法错误，但括号恰好仍配平）；
//! 3. JS 引用的 DOM id 必须真的存在于 HTML。
//!
//! Go 侧的 `dashboardHTML` 由反引号定界，不可能含模板字符串；Rust 这边用的是
//! `r##"..."##`，反引号合法，所以本测试额外支持模板字符串并递归检查 `${...}`
//! 插值里的括号。
//!
//! 约定同 Go 侧：正则字面量按普通字符处理，新增正则时请保持"不含花括号与引号"
//! （当前唯一的正则 `/</g` 满足这一点）。

use std::fs;

const DASHBOARD: &str = "DASHBOARD_HTML";

/// js 中字节偏移对应的 1 基文档行号（相对 <script> 自身所在行）。
fn doc_line(js: &str, pos: usize) -> usize {
    js[..pos].bytes().filter(|&b| b == b'\n').count() + 1
}

/// 取出 `DASHBOARD_HTML` 里的 <script> 正文，返回 (js, js 起始处的 api.rs 绝对行号)。
fn extract_js(src: &str) -> Result<(String, usize), String> {
    let marker = "r##\"";
    let anchor = src
        .find(DASHBOARD)
        .ok_or_else(|| "找不到 DASHBOARD_HTML".to_owned())?;
    let rel = src[anchor..]
        .find(marker)
        .ok_or_else(|| "DASHBOARD_HTML 不是 r##\" 字符串".to_owned())?;
    let open = anchor + rel + marker.len();
    let end = open + src[open..].find("\"##").ok_or_else(|| "r##\" 字符串未闭合".to_owned())?;
    let html = &src[open..end];

    let sk = html
        .find("<script>")
        .ok_or_else(|| "HTML 里没有 <script> 块".to_owned())?;
    let ek = html[sk..]
        .find("</script>")
        .ok_or_else(|| "HTML 里没有 </script>".to_owned())?
        + sk;
    let js = &html[sk + "<script>".len()..ek];

    // 文档行号起点：<script> 标签在 src/api.rs 中的绝对行号
    let abs = open + sk;
    let base = src[..abs].bytes().filter(|&b| b == b'\n').count() + 1;

    Ok((js.to_owned(), base))
}

fn extract_html(src: &str) -> Result<String, String> {
    let marker = "r##\"";
    let anchor = src
        .find(DASHBOARD)
        .ok_or_else(|| "找不到 DASHBOARD_HTML".to_owned())?;
    let rel = src[anchor..]
        .find(marker)
        .ok_or_else(|| "DASHBOARD_HTML 不是 r##\" 字符串".to_owned())?;
    let open = anchor + rel + marker.len();
    let end = open + src[open..].find("\"##").ok_or_else(|| "r##\" 字符串未闭合".to_owned())?;
    Ok(src[open..end].to_owned())
}

/// 把字节偏移回退到字符边界：脚本文本里有中文注释，pos±60 可能落在多字节字符中间
fn bnd(js: &str, mut e: usize) -> usize {
    if e <= js.len() {
        while e > 0 && !js.is_char_boundary(e) {
            e -= 1;
        }
    }
    e.min(js.len())
}

/// pos 附近的一段脚本原文，换行折成空格，方便把报错行号对到具体代码
fn ctx(js: &str, pos: usize) -> String {
    let from = bnd(js, pos.saturating_sub(60));
    let to = bnd(js, pos + 60);
    format!("…{}", js[from..to].replace('\n', " "))
}

/// 判断这个 `/` 是正则字面量的开头还是除法运算符。正则本体可以含 `:` 与 `?`，
/// 当成除号处理就会把三元冒号算错。
///
/// 规则：前面一个 token 是标识符或数字、或者由 `)` `]` 收尾时是除法（`H*i/4`、
/// `a&&b/c`）；其余情况按正则处理。前面是 return / typeof 这类关键字时也是正则，
/// 它们虽然是标识符但语法上后面只能是表达式。
fn starts_regex(prev_sig: u8, prev_ident: &str) -> bool {
    if prev_sig == b')' || prev_sig == b']' {
        return false;
    }
    matches!(
        prev_ident,
        "" | "return" | "typeof" | "instanceof" | "case" | "delete" | "void" | "new" | "in"
            | "of" | "do" | "else" | "throw" | "yield" | "await"
    )
}

fn check(js: &str, base: usize) -> Result<(), String> {
    let mut braces: std::collections::HashMap<u8, Vec<usize>> = std::collections::HashMap::new();
    // 模板插值的嵌套深度。插值的收尾 } 是插值结束符而非代码块，既不入括号栈也不计深度
    let mut interp_depth: Vec<usize> = Vec::new();

    const CODE: u8 = 0;
    const STRING: u8 = 1;
    const TPL: u8 = 2;
    const LINE_CT: u8 = 3;
    const BLOCK_CT: u8 = 4;

    let mut st = CODE;
    let mut quote: u8 = 0;
    // 未闭合的字符串/模板栈：进入时压入，闭合时弹出。EOF 时非空说明有串没闭合
    let mut open_strings: Vec<usize> = Vec::new();
    let mut open_pos: usize = 0;
    // 三元配对：q_open[d] = 第 d 层括号里还没配上 ':' 的 '?' 的字节偏移。
    // 新开括号必须另起一层，不能继承外层——合法 JS 里 '?' 和它的 ':' 一定在同一层
    // 括号深度上，继承了就让「错层配平」直接漏过去（见 test_check_catches_misnested_ternary）。
    let mut q_open: Vec<Vec<usize>> = vec![vec![]];
    // 花括号作用域：Some((d, n)) = 这个花括号在第 d 层括号上，打开时同层已有 n 个未配对
    // 的 '?'。同一个 ':' 要分两种：对象属性 / switch 标签（它前面的 '?' 在字面量之前，
    // 数不超过 n），以及字面量内部的三元（'?' 在字面量之后开出来的，数超过 n）。None = 普通块。
    let mut brace_obj: Vec<Option<(usize, usize)>> = Vec::new();
    // 上一个非空白字符与正在累积的标识符：用于识别对象字面量、标签冒号
    let mut last_sig: u8 = 0;
    let mut ident: String = String::new();
    // `case` 出现的括号深度：同深度的下一个 ':' 是标签而非三元（`default:` 直接认）
    let mut case_pending: Option<usize> = None;
    // `switch(` 的标识符在圆括号处就消耗掉了，留到对应的花括号再取用
    let mut switch_pending = false;
    let mut i = 0;
    let b = js.as_bytes();

    while i < b.len() {
        let c = b[i];
        match st {
            STRING | TPL => {
                let q = if st == TPL { b'`' } else { quote };
                if st == TPL && c == b'$' && i + 1 < b.len() && b[i + 1] == b'{' {
                    interp_depth.push(0);
                    st = CODE;
                    i += 2;
                    continue;
                }
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    st = CODE;
                    open_strings.pop();
                }
                i += 1;
                continue;
            }
            LINE_CT => {
                if c == b'\n' {
                    st = CODE;
                }
                i += 1;
                continue;
            }
            BLOCK_CT => {
                if c == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                    st = CODE;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            _ => {}
        }

        // 标识符字符先累积：case / default / return 要靠它们区分标签冒号、
        // 对象属性冒号与真正的三元冒号
        if c.is_ascii_alphanumeric() || c == b'_' {
            ident.push(c as char);
            last_sig = c;
            i += 1;
            continue;
        }
        let prev_ident = std::mem::take(&mut ident);
        // 花括号分类要看「上一个有效字符」，而下面的赋值会把它覆盖成当前字符，
        // 所以先留一份：`?{…}` 这种三元的对象字面量全靠这个 '?' 认出来
        let prev_sig = last_sig;
        let depth = q_open.len() - 1;
        if !c.is_ascii_whitespace() {
            last_sig = c;
        }
        // `case` 后面是 case 表达式，再接的 ':' 是标签而非三元；语句结束符让
        // 这两个 pending 状态失效，别把它们带出当前语句
        if prev_ident == "case" {
            case_pending = Some(depth);
        }
        if c == b';' {
            case_pending = None;
            switch_pending = false;
        }

        // 三元配对。合法 JS 里 `?` 和它的 `:` 必定处在同一层括号深度上，所以每层单独
        // 计数、互不继承。这类错恰恰是配平检查抓不到的：
        // `((a||0)>0?((b).toFixed(1)+' MB':'-')` 里 `?` 留在外层、`:` 被推进了内层括号，
        // V8 报 "Unexpected token ':'" 直接判死整段脚本，而括号和引号全都配平——
        // 面板就只剩一片静态骨架，还一次网络请求都不发。
        if c == b'?' {
            // 可选链 ?. 与空值合并 ?? 都不是条件运算
            let nxt = if i + 1 < b.len() { b[i + 1] } else { 0 };
            if nxt == b'?' {
                // ?? 要把第二个 '?' 一起跳过去，否则它会单独被算成条件运算
                i += 1;
            } else if nxt != b'.' {
                q_open.last_mut().unwrap().push(i);
            }
        } else if c == b':' {
            // switch 的 case/default 标签、以及对象字面量属性冒号，都不是三元冒号。
            // 两者在同一括号深度上长得一模一样，靠「开这个字面量时已经有多少未配对的 '?'」
            // 分开：`?{a:1}` 的属性冒号在 '?' 之后，`{a:x?y:z}` 的三元冒号在 '?' 之前
            let label = prev_ident == "default" || case_pending == Some(depth);
            case_pending = None;
            let prop = match brace_obj.last() {
                Some(Some((d, n))) => *d == depth && q_open[depth].len() <= *n,
                _ => false,
            };
            if !label && !prop {
                let q = q_open.last_mut().unwrap();
                if q.is_empty() {
                    let at = base + doc_line(js, i) - 1;
                    return Err(format!(
                        "api.rs 第 {at} 行：多余的 ':'（三元的 `?` 不在同一层括号里，\
                         V8 报 Unexpected token ':' 并使整段脚本失效）"
                    ));
                }
                q.pop();
            }
        }

        if c == b'\'' || c == b'"' {
            quote = c;
            open_pos = i;
            open_strings.push(i);
            st = STRING;
        } else if c == b'`' {
            open_pos = i;
            open_strings.push(i);
            st = TPL;
        } else if c == b'/' {
            if i + 1 < b.len() && b[i + 1] == b'/' {
                st = LINE_CT;
                i += 2;
                continue;
            }
            if i + 1 < b.len() && b[i + 1] == b'*' {
                st = BLOCK_CT;
                i += 2;
                continue;
            }
            // 正则字面量：本体里可以出现 ':' 与 '?'（Go 面板就有 replace(/[:.]/g,…)），
            // 按除号处理会把字符类里的冒号算成三元冒号
            if starts_regex(prev_sig, &prev_ident) {
                i += 1;
                let mut in_class = false;
                while i < b.len() {
                    let cc = b[i];
                    if cc == b'\\' {
                        i += 2;
                        continue;
                    }
                    if in_class {
                        in_class = cc != b']';
                        i += 1;
                        continue;
                    }
                    if cc == b'[' {
                        in_class = true;
                        i += 1;
                        continue;
                    }
                    i += 1;
                    if cc == b'/' {
                        break;
                    }
                }
                continue;
            }
            // 普通除号不在此处递增 i：循环末尾还有一次 i += 1，重复递增会悄悄跳掉
            // `/` 后面那一个字符。实测把 `i/(MAXPTS-1)*W` 的 `(` 整个吃掉，于是它配对的
            // `)` 落到空栈上，报「多余的 )」——而脚本文本本身完全合法
        } else if c == b'{' {
            if !interp_depth.is_empty() {
                *interp_depth.last_mut().unwrap() += 1;
            } else {
                braces.entry(b'{').or_default().push(base + doc_line(js, i) - 1);
                // 控制流块的花括号跟在 ) ; } > 或标识符（if/for/else/catch…）后面；
                // 跟在 ( = , : ? ! & | + - * 后面的才是对象字面量
                let is_obj = matches!(
                    prev_sig,
                    b'(' | b'=' | b',' | b':' | b'?' | b'!' | b'&' | b'|' | b'+' | b'-' | b'*'
                ) || prev_ident == "return" || prev_ident == "yield";
                // 对象字面量（属性冒号）与 switch（case 标签）在这个括号深度上抑制 ':'；
                // 普通控制流块不抑制，块内错层的 ':' 仍然算数
                let sw = switch_pending;
                switch_pending = false;
                let suppress = if is_obj || sw {
                    Some((depth, q_open[depth].len()))
                } else {
                    None
                };
                brace_obj.push(suppress);
            }
        } else if c == b'(' {
            braces.entry(b'(').or_default().push(base + doc_line(js, i) - 1);
            // 从空栈起算，绝不继承外层计数：继承了就把「错层配平」当成合法
            q_open.push(vec![]);
            // `switch(k){` 走到这里时标识符已经消耗掉了，先记着等花括号用
            switch_pending = prev_ident == "switch";
        } else if c == b'[' {
            braces.entry(b'[').or_default().push(base + doc_line(js, i) - 1);
        } else if c == b'}' {
            if !interp_depth.is_empty() && *interp_depth.last().unwrap() == 0 {
                interp_depth.pop();
                st = TPL;
                i += 1;
                continue;
            }
            let v = braces.entry(b'{').or_default();
            if v.is_empty() {
                let at = base + doc_line(js, i) - 1;
                return Err(format!(
                    "api.rs 第 {at} 行：多余的 '{c}'（括号配平错误）{}",
                    ctx(js, i)
                ));
            }
            v.pop();
            brace_obj.pop();
            // 块结束了，pending 的标签状态不能再带出来
            case_pending = None;
            switch_pending = false;
            if !interp_depth.is_empty() {
                *interp_depth.last_mut().unwrap() -= 1;
            }
        } else if c == b')' {
            let v = braces.entry(b'(').or_default();
            if v.is_empty() {
                let at = base + doc_line(js, i) - 1;
                return Err(format!(
                    "api.rs 第 {at} 行：多余的 '{c}'（括号配平错误）{}",
                    ctx(js, i)
                ));
            }
            v.pop();
            if q_open.len() > 1 {
                // 这一层括号关闭时 `?` 还没配上 `:`——合法 JS 里 `?` 和 `:` 同层，
                // 所以这一定是漏了 `:`（`(a?b)`）。错层的 ':' 会在上面那个分支先报，
                // 到这里还剩下的就是纯粹没写完的三元
                let leftover = q_open.pop().unwrap();
                if !leftover.is_empty() {
                    let where_at: String = leftover
                        .iter()
                        .map(|pos| (base + doc_line(js, *pos) - 1).to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(format!(
                        "api.rs 第 {where_at} 行：未闭合的三元条件（`?` 之后没有配对的 `:`）"
                    ));
                }
            }
        } else if c == b']' {
            let v = braces.entry(b'[').or_default();
            if v.is_empty() {
                let at = base + doc_line(js, i) - 1;
                return Err(format!(
                    "api.rs 第 {at} 行：多余的 '{c}'（括号配平错误）{}",
                    ctx(js, i)
                ));
            }
            v.pop();
        }
        i += 1;
    }

    if st != CODE || !open_strings.is_empty() {
        let kind = if st == TPL {
            "模板"
        } else if st == STRING {
            "字符串"
        } else {
            "注释"
        };
        let pos = *open_strings.last().unwrap_or(&open_pos);
        let at = base + doc_line(js, pos) - 1;
        let end = pos + 40.min(js.len().saturating_sub(pos));
        let ctx = &js[pos..end];
        return Err(format!(
            "api.rs 第 {at} 行：{kind}未闭合（open_pos={pos}，此处内容={ctx:?}）"
        ));
    }
    if !interp_depth.is_empty() {
        let pos = *interp_depth.last().unwrap_or(&open_pos);
        let at = base + doc_line(js, pos) - 1;
        return Err(format!("api.rs 第 {at} 行：模板插值未闭合"));
    }
    // 反向：`?` 留了没被 `:` 吃掉，同样是语法错误。报告它所在的行，好直接跳过去看
    if let Some(pending) = q_open.last() {
        if !pending.is_empty() {
            let where_at: String = pending
                .iter()
                .map(|pos| (base + doc_line(js, *pos) - 1).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "api.rs 第 {where_at} 行：未闭合的三元条件（`?` 之后没有配对的 `:`）"
            ));
        }
    }
    for (&c, lines) in &braces {
        if lines.is_empty() {
            continue;
        }
        let where_at: String = lines.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
        return Err(format!("api.rs 第 {where_at} 行：未闭合的 '{}'", c as char));
    }
    Ok(())
}

/// 检查两个字符串字面量是否直接相邻。
///
/// 这类写法在 JS 里永远是语法错误，浏览器报 "Unexpected string"，整段脚本失效、
/// 面板只剩静态骨架。它真的发生过：想往 onclick 属性里输出 `\'` 时写成了 `\\'`，
/// JS 把 `\\` 读成一个反斜杠，紧随的那个 `'` 就提前结束了字符串字面量，剩下的
/// 内容变成一串裸字面量。括号恰好仍然配平，上面的检查抓不到。
fn check_no_adjacent_strings(js: &str, base: usize) -> Result<(), String> {
    const QUOTES: [u8; 3] = [b'\'' , b'"', b'`'];

    // 跳过空白与注释，返回下一个有效字符位置；到结尾返回 None
    let skip = |mut j: usize, line: &mut usize| -> Option<usize> {
        while j < js.len() {
            let c = js.as_bytes()[j];
            match c {
                b' ' | b'\t' | b'\r' => j += 1,
                b'\n' => {
                    *line += 1;
                    j += 1
                }
                b'/' if j + 1 < js.len() && js.as_bytes()[j + 1] == b'/' => {
                    while j < js.len() && js.as_bytes()[j] != b'\n' {
                        j += 1;
                    }
                }
                b'/' if j + 1 < js.len() && js.as_bytes()[j + 1] == b'*' => {
                    j += 2;
                    while j + 1 < js.len() && !(js.as_bytes()[j] == b'*' && js.as_bytes()[j + 1] == b'/')
                    {
                        if js.as_bytes()[j] == b'\n' {
                            *line += 1;
                        }
                        j += 1;
                    }
                    j += 2;
                }
                _ => return Some(j),
            }
        }
        None
    };

    let b = js.as_bytes();
    let mut in_str: u8 = 0;
    let mut line = 1usize;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if in_str != 0 {
            match c {
                b'\\' => i += 2,
                b'\n' => {
                    line += 1;
                    i += 1
                }
                q if q == in_str => {
                    in_str = 0;
                    let saved = line;
                    if let Some(j) = skip(i + 1, &mut line) {
                        if QUOTES.contains(&b[j]) {
                            return Err(format!(
                                "api.rs 第 {at} 行：字符串字面量后紧跟另一个字符串字面量（浏览器报 Unexpected string，整段脚本失效）",
                                at = base + saved - 1
                            ));
                        }
                    }
                    i += 1
                }
                _ => i += 1,
            }
            continue;
        }
        if c == b'\n' {
            line += 1;
        } else if QUOTES.contains(&c) {
            in_str = c;
        }
        i += 1;
    }
    if in_str != 0 {
        return Err(format!("api.rs 第 {at} 行：字符串未闭合", at = base + line - 1));
    }
    Ok(())
}

/// 逐字符扫代码（跳过字符串与注释），收集 `getElementById('id')` 里真实出现的 id。
fn used_ids(js: &str) -> Vec<String> {
    const CODE: u8 = 0;
    const STRING: u8 = 1;
    const LINE_CT: u8 = 2;
    const BLOCK_CT: u8 = 3;

    let needle = b"getElementById(";
    let mut out = Vec::new();
    let mut st = CODE;
    let mut quote: u8 = 0;
    let mut i = 0;
    let b = js.as_bytes();
    while i < b.len() {
        let c = b[i];
        match st {
            STRING => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == quote {
                    st = CODE;
                }
                i += 1;
                continue;
            }
            LINE_CT => {
                if c == b'\n' {
                    st = CODE;
                }
                i += 1;
                continue;
            }
            BLOCK_CT => {
                if c == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                    st = CODE;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            _ => {}
        }
        match c {
            b'\'' | b'"' => {
                quote = c;
                st = STRING;
                i += 1;
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                st = LINE_CT;
                i += 2;
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                st = BLOCK_CT;
                i += 2;
            }
            _ => {
                if i + needle.len() <= b.len() && b[i..i + needle.len()] == *needle {
                    let mut j = i + needle.len();
                    if j < b.len() && (b[j] == b'\'' || b[j] == b'"') {
                        let q = b[j];
                        j += 1;
                        let start = j;
                        while j < b.len() && b[j] != q {
                            j += 1;
                        }
                        if j < b.len() {
                            // 'pane-'+tab 这类拼接出来的 id 无法静态核对，跳过
                            if j + 1 < b.len() && b[j + 1] == b'+' {
                                i = j + 1;
                                continue;
                            }
                            out.push(String::from_utf8_lossy(&b[start..j]).into_owned());
                            i = j + 1;
                            continue;
                        }
                    }
                    i += 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    out
}

/// 三元检查器自己的回归测试。它要抓的正是配平检查放过、而 V8 直接判死整段脚本
/// 的那一类错——那次事故后面板只剩静态骨架，一次网络请求都不发，console 里也没有
/// 任何提示，查了很久才定位到。这里的用例钉住「抓得到该抓的、不误报常见的」两边。
#[test]
fn test_check_catches_misnested_ternary() {
    // 真实事故的原型：`?` 留在外层括号，`:` 被推进了内层括号。
    // 括号和引号全部配平，V8 报 "Unexpected token ':'" 让整段脚本失效。
    let bad = "[\n  ['a',(m||0)>0?((m).toFixed(1)+' MB':'-')+' / '+(n>0?n:'-')],\n];\n";
    assert!(check(bad, 1).is_err(), "错层三元必须报错");

    // 同一结构写对了：必须放行
    let ok = "[\n  ['a',(m>0?m.toFixed(1)+' MB':'-')+' / '+(n>0?n:'-')],\n];\n";
    assert!(check(ok, 1).is_ok(), "配平正确的三元被误报：{:?}", check(ok, 1));

    // 分支内容整体加括号是常见且合法的写法
    let ok_paren = "const s=(a?(b):(c))+' / '+(d?e:f);\n";
    assert!(check(ok_paren, 1).is_ok(), "带括号的三元被误报：{:?}", check(ok_paren, 1));

    // 三元的两个分支都是对象字面量（AUTH_HDR 的实际写法）：属性冒号不是三元冒号
    let ok_obj = "const H=(u||p)?{A:'x'+u}:{};\n";
    assert!(check(ok_obj, 1).is_ok(), "三元对象字面量被误报：{:?}", check(ok_obj, 1));

    // 标签冒号、可选链、空值合并都不参与配对
    let ok_misc = "switch(k){case 1:a;break;default:a;break;}\nb?.c\nc??d\n";
    assert!(check(ok_misc, 1).is_ok(), "标签/可选链/空值合并被误报：{:?}", check(ok_misc, 1));

    // 正则字面量的字符类里可以有冒号，不能当成三元冒号
    let ok_regex = "s.replace(/[:.]/g,'-')+' / '+(b?c:d);\n";
    assert!(check(ok_regex, 1).is_ok(), "正则里的冒号被误报：{:?}", check(ok_regex, 1));

    // 反向：多余的 ':'、没配对的 '?' 都要报。
    // 最后一例专门钉住「括号全配平、只是漏了 ':'」——最容易漏掉的一种
    assert!(check("const s=(a:b);\n", 1).is_err(), "多余的 ':' 必须报错");
    assert!(check("const s=a?b;\n", 1).is_err(), "未闭合的三元必须报错");
    assert!(check("const s=(a?b);\n", 1).is_err(), "漏了 ':' 的三元必须报错");
}

/// 钉住「除号后面那个字符被跳过」这类漏字符缺陷。
///
/// `/` 分支里普通除法那一路自己递增 i，而循环末尾还有一次 i += 1，重复递增会悄悄吃掉
/// `/` 紧跟的那个字符。真实踩到的写法是 drawChart 里的 `i/(MAXPTS-1)*W`：`(` 整个被跳掉，
/// 它配对的 `)` 落到空栈上，报「多余的 )」——脚本本身完全合法，是检查器自己误报。
/// 当时整个面板的语法检查因此卡住，改了一整轮都在给合法的代码找不存在的错。
#[test]
fn test_check_does_not_skip_char_after_slash() {
    // 真实事故的原型：drawChart 里 `x=i/(MAXPTS-1)*W`，`(` 被跳掉后它配对的 `)`
    // 落到空栈上，报「多余的 )」
    let ok_div = "const x=i/(MAXPTS-1)*W;\n";
    assert!(check(ok_div, 1).is_ok(), "除法后紧跟括号被误报：{:?}", check(ok_div, 1));

    // 嵌套除法：两处 `/` 各要正确前进一次，跳掉任意一个都会失衡
    let ok_nested = "const x=a/(b/(c-1))*2;\n";
    assert!(check(ok_nested, 1).is_ok(), "嵌套除法被误报：{:?}", check(ok_nested, 1));

    // 连续除法
    let ok_chain = "const x=a/b/c*(d+e);\n";
    assert!(check(ok_chain, 1).is_ok(), "连续除法被误报：{:?}", check(ok_chain, 1));

    // 括号组后面接属性 / 下标，也要照常处理
    let ok_dot = "const x=a/(b).toFixed(1);\n";
    assert!(check(ok_dot, 1).is_ok(), "括号后接属性被误报：{:?}", check(ok_dot, 1));
    let ok_brack = "const x=a/(b)[0];\n";
    assert!(check(ok_brack, 1).is_ok(), "括号后接下标被误报：{:?}", check(ok_brack, 1));

    // 行注释、块注释、正则仍然要按原样整段跳过
    let ok_comments = "a/=b;// 注释(里有\na/=b;/* 注释(里有 */a/=b;\n";
    assert!(check(ok_comments, 1).is_ok(), "注释被误报：{:?}", check(ok_comments, 1));
    let ok_regex2 = "a/=b;s.replace(/[:.]/g,'-')\n";
    assert!(check(ok_regex2, 1).is_ok(), "正则被误报：{:?}", check(ok_regex2, 1));

    // 反着也要能报：同样位置真缺左括号，仍然要抓
    assert!(check("const x=a/b)\n", 1).is_err(), "缺左括号的除法必须报错");
}

#[test]
fn test_dashboard_inline_js_syntax() {
    let src = fs::read_to_string("src/api.rs").expect("读取 src/api.rs");
    let (js, base) = extract_js(&src).expect("提取 DASHBOARD_HTML");
    assert!(!js.is_empty(), "DASHBOARD_HTML 里没有 <script> 内容");
    check(&js, base).unwrap_or_else(|e| panic!("DASHBOARD_HTML 内联 <script> 语法错误：{e}"));
    check_no_adjacent_strings(&js, base)
        .unwrap_or_else(|e| panic!("DASHBOARD_HTML 内联 <script>：{e}"));
}

#[test]
fn test_dashboard_element_ids_exist() {
    // 括号恰好仍然配平、但 JS 引用了不存在的 DOM id 时上面的检查抓不到，面板照旧是坏的
    let src = fs::read_to_string("src/api.rs").expect("读取 src/api.rs");
    let (js, _base) = extract_js(&src).expect("提取 DASHBOARD_HTML");
    check(&js, _base).expect("DASHBOARD_HTML 内联 <script> 语法错误");
    let html = extract_html(&src).expect("提取 DASHBOARD_HTML");

    let mut used = std::collections::BTreeSet::new();
    for id in used_ids(&js) {
        used.insert(id);
    }
    let missing: Vec<String> = used
        .iter()
        .filter(|id| !html.contains(&format!("id=\"{id}\"")))
        .map(|id| id.to_owned())
        .collect();
    assert!(
        missing.is_empty(),
        "JS 引用了 HTML 中不存在的 id：{}",
        missing.join(", ")
    );
}

#[test]
fn test_dashboard_escapes_html_and_attribute_delimiters() {
    let src = fs::read_to_string("src/api.rs").expect("读取 src/api.rs");
    let html = extract_html(&src).expect("提取 DASHBOARD_HTML");
    for token in [
        "replace(/&/g,'&amp;')",
        "replace(/</g,'&lt;')",
        "replace(/>/g,'&gt;')",
        "replace(/\\x22/g,'&quot;')",
        "replace(/\\x27/g,'&#39;')",
    ] {
        assert!(html.contains(token), "dashboard esc() missing {token:?}");
    }
}
