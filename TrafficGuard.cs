using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

public class IPStat
{
    public long Total;
    public Queue<DateTime> Times = new Queue<DateTime>();
}

public class TrafficGuard
{
    static int Port = 8081;
    static string Backend = "http://127.0.0.1:8080";
    static int WindowSec = 10;
    static int MaxReqPerWindow = 100;
    static int BlockSec = 300;
    static string LogDir = @"C:\traffic-guard";

    static long totalReq = 0;
    static long totalBlocked = 0;
    static long totalBytes = 0;
    static DateTime started = DateTime.Now;

    static ConcurrentDictionary<string, IPStat> ips = new ConcurrentDictionary<string, IPStat>();
    static ConcurrentDictionary<string, long> pages = new ConcurrentDictionary<string, long>();
    static ConcurrentDictionary<string, long> codes = new ConcurrentDictionary<string, long>();
    static ConcurrentDictionary<string, long> agents = new ConcurrentDictionary<string, long>();
    static ConcurrentDictionary<string, DateTime> autoBlock = new ConcurrentDictionary<string, DateTime>();
    static ConcurrentDictionary<string, DateTime> manualBlock = new ConcurrentDictionary<string, DateTime>();
    static ConcurrentQueue<string> recent = new ConcurrentQueue<string>();

    static string GuardPassword = "admin123";
    static string authToken = Guid.NewGuid().ToString("N");
    static string VipFile = @"C:\traffic-guard\vip.txt";
    static HashSet<string> vipIPs = new HashSet<string>();

    public static void Main(string[] args)
    {
        if (args.Length > 0) int.TryParse(args[0], out Port);
        if (args.Length > 1) Backend = args[1];
        try { Directory.CreateDirectory(LogDir); } catch { }
        try
        {
            string pf = Path.Combine(LogDir, "password.txt");
            if (File.Exists(pf)) { string[] pl = File.ReadAllLines(pf); if (pl.Length > 0 && !string.IsNullOrWhiteSpace(pl[0])) GuardPassword = pl[0].Trim(); }
        }
        catch { }
        try
        {
            if (File.Exists(VipFile)) foreach (string line in File.ReadAllLines(VipFile)) { string ip = line.Trim(); if (ip.Length > 0) vipIPs.Add(ip); }
        }
        catch { }

        HttpListener l = new HttpListener();
        l.Prefixes.Add("http://+:" + Port + "/");
        l.Start();
        Console.WriteLine("TrafficGuard listening on " + Port + " -> " + Backend);
        while (true)
        {
            HttpListenerContext ctx = l.GetContext();
            ThreadPool.QueueUserWorkItem(_ => Handle(ctx));
        }
    }

    static string ClientIP(HttpListenerRequest r)
    {
        string ip = r.RemoteEndPoint != null ? r.RemoteEndPoint.Address.ToString() : "?";
        string x = r.Headers["X-Forwarded-For"];
        if (!string.IsNullOrEmpty(x)) { ip = x.Split(',')[0].Trim(); }
        if (ip == "::1") ip = "127.0.0.1";
        return ip;
    }

    static void Handle(HttpListenerContext ctx)
    {
        try
        {
            HttpListenerRequest req = ctx.Request;
            string ip = ClientIP(req);
            string path = req.Url.AbsolutePath;

            if (IsBlocked(ip)) { Interlocked.Increment(ref totalBlocked); Deny(ctx, ip, 403); return; }

            if (HitRateLimit(ip))
            {
                autoBlock[ip] = DateTime.Now.AddSeconds(BlockSec);
                Interlocked.Increment(ref totalBlocked);
                Deny(ctx, ip, 429);
                return;
            }

            if (path == "/__guard__/login") { HandleLogin(ctx); return; }
            if (path == "/__guard__/logout") { HandleLogout(ctx); return; }
            if (path == "/__guard__" || path == "/__guard__/")
            {
                if (!IsAuthed(ctx)) { ServeLoginPage(ctx, false); return; }
                Dashboard(ctx); return;
            }
            if (path == "/__guard__/block" || path == "/__guard__/vip" || path == "/__guard__/comment")
            {
                if (!IsAuthed(ctx)) { ServeLoginPage(ctx, false); return; }
                if (path == "/__guard__/block") BlockAction(ctx);
                else if (path == "/__guard__/vip") VipAction(ctx);
                else CommentAction(ctx);
                return;
            }

            Interlocked.Increment(ref totalReq);
            Proxy(ctx);
        }
        catch { try { ctx.Response.Abort(); } catch { } }
    }

    static bool IsBlocked(string ip)
    {
        DateTime t;
        if (manualBlock.TryGetValue(ip, out t)) return true;
        if (autoBlock.TryGetValue(ip, out t))
        {
            if (t > DateTime.Now) return true;
            autoBlock.TryRemove(ip, out t);
        }
        return false;
    }

    static bool HitRateLimit(string ip)
    {
        IPStat s = ips.GetOrAdd(ip, _ => new IPStat());
        lock (s)
        {
            DateTime now = DateTime.Now;
            while (s.Times.Count > 0 && (now - s.Times.Peek()).TotalSeconds > WindowSec) s.Times.Dequeue();
            s.Times.Enqueue(now);
            Interlocked.Increment(ref s.Total);
            return s.Times.Count > MaxReqPerWindow;
        }
    }

    static void Deny(HttpListenerContext ctx, string ip, int code)
    {
        byte[] b = Encoding.UTF8.GetBytes("请求过于频繁或已被拦截 (blocked)");
        try
        {
            ctx.Response.StatusCode = code;
            ctx.Response.ContentType = "text/plain; charset=utf-8";
            ctx.Response.ContentLength64 = b.Length;
            ctx.Response.OutputStream.Write(b, 0, b.Length);
            ctx.Response.Close();
        }
        catch { }
        Log(ip, "BLOCK", "/__blocked__", code, b.Length, null);
    }

    static void Proxy(HttpListenerContext ctx)
    {
        HttpListenerRequest req = ctx.Request;
        string ip = ClientIP(req);
        string method = req.HttpMethod;
        string path = req.Url.AbsolutePath;
        string query = req.Url.Query;
        string ua = req.UserAgent;
        long bytes = 0;
        int code = 502;

        try
        {
            HttpWebRequest web = (HttpWebRequest)WebRequest.Create(Backend + path + query);
            web.Method = method;
            web.Timeout = 30000;
            web.ReadWriteTimeout = 30000;
            web.AllowAutoRedirect = false;
            web.UserAgent = ua;
            web.Headers["X-Forwarded-For"] = ip;
            web.Headers["X-Real-IP"] = ip;
            if (vipIPs.Contains(ip)) web.Headers["X-VIP"] = "1";
            web.Accept = req.Headers["Accept"];
            if (req.ContentType != null) web.ContentType = req.ContentType;

            if (method == "POST" || method == "PUT" || method == "PATCH")
            {
                if (req.ContentLength64 > 0)
                {
                    web.ContentLength = req.ContentLength64;
                    using (Stream ins = req.InputStream)
                    using (Stream os = web.GetRequestStream())
                    {
                        byte[] buf = new byte[8192]; int n;
                        while ((n = ins.Read(buf, 0, buf.Length)) > 0) os.Write(buf, 0, n);
                    }
                }
            }

            HttpWebResponse resp = null;
            try { resp = (HttpWebResponse)web.GetResponse(); }
            catch (WebException we) { resp = we.Response as HttpWebResponse; }

            if (resp != null)
            {
                code = (int)resp.StatusCode;
                ctx.Response.StatusCode = code;
                ctx.Response.ContentType = resp.ContentType;
                if (resp.ContentLength >= 0) ctx.Response.ContentLength64 = resp.ContentLength;
                using (Stream rs = resp.GetResponseStream())
                using (Stream os = ctx.Response.OutputStream)
                {
                    byte[] buf = new byte[8192]; int n;
                    while ((n = rs.Read(buf, 0, buf.Length)) > 0) { os.Write(buf, 0, n); bytes += n; }
                }
                resp.Close();
            }
            else
            {
                code = 502;
                byte[] b = Encoding.UTF8.GetBytes("后端服务不可用");
                ctx.Response.StatusCode = 502;
                ctx.Response.ContentType = "text/plain; charset=utf-8";
                ctx.Response.ContentLength64 = b.Length;
                ctx.Response.OutputStream.Write(b, 0, b.Length);
            }
        }
        catch
        {
            code = 502;
            try
            {
                byte[] b = Encoding.UTF8.GetBytes("代理错误");
                ctx.Response.StatusCode = 502;
                ctx.Response.ContentType = "text/plain; charset=utf-8";
                ctx.Response.ContentLength64 = b.Length;
                ctx.Response.OutputStream.Write(b, 0, b.Length);
            }
            catch { }
        }
        try { ctx.Response.Close(); } catch { }
        Log(ip, method, path, code, bytes, ua);
    }

    static void Log(string ip, string method, string path, int code, long bytes, string ua)
    {
        pages.AddOrUpdate(path, 1, (k, v) => v + 1);
        codes.AddOrUpdate(code.ToString(), 1, (k, v) => v + 1);
        if (!string.IsNullOrEmpty(ua)) { string a = ua.Length > 60 ? ua.Substring(0, 60) : ua; agents.AddOrUpdate(a, 1, (k, v) => v + 1); }
        Interlocked.Add(ref totalBytes, bytes);
        recent.Enqueue(string.Format("{0:HH:mm:ss}  {1,-15}  {2,-6}  {3,-40}  {4}  {5}B", DateTime.Now, ip, method, path.Length > 40 ? path.Substring(0, 40) : path, code, bytes));
        while (recent.Count > 200) { string _; recent.TryDequeue(out _); }
        try
        {
            File.AppendAllText(Path.Combine(LogDir, "requests.log"),
                string.Format("{0:yyyy-MM-dd HH:mm:ss}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\r\n",
                DateTime.Now, ip, method, path, code, bytes, ua == null ? "" : ua), Encoding.UTF8);
        }
        catch { }
    }

    static void Dashboard(HttpListenerContext ctx)
    {
        StringBuilder sb = new StringBuilder();
        TimeSpan up = DateTime.Now - started;
        double qps = up.TotalSeconds > 0 ? totalReq / up.TotalSeconds : 0;

        sb.Append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">");
        sb.Append("<meta http-equiv=\"refresh\" content=\"3\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>流量卫士 · 监控面板</title><style>");
        sb.Append("body{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;background:#0a0f1a;color:#dde;margin:0;padding:24px 16px;}");
        sb.Append("h1{font-size:22px;margin:0 0 4px;color:#fff;}.sub{color:#889;font-size:13px;margin:0 0 20px;}");
        sb.Append(".cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:22px;}");
        sb.Append(".c{flex:1 1 140px;background:#131a2b;border:1px solid #22304a;border-radius:12px;padding:14px 16px;}");
        sb.Append(".c .v{font-size:26px;font-weight:700;color:#7fe3ff;}.c .l{font-size:12px;color:#889;margin-top:4px;}");
        sb.Append(".c.warn .v{color:#ffb86b;}.c.danger .v{color:#ff6b6b;}");
        sb.Append(".sec{background:#101625;border:1px solid #22304a;border-radius:12px;padding:16px 18px;margin-bottom:18px;}");
        sb.Append(".sec h2{font-size:15px;margin:0 0 12px;color:#fff;border-bottom:1px solid #22304a;padding-bottom:8px;}");
        sb.Append("table{width:100%;border-collapse:collapse;font-size:13px;}");
        sb.Append("th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #1c2740;}th{color:#889;font-weight:600;}");
        sb.Append("td.mono,code{font-family:Consolas,monospace;}");
        sb.Append(".row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:10px;}");
        sb.Append("input{background:#0a0f1a;border:1px solid #2a3a5a;color:#dde;padding:8px 10px;border-radius:8px;font-size:13px;}");
        sb.Append("button{background:#7fe3ff;color:#0a0f1a;border:none;padding:8px 14px;border-radius:8px;font-weight:700;cursor:pointer;font-size:13px;}");
        sb.Append("button.danger{background:#ff6b6b;color:#fff;}");
        sb.Append(".badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;background:#22304a;color:#aac;}");
        sb.Append("</style></head><body>");
        sb.Append("<h1>🛡 流量卫士 · 监控面板</h1>");
        sb.Append("<p class=\"sub\">反向代理 " + Backend + " · 每 3 秒自动刷新</p>");

        sb.Append("<div class=\"cards\">");
        sb.Append("<div class=\"c\"><div class=\"v\">" + totalReq + "</div><div class=\"l\">总请求数</div></div>");
        sb.Append("<div class=\"c\"><div class=\"v\">" + ips.Count + "</div><div class=\"l\">唯一 IP 数</div></div>");
        sb.Append("<div class=\"c\"><div class=\"v\">" + qps.ToString("0.0") + "</div><div class=\"l\">平均 QPS</div></div>");
        sb.Append("<div class=\"c danger\"><div class=\"v\">" + totalBlocked + "</div><div class=\"l\">被拦截次数</div></div>");
        sb.Append("<div class=\"c\"><div class=\"v\">" + (totalBytes / 1048576.0).ToString("0.00") + " MB</div><div class=\"l\">总流量</div></div>");
        sb.Append("<div class=\"c\"><div class=\"v\">" + (int)up.TotalMinutes + " 分</div><div class=\"l\">运行时长</div></div>");
        sb.Append("</div>");

        // 最近请求
        sb.Append("<div class=\"sec\"><h2>最近请求</h2><table><tr><th>时间</th><th>IP</th><th>方法</th><th>路径</th><th>状态</th><th>字节</th></tr>");
        string[] arr = recent.ToArray();
        int start = arr.Length - 30; if (start < 0) start = 0;
        for (int i = arr.Length - 1; i >= start; i--)
        {
            string[] f = arr[i].Split(new string[] { "  " }, StringSplitOptions.RemoveEmptyEntries);
            sb.Append("<tr>");
            for (int j = 0; j < f.Length && j < 6; j++) sb.Append("<td class=\"mono\">" + HtmlEnc(f[j]) + "</td>");
            sb.Append("</tr>");
        }
        sb.Append("</table></div>");

        // Top 页面
        sb.Append("<div class=\"sec\"><h2>热门页面 Top 10</h2><table><tr><th>路径</th><th>次数</th></tr>");
        foreach (var kv in pages.OrderByDescending(k => k.Value).Take(10))
            sb.Append("<tr><td class=\"mono\">" + HtmlEnc(kv.Key) + "</td><td>" + kv.Value + "</td></tr>");
        sb.Append("</table></div>");

        // Top IP
        sb.Append("<div class=\"sec\"><h2>访问最多的 IP Top 10</h2><table><tr><th>IP</th><th>请求数</th><th>操作</th></tr>");
        foreach (var kv in ips.OrderByDescending(k => k.Value.Total).Take(10))
            sb.Append("<tr><td class=\"mono\">" + kv.Key + "</td><td>" + kv.Value.Total + "</td><td><a href=\"/__guard__/block?action=block&ip=" + Uri.EscapeDataString(kv.Key) + "\">封禁</a></td></tr>");
        sb.Append("</table></div>");

        // 状态码
        sb.Append("<div class=\"sec\"><h2>状态码分布</h2><table><tr><th>状态码</th><th>次数</th></tr>");
        foreach (var kv in codes.OrderByDescending(k => k.Value).Take(10))
            sb.Append("<tr><td class=\"mono\">" + kv.Key + "</td><td>" + kv.Value + "</td></tr>");
        sb.Append("</table></div>");

        // User-Agent
        sb.Append("<div class=\"sec\"><h2>User-Agent Top 10</h2><table><tr><th>UA</th><th>次数</th></tr>");
        foreach (var kv in agents.OrderByDescending(k => k.Value).Take(10))
            sb.Append("<tr><td class=\"mono\">" + HtmlEnc(kv.Key) + "</td><td>" + kv.Value + "</td></tr>");
        sb.Append("</table></div>");

        // 封禁列表
        sb.Append("<div class=\"sec\"><h2>封禁中的 IP</h2>");
        sb.Append("<table><tr><th>IP</th><th>类型</th><th>到期</th><th>操作</th></tr>");
        foreach (var kv in manualBlock)
            sb.Append("<tr><td class=\"mono\">" + kv.Key + "</td><td>手动</td><td>永久</td><td><a href=\"/__guard__/block?action=unblock&ip=" + Uri.EscapeDataString(kv.Key) + "\">解封</a></td></tr>");
        foreach (var kv in autoBlock)
            if (kv.Value > DateTime.Now)
                sb.Append("<tr><td class=\"mono\">" + kv.Key + "</td><td>自动</td><td>" + kv.Value.ToString("HH:mm:ss") + "</td><td><a href=\"/__guard__/block?action=unblock&ip=" + Uri.EscapeDataString(kv.Key) + "\">解封</a></td></tr>");
        sb.Append("</table>");
        sb.Append("<div class=\"row\"><form method=\"get\" action=\"/__guard__/block\"><input type=\"hidden\" name=\"action\" value=\"block\"><input type=\"text\" name=\"ip\" placeholder=\"手动封禁 IP\"><button class=\"danger\" type=\"submit\">封禁</button></form></div>");
        sb.Append("</div>");

        sb.Append("<div class=\"sec\"><h2>VIP 用户 IP（访问 sun-site 显示爱心特效 + 留言 VIP 标识）</h2>");
        sb.Append("<table><tr><th>IP</th><th>操作</th></tr>");
        foreach (string vip in vipIPs)
            sb.Append("<tr><td class=\"mono\">" + HtmlEnc(vip) + "</td><td><a href=\"/__guard__/vip?action=remove&ip=" + Uri.EscapeDataString(vip) + "\">移除</a></td></tr>");
        if (vipIPs.Count == 0) sb.Append("<tr><td colspan=\"2\">暂无 VIP 用户</td></tr>");
        sb.Append("</table>");
        sb.Append("<div class=\"row\"><form method=\"get\" action=\"/__guard__/vip\"><input type=\"hidden\" name=\"action\" value=\"add\"><input type=\"text\" name=\"ip\" placeholder=\"添加 VIP IP\"><button type=\"submit\">添加</button></form></div>");
        sb.Append("</div>");

        sb.Append("<div class=\"sec\"><h2>留言管理</h2>");
        try
        {
            string cf = @"C:\sunsite\comments.jsonl";
            if (File.Exists(cf))
            {
                string[] cl = File.ReadAllLines(cf);
                int cnt = 0;
                sb.Append("<table><tr><th>昵称</th><th>内容</th><th>地域</th><th>IP</th><th>时间</th><th>操作</th></tr>");
                for (int i = 0; i < cl.Length; i++)
                {
                    string l = cl[i].Trim();
                    if (l.Length == 0 || l[0] != '{') continue;
                    cnt++;
                    sb.Append("<tr><td>" + HtmlEnc(JsonField(l, "nick")) + "</td><td>" + HtmlEnc(JsonField(l, "text")) + "</td><td>" + HtmlEnc(JsonField(l, "region")) + "</td><td class=\"mono\">" + HtmlEnc(JsonField(l, "ip")) + "</td><td class=\"mono\">" + JsonField(l, "time") + "</td><td><a href=\"/__guard__/comment?action=delete&idx=" + i + "\" onclick=\"return confirm('确认删除该留言？');\">删除</a></td></tr>");
                }
                sb.Append("</table>");
                if (cnt == 0) sb.Append("<p>暂无留言</p>");
            }
            else
            {
                sb.Append("<p>暂无留言</p>");
            }
        }
        catch { sb.Append("<p>留言读取失败</p>"); }
        sb.Append("</div>");

        sb.Append("</body></html>");

        byte[] buf = Encoding.UTF8.GetBytes(sb.ToString());
        ctx.Response.StatusCode = 200;
        ctx.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        ctx.Response.ContentType = "text/html; charset=utf-8";
        ctx.Response.ContentLength64 = buf.Length;
        ctx.Response.OutputStream.Write(buf, 0, buf.Length);
        ctx.Response.Close();
    }

    static void BlockAction(HttpListenerContext ctx)
    {
        string action = ctx.Request.QueryString["action"];
        string target = ctx.Request.QueryString["ip"];
        if (!string.IsNullOrEmpty(target) && !string.IsNullOrEmpty(action))
        {
            if (action == "block") manualBlock[target] = DateTime.MaxValue;
            else if (action == "unblock") { DateTime _; manualBlock.TryRemove(target, out _); autoBlock.TryRemove(target, out _); }
        }
        ctx.Response.StatusCode = 302;
        ctx.Response.RedirectLocation = "/__guard__/";
        ctx.Response.Close();
    }

    static bool IsAuthed(HttpListenerContext ctx)
    {
        Cookie c = ctx.Request.Cookies["guard_auth"];
        return c != null && c.Value == authToken;
    }

    static void HandleLogin(HttpListenerContext ctx)
    {
        string password = "";
        if (ctx.Request.HttpMethod == "POST")
        {
            try
            {
                using (StreamReader sr = new StreamReader(ctx.Request.InputStream, Encoding.UTF8))
                    password = GetFormValue(sr.ReadToEnd(), "password");
            }
            catch { }
        }
        if (password == GuardPassword)
        {
            ctx.Response.SetCookie(new Cookie("guard_auth", authToken, "/", ""));
            ctx.Response.RedirectLocation = "/__guard__/";
            ctx.Response.StatusCode = 302;
        }
        else
        {
            ServeLoginPage(ctx, true);
            return;
        }
        ctx.Response.Close();
    }

    static void HandleLogout(HttpListenerContext ctx)
    {
        ctx.Response.SetCookie(new Cookie("guard_auth", "", "/", "") { Expires = DateTime.Now.AddDays(-1) });
        ctx.Response.RedirectLocation = "/__guard__/";
        ctx.Response.StatusCode = 302;
        ctx.Response.Close();
    }

    static void ServeLoginPage(HttpListenerContext ctx, bool error)
    {
        StringBuilder sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>流量卫士 · 登录</title><style>");
        sb.Append("body{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;background:#0a0f1a;color:#dde;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}");
        sb.Append(".box{background:#131a2b;border:1px solid #22304a;border-radius:14px;padding:28px 26px;width:300px;}");
        sb.Append("h1{font-size:20px;color:#fff;margin:0 0 18px;text-align:center;}");
        sb.Append("input{width:100%;box-sizing:border-box;background:#0a0f1a;border:1px solid #2a3a5a;color:#dde;padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:12px;}");
        sb.Append("button{width:100%;background:#7fe3ff;color:#0a0f1a;border:none;padding:10px;border-radius:8px;font-weight:700;cursor:pointer;font-size:14px;}");
        sb.Append(".err{color:#ff6b6b;font-size:12px;text-align:center;margin-bottom:10px;}");
        sb.Append("</style></head><body><div class=\"box\"><h1>🛡 流量卫士</h1>");
        if (error) sb.Append("<div class=\"err\">密码错误</div>");
        sb.Append("<form method=\"post\" action=\"/__guard__/login\"><input type=\"password\" name=\"password\" placeholder=\"管理密码\" autofocus><button type=\"submit\">登 录</button></form>");
        sb.Append("</div></body></html>");
        byte[] buf = Encoding.UTF8.GetBytes(sb.ToString());
        ctx.Response.StatusCode = 200;
        ctx.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        ctx.Response.ContentType = "text/html; charset=utf-8";
        ctx.Response.ContentLength64 = buf.Length;
        ctx.Response.OutputStream.Write(buf, 0, buf.Length);
        ctx.Response.Close();
    }

    static void VipAction(HttpListenerContext ctx)
    {
        string action = ctx.Request.QueryString["action"];
        string ip = ctx.Request.QueryString["ip"];
        if (!string.IsNullOrEmpty(action) && !string.IsNullOrEmpty(ip))
        {
            if (action == "add") { vipIPs.Add(ip); SaveVips(); }
            else if (action == "remove") { vipIPs.Remove(ip); SaveVips(); }
        }
        ctx.Response.RedirectLocation = "/__guard__/";
        ctx.Response.StatusCode = 302;
        ctx.Response.Close();
    }

    static void SaveVips()
    {
        try { File.WriteAllLines(VipFile, vipIPs.ToArray()); } catch { }
    }

    static string GetFormValue(string body, string key)
    {
        if (string.IsNullOrEmpty(body)) return "";
        foreach (string pair in body.Split('&'))
        {
            int i = pair.IndexOf('=');
            if (i < 0) continue;
            string k = pair.Substring(0, i);
            string v = pair.Substring(i + 1);
            if (k == key) { try { return Uri.UnescapeDataString(v.Replace("+", " ")); } catch { return v; } }
        }
        return "";
    }

    static string JsonField(string json, string field)
    {
        string key = "\"" + field + "\"";
        int i = json.IndexOf(key, StringComparison.Ordinal);
        if (i < 0) return "";
        i = json.IndexOf(':', i + key.Length);
        if (i < 0) return "";
        i++;
        while (i < json.Length && (json[i] == ' ' || json[i] == '"')) i++;
        int end = json.IndexOf('"', i);
        if (end < 0) end = json.Length;
        return json.Substring(i, end - i);
    }

    static void CommentAction(HttpListenerContext ctx)
    {
        string action = ctx.Request.QueryString["action"];
        string idxStr = ctx.Request.QueryString["idx"];
        int idx;
        if (action == "delete" && int.TryParse(idxStr, out idx))
        {
            try
            {
                string cf = @"C:\sunsite\comments.jsonl";
                if (File.Exists(cf))
                {
                    List<string> lines = new List<string>(File.ReadAllLines(cf));
                    if (idx >= 0 && idx < lines.Count) { lines.RemoveAt(idx); File.WriteAllLines(cf, lines.ToArray()); }
                }
            }
            catch { }
        }
        ctx.Response.RedirectLocation = "/__guard__/";
        ctx.Response.StatusCode = 302;
        ctx.Response.Close();
    }

    static string HtmlEnc(string s)
    {
        return System.Net.WebUtility.HtmlEncode(s);
    }
}
