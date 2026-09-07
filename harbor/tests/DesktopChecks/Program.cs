using Harbor;
using System.Text;
using System.Text.Json.Nodes;

if(args.Length>0&&args[0]=="--sleep"){await Task.Delay(TimeSpan.FromMinutes(2));return;}
if(args.Length==2&&args[0]=="--native-recovery")
{
    string directory=Path.GetFullPath(args[1]);Directory.CreateDirectory(directory);Storage.Root=directory;
    var store=new WindowsProxyStore();var beforeSettings=store.Read();
    var changed=beforeSettings with{Bypass=beforeSettings.Bypass+";harbor-validation.invalid"};
    System.Diagnostics.Process? owner=null,engine=null,guardian=null;
    try
    {
        System.Diagnostics.Process Sleep(){var info=new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};info.ArgumentList.Add("--sleep");return System.Diagnostics.Process.Start(info)!;}
        owner=Sleep();engine=Sleep();
        var recovery=new Lease(beforeSettings,changed,owner.Id,owner.StartTime.ToUniversalTime().Ticks,engine.Id,engine.StartTime.ToUniversalTime().Ticks,"prepared");Storage.Write(Storage.JournalPath,recovery);
        string app=Environment.GetEnvironmentVariable("HARBOR_TEST_APP") ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../../../desktop/bin/Debug/net9.0-windows/Harbor.exe"));
        var start=new System.Diagnostics.ProcessStartInfo(app){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add("--guard");start.ArgumentList.Add(Storage.JournalPath);guardian=System.Diagnostics.Process.Start(start)!;
        if(await guardian.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(8))!="READY")throw new Exception("Guardian readiness failed");
        store.Write(changed);if(store.Read()!=changed)throw new Exception("Native write verification failed");Storage.Write(Storage.JournalPath,recovery with{Phase="applied"});
        owner.Kill();await guardian.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        if(store.Read()!=beforeSettings||File.Exists(Storage.JournalPath)||guardian.ExitCode!=0)throw new Exception("Native recovery verification failed");
        string assemblyHash=Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.ChangeExtension(app,"dll"))));
        File.WriteAllText(Path.Combine(directory,"result.json"),System.Text.Json.JsonSerializer.Serialize(new{checkedAt=DateTimeOffset.UtcNow,applicationSha256=assemblyHash,passed=true,test="Real guardian restores a bypass-only marker after owner process crash",proxyServerUnchanged=true,flagsUnchanged=true,pacUnchanged=true}));
        Console.WriteLine("PASS real guardian process and WinINET recovery; server, flags and PAC unchanged");
    }
    finally
    {
        if(store.Read()==changed)store.Write(beforeSettings);
        foreach(var process in new[]{guardian,engine,owner}){if(process!=null){if(!process.HasExited)process.Kill();process.Dispose();}}
    }
    return;
}
int passed=0;
void Check(string name,Action action){action();passed++;Console.WriteLine("PASS "+name);}
void Assert(bool condition,string message="Assertion failed"){if(!condition)throw new Exception(message);}
void Reject(Action action){bool failed=false;try{action();}catch{failed=true;}Assert(failed,"Expected rejection");}
string uuid="4a4660d1-06d6-4a56-8e77-d6139be8f657";
Check("Clash YAML: mixed protocols with explicit REALITY rejection",()=>
{
    string yaml=$"proxies:\n - name: 线路甲\n   type: ss\n   server: proxy.example\n   port: 443\n   cipher: aes-128-gcm\n   password: secret\n - name: TLS\n   type: vless\n   server: proxy.example\n   port: 443\n   uuid: {uuid}\n   tls: true\n   network: ws\n   ws-opts:\n     path: /edge\n     headers:\n       Host: cdn.example\n - name: Reality\n   type: vless\n   server: proxy.example\n   port: 443\n   uuid: {uuid}\n   reality-opts:\n     public-key: abc\n";
    var result=ProfileImport.Parse(yaml);Assert(result.Nodes.Count==2&&result.Issues.Count==1);Assert(result.Nodes[1]!["wsHost"]!.GetValue<string>()=="cdn.example");Assert(result.Issues[0].Reason.Contains("reality"));
});
Check("Base64 subscriptions, UTF-8 labels and duplicate names",()=>
{
    string links="trojan://secret@proxy.example:443#%E7%BA%BF%E8%B7%AF\nsocks5://user:password@proxy.example:1080#%E7%BA%BF%E8%B7%AF";
    var result=ProfileImport.Parse(Convert.ToBase64String(Encoding.UTF8.GetBytes(links)));Assert(result.Nodes.Count==2);Assert(result.Nodes[0]!["name"]!.GetValue<string>()=="线路");Assert(result.Nodes[1]!["name"]!.GetValue<string>()=="线路 (2)");
});
Check("SIP002 modern and legacy encodings",()=>
{
    string modern="ss://"+Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-256-gcm:colon:password")).TrimEnd('=')+"@127.0.0.1:8388#SS";
    string legacy="ss://"+Convert.ToBase64String(Encoding.UTF8.GetBytes("chacha20-ietf-poly1305:password@127.0.0.1:8388"))+"#Old";
    var result=ProfileImport.Parse(modern+"\n"+legacy);Assert(result.Nodes.Count==2&&result.Issues.Count==0);Assert(result.Nodes[0]!["password"]!.GetValue<string>()=="colon:password");
});
Check("SIP008 JSON",()=>
{
    var result=ProfileImport.Parse("{\"version\":1,\"servers\":[{\"server\":\"localhost\",\"server_port\":8388,\"method\":\"aes-128-gcm\",\"password\":\"secret\",\"remarks\":\"home\"}]}");Assert(result.Nodes.Count==1&&result.Format.Contains("SIP008"));
});
Check("VLESS TLS and VMess AEAD links",()=>
{
    var vm=new JsonObject{{"v","2"},{"ps","VMess"},{"add","localhost"},{"port","443"},{"id",uuid},{"aid","0"},{"net","ws"},{"type","none"},{"path","/ws"},{"tls","tls"}};
    var result=ProfileImport.Parse($"vless://{uuid}@localhost:443?encryption=none&security=tls&type=tcp#VLESS\nvmess://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(vm.ToJsonString())));Assert(result.Nodes.Count==2&&result.Issues.Count==0);
});
Check("No certificate or encryption downgrade",()=>
{
    foreach(string link in new[]{"trojan://secret@host.example:443?allowInsecure=1",$"vless://{uuid}@host.example:443?security=none",$"vless://{uuid}@host.example:443?security=reality&pbk=key",$"vless://{uuid}@host.example:443?security=tls&flow=xtls-rprx-vision"}){var result=ProfileImport.Parse(link);Assert(result.Nodes.Count==0&&result.Issues.Count==1);}
});
Check("Unknown protocols retained as unsupported; no fake support",()=>
{
    var result=ProfileImport.Parse("hysteria2://secret@host.example:443\ntuic://id:password@host.example:443");Assert(result.Nodes.Count==0&&result.Issues.Count==2);
});
Check("YAML aliases, oversize and malformed input rejected",()=>
{
    Reject(()=>ProfileImport.Parse("proxies: &loop [*loop]"));Reject(()=>ProfileImport.Parse(new string('a',ProfileImport.MaximumBytes+1)));Reject(()=>ProfileImport.Parse("invalid%%base64"));
});
var before=new ProxySettings(9,"old:8080","<local>","https://pac.example/config");var applied=ProxySettings.ForHarbor("127.0.0.1:7897");
var lease=new Lease(before,applied,1,1,2,2,"applied");
Check("Recovery restores complete original PAC and flags",()=>{var store=new FakeStore(applied);var result=Recovery.Evaluate(store,lease);Assert(result.State=="restored"&&store.Read()==before);Assert(Recovery.Evaluate(store,lease).State=="unchanged");});
Check("Recovery respects external edits to every field",()=>
{
    foreach(var changed in new[]{applied with{Flags=0},applied with{Server="other:9000"},applied with{Bypass="other"},applied with{AutoConfigUrl="https://other.example"}}){var store=new FakeStore(changed);Assert(Recovery.Evaluate(store,lease).State=="conflict"&&store.Writes==0&&store.Read()==changed);}
});
Check("Prepared journal recovers partial Windows write",()=>{var store=new FakeStore(before with{Server=applied.Server});Assert(Recovery.Evaluate(store,lease with{Phase="prepared"}).State=="restored");Assert(store.Read()==before);});
Check("Restore failure is visible and preserves recovery work",()=>{var store=new FakeStore(applied){Fail=true};Reject(()=>Recovery.Evaluate(store,lease));Assert(store.Read()==applied);});
Check("DPAPI round trip and on-disk credential privacy",()=>
{
    string directory=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../../../.cache/desktop-checks"));Directory.CreateDirectory(directory);Storage.Root=directory;
    string path=Path.Combine(directory,"secrets.dat");var value=new JsonObject{{"url","https://subscribe.example/secret-token-123"},{"password","test-password-do-not-persist-plain"}};Storage.Write(path,value);byte[] bytes=File.ReadAllBytes(path);Assert(!Encoding.UTF8.GetString(bytes).Contains("secret-token-123")&&!Encoding.UTF8.GetString(bytes).Contains("test-password"));Assert(Storage.Read<JsonObject>(path)!.ToJsonString()==value.ToJsonString());
    bytes[bytes.Length/2]^=1;File.WriteAllBytes(path,bytes);Reject(()=>Storage.Read<JsonObject>(path));File.Delete(path);
});
Check("Subscription merge preserves referenced removed nodes",()=>
{
    JsonObject node(string name)=>new(){{"name",name},{"kind","socks5"},{"server","localhost"},{"port",1080}};
    var profile=new JsonObject{{"nodes",new JsonArray(node("Feed · old"),node("Manual"))},{"rules",new JsonArray()},{"groups",new JsonArray()},{"finalPolicy","Feed · old"}};
    var previous=new SubscriptionEntry("id","Feed","https://feed.example/private",["Feed · old"],DateTimeOffset.UtcNow,"","","",0);
    var next=Subscriptions.Merge(profile,new JsonArray(node("new")),previous,"Feed · ",out var names,out int retained);
    Assert(retained==1&&next["nodes"]!.AsArray().Count==3&&names.Contains("Feed · old"));Assert(profile["nodes"]!.AsArray().Count==2,"Input profile mutated");
});
Check("Subscription downloader rejects HTTPS downgrade and invalid encodings",()=>
{
    using var redirect=new HttpFixture(_=>{var response=new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Redirect);response.Headers.Location=new Uri("http://feed.invalid/private-token");return response;});
    Reject(()=>Subscriptions.FetchWithHandlerAsync("https://feed.invalid/token",redirect).GetAwaiter().GetResult());Assert(redirect.Calls==1);
    Reject(()=>Subscriptions.FetchWithHandlerAsync("http://feed.invalid/token",redirect).GetAwaiter().GetResult());Assert(redirect.Calls==1);
    using var invalid=new HttpFixture(_=>new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new System.Net.Http.ByteArrayContent(new byte[]{0xff,0xff})});Reject(()=>Subscriptions.FetchWithHandlerAsync("https://feed.invalid/token",invalid).GetAwaiter().GetResult());
});
Check("Subscription downloader honors ETag and bounds untrusted bodies",()=>
{
    var previous=new SubscriptionEntry("id","Feed","https://feed.invalid/token",[],DateTimeOffset.UtcNow,"\"v1\"","","digest",0);
    using var unchanged=new HttpFixture(request=>{Assert(request.Headers.IfNoneMatch.Single().Tag=="\"v1\"");return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.NotModified);});Assert(Subscriptions.FetchWithHandlerAsync(previous.Url,unchanged,previous).GetAwaiter().GetResult().NotModified);
    using var oversized=new HttpFixture(_=>new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new System.Net.Http.StreamContent(new MemoryStream(new byte[ProfileImport.MaximumBytes+1]))});Reject(()=>Subscriptions.FetchWithHandlerAsync(previous.Url,oversized).GetAwaiter().GetResult());
});
Check("Workspace atomically stores profile and subscription ownership",()=>
{
    var original=new JsonObject{{"version",1}};var subscriptions=new List<SubscriptionEntry>{new("id","Feed","https://feed.invalid/token",["owned-node"],DateTimeOffset.UtcNow,"","","",0)};
    Storage.SaveWorkspace(original,subscriptions);var saved=Storage.LoadWorkspace()!;Assert(saved.Profile["version"]!.GetValue<int>()==1&&saved.Subscriptions[0].NodeNames[0]=="owned-node");
    File.SetAttributes(Storage.WorkspacePath,FileAttributes.ReadOnly);
    try{Reject(()=>Storage.SaveWorkspace(new JsonObject{{"version",2}},[]));Assert(Storage.LoadWorkspace()!.Profile["version"]!.GetValue<int>()==1&&Subscriptions.Read().Count==1);}
    finally{File.SetAttributes(Storage.WorkspacePath,FileAttributes.Normal);}
});
Check("SS2022 imports accept fixed-size PSKs and reject EIH key chains",()=>
{
    foreach(int size in new[]{16,32})
    {
        string method=size==16?"2022-blake3-aes-128-gcm":"2022-blake3-aes-256-gcm";string key=Convert.ToBase64String(new byte[size]);
        string uri="ss://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(method+":"+key))+"@127.0.0.1:8388#SS2022";
        var valid=ProfileImport.Parse(uri);Assert(valid.Nodes.Count==1&&valid.Issues.Count==0);
        var invalid=ProfileImport.Parse("ss://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(method+":"+key+":"+key))+"@127.0.0.1:8388");Assert(invalid.Nodes.Count==0&&invalid.Issues.Count==1);
    }
});
Check("Domain block imports preserve exceptions and reject non-domain filters",()=>
{
    var result=BlockRules.Parse("0.0.0.0 tracker.invalid metrics.invalid\n||ads.invalid^\n@@||safe.ads.invalid^\nexample.invalid/path\nsite.invalid##.ad\n203.0.113.12 other.invalid\n");
    Assert(result.Blocked.Length==3&&result.Allowed.SequenceEqual(new[]{"safe.ads.invalid"})&&result.Unsupported==3);
    Assert(BlockRules.Parse("not-tracker.invalid").Blocked.Single()=="not-tracker.invalid");
});
Check("Coexistence guard blocks takeover but permits local-only operation",()=>
{
    var existing=new NetworkState(true,true,"test",[]);
    NetworkEnvironment.EnsureCanCapture(true,true,false,false,existing);
    Reject(()=>NetworkEnvironment.EnsureCanCapture(true,false,true,false,existing));
    Reject(()=>NetworkEnvironment.EnsureCanCapture(true,false,false,true,existing));
    Reject(()=>NetworkEnvironment.EnsureCanCapture(false,true,true,false,existing));
    Reject(()=>NetworkEnvironment.EnsureCanCapture(false,true,false,true,existing));
    NetworkEnvironment.EnsureCanCapture(false,true,false,false,existing);
});
Check("Isolated mode blocks native proxy writes and ignores stale recovery journals",()=>
{
    Storage.Write(Storage.JournalPath,lease);byte[] journal=File.ReadAllBytes(Storage.JournalPath);
    NetworkSafety.ProhibitSystemWrites();
    Reject(()=>new WindowsProxyStore().Write(applied));
    Assert(Recovery.Restore(Storage.JournalPath).State=="isolated");
    Assert(File.ReadAllBytes(Storage.JournalPath).SequenceEqual(journal));
    File.Delete(Storage.JournalPath);
});
Check("First import chooses a real outbound and preserves subsequent user routing",()=>
{
    var empty=JsonNode.Parse("{\"nodes\":[],\"groups\":[],\"rules\":[],\"finalPolicy\":\"DIRECT\"}")!.AsObject();
    var after=empty.DeepClone().AsObject();after["nodes"]!.AsArray().Add(new JsonObject{["name"]="第一条"});
    Assert(ProfileWorkflow.SelectFirstImport(empty,after)&&after["finalPolicy"]!.GetValue<string>()=="第一条");
    var deliberate=after.DeepClone().AsObject();deliberate["finalPolicy"]="DIRECT";
    Assert(!ProfileWorkflow.SelectFirstImport(deliberate,after));
    empty["finalPolicy"]="REJECT";Assert(!ProfileWorkflow.SelectFirstImport(empty,after));
});
Check("DNS presets retain strict TLS, distinguish custom trust and do not change routing",()=>
{
    var value=new JsonObject{["finalPolicy"]="keep",["tun"]=false};
    foreach(string preset in new[]{"自动 · 加密解析","阿里 DNS · 加密解析","Cloudflare · 加密解析","AdGuard · 广告与追踪过滤"})
    {
        ProfileWorkflow.ApplyDnsPreset(value,preset);Assert(ProfileWorkflow.DnsPreset(value)==preset);
        Assert(value["dnsTls"]!.AsArray().Count==2&&value["finalPolicy"]!.GetValue<string>()=="keep"&&!value["tun"]!.GetValue<bool>());
        value["dnsTls"]![0]!["caPem"]="custom trust";Assert(ProfileWorkflow.DnsPreset(value)=="自定义");
    }
    Reject(()=>ProfileWorkflow.ApplyDnsPreset(value,"typo"));
});
Check("Only legacy Cloudflare defaults migrate to DoH; custom trust and plain DNS stay explicit",()=>
{
    var value=JsonNode.Parse("{\"dnsTls\":[{\"address\":\"1.1.1.1:853\",\"serverName\":\"cloudflare-dns.com\",\"caPem\":\"\"}],\"finalPolicy\":\"keep\"}")!.AsObject();
    var custom=value.DeepClone().AsObject();custom["dnsTls"]![0]!["caPem"]="custom CA";Assert(!ProfileWorkflow.UpgradeDefaultDns(custom));
    Assert(ProfileWorkflow.UpgradeDefaultDns(value)&&ProfileWorkflow.DnsPreset(value)=="自动 · 加密解析");
    Assert(value["dnsTls"]![0]!["httpsPath"]!.GetValue<string>()=="/dns-query"&&value["finalPolicy"]!.GetValue<string>()=="keep");
    Assert(!ProfileWorkflow.UpgradeDefaultDns(value));value["dnsTls"]=new JsonArray();Assert(!ProfileWorkflow.UpgradeDefaultDns(value));
});
Check("Legacy egress gets an independent physical path and explicit system routing is retained",()=>
{
    var profile=new JsonObject{["finalPolicy"]="keep"};
    Assert(ProfileWorkflow.UpgradeEgress(profile)&&profile["egressMode"]!.GetValue<string>()=="physical");
    profile["egressMode"]="system";Assert(!ProfileWorkflow.UpgradeEgress(profile)&&profile["egressMode"]!.GetValue<string>()=="system");
    Assert(profile["finalPolicy"]!.GetValue<string>()=="keep");
});
Check("DNS editor round trip preserves HTTPS transport and custom trust",()=>
{
    var server=new JsonObject{["address"]="127.0.0.1:8443",["serverName"]="fixture.invalid",["httpsPath"]="/dns-query",["caPem"]="custom CA"};
    var saved=ProfileWorkflow.ParseDnsEndpoints(ProfileWorkflow.DnsEndpointText(server),new JsonArray(server.DeepClone()));Assert(JsonNode.DeepEquals(server,saved[0]));
    var dot=ProfileWorkflow.ParseDnsEndpoints("1.1.1.1:853 cloudflare-dns.com",saved);Assert(dot[0]!["httpsPath"]==null);
    Reject(()=>ProfileWorkflow.ParseDnsEndpoints("",saved));
});
Check("Connection error labels distinguish DNS timeout, NXDOMAIN and empty answers",()=>
{
    Assert(ConnectionFailure.Describe("DNS lookup failed for node.invalid: A: DNS failed: DNS upstream timeout") == "DNS 超时");
    Assert(ConnectionFailure.Describe("DNS lookup failed for node.invalid: A: NXDomain") == "域名不存在");
    Assert(ConnectionFailure.Describe("DNS lookup failed for node.invalid: A: NODATA") == "DNS 没有地址记录");
    Assert(ConnectionFailure.Describe("DNS lookup failed for node.invalid: TLS certificate or handshake failed") == "DNS 证书验证失败");
});
JsonObject VerificationFixture() => JsonNode.Parse("""
{"nodes":[{"name":"private-line-a","server":"127.0.0.1","port":9,"password":"local-fixture-only"},{"name":"private-line-b","server":"127.0.0.1","port":10}],"dnsTls":[{"address":"223.5.5.5:443","serverName":"dns.alidns.com","httpsPath":"/dns-query"}],"egressMode":"physical","privacy":{"blockDirect":false},"finalPolicy":"private-line-a"}
""")!.AsObject();
Check("Verification history survives restart, remains encrypted and clears completely",()=>
{
    var profile=VerificationFixture();var history=new VerificationHistory();var now=DateTimeOffset.UtcNow;
    history.Record(profile,"private-line-a",true,321,now);history.Record(profile,"private-line-b",false,0,now,"连接超时");
    var loaded=VerificationHistory.Load();Assert(loaded.Get(profile,"private-line-a") is {Success:true,ElapsedMs:321});Assert(loaded.Get(profile,"private-line-b")?.Failure=="连接超时");
    string disk=Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(Storage.Root,"line-checks.dat")));Assert(!disk.Contains("private-line-a")&&!disk.Contains("local-fixture-only"));
    loaded.Clear();Assert(VerificationHistory.Load().Get(profile,"private-line-a")==null&&!File.Exists(Path.Combine(Storage.Root,"line-checks.dat")));
});
Check("Changing one node preserves other verification results; credentials and DNS invalidate",()=>
{
    var profile=VerificationFixture();var history=new VerificationHistory();var now=DateTimeOffset.UtcNow;
    history.Record(profile,"private-line-a",true,100,now);history.Record(profile,"private-line-b",true,200,now);
    profile["nodes"]![0]!["password"]="replacement-fixture-password";
    Assert(history.Get(profile,"private-line-a")==null&&history.Get(profile,"private-line-b")!=null);
    Assert(history.ForProfile(profile).Count==1);
    var changed=profile.DeepClone().AsObject();changed["dnsTls"]![0]!["httpsPath"]="/different-query";Assert(history.Get(changed,"private-line-b")==null);
    changed=profile.DeepClone().AsObject();changed["egressMode"]="system";Assert(history.Get(changed,"private-line-b")==null);
    changed=profile.DeepClone().AsObject();changed["privacy"]!["blockDirect"]=true;Assert(history.Get(changed,"private-line-b")==null);
    history.Record(profile,"private-line-b",true,201,now);Assert(VerificationHistory.Load().Get(profile,"private-line-a")==null);history.Clear();
});
Check("Route selection, listener edits and JSON property order retain relevant verification",()=>
{
    var profile=VerificationFixture();string? key=VerificationHistory.Fingerprint(profile,"private-line-a");
    var reordered=new JsonObject();foreach(var property in profile.Reverse())reordered[property.Key]=property.Value?.DeepClone();
    reordered["nodes"]![0]=JsonNode.Parse("""{"password":"local-fixture-only","port":9,"server":"127.0.0.1","name":"private-line-a"}""");
    reordered["finalPolicy"]="private-line-b";reordered["listen"]="127.0.0.1:9999";reordered["rules"]=new JsonArray();reordered["routingMode"]="direct";
    Assert(key==VerificationHistory.Fingerprint(reordered,"private-line-a"));
});
Check("Old and future-dated verification never count as recently successful",()=>
{
    var now=DateTimeOffset.UtcNow;var check=new LineCheck("fixture","hash",true,100,now.AddHours(-25),"");
    Assert(!check.Fresh(now)&&check.Summary(now).Contains("需复测"));Assert(!(check with{CheckedAt=now.AddHours(1)}).Fresh(now));
    Assert((check with{CheckedAt=now.AddMinutes(-1)}).Fresh(now));
});
async Task CheckAsync(string name, Func<Task> action) { await action(); passed++; Console.WriteLine("PASS " + name); }
await CheckAsync("Verification batch bounds concurrency, deduplicates its snapshot and counts outcomes", async () =>
{
    int active = 0, peak = 0, reports = 0;
    var seen = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();
    var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var both = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var names = new List<string> { "success", "failure", "skip", "success" };
    var task = VerificationBatch.RunAsync(names, async (name, token) =>
    {
        int count = Interlocked.Increment(ref active); InterlockedExtensionsMax(ref peak, count);
        seen.AddOrUpdate(name, 1, (_, value) => value + 1);
        if (count == 2) both.TrySetResult();
        try { await release.Task.WaitAsync(token); return name switch { "success" => VerificationOutcome.Success, "failure" => VerificationOutcome.Failure, _ => VerificationOutcome.Skipped }; }
        finally { Interlocked.Decrement(ref active); }
    }, state => { Assert(state.Completed == reports++); Assert(state.Completed == state.Successful + state.Failed + state.Skipped); }, CancellationToken.None);
    await both.Task.WaitAsync(TimeSpan.FromSeconds(3));
    names.Add("must-not-enter-snapshot");
    Assert(peak == 2 && seen.Count == 2); release.SetResult();
    var result = await task.WaitAsync(TimeSpan.FromSeconds(3));
    Assert(result is { Total: 3, Completed: 3, Successful: 1, Failed: 1, Skipped: 1 });
    Assert(seen.Count == 3 && seen.Values.All(count => count == 1) && active == 0);
});
await CheckAsync("Cancelling a batch stops queued work and excludes late successful results", async () =>
{
    using var cancellation = new CancellationTokenSource();
    var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    int started = 0;
    var task = VerificationBatch.RunAsync(["first", "second", "queued"], async (_, _) =>
    {
        if (Interlocked.Increment(ref started) == 2) entered.TrySetResult();
        await release.Task; return VerificationOutcome.Success;
    }, _ => { }, cancellation.Token);
    await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); cancellation.Cancel(); release.SetResult();
    var result = await task.WaitAsync(TimeSpan.FromSeconds(3));
    Assert(started == 2 && result is { Total: 3, Completed: 0, Successful: 0, Failed: 0 });
    int calls = 0;
    var cancelled = await VerificationBatch.RunAsync(["already-cancelled"], (_, _) => { calls++; return Task.FromResult(VerificationOutcome.Failure); }, _ => { }, cancellation.Token);
    Assert(calls == 0 && cancelled.Completed == 0);
});
await CheckAsync("Completed batch results survive cancellation and an empty batch does no work", async () =>
{
    using var cancellation = new CancellationTokenSource();
    var firstDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var bothEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    int started = 0;
    var task = VerificationBatch.RunAsync(["complete", "cancel", "queued"], async (name, token) =>
    {
        if (Interlocked.Increment(ref started) == 2) bothEntered.TrySetResult();
        if (name == "complete") { await bothEntered.Task; return VerificationOutcome.Success; }
        await Task.Delay(Timeout.InfiniteTimeSpan, token); return VerificationOutcome.Failure;
    }, state => { if (state.Completed == 1) { cancellation.Cancel(); firstDone.TrySetResult(); } }, cancellation.Token);
    await firstDone.Task.WaitAsync(TimeSpan.FromSeconds(3));
    var result = await task.WaitAsync(TimeSpan.FromSeconds(3));
    Assert(result is { Completed: 1, Successful: 1, Failed: 0 } && started == 2);
    var empty = await VerificationBatch.RunAsync([], (_, _) => throw new Exception("Empty batch ran"), _ => { }, CancellationToken.None);
    Assert(empty is { Total: 0, Completed: 0 });
});
void InterlockedExtensionsMax(ref int target, int value)
{
    int current; do { current = Volatile.Read(ref target); if (current >= value) return; } while (Interlocked.CompareExchange(ref target, value, current) != current);
}
await SubscriptionChecks.RunAsync(Check, CheckAsync);
Check("Legacy routing stays rule-based and direct mode can start without importing nodes", () =>
{
    var value = new JsonObject { ["nodes"] = new JsonArray(), ["finalPolicy"] = "DIRECT" };
    Assert(ProfileWorkflow.RoutingMode(value) == "rules" && ProfileWorkflow.NeedsFirstNode(value));
    value["routingMode"] = ProfileWorkflow.RoutingKey("全部直连");
    Assert(ProfileWorkflow.RoutingLabel(value) == "全部直连" && !ProfileWorkflow.NeedsFirstNode(value));
    value["routingMode"] = "global"; Assert(ProfileWorkflow.NeedsFirstNode(value));
    value["nodes"] = new JsonArray(new JsonObject { ["name"] = "fixture" }); Assert(!ProfileWorkflow.NeedsFirstNode(value));
});
WorkspaceHistoryChecks.Run(Check);
DirectExceptionChecks.Run(Check);
TrafficRouteChecks.Run(Check);
Console.WriteLine($"{passed} checks passed.");

internal sealed class FakeStore(ProxySettings current):IProxyStore
{
    public int Writes;public bool Fail;
    public ProxySettings Read()=>current;
    public void Write(ProxySettings settings){if(Fail)throw new IOException("injected write failure");Writes++;current=settings;}
}

internal sealed class HttpFixture(Func<System.Net.Http.HttpRequestMessage,System.Net.Http.HttpResponseMessage> respond):System.Net.Http.HttpMessageHandler
{
    public int Calls;
    protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(System.Net.Http.HttpRequestMessage request,CancellationToken token){Calls++;return Task.FromResult(respond(request));}
}
