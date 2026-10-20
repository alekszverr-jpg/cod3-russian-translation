using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Drawing;

public class FileEntry {
    public string path, source_sha256, sha256, patch, patch_sha256;
    public long source_size, size;
    public long source_offset, offset;
    public bool modified;
}
public class PlatformEntry {
    public string platform, label, mode, source_hint;
    public long total_bytes;
    public List<FileEntry> files;
    public List<FileEntry> iso_files;
    public string iso_template, iso_template_sha256;
}
public class PackageManifest {
    public string version, xdelta_sha256;
    public List<PlatformEntry> platforms;
}
public static class Installer {
    public static readonly string Home=AppDomain.CurrentDomain.BaseDirectory;
    public static PackageManifest Manifest;
    public static void Load() {
        var parser=new JavaScriptSerializer();parser.MaxJsonLength=Int32.MaxValue;
        Manifest=parser.Deserialize<PackageManifest>(File.ReadAllText(Path.Combine(Home,"manifest.json"),Encoding.UTF8));
        if(Manifest==null || Manifest.platforms==null || Manifest.version!="1.0")throw new Exception("Неверный комплект патчей.");
    }
    public static string Hash(string path) {
        using(var f=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();
    }
    public static string Safe(string root,string relative) {
        if(String.IsNullOrEmpty(relative)||Path.IsPathRooted(relative))throw new Exception("Недопустимый путь в манифесте.");
        string parent=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
        string result=Path.GetFullPath(Path.Combine(parent,relative.Replace('/',Path.DirectorySeparatorChar)));
        if(!result.StartsWith(parent,StringComparison.OrdinalIgnoreCase))throw new Exception("Путь выходит за пределы папки.");
        return result;
    }
    static void Check(string path,long size,string hash,string description) {
        if(!File.Exists(path))throw new Exception("Не найден файл: "+description);
        if(new FileInfo(path).Length!=size || !String.Equals(Hash(path),hash,StringComparison.OrdinalIgnoreCase))
            throw new Exception("Файл не подходит или повреждён: "+description+". Нужна поддерживаемая исходная версия игры.");
    }
    static void CopyBytes(Stream source,Stream target,long count) {
        byte[] buffer=new byte[1024*1024];
        while(count>0) {
            int got=source.Read(buffer,0,(int)Math.Min(count,buffer.Length));
            if(got==0)throw new EndOfStreamException("Файл неожиданно закончился.");
            target.Write(buffer,0,got);count-=got;
        }
    }
    static List<FileEntry> ValidateIso(PlatformEntry p,long sourceLength) {
        if(p.mode!="iso" || p.files.Count!=1 || p.iso_files.Count==0 || p.total_bytes!=p.files[0].size)
            throw new Exception("Неверный план сборки ISO.");
        var ordered=p.iso_files.OrderBy(x=>x.offset).ToList();long end=0;
        foreach(var f in ordered) {
            if(f.offset<end || f.size<0 || f.offset>p.total_bytes || f.size>p.total_bytes-f.offset ||
               f.source_offset<0 || f.source_size<0 || f.source_offset>sourceLength || f.source_size>sourceLength-f.source_offset ||
               (!f.modified && (f.size!=f.source_size || f.sha256!=f.source_sha256)))
                throw new Exception("Неверные границы файла в ISO: "+f.path);
            end=f.offset+f.size;
        }
        return ordered;
    }
    static void ApplyDelta(string tool,string input,string patch,string target,string name) {
        var info=new ProcessStartInfo(tool,"-d -s "+Quote(input)+" "+Quote(patch)+" "+Quote(target));
        info.UseShellExecute=false;info.CreateNoWindow=true;
        info.RedirectStandardError=true;info.RedirectStandardOutput=true;
        using(var process=Process.Start(info)) {
            Task<string> err=Task.Factory.StartNew(()=>process.StandardError.ReadToEnd());
            Task<string> stdout=Task.Factory.StartNew(()=>process.StandardOutput.ReadToEnd());
            process.WaitForExit();Task.WaitAll(err,stdout);
            if(process.ExitCode!=0)throw new Exception("Не удалось применить патч к "+name+": "+err.Result);
        }
    }
    static void BuildIso(PlatformEntry p,string source,string output,string tool,Action<string> log) {
        var ordered=ValidateIso(p,new FileInfo(source).Length);
        var gaps=new List<Tuple<long,long>>();long end=0;
        foreach(var f in ordered) {
            if(f.offset>end)gaps.Add(Tuple.Create(end,f.offset-end));
            end=f.offset+f.size;
        }
        if(end<p.total_bytes)gaps.Add(Tuple.Create(end,p.total_bytes-end));
        string work=output+".work-"+Guid.NewGuid().ToString("N");
        string original=Path.Combine(work,"original.bin"),patched=Path.Combine(work,"patched.bin");
        Directory.CreateDirectory(work);
        try {
            using(var input=File.OpenRead(source))
            using(var target=new FileStream(output,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)) {
                target.SetLength(p.total_bytes);
                using(var packed=File.OpenRead(Safe(Home,p.iso_template)))
                using(var gzip=new GZipStream(packed,CompressionMode.Decompress))
                using(var reader=new BinaryReader(gzip)) {
                    if(Encoding.ASCII.GetString(reader.ReadBytes(8))!="COD3ISO1" || reader.ReadInt64()!=p.total_bytes || reader.ReadInt32()!=gaps.Count)
                        throw new Exception("Неверный шаблон структуры ISO.");
                    foreach(var gap in gaps) {
                        if(reader.ReadInt64()!=gap.Item1 || reader.ReadInt64()!=gap.Item2)
                            throw new Exception("Неверные границы структуры ISO.");
                        target.Position=gap.Item1;CopyBytes(gzip,target,gap.Item2);
                    }
                    if(gzip.ReadByte()!=-1)throw new Exception("Лишние данные в шаблоне ISO.");
                }
                int index=0;
                foreach(var f in ordered) {
                    input.Position=f.source_offset;target.Position=f.offset;
                    if(f.modified) {
                        using(var extracted=new FileStream(original,FileMode.CreateNew,FileAccess.Write,FileShare.None))CopyBytes(input,extracted,f.source_size);
                        Check(original,f.source_size,f.source_sha256,f.path);
                        ApplyDelta(tool,original,Safe(Home,f.patch),patched,f.path);
                        Check(patched,f.size,f.sha256,f.path);
                        using(var decoded=File.OpenRead(patched))CopyBytes(decoded,target,f.size);
                        File.Delete(original);File.Delete(patched);
                    } else CopyBytes(input,target,f.size);
                    log("Сборка ISO "+(++index)+" / "+ordered.Count+": "+f.path);
                }
            }
            Check(output,p.total_bytes,p.files[0].sha256,p.files[0].path);
        } finally {
            if(File.Exists(original))File.Delete(original);
            if(File.Exists(patched))File.Delete(patched);
            Directory.Delete(work,false);
        }
        log("Перевод установлен. Готовый ISO совпадает с релизом побайтно. Исходник сохранён.");
    }
    public static void Run(string platform,string source,string output,bool checkOnly,bool resultOnly,Action<string> log) {
        PlatformEntry p=Manifest.platforms.FirstOrDefault(x=>x.platform.Equals(platform,StringComparison.OrdinalIgnoreCase));
        if(p==null)throw new Exception("Неизвестная платформа.");
        source=Path.GetFullPath(source);
        if(resultOnly) {
            int j=0;
            foreach(var f in p.files){Check(p.mode=="iso"?source:Safe(source,f.path),f.size,f.sha256,f.path);log("Проверка результата "+(++j)+" / "+p.files.Count);}
            log("Готовая игра совпадает с релизом побайтно.");return;
        }
        string tool=Path.Combine(Home,"third_party","xdelta3.exe");
        if(!File.Exists(tool)||Hash(tool)!=Manifest.xdelta_sha256)throw new Exception("Утилита xdelta3 отсутствует или повреждена. Распакуйте комплект заново.");
        if(!checkOnly) {
            if(String.IsNullOrWhiteSpace(output))throw new Exception("Укажите путь для готовой игры.");
            output=Path.GetFullPath(output);
            if(File.Exists(output)||Directory.Exists(output))throw new Exception("Путь результата уже существует. Выберите новое имя или новую папку.");
            string a=source.TrimEnd('\\')+"\\",b=output.TrimEnd('\\')+"\\";
            if(a.StartsWith(b,StringComparison.OrdinalIgnoreCase)||b.StartsWith(a,StringComparison.OrdinalIgnoreCase))throw new Exception("Исходник и результат должны находиться отдельно.");
            long free=new DriveInfo(Path.GetPathRoot(output)).AvailableFreeSpace;
            long scratch=256L*1024*1024;
            if(p.iso_files!=null)scratch=Math.Max(scratch,p.iso_files.Where(x=>x.modified).Select(x=>x.source_size+x.size+64L*1024*1024).DefaultIfEmpty(0).Max());
            if(free<p.total_bytes+scratch)throw new Exception("Недостаточно свободного места для готовой игры.");
        }
        int i=0;
        log("Проверяю исходную игру. Большой ISO может проверяться несколько минут.");
        foreach(var f in p.files) {
            string input=p.mode=="iso"?source:Safe(source,f.path);
            Check(input,f.source_size,f.source_sha256,f.path);
            if(f.modified && p.iso_files==null) {
                string patch=Safe(Home,f.patch);
                if(!File.Exists(patch)||Hash(patch)!=f.patch_sha256)throw new Exception("Патч отсутствует или повреждён: "+f.patch);
            }
            log("Исходник "+(++i)+" / "+p.files.Count+": "+f.path);
        }
        if(p.iso_files!=null) {
            ValidateIso(p,new FileInfo(source).Length);
            string template=Safe(Home,p.iso_template);
            if(!File.Exists(template)||Hash(template)!=p.iso_template_sha256)throw new Exception("Шаблон структуры ISO отсутствует или повреждён.");
            foreach(var f in p.iso_files.Where(x=>x.modified)) {
                string patch=Safe(Home,f.patch);
                if(!File.Exists(patch)||Hash(patch)!=f.patch_sha256)throw new Exception("Патч отсутствует или повреждён: "+f.patch);
            }
        }
        if(checkOnly){log("Исходная версия подходит. Патчи проверены.");return;}
        i=0;
        if(p.mode=="folder")Directory.CreateDirectory(output);
        else Directory.CreateDirectory(Path.GetDirectoryName(output));
        if(p.iso_files!=null){BuildIso(p,source,output,tool,log);return;}
        foreach(var f in p.files) {
            string input=p.mode=="iso"?source:Safe(source,f.path);
            string target=p.mode=="iso"?output:Safe(output,f.path);
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            if(f.modified) {
                var info=new ProcessStartInfo(tool,"-d -s "+Quote(input)+" "+Quote(Safe(Home,f.patch))+" "+Quote(target));
                info.UseShellExecute=false;info.CreateNoWindow=true;
                info.RedirectStandardError=true;info.RedirectStandardOutput=true;
                using(var process=Process.Start(info)) {
                    Task<string> err=Task.Factory.StartNew(()=>process.StandardError.ReadToEnd());
                    Task<string> stdout=Task.Factory.StartNew(()=>process.StandardOutput.ReadToEnd());
                    process.WaitForExit();Task.WaitAll(err,stdout);
                    if(process.ExitCode!=0)throw new Exception("Не удалось применить патч к "+f.path+": "+err.Result);
                }
            } else File.Copy(input,target,false);
            Check(target,f.size,f.sha256,f.path);
            log("Готово "+(++i)+" / "+p.files.Count+": "+f.path);
        }
        log("Перевод установлен. Все готовые файлы проверены. Исходник сохранён.");
    }
    static string Quote(string text) {
        if(text.IndexOf('"')>=0)throw new Exception("Кавычки в пути не поддерживаются.");
        return "\""+text+"\"";
    }
    [STAThread]
    public static int Main(string[] args) {
        try {
            if(args.Length>0){
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false)){AutoFlush=true});
                Console.SetError(new StreamWriter(Console.OpenStandardError(),new UTF8Encoding(false)){AutoFlush=true});
            }
            Load();
            if(args.Length==2 && args[0]=="--render-ui") {
                Application.EnableVisualStyles();
                using(var form=new InstallerForm()) {
                    IntPtr handle=form.Handle;
                    foreach(Control child in form.Controls){IntPtr childHandle=child.Handle;}
                    form.PerformLayout();
                    using(var bitmap=new Bitmap(form.Width,form.Height)) {
                        form.DrawToBitmap(bitmap,new Rectangle(0,0,form.Width,form.Height));bitmap.Save(args[1]);
                    }
                }
                return 0;
            }
            if(args.Length>0) {
                var values=new Dictionary<string,string>();bool check=false,result=false;
                for(int i=0;i<args.Length;i++) {
                    if(args[i]=="--check"){check=true;continue;}
                    if(args[i]=="--verify-result"){result=true;continue;}
                    if(i+1>=args.Length)throw new Exception("Недостаточно аргументов.");
                    values.Add(args[i],args[++i]);
                }
                Run(values["--platform"],values["--source"],values.ContainsKey("--output")?values["--output"]:null,check,result,Console.WriteLine);
                return 0;
            }
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InstallerForm());return 0;
        } catch(Exception e) {
            if(args.Length>0)Console.Error.WriteLine(e.Message);
            else MessageBox.Show(e.Message,"Call of Duty 3 — перевод",MessageBoxButtons.OK,MessageBoxIcon.Error);
            return 1;
        }
    }
}
public class InstallerForm:Form {
    ComboBox platforms=new ComboBox();TextBox source=new TextBox(),output=new TextBox(),log=new TextBox();
    Button sourceBrowse=new Button(),outputBrowse=new Button(),check=new Button(),install=new Button();
    bool busy;
    public InstallerForm() {
        Text="Call of Duty 3 — перевод от Savkin · 1.0";ClientSize=new Size(680,510);
        MinimumSize=new Size(696,549);MaximumSize=MinimumSize;StartPosition=FormStartPosition.CenterScreen;
        Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(248,247,243);
        var title=new Label{Text="Call of Duty 3 · Русский перевод",Location=new Point(22,18),AutoSize=true,Font=new Font("Segoe UI",17,FontStyle.Bold)};
        var desc=new Label{Text="Перевод от Savkin   •   Версия 1.0",Location=new Point(24,54),AutoSize=true};
        Controls.Add(title);Controls.Add(desc);
        AddLabel("Платформа",24,88);platforms.SetBounds(24,112,630,30);platforms.DropDownStyle=ComboBoxStyle.DropDownList;
        foreach(var p in Installer.Manifest.platforms)platforms.Items.Add(p.label);platforms.SelectedIndex=0;Controls.Add(platforms);
        AddLabel("Исходная игра",24,151);source.SetBounds(24,176,523,28);sourceBrowse.SetBounds(556,174,98,31);sourceBrowse.Text="Выбрать…";
        Controls.Add(source);Controls.Add(sourceBrowse);
        AddLabel("Куда сохранить готовую игру — новый файл или новая папка",24,214);
        output.SetBounds(24,239,523,28);outputBrowse.SetBounds(556,237,98,31);outputBrowse.Text="Выбрать…";
        Controls.Add(output);Controls.Add(outputBrowse);
        check.SetBounds(24,282,220,36);check.Text="Проверить исходник";install.SetBounds(434,282,220,36);install.Text="Установить перевод";
        Controls.Add(check);Controls.Add(install);
        log.SetBounds(24,332,630,150);log.Multiline=true;log.ReadOnly=true;log.ScrollBars=ScrollBars.Vertical;log.BackColor=Color.White;Controls.Add(log);
        sourceBrowse.Click+=(s,e)=>BrowseSource();outputBrowse.Click+=(s,e)=>BrowseOutput();
        check.Click+=(s,e)=>Start(true);install.Click+=(s,e)=>Start(false);
        FormClosing+=(s,e)=>{if(busy){e.Cancel=true;MessageBox.Show("Дождитесь завершения операции.");}};
    }
    void AddLabel(string text,int x,int y){Controls.Add(new Label{Text=text,Location=new Point(x,y),AutoSize=true});}
    PlatformEntry Current {get{return Installer.Manifest.platforms[platforms.SelectedIndex];}}
    void BrowseSource() {
        if(Current.mode=="iso")using(var d=new OpenFileDialog{Filter="Образ PS2 (*.iso)|*.iso|Все файлы|*.*"}){if(d.ShowDialog()==DialogResult.OK)source.Text=d.FileName;}
        else using(var d=new FolderBrowserDialog{Description=Current.source_hint}){if(d.ShowDialog()==DialogResult.OK)source.Text=d.SelectedPath;}
    }
    void BrowseOutput() {
        if(Current.mode=="iso")using(var d=new SaveFileDialog{Filter="Образ PS2 (*.iso)|*.iso",FileName="Call_of_Duty_3_RU_Savkin_v1.0.iso"}){if(d.ShowDialog()==DialogResult.OK)output.Text=d.FileName;}
        else using(var d=new FolderBrowserDialog{Description="Выберите родительскую папку для переведённой игры"}){if(d.ShowDialog()==DialogResult.OK)output.Text=Path.Combine(d.SelectedPath,"Call of Duty 3 RU "+Current.platform);}
    }
    void Start(bool checkOnly) {
        string p=Current.platform,src=source.Text,dst=output.Text;
        if(String.IsNullOrWhiteSpace(src)){MessageBox.Show("Выберите исходную игру.");return;}
        busy=true;foreach(Control c in new Control[]{platforms,source,output,sourceBrowse,outputBrowse,check,install})c.Enabled=false;
        log.Clear();
        Task.Factory.StartNew(()=>{
            string error=null;
            try{Installer.Run(p,src,dst,checkOnly,false,x=>Invoke(new Action(()=>{log.AppendText(x+Environment.NewLine);})));}
            catch(Exception e){error=e.Message;}
            Invoke(new Action(()=>{
                busy=false;foreach(Control c in new Control[]{platforms,source,output,sourceBrowse,outputBrowse,check,install})c.Enabled=true;
                if(error!=null){log.AppendText("Ошибка: "+error+Environment.NewLine);MessageBox.Show(error,"Перевод не установлен",MessageBoxButtons.OK,MessageBoxIcon.Error);}
            }));
        });
    }
}
