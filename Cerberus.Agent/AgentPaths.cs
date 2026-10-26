namespace Cerberus.Agent;

public sealed class AgentPaths
{
    public string DataDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cerberus");

    public string ConfigFile => Path.Combine(DataDir, "cerberus.json");

    public string QueueDir => Path.Combine(DataDir, "queue");

    /// <summary>首次啟動時把隨附的預設設定複製到 ProgramData。</summary>
    public void EnsureConfig()
    {
        Directory.CreateDirectory(DataDir);
        if (!File.Exists(ConfigFile))
            File.Copy(Path.Combine(AppContext.BaseDirectory, "cerberus.json"), ConfigFile);
    }
}
