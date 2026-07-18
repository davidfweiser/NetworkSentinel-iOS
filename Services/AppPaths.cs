namespace NetworkSentinel.Services;

/// <summary>macOS Application Support data directory for settings, allowlist, logs.</summary>
public static class AppPaths
{
    public static string DataDirectory
    {
        get
        {
            // ~/Library/Application Support/NetworkSentinel
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string baseDir;
            if (!string.IsNullOrWhiteSpace(home))
            {
                baseDir = Path.Combine(home, "Library", "Application Support");
            }
            else
            {
                baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            }

            var dir = Path.Combine(baseDir, "NetworkSentinel");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }
}
