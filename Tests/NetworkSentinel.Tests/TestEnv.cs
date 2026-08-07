using System.Runtime.CompilerServices;

namespace NetworkSentinel.Tests;

/// <summary>
/// Points HOME at a throwaway directory before any test touches AppPaths, so
/// services that persist state (settings, suppressions, the allowlist seed file)
/// never write into the real user profile.
///
/// The Linux build redirects XDG_DATA_HOME; macOS AppPaths resolves
/// ~/Library/Application Support from the user profile, so HOME is the knob here.
/// </summary>
internal static class TestEnv
{
    [ModuleInitializer]
    internal static void Init()
    {
        var dir = Path.Combine(Path.GetTempPath(), "networksentinel-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        Environment.SetEnvironmentVariable("HOME", dir);

        // Fail loudly rather than quietly persisting into the developer's real
        // ~/Library/Application Support: a silent miss here would mean every test
        // below is writing to live state.
        var resolved = NetworkSentinel.Services.AppPaths.DataDirectory;
        if (!resolved.StartsWith(dir, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Test data directory was not redirected (got '{resolved}', expected under '{dir}').");
    }
}
