using System;
using System.Linq;
using System.Runtime.InteropServices;
using Avalonia;
using NetworkSentinel.Tui;

namespace NetworkSentinel;

internal static class Program
{
    [DllImport("libc")]
    private static extern uint geteuid();

    [STAThread]
    public static void Main(string[] args)
    {
        if (WantsHelp(args))
        {
            PrintUsage();
            return;
        }

        if (WantsTui(args))
        {
            RunTui();
            return;
        }

        // Prefer elevating only pfctl via osascript while the GUI stays as the user.
        if (IsRunningAsRoot() && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NETWORKSENTINEL_ALLOW_ROOT_GUI")))
        {
            Console.Error.WriteLine(
                """
                Network Sentinel: running GUI as root is not recommended.

                Run as your normal user instead:

                    ./NetworkSentinel
                    # or:  dotnet run -c Release

                For a terminal UI:

                    ./NetworkSentinel --tui

                Firewall changes will prompt for your Mac admin password.
                Set NETWORKSENTINEL_ALLOW_ROOT_GUI=1 to override this warning.
                """);
            // Still allow root GUI on macOS (unlike Wayland) — just warn.
        }

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Network Sentinel GUI failed to start:");
            Console.Error.WriteLine(ex);
            Console.Error.WriteLine(
                """

                Try the terminal UI:

                    ./NetworkSentinel --tui
                    # or:  NETWORKSENTINEL_TUI=1 ./NetworkSentinel
                """);
            Environment.Exit(1);
        }
    }

    private static void RunTui()
    {
        try
        {
            using var app = new TuiApp();
            app.RunAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Network Sentinel TUI failed:");
            Console.Error.WriteLine(ex);
            Environment.Exit(1);
        }
    }

    private static bool WantsHelp(string[] args)
        => args.Any(a => a is "-h" or "--help" or "-?" or "help");

    /// <summary>
    /// TUI when: --tui / -t / tui arg, NETWORKSENTINEL_TUI=1, or no graphical session
    /// and not forced GUI via NETWORKSENTINEL_GUI=1.
    /// </summary>
    private static bool WantsTui(string[] args)
    {
        if (args.Any(a => a is "--tui" or "-t" or "tui" or "--console"))
            return true;

        var env = Environment.GetEnvironmentVariable("NETWORKSENTINEL_TUI");
        if (string.Equals(env, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "yes", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(Environment.GetEnvironmentVariable("NETWORKSENTINEL_GUI"), "1", StringComparison.OrdinalIgnoreCase))
            return false;

        // Auto-select TUI when there is no Aqua session (SSH / headless).
        // On macOS GUI logins, SESSIONTYPE or security session is usually present;
        // also check common SSH indicator.
        var ssh = Environment.GetEnvironmentVariable("SSH_CONNECTION");
        if (!string.IsNullOrEmpty(ssh) && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")))
            return Console.IsInputRedirected == false;

        return false;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            Network Sentinel — macOS network monitor & intrusion awareness

            Usage:
              NetworkSentinel [options]

            Options:
              (default)          Avalonia GUI
              --tui, -t, tui     Terminal UI (Spectre.Console)
              --console          Same as --tui
              -h, --help         Show this help

            Environment:
              NETWORKSENTINEL_TUI=1              Force TUI
              NETWORKSENTINEL_GUI=1              Force GUI
              NETWORKSENTINEL_ALLOW_ROOT_GUI=1   Suppress root-GUI warning

            TUI keys (once running):
              1-7 / Tab   views    p pause    a auto-block    b block
              x unblock   u auth   / filter   h help          q quit

            Examples:
              dotnet run -c Release
              dotnet run -c Release -- --tui
              ./NetworkSentinel --tui
            """);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    private static bool IsRunningAsRoot()
    {
        try
        {
            return geteuid() == 0;
        }
        catch
        {
            return false;
        }
    }
}
