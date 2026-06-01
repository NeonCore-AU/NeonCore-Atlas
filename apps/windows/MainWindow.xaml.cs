namespace NeonCore.Windows;

public sealed partial class MainWindow : Microsoft.UI.Xaml.Window
{
    private readonly NeonCoreDaemonClient daemonClient = new();
    private readonly NeonCoreWintunTunnel tunnel = new();
    public MainWindow() { InitializeComponent(); }
}

public sealed class NeonCoreDaemonClient
{
    public string EndpointDescription => "Future named-pipe client for neoncore-daemon";
}
