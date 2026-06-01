namespace NeonCore.Atlas;

public sealed partial class MainWindow : Microsoft.UI.Xaml.Window
{
    private readonly AtlasDaemonClient daemonClient = new();
    private readonly WintunTunnel tunnel = new();
    public MainWindow() { InitializeComponent(); }
}

public sealed class AtlasDaemonClient
{
    public string EndpointDescription => "Future named-pipe client for neoncore-daemon";
}
