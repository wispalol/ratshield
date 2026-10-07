package com.ratshield.platform;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class WindowsNotificationProviderImpl implements WindowsNotificationProvider {
    private final List<String> diagnostics = new ArrayList<>();
    private Boolean available;

    @Override
    public boolean available() {
        if (available != null) {
            return available;
        }
        available = CommandRunner.isWindows();
        return available;
    }

    @Override
    public Delivery notify(String title, String body) {
        if (!available()) {
            return new Delivery(false, "Native notifications require Windows");
        }
        String script = """
                try {
                  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                  $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
                  $template = '<toast><visual><binding template="ToastGeneric"><text>%s</text><text>%s</text></binding></visual></toast>'
                  $xml.LoadXml(($template -f '%s', '%s'))
                  $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
                  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('RATShield').Show($toast)
                  'ok'
                } catch {
                  'failed: ' + $_.Exception.Message
                }
                """.formatted(escape(title), escape(body), escape(title), escape(body));
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(15), "powershell", "-NoProfile",
                "-NonInteractive", "-Command", script);
        if (result.ok() && result.stdout().trim().startsWith("ok")) {
            return new Delivery(true, "Windows toast delivered");
        }
        String message = result.stdout().trim().isEmpty() ? result.stderr().trim() : result.stdout().trim();
        diagnostics.add("toast delivery failed: " + message);
        return new Delivery(false, message);
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&apos;");
    }

    @Override
    public List<String> diagnostics() {
        return List.copyOf(diagnostics);
    }
}
