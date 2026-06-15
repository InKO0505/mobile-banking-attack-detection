package kz.aitu.overlaytest;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;

public class MainActivity extends Activity {
    private static final int OVERLAY_REQ = 1234;
    // Stay visible 2 s so the banking-app focus-loss is long enough for RASP to capture
    private static final long VISIBLE_MS = 2000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!Settings.canDrawOverlays(this)) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName()));
            startActivityForResult(intent, OVERLAY_REQ);
        } else {
            launchService();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == OVERLAY_REQ && Settings.canDrawOverlays(this)) {
            launchService();
        } else {
            finish();
        }
    }

    private void launchService() {
        startService(new Intent(this, OverlayService.class));
        new Handler(Looper.getMainLooper()).postDelayed(this::finish, VISIBLE_MS);
    }
}
