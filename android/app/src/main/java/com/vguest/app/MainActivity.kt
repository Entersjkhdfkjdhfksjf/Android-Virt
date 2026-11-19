package com.vguest.app

import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var statusView: TextView
    private lateinit var logView: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var cmdInput: EditText
    private lateinit var importBtn: Button
    private lateinit var selfTestBtn: Button
    private lateinit var binderTestBtn: Button
    private lateinit var runBtn: Button

    private val rootfsDir: File get() = File(filesDir, "rootfs")
    private val metaDbFile: File get() = File(filesDir, "rootfs_meta.db")
    private val runnerBin: File get() = File(applicationInfo.nativeLibraryDir, "libguest_runner.so")

    private val pickRootfsLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) importFromUri(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0F1117"))
            setPadding(28, 36, 28, 28)
        }

        val title = TextView(this).apply {
            text = "VGuest AOSP 12 — Phase 4 Verification Console"
            setTextColor(Color.parseColor("#E6EDF3"))
            textSize = 20f
            setTypeface(Typeface.SANS_SERIF, Typeface.BOLD)
        }
        root.addView(title)

        statusView = TextView(this).apply {
            setTextColor(Color.parseColor("#8B949E"))
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setPadding(0, 8, 0, 16)
        }
        root.addView(statusView)

        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        importBtn = Button(this).apply {
            text = "Import rootfs.tar.zst"
            setOnClickListener { pickRootfsLauncher.launch(arrayOf("*/*")) }
        }
        selfTestBtn = Button(this).apply {
            text = "Phase 2+3 Test"
            setOnClickListener { runPhase23SelfTest() }
        }
        binderTestBtn = Button(this).apply {
            text = "Phase 4 Binder Test"
            setOnClickListener { runPhase4BinderTest() }
        }
        val clearBtn = Button(this).apply {
            text = "Clear"
            setOnClickListener { logView.text = "" }
        }
        btnRow.addView(importBtn)
        btnRow.addView(selfTestBtn)
        btnRow.addView(binderTestBtn)
        btnRow.addView(clearBtn)
        root.addView(btnRow)

        val cmdRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 12, 0, 12)
        }
        cmdInput = EditText(this).apply {
            hint = "Guest sh command (e.g. id && getprop ro.build.version.sdk)"
            setText("id && pwd && ls /apex | head -n 10")
            setTextColor(Color.parseColor("#E6EDF3"))
            setHintTextColor(Color.parseColor("#6E7681"))
            setBackgroundColor(Color.parseColor("#161B22"))
            typeface = Typeface.MONOSPACE
            textSize = 13f
            setPadding(16, 12, 16, 12)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        runBtn = Button(this).apply {
            text = "Run"
            setOnClickListener {
                val cmd = cmdInput.text.toString().trim()
                if (cmd.isNotEmpty()) runGuestShell(cmd)
            }
        }
        cmdRow.addView(cmdInput)
        cmdRow.addView(runBtn)
        root.addView(cmdRow)

        logView = TextView(this).apply {
            setTextColor(Color.parseColor("#7EE787"))
            setBackgroundColor(Color.parseColor("#0A0D12"))
            typeface = Typeface.MONOSPACE
            textSize = 12.5f
            setPadding(18, 18, 18, 18)
            movementMethod = ScrollingMovementMethod()
        }
        logScroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
            addView(logView)
        }
        root.addView(logScroll)

        setContentView(root)
        refreshStatus()
        appendLog("Ready. Tap 'Phase 4 Binder Test' to launch servicemanager & query 'service list'.")
    }

    private fun refreshStatus() {
        val hasRootfs = File(rootfsDir, "system/bin/sh").exists()
        val hasDb = metaDbFile.exists()
        val hasRunner = runnerBin.exists() && runnerBin.canExecute()
        val sockLen = File(rootfsDir, "dev/socket/property_service").absolutePath.length
        statusView.text = "runner=${if (hasRunner) "OK" else "MISSING"} | " +
            "rootfs=${if (hasRootfs) "READY" else "NOT IMPORTED"} | " +
            "meta_db=${if (hasDb) "OK" else "MISSING"} | " +
            "prop_sock_len=${sockLen}B"
    }

    private fun setBusy(busy: Boolean) {
        runOnUiThread {
            importBtn.isEnabled = !busy
            selfTestBtn.isEnabled = !busy
            binderTestBtn.isEnabled = !busy
            runBtn.isEnabled = !busy
        }
    }

    private fun appendLog(line: String) {
        runOnUiThread {
            logView.append(line + "\n")
            logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    private fun importFromUri(uri: Uri) {
        setBusy(true)
        appendLog("\n=== Importing $uri ===")
        executor.execute {
            try {
                contentResolver.openInputStream(uri)?.use { stream ->
                    RootfsExtractor.extractTarZst(stream, filesDir) { msg -> appendLog(msg) }
                } ?: appendLog("[ERROR] Failed to open URI stream")
            } catch (t: Throwable) {
                appendLog("[ERROR] Import failed: ${t.javaClass.simpleName}: ${t.message}")
            } finally {
                runOnUiThread { refreshStatus() }
                setBusy(false)
            }
        }
    }

    private fun runPhase23SelfTest() {
        val script = listOf(
            "echo '--- [1] Virtual Identity & CWD ---'",
            "id; pwd",
            "echo '--- [2] Flattened APEX Modules ---'",
            "ls /apex | head -n 10",
            "echo '--- [3] Seeded Bionic Properties ---'",
            "getprop ro.build.version.sdk; getprop ro.zygote; getprop ro.hardware.gralloc",
            "echo '--- [4] Live Property Service Write ---'",
            "setprop debug.vguest.ping hello_tab_s7 && getprop debug.vguest.ping",
            "echo '--- [5] Pseudo-FS SELinux & Mounts ---'",
            "cat /sys/fs/selinux/enforce; head -n 3 /proc/mounts"
        ).joinToString("; ")
        runGuestShell(script)
    }

    private fun runPhase4BinderTest() {
        val script = listOf(
            "echo '--- Starting AOSP 12 servicemanager on virtual /dev/binder ---'",
            "/system/bin/servicemanager &",
            "SM_PID=\$!",
            "sleep 1",
            "echo '--- Querying service list via virtual /dev/binder ---'",
            "/system/bin/service list",
            "kill \$SM_PID 2>/dev/null || true"
        ).joinToString("; ")
        runGuestShell(script)
    }

    private fun runGuestShell(shellCmd: String) {
        if (!runnerBin.exists()) {
            appendLog("[ERROR] Missing ${runnerBin.absolutePath}")
            return
        }
        if (!File(rootfsDir, "system/bin/sh").exists()) {
            appendLog("[ERROR] Rootfs not imported yet. Tap 'Import rootfs.tar.zst' first.")
            return
        }

        setBusy(true)
        appendLog("\n=== Executing in AOSP 12 Guest ===")
        executor.execute {
            try {
                val args = mutableListOf(
                    runnerBin.absolutePath,
                    "--rootfs", rootfsDir.absolutePath,
                    "--meta-db", metaDbFile.absolutePath,
                    "--verbose",
                    "--",
                    "/system/bin/sh", "-c", shellCmd
                )
                val proc = ProcessBuilder(args)
                    .redirectErrorStream(true)
                    .start()

                BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                    var line: String? = reader.readLine()
                    while (line != null) {
                        appendLog(line)
                        line = reader.readLine()
                    }
                }
                val rc = proc.waitFor()
                appendLog("=== Guest exited with code $rc ===")
            } catch (t: Throwable) {
                appendLog("[ERROR] Launch failed: ${t.javaClass.simpleName}: ${t.message}")
            } finally {
                setBusy(false)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        executor.shutdownNow()
    }
}
