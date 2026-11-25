package com.vguest.app

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.widget.Toast
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.system.Os
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
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

    companion object {
        private const val FB_WIDTH = 1400
        private const val FB_HEIGHT = 876

        // Linux input_event constants
        private const val EV_SYN = 0x00
        private const val EV_KEY = 0x01
        private const val EV_ABS = 0x03
        private const val SYN_REPORT = 0x00
        private const val BTN_TOUCH = 0x14a
        private const val BTN_TOOL_PEN = 0x140
        private const val ABS_X = 0x00
        private const val ABS_Y = 0x01
        private const val ABS_PRESSURE = 0x18
        private const val ABS_MT_SLOT = 0x2f
        private const val ABS_MT_POSITION_X = 0x35
        private const val ABS_MT_POSITION_Y = 0x36
        private const val ABS_MT_TRACKING_ID = 0x39
        private const val ABS_MT_PRESSURE = 0x3a
    }

    private val executor = Executors.newSingleThreadExecutor()
    private var activeProcess: Process? = null

    private lateinit var statusView: TextView
    private lateinit var logView: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var cmdInput: EditText
    private lateinit var displayContainer: LinearLayout
    private lateinit var surfaceView: SurfaceView
    private lateinit var importBtn: Button
    private lateinit var selfTestBtn: Button
    private lateinit var binderTestBtn: Button
    private lateinit var displayTestBtn: Button
    private lateinit var stopBtn: Button
    private lateinit var bootIpcBtn: Button
    private lateinit var bootArtBtn: Button
    private lateinit var bootFullBtn: Button
    private lateinit var runBtn: Button

    private val rootfsDir: File get() = File(filesDir, "rootfs")
    private val metaDbFile: File get() = File(filesDir, "rootfs_meta.db")
    private val runnerBin: File get() = File(applicationInfo.nativeLibraryDir, "libguest_runner.so")
    private val fbDemoBin: File get() = File(applicationInfo.nativeLibraryDir, "libvguest_fb_demo.so")

    private val pickRootfsLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) importFromUri(uri)
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0F1117"))
            setPadding(24, 30, 24, 24)
        }

        val title = TextView(this).apply {
            text = "VGuest AOSP 12 — Phase 6 Runtime Bring-Up Console"
            setTextColor(Color.parseColor("#E6EDF3"))
            textSize = 19f
            setTypeface(Typeface.SANS_SERIF, Typeface.BOLD)
        }
        root.addView(title)

        statusView = TextView(this).apply {
            setTextColor(Color.parseColor("#8B949E"))
            textSize = 12.5f
            typeface = Typeface.MONOSPACE
            setPadding(0, 6, 0, 12)
        }
        root.addView(statusView)

        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        importBtn = Button(this).apply {
            text = "Import"
            setOnClickListener { pickRootfsLauncher.launch(arrayOf("*/*")) }
        }
        selfTestBtn = Button(this).apply {
            text = "P2+3 Test"
            setOnClickListener { runPhase23SelfTest() }
        }
        binderTestBtn = Button(this).apply {
            text = "P4 Binder"
            setOnClickListener { runPhase4BinderTest() }
        }
        displayTestBtn = Button(this).apply {
            text = "P5 Display + S Pen"
            setOnClickListener { runPhase5DisplayTest() }
        }
        stopBtn = Button(this).apply {
            text = "Stop"
            isEnabled = false
            setOnClickListener { stopActiveGuest() }
        }
        val copyBtn = Button(this).apply {
            text = "Copy Log"
            setOnClickListener {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("VGuestLog", logView.text))
                Toast.makeText(this@MainActivity, "Copied log to clipboard", Toast.LENGTH_SHORT).show()
            }
        }
        val clearBtn = Button(this).apply {
            text = "Clear"
            setOnClickListener { logView.text = "" }
        }
        btnRow.addView(importBtn)
        btnRow.addView(selfTestBtn)
        btnRow.addView(binderTestBtn)
        btnRow.addView(displayTestBtn)
        btnRow.addView(stopBtn)
        btnRow.addView(copyBtn)
        btnRow.addView(clearBtn)
        root.addView(btnRow)

        val p6Row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        bootIpcBtn = Button(this).apply {
            text = "P6: 3-Binder IPC"
            setOnClickListener { runBootStage("ipc") }
        }
        bootArtBtn = Button(this).apply {
            text = "P6: ART VM"
            setOnClickListener { runBootStage("art") }
        }
        bootFullBtn = Button(this).apply {
            text = "P6: Boot Zygote"
            setOnClickListener { runBootStage("full") }
        }
        p6Row.addView(bootIpcBtn)
        p6Row.addView(bootArtBtn)
        p6Row.addView(bootFullBtn)
        root.addView(p6Row)

        // Live hardware-accelerated SurfaceView for guest display (shown during Phase 5+)
        displayContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.4f
            ).apply { setMargins(0, 8, 0, 8) }
        }
        surfaceView = SurfaceView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT
            )
            holder.addCallback(object : SurfaceHolder.Callback {
                override fun surfaceCreated(holder: SurfaceHolder) {
                    DisplayBridge.nativeAttachSurface(holder.surface)
                }
                override fun surfaceChanged(holder: SurfaceHolder, f: Int, w: Int, h: Int) {
                    DisplayBridge.nativeAttachSurface(holder.surface)
                }
                override fun surfaceDestroyed(holder: SurfaceHolder) {
                    DisplayBridge.nativeDetachSurface()
                }
            })
            setOnTouchListener { v, ev -> dispatchMotionToGuest(v, ev); true }
            setOnHoverListener { v, ev -> dispatchMotionToGuest(v, ev); true }
        }
        displayContainer.addView(surfaceView)
        root.addView(displayContainer)

        val cmdRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 8, 0, 8)
        }
        cmdInput = EditText(this).apply {
            hint = "Guest sh command"
            setText("id && pwd && ls /apex | head -n 10")
            setTextColor(Color.parseColor("#E6EDF3"))
            setHintTextColor(Color.parseColor("#6E7681"))
            setBackgroundColor(Color.parseColor("#161B22"))
            typeface = Typeface.MONOSPACE
            textSize = 13f
            setPadding(14, 10, 14, 10)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        runBtn = Button(this).apply {
            text = "Run"
            setOnClickListener {
                val cmd = cmdInput.text.toString().trim()
                if (cmd.isNotEmpty()) runGuestShell(cmd, showDisplay = false)
            }
        }
        cmdRow.addView(cmdInput)
        cmdRow.addView(runBtn)
        root.addView(cmdRow)

        logView = TextView(this).apply {
            setTextColor(Color.parseColor("#7EE787"))
            setBackgroundColor(Color.parseColor("#0A0D12"))
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setPadding(14, 14, 14, 14)
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
        appendLog("Ready. Tap 'P5 Display + S Pen' to launch the live 60 FPS shared-memory SurfaceView!")
    }

    private fun dispatchMotionToGuest(v: View, ev: MotionEvent) {
        if (v.width <= 0 || v.height <= 0) return
        val toolType = ev.getToolType(0)
        val isStylus = (toolType == MotionEvent.TOOL_TYPE_STYLUS ||
            toolType == MotionEvent.TOOL_TYPE_ERASER)
        val devIdx = if (isStylus) 1 else 0

        val gx = ((ev.x / v.width) * (FB_WIDTH - 1)).toInt().coerceIn(0, FB_WIDTH - 1)
        val gy = ((ev.y / v.height) * (FB_HEIGHT - 1)).toInt().coerceIn(0, FB_HEIGHT - 1)
        val pressure = (ev.pressure * 4096f).toInt().coerceIn(0, 4096)

        when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                if (isStylus) {
                    DisplayBridge.nativeInjectInput(devIdx, EV_KEY, BTN_TOOL_PEN, 1)
                    DisplayBridge.nativeInjectInput(devIdx, EV_KEY, BTN_TOUCH, 1)
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_X, gx)
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_Y, gy)
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_PRESSURE, pressure)
                } else {
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_MT_SLOT, 0)
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_MT_TRACKING_ID, 1)
                    DisplayBridge.nativeInjectInput(devIdx, EV_KEY, BTN_TOUCH, 1)
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_MT_POSITION_X, gx)
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_MT_POSITION_Y, gy)
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_MT_PRESSURE, pressure)
                }
                DisplayBridge.nativeInjectInput(devIdx, EV_SYN, SYN_REPORT, 0)
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                if (isStylus) {
                    DisplayBridge.nativeInjectInput(devIdx, EV_KEY, BTN_TOUCH, 0)
                    DisplayBridge.nativeInjectInput(devIdx, EV_KEY, BTN_TOOL_PEN, 0)
                } else {
                    DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_MT_TRACKING_ID, -1)
                    DisplayBridge.nativeInjectInput(devIdx, EV_KEY, BTN_TOUCH, 0)
                }
                DisplayBridge.nativeInjectInput(devIdx, EV_SYN, SYN_REPORT, 0)
            }
            MotionEvent.ACTION_HOVER_MOVE -> if (isStylus) {
                DisplayBridge.nativeInjectInput(devIdx, EV_KEY, BTN_TOOL_PEN, 1)
                DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_X, gx)
                DisplayBridge.nativeInjectInput(devIdx, EV_ABS, ABS_Y, gy)
                DisplayBridge.nativeInjectInput(devIdx, EV_SYN, SYN_REPORT, 0)
            }
        }
    }

    private fun refreshStatus() {
        val hasRootfs = File(rootfsDir, "system/bin/sh").exists()
        val hasDb = metaDbFile.exists()
        val hasRunner = runnerBin.exists() && runnerBin.canExecute()
        statusView.text = "runner=${if (hasRunner) "OK" else "MISSING"} | " +
            "rootfs=${if (hasRootfs) "READY" else "NOT IMPORTED"} | " +
            "meta_db=${if (hasDb) "OK" else "MISSING"} | " +
            "display=${FB_WIDTH}x${FB_HEIGHT}@60Hz"
    }

    private fun setBusy(busy: Boolean) {
        runOnUiThread {
            importBtn.isEnabled = !busy
            selfTestBtn.isEnabled = !busy
            binderTestBtn.isEnabled = !busy
            displayTestBtn.isEnabled = !busy
            runBtn.isEnabled = !busy
            bootIpcBtn.isEnabled = !busy
            bootArtBtn.isEnabled = !busy
            bootFullBtn.isEnabled = !busy
            stopBtn.isEnabled = busy
        }
    }

    private fun appendLog(line: String) {
        runOnUiThread {
            logView.append(line + "\n")
            logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    private fun stopActiveGuest() {
        activeProcess?.destroyForcibly()
        activeProcess = null
        runOnUiThread { displayContainer.visibility = View.GONE }
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
            "echo '--- [3] Pseudo-FS SELinux & Mounts ---'",
            "cat /sys/fs/selinux/enforce; head -n 3 /proc/mounts"
        ).joinToString("\n")
        runGuestShell(script, showDisplay = false)
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
        ).joinToString("\n")
        runGuestShell(script, showDisplay = false)
    }

    private fun runPhase5DisplayTest() {
        if (!fbDemoBin.exists()) {
            appendLog("[ERROR] Missing ${fbDemoBin.absolutePath}")
            return
        }
        // Install guest framebuffer demo into <rootfs>/vendor/bin/vguest_fb_demo
        val vendorBin = File(rootfsDir, "vendor/bin")
        vendorBin.mkdirs()
        val dst = File(vendorBin, "vguest_fb_demo")
        fbDemoBin.copyTo(dst, overwrite = true)
        runCatching { Os.chmod(dst.absolutePath, 0x1ED) } // 0755

        if (!DisplayBridge.nativeInitDisplay(rootfsDir.absolutePath, FB_WIDTH, FB_HEIGHT)) {
            appendLog("[ERROR] Failed to initialize shared framebuffer ring")
            return
        }
        appendLog("[display] Draw on the canvas! Finger = Green, S Pen = Orange (pressure-sensitive). Tap Stop to exit.")
        runGuestShell("/vendor/bin/vguest_fb_demo", showDisplay = true)
    }

    private fun syncVendorEglLibs() {
        val eglDir = File(rootfsDir, "vendor/lib64/egl")
        eglDir.mkdirs()
        for (name in listOf("libEGL_swiftshader.so", "libGLESv1_CM_swiftshader.so", "libGLESv2_swiftshader.so")) {
            val src = File(applicationInfo.nativeLibraryDir, name)
            val dst = File(eglDir, name)
            if (src.exists()) {
                src.copyTo(dst, overwrite = true)
                runCatching { Os.chmod(dst.absolutePath, 0x1ED) }
            }
        }
        val hwDir = File(rootfsDir, "vendor/lib64/hw")
        hwDir.mkdirs()
        fun copyIfChanged(srcName: String, dstFile: File) {
            val src = File(applicationInfo.nativeLibraryDir, srcName)
            if (src.exists()) {
                dstFile.parentFile?.mkdirs()
                src.copyTo(dstFile, overwrite = true)
                runCatching { Os.chmod(dstFile.absolutePath, 0x1ED) }
            }
        }
        copyIfChanged("libvguest_gralloc.so", File(hwDir, "gralloc.virt.so"))
        copyIfChanged("libvguest_gralloc.so", File(hwDir, "gralloc.default.so"))
        copyIfChanged("libvguest_hwcomposer.so", File(hwDir, "hwcomposer.virt.so"))
        copyIfChanged("libvguest_hwcomposer.so", File(hwDir, "hwcomposer.default.so"))
        copyIfChanged("libvguest_mapper20_impl.so", File(hwDir, "android.hardware.graphics.mapper@2.0-impl.so"))
        val vendorHwBin = File(rootfsDir, "vendor/bin/hw")
        copyIfChanged("libvguest_allocator20_svc.so", File(vendorHwBin, "android.hardware.graphics.allocator@2.0-service"))
        copyIfChanged("libvguest_composer21_svc.so", File(vendorHwBin, "android.hardware.graphics.composer@2.1-service"))
        copyIfChanged("libvguest_suspend_svc.so", File(vendorHwBin, "android.system.suspend@1.0-service"))
    }

    private fun runBootStage(stage: String) {
        if (!runnerBin.exists() || !File(rootfsDir, "system/bin/sh").exists()) {
            appendLog("[ERROR] Rootfs or runner missing.")
            return
        }
        syncVendorEglLibs()
        if (stage == "full") {
            DisplayBridge.nativeInitDisplay(rootfsDir.absolutePath, FB_WIDTH, FB_HEIGHT)
        }
        setBusy(true)
        runOnUiThread { displayContainer.visibility = if (stage == "full") View.VISIBLE else View.GONE }
        appendLog("\n=== Launching Phase 6 Boot Stage: $stage ===")
        executor.execute {
            try {
                val args = listOf(
                    runnerBin.absolutePath,
                    "--rootfs", rootfsDir.absolutePath,
                    "--meta-db", metaDbFile.absolutePath,
                    "--boot", stage,
                    "--verbose"
                )
                val proc = ProcessBuilder(args).redirectErrorStream(true).start()
                activeProcess = proc
                BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                    var line: String? = reader.readLine()
                    while (line != null) {
                        appendLog(line)
                        line = reader.readLine()
                    }
                }
                val rc = proc.waitFor()
                appendLog("=== Boot stage '$stage' exited with code $rc ===")
            } catch (t: Throwable) {
                appendLog("[ERROR] Boot failed: ${t.javaClass.simpleName}: ${t.message}")
            } finally {
                activeProcess = null
                setBusy(false)
            }
        }
    }

    private fun runGuestShell(shellCmd: String, showDisplay: Boolean) {
        if (!runnerBin.exists()) {
            appendLog("[ERROR] Missing ${runnerBin.absolutePath}")
            return
        }
        if (!File(rootfsDir, "system/bin/sh").exists()) {
            appendLog("[ERROR] Rootfs not imported yet. Tap 'Import' first.")
            return
        }
        syncVendorEglLibs()

        setBusy(true)
        runOnUiThread {
            displayContainer.visibility = if (showDisplay) View.VISIBLE else View.GONE
        }
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
                activeProcess = proc

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
                activeProcess = null
                setBusy(false)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopActiveGuest()
        DisplayBridge.nativeDetachSurface()
        executor.shutdownNow()
    }
}
