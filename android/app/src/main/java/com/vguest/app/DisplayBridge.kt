package com.vguest.app

import android.view.Surface

object DisplayBridge {
    init {
        System.loadLibrary("vguest_display")
    }

    external fun nativeInitDisplay(rootfsPath: String, width: Int, height: Int): Boolean
    external fun nativeAttachSurface(surface: Surface)
    external fun nativeDetachSurface()
    external fun nativeInjectInput(devIdx: Int, type: Int, code: Int, value: Int)
}
