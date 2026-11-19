package com.vguest.app

import android.system.Os
import com.github.luben.zstd.ZstdInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

object RootfsExtractor {

    fun extractTarZst(
        input: InputStream,
        destBaseDir: File,
        onProgress: (String) -> Unit
    ) {
        val rootfsDir = File(destBaseDir, "rootfs")
        if (rootfsDir.exists()) {
            onProgress("[import] Removing previous rootfs...")
            rootfsDir.deleteRecursively()
        }
        File(destBaseDir, "rootfs_meta.db").delete()

        val canonicalBase = destBaseDir.canonicalPath
        var files = 0
        var dirs = 0
        var symlinks = 0
        val buf = ByteArray(64 * 1024)

        ZstdInputStream(BufferedInputStream(input, 128 * 1024)).use { zstd ->
            TarArchiveInputStream(zstd).use { tar ->
                var entry: TarArchiveEntry? = tar.nextEntry
                while (entry != null) {
                    val cleanName = entry.name.removePrefix("./").removePrefix("/")
                    if (cleanName.isNotEmpty()) {
                        val outFile = File(destBaseDir, cleanName)
                        if (!outFile.canonicalPath.startsWith(canonicalBase)) {
                            throw SecurityException("Tar entry escapes base dir: ${entry.name}")
                        }

                        when {
                            entry.isDirectory -> {
                                outFile.mkdirs()
                                runCatching { Os.chmod(outFile.absolutePath, 0x1ED) } // 0755
                                dirs++
                            }
                            entry.isSymbolicLink -> {
                                outFile.parentFile?.mkdirs()
                                if (outFile.exists() || isSymlink(outFile)) {
                                    outFile.delete()
                                }
                                Os.symlink(entry.linkName, outFile.absolutePath)
                                symlinks++
                            }
                            entry.isLink -> {
                                outFile.parentFile?.mkdirs()
                                val target = File(destBaseDir, entry.linkName.removePrefix("./"))
                                if (outFile.exists()) outFile.delete()
                                if (target.exists()) {
                                    Os.link(target.absolutePath, outFile.absolutePath)
                                }
                            }
                            entry.isFile -> {
                                outFile.parentFile?.mkdirs()
                                if (isSymlink(outFile)) outFile.delete()
                                FileOutputStream(outFile).use { fos ->
                                    while (true) {
                                        val n = tar.read(buf)
                                        if (n <= 0) break
                                        fos.write(buf, 0, n)
                                    }
                                }
                                val isExec = (entry.mode and 0x49) != 0 // 0111
                                val hostMode = if (isExec) 0x1ED else 0x1A4 // 0755 or 0644
                                runCatching { Os.chmod(outFile.absolutePath, hostMode) }
                                files++
                                if (files % 500 == 0) {
                                    onProgress("[import] Extracted $files files, $symlinks symlinks...")
                                }
                            }
                        }
                    }
                    entry = tar.nextEntry
                }
            }
        }
        onProgress("[import] Done: $files files, $dirs dirs, $symlinks symlinks.")
    }

    private fun isSymlink(file: File): Boolean {
        return try {
            val st = Os.lstat(file.absolutePath)
            (st.st_mode and 0xF000) == 0xA000 // S_IFLNK
        } catch (_: Throwable) {
            false
        }
    }
}
