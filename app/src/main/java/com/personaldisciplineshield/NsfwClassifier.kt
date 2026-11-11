package com.personaldisciplineshield

import android.content.Context
import android.graphics.Bitmap
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

/**
 * Optional on-device image classifier. Put a TFLite model at app/src/main/assets/nsfw.tflite.
 * ASSUMPTIONS (adjust to your model): input [1,H,W,3] float32 scaled 0..1, output [1,N]
 * where the LAST class is "explicit". Many models use different scaling/class order - check yours.
 */
class NsfwClassifier(context: Context) {
    private val interpreter: Interpreter? = try {
        Interpreter(load(context))
    } catch (_: Exception) {
        null
    }

    val available get() = interpreter != null

    fun score(src: Bitmap): Float {
        val i = interpreter ?: return 0f
        val shape = i.getInputTensor(0).shape()
        val h = shape[1]
        val w = shape[2]
        val scaled = Bitmap.createScaledBitmap(src, w, h, true)
        val buf = ByteBuffer.allocateDirect(4 * w * h * 3).order(ByteOrder.nativeOrder())
        val px = IntArray(w * h)
        scaled.getPixels(px, 0, w, 0, 0, w, h)
        for (p in px) {
            buf.putFloat(((p shr 16) and 0xFF) / 255f)
            buf.putFloat(((p shr 8) and 0xFF) / 255f)
            buf.putFloat((p and 0xFF) / 255f)
        }
        if (scaled !== src) scaled.recycle()
        val out = Array(1) { FloatArray(i.getOutputTensor(0).shape()[1]) }
        i.run(buf, out)
        return out[0].last()
    }

    private fun load(c: Context): MappedByteBuffer {
        val fd = c.assets.openFd("nsfw.tflite")
        FileInputStream(fd.fileDescriptor).use {
            return it.channel.map(FileChannel.MapMode.READ_ONLY, fd.startOffset, fd.declaredLength)
        }
    }
}
