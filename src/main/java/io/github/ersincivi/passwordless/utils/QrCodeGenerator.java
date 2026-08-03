package io.github.ersincivi.passwordless.utils;

import java.io.ByteArrayOutputStream;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

public class QrCodeGenerator {

    private static final String QR_CODE_FORMAT = "PNG";

    private QrCodeGenerator() {
    }

    public static byte[] generateQrCodeImage(String totpUri, int width, int height) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(totpUri, BarcodeFormat.QR_CODE, width, height);

        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, QR_CODE_FORMAT, pngOutputStream);
        return pngOutputStream.toByteArray();
    }

}
