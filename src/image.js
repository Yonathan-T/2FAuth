import jsQR from 'jsqr';
import jpeg from 'jpeg-js';
import { PNG } from 'pngjs';

export function decodeQRFromImage(buffer) {
  if (!buffer || buffer.length === 0) {
    throw new Error('Image buffer is empty');
  }

  const uint8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  let pixels;
  let width;
  let height;

  if (uint8[0] === 0x7b || uint8[0] === 0x3c) {
    const textSample = new TextDecoder().decode(uint8.slice(0, 100));
    throw new Error(`Expected image file, received server response: ${textSample}`);
  }

  if (uint8[0] === 0x89 && uint8[1] === 0x50 && uint8[2] === 0x4e && uint8[3] === 0x47) {
    try {
      const png = PNG.sync.read(Buffer.from(uint8));
      pixels = new Uint8ClampedArray(png.data);
      width = png.width;
      height = png.height;
    } catch (err) {
      throw new Error(`Failed to decode PNG pixels: ${err.message}`);
    }
  } else {
    try {
      const rawData = jpeg.decode(uint8, { useTArray: true });
      pixels = new Uint8ClampedArray(rawData.data);
      width = rawData.width;
      height = rawData.height;
    } catch (err) {
      throw new Error(`Failed to decode image pixels: ${err.message}`);
    }
  }

  const qrCode = jsQR(pixels, width, height);

  if (!qrCode || !qrCode.data) {
    throw new Error('No QR code detected in image');
  }

  return qrCode.data;
}
