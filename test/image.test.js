import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeQRFromImage } from '../src/image.js';

test('decodeQRFromImage rejects null or empty buffer', () => {
  assert.throws(() => decodeQRFromImage(null), /Image buffer is empty/);
  assert.throws(() => decodeQRFromImage(new Uint8Array(0)), /Image buffer is empty/);
});

test('decodeQRFromImage throws descriptive error on corrupt image data', () => {
  const garbage = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  assert.throws(() => decodeQRFromImage(garbage), /Failed to decode image pixels/);
});
