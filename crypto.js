/**
 * 可直接在 Chrome Console 中执行的加盐对称加解密算法
 * 使用 Web Crypto API 实现, 使用 AES-GCM 算法
 * Tips:
 *  1. AES-GCM 是一种 AEAD（Authenticated Encryption with Associated Data）加密模式，它自带填充（padding），所以不需要设置额外的填充方式
 *  2. AES-GCM 的 IV 长度固定为 12 字节，不可更改, 并且暴露在外面也是安全的
 *  3. 为了保持简单, 这里将 IV、Salt、密文拼接后再进行 Base64 编码, 以便于保存和传输
 *  4. 为了简化记忆 Key, 这里支持用户使用普通字符串作为密钥, 程序会使用 PBKDF2 算法将其转换为密钥
 */

// 加密算法
const encryptionAlgorithm = { name: "AES-GCM", length: 256 };

// 生成盐: 将生成 16 字节的随机值
function generateSalt() {
  return window.crypto.getRandomValues(new Uint8Array(16));
}

// 生成 IV: 将生成 12 字节的随机值
function generateIv() {
  return window.crypto.getRandomValues(new Uint8Array(12));
}

// 导出密钥: 将密钥转换为 Base64 字符串
async function exportKey(key) {
  return arrayBufferToBase64(await crypto.subtle.exportKey("raw", key));
}

// 导入密钥: 将 Base64 字符串转换为密钥
async function importKey(base64Key) {
  const keyBuffer = base64ToArrayBuffer(base64Key);
  return crypto.subtle.importKey("raw", keyBuffer, encryptionAlgorithm, false, [
    "encrypt",
    "decrypt",
  ]);
}

// 辅助函数: 将加密后的 ArrayBuffer 转换为 Base64 字符串, 基于 UTF-8 编码
function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// 辅助函数: 将 Base64 字符串转换为 ArrayBuffer, 基于 UTF-8 编码
function base64ToArrayBuffer(base64) {
  const binaryStr = atob(base64);
  const len = binaryStr.length;
  const byteArray = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    byteArray[i] = binaryStr.charCodeAt(i);
  }
  return byteArray.buffer;
}

// 辅助函数: 将用户输入的普通字符串转换为密钥
async function deriveKeyFromPassword(password, salt) {
  const passwordBuffer = new TextEncoder().encode(password);
  const importedPassword = await crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    importedPassword,
    encryptionAlgorithm,
    true,
    ["encrypt", "decrypt"]
  );
}

// 加密函数: 返回拼接了 IV 和盐值的密文
async function encryptMessage(key, salt, message) {
  const encodedMessage = new TextEncoder().encode(message);
  const iv = generateIv();
  const encrypted = await crypto.subtle.encrypt(
    { name: encryptionAlgorithm.name, iv: iv },
    key,
    encodedMessage
  );

  // 将 iv 和盐值拼接到密文前面
  const resultBuffer = new Uint8Array(
    iv.byteLength + salt.byteLength + encrypted.byteLength
  );
  resultBuffer.set(new Uint8Array(iv), 0);
  resultBuffer.set(new Uint8Array(salt), iv.byteLength);
  resultBuffer.set(new Uint8Array(encrypted), iv.byteLength + salt.byteLength);
  return arrayBufferToBase64(resultBuffer.buffer);
}

// 解密函数: 从输入字符串中分离出 IV、盐值和密文
async function decryptMessage(password, encrypted) {
  const encryptedBuffer = base64ToArrayBuffer(encrypted);
  const iv = encryptedBuffer.slice(0, 12); // 前 12 字节是 IV
  const salt = encryptedBuffer.slice(12, 28); // 接下来的 16 字节是盐值
  const cipherText = encryptedBuffer.slice(28); // 剩余的是密文

  // 使用密码和盐值重新生成密钥，以便在不存储密钥的情况下解密数据
  const key = await deriveKeyFromPassword(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: encryptionAlgorithm.name, iv: iv },
    key,
    cipherText
  );
  return new TextDecoder().decode(new Uint8Array(decrypted));
}

(async () => {
  console.log("============ 运行示例例 ============");

  const password = "123456";
  console.log("Password:", password);

  const salt = generateSalt();
  console.log("Salt:", arrayBufferToBase64(salt));

  const key = await deriveKeyFromPassword(password, salt);
  console.log("Derived key:", await exportKey(key));

  const message = "This is a test message";
  console.log("Original message:", message);

  const encrypted = await encryptMessage(key, salt, message);
  console.log("Encrypted message:", encrypted);

  const decrypted = await decryptMessage(password, encrypted);
  console.log("Decrypted message:", decrypted);
})();
